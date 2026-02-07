#include <stdlib.h>
#include <string.h>
#include "merkle_dag.h"

#include "sha256.h"

static void compute_hash(uint8_t *out,
                         const uint8_t *key, size_t key_len,
                         const uint8_t *value, size_t value_len,
                         const uint8_t *parents, uint32_t parent_count) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, key, key_len);
    sha256_update(&ctx, value, value_len);
    sha256_update(&ctx, parents, parent_count * 32);
    sha256_final(&ctx, out);
}


merkle_dag_t *dag_create(size_t max_nodes, size_t arena_size) {
    merkle_dag_t *dag = malloc(sizeof(merkle_dag_t));
    if (!dag) return NULL;

    dag->slab = ring_slab_create(sizeof(dag_node_t), max_nodes);
    if (!dag->slab) {
        free(dag);
        return NULL;
    }

    dag->arena = arena_create(arena_size);
    if (!dag->arena) {
        ring_slab_destroy(dag->slab);
        free(dag);
        return NULL;
    }

    dag->nodes = NULL;
    dag->tips = NULL;
    dag->referenced_as_parent = NULL;
    return dag;
}

void dag_destroy(merkle_dag_t *dag) {
    if (!dag) return;
    HASH_CLEAR(hh, dag->nodes);
    HASH_CLEAR(hh_tips, dag->tips);

    hash_set_entry_t *ref, *tmp;
    HASH_ITER(hh, dag->referenced_as_parent, ref, tmp) {
        HASH_DELETE(hh, dag->referenced_as_parent, ref);
        free(ref);
    }

    ring_slab_destroy(dag->slab);
    arena_destroy(dag->arena);
    free(dag);
}

void dag_reset(merkle_dag_t *dag) {
    HASH_CLEAR(hh, dag->nodes);
    HASH_CLEAR(hh_tips, dag->tips);

    hash_set_entry_t *ref, *tmp;
    HASH_ITER(hh, dag->referenced_as_parent, ref, tmp) {
        HASH_DELETE(hh, dag->referenced_as_parent, ref);
        free(ref);
    }

    ring_slab_reset(dag->slab);
    arena_reset(dag->arena);
}

// ============================================================================
// BUG FIX #1: Selective Removal
// ============================================================================

/**
 * Remove only nodes whose hashes appear in the provided list.
 * Nodes NOT in the list survive.  Tips and referenced_as_parent
 * are rebuilt from the remaining nodes.
 *
 * Slab/arena memory for removed nodes is NOT individually freed —
 * those are bulk allocators.  Hash table entries are removed so
 * the nodes become unreachable.  If the DAG is now empty, a full
 * slab/arena reset reclaims everything.
 *
 * @return Number of nodes actually removed.
 */
size_t dag_remove_by_hashes(merkle_dag_t *dag,
                            const uint8_t *hashes, size_t count) {
    if (!dag || !hashes || count == 0) return 0;

    size_t removed = 0;

    // Phase 1: Remove targeted nodes from nodes table and tips
    for (size_t i = 0; i < count; i++) {
        const uint8_t *hash = hashes + (i * DAG_HASH_SIZE);

        dag_node_t *node;
        HASH_FIND(hh, dag->nodes, hash, DAG_HASH_SIZE, node);
        if (!node) continue;

        // Remove from tips if present
        dag_node_t *in_tips;
        HASH_FIND(hh_tips, dag->tips, hash, DAG_HASH_SIZE, in_tips);
        if (in_tips) {
            HASH_DELETE(hh_tips, dag->tips, in_tips);
        }

        // Remove from nodes
        HASH_DELETE(hh, dag->nodes, node);
        removed++;
    }

    if (removed == 0) return 0;

    // If DAG is now empty, full reset reclaims slab/arena
    if (HASH_COUNT(dag->nodes) == 0) {
        HASH_CLEAR(hh_tips, dag->tips);

        hash_set_entry_t *ref, *tmp;
        HASH_ITER(hh, dag->referenced_as_parent, ref, tmp) {
            HASH_DELETE(hh, dag->referenced_as_parent, ref);
            free(ref);
        }

        ring_slab_reset(dag->slab);
        arena_reset(dag->arena);
        return removed;
    }

    // Phase 2: Rebuild referenced_as_parent from remaining nodes
    {
        hash_set_entry_t *ref, *tmp;
        HASH_ITER(hh, dag->referenced_as_parent, ref, tmp) {
            HASH_DELETE(hh, dag->referenced_as_parent, ref);
            free(ref);
        }
    }

    dag_node_t *n, *ntmp;
    HASH_ITER(hh, dag->nodes, n, ntmp) {
        for (uint32_t j = 0; j < n->parent_count; j++) {
            const uint8_t *parent_hash = n->parents + (j * DAG_HASH_SIZE);

            hash_set_entry_t *existing;
            HASH_FIND(hh, dag->referenced_as_parent, parent_hash,
                      DAG_HASH_SIZE, existing);
            if (!existing) {
                existing = malloc(sizeof(hash_set_entry_t));
                if (existing) {
                    memcpy(existing->hash, parent_hash, DAG_HASH_SIZE);
                    HASH_ADD(hh, dag->referenced_as_parent, hash,
                             DAG_HASH_SIZE, existing);
                }
            }
        }
    }

    // Phase 3: Rebuild tips — remaining nodes not referenced as parent
    HASH_CLEAR(hh_tips, dag->tips);

    HASH_ITER(hh, dag->nodes, n, ntmp) {
        hash_set_entry_t *is_parent;
        HASH_FIND(hh, dag->referenced_as_parent, n->hash,
                  DAG_HASH_SIZE, is_parent);
        if (!is_parent) {
            HASH_ADD(hh_tips, dag->tips, hash, DAG_HASH_SIZE, n);
        }
    }

    return removed;
}

/**
 * Collect all node hashes in the DAG into a flat buffer.
 *
 * @param dag       The DAG
 * @param out       Output buffer (caller provides max_count * DAG_HASH_SIZE bytes)
 * @param max_count Maximum hashes to collect
 * @return          Number of hashes written
 */
size_t dag_collect_hashes(merkle_dag_t *dag, uint8_t *out, size_t max_count) {
    if (!dag || !out) return 0;

    size_t i = 0;
    dag_node_t *node, *tmp;
    HASH_ITER(hh, dag->nodes, node, tmp) {
        if (i >= max_count) break;
        memcpy(out + (i * DAG_HASH_SIZE), node->hash, DAG_HASH_SIZE);
        i++;
    }
    return i;
}

// ============================================================================
// Node Insertion
// ============================================================================

dag_node_t *dag_add(merkle_dag_t *dag,
                    const uint8_t *key, size_t key_len,
                    const uint8_t *value, size_t value_len,
                    const uint8_t *parents, uint32_t parent_count) {

    // compute hash first from inputs
    uint8_t hash[DAG_HASH_SIZE];
    compute_hash(hash, key, key_len, value, value_len, parents, parent_count);

    // check dedup before allocating anything
    if (dag_has(dag, hash)) {
        return dag_find(dag, hash);
    }

    // now allocate node from slab
    dag_node_t *node = ring_slab_alloc(dag->slab);
    if (!node) return NULL;

    // copy hash
    memcpy(node->hash, hash, DAG_HASH_SIZE);

    // copy key — FIX: free slab on arena failure
    node->key = arena_alloc(dag->arena, key_len);
    if (!node->key) {
        return NULL;
    }
    memcpy(node->key, key, key_len);
    node->key_len = key_len;

    // copy value
    node->value = arena_alloc(dag->arena, value_len);
    node->value = arena_alloc(dag->arena, value_len);
    if (!node->value) {
        return NULL;
    }
    memcpy(node->value, value, value_len);
    node->value_len = value_len;

    // copy parents
    node->parent_count = parent_count;
    if (parent_count > 0) {
        node->parents = arena_alloc(dag->arena, parent_count * DAG_HASH_SIZE);
        if (!node->parents) {
            return NULL;
        }
        memcpy(node->parents, parents, parent_count * DAG_HASH_SIZE);
    } else {
        node->parents = NULL;
    }

    // Depth is 0 here — recomputed at sort time in dag_iter_topo().
    // This avoids the bug where out-of-order gossip delivery causes
    // wrong depth when child arrives before parent.
    node->depth = 0;

    // Track parent references and update tips
    for (uint32_t i = 0; i < parent_count; i++) {
        const uint8_t *parent_hash = parents + (i * DAG_HASH_SIZE);

        // Mark this hash as referenced as a parent
        hash_set_entry_t *ref;
        HASH_FIND(hh, dag->referenced_as_parent, parent_hash, DAG_HASH_SIZE, ref);
        if (!ref) {
            ref = malloc(sizeof(hash_set_entry_t));
            if (ref) {
                memcpy(ref->hash, parent_hash, DAG_HASH_SIZE);
                HASH_ADD(hh, dag->referenced_as_parent, hash, DAG_HASH_SIZE, ref);
            }
        }

        // Remove parent from tips if it exists (it's no longer a tip)
        dag_node_t *p = dag_find(dag, parent_hash);
        if (p) {
            dag_node_t *in_tips;
            HASH_FIND(hh_tips, dag->tips, p->hash, DAG_HASH_SIZE, in_tips);
            if (in_tips) {
                HASH_DELETE(hh_tips, dag->tips, in_tips);
            }
        }
    }

    // add to nodes table
    HASH_ADD(hh, dag->nodes, hash, DAG_HASH_SIZE, node);

    // Only add to tips if NOT already referenced as a parent
    hash_set_entry_t *already_parent;
    HASH_FIND(hh, dag->referenced_as_parent, hash, DAG_HASH_SIZE, already_parent);
    if (!already_parent) {
        HASH_ADD(hh_tips, dag->tips, hash, DAG_HASH_SIZE, node);
    }

    return node;
}

dag_node_t *dag_find(merkle_dag_t *dag, const uint8_t *hash) {
    dag_node_t *node;
    HASH_FIND(hh, dag->nodes, hash, DAG_HASH_SIZE, node);
    return node;
}

bool dag_has(merkle_dag_t *dag, const uint8_t *hash) {
    return dag_find(dag, hash) != NULL;
}

bool dag_parents_complete(merkle_dag_t *dag, dag_node_t *node) {
    for (uint32_t i = 0; i < node->parent_count; i++) {
        if (!dag_has(dag, node->parents + (i * DAG_HASH_SIZE))) {
            return false;
        }
    }
    return true;
}

size_t dag_tip_count(merkle_dag_t *dag) {
    return HASH_CNT(hh_tips, dag->tips);
}

static int compare_hashes(const void *a, const void *b) {
    return memcmp(a, b, DAG_HASH_SIZE);
}

void dag_root_hash(merkle_dag_t *dag, uint8_t *out) {
    size_t count = dag_tip_count(dag);
    if (count == 0) {
        memset(out, 0, DAG_HASH_SIZE);
        return;
    }

    uint8_t *tip_hashes = malloc(count * DAG_HASH_SIZE);
    if (!tip_hashes) {
        memset(out, 0, DAG_HASH_SIZE);
        return;
    }

    size_t i = 0;
    dag_node_t *node, *tmp;
    HASH_ITER(hh_tips, dag->tips, node, tmp) {
        memcpy(tip_hashes + (i * DAG_HASH_SIZE), node->hash, DAG_HASH_SIZE);
        i++;
    }

    qsort(tip_hashes, count, DAG_HASH_SIZE, compare_hashes);

    SHA256_CTX ctx;
    sha256_init(&ctx);
    for (i = 0; i < count; i++) {
        sha256_update(&ctx, tip_hashes + (i * DAG_HASH_SIZE), DAG_HASH_SIZE);
    }
    sha256_final(&ctx, out);

    free(tip_hashes);
}

void dag_get_tips(merkle_dag_t *dag, uint8_t *out, size_t *count) {
    size_t i = 0;
    dag_node_t *node, *tmp;
    HASH_ITER(hh_tips, dag->tips, node, tmp) {
        memcpy(out + (i * DAG_HASH_SIZE), node->hash, DAG_HASH_SIZE);
        i++;
    }
    *count = i;

    qsort(out, i, DAG_HASH_SIZE, compare_hashes);
}


size_t dag_count(merkle_dag_t *dag) {
    return HASH_COUNT(dag->nodes);
}

// Topo ?
static uint32_t recompute_depth(dag_node_t *node, merkle_dag_t *dag) {
    if (node->depth != UINT32_MAX) return node->depth;

    uint32_t max_parent_depth = 0;

    for (uint32_t i = 0; i < node->parent_count; i++) {
        const uint8_t *parent_hash = node->parents + (i * DAG_HASH_SIZE);
        dag_node_t *parent = dag_find(dag, parent_hash);

        if (parent) {
            uint32_t pd = recompute_depth(parent, dag);
            if (pd + 1 > max_parent_depth) {
                max_parent_depth = pd + 1;
            }
        }

    }

    node->depth = max_parent_depth;
    return max_parent_depth;
}

static int compare_nodes(const void *a, const void *b) {
    dag_node_t *node_a = *(dag_node_t **)a;
    dag_node_t *node_b = *(dag_node_t **)b;

    if (node_a->depth < node_b->depth) return -1;
    if (node_a->depth > node_b->depth) return 1;
    return memcmp(node_a->hash, node_b->hash, DAG_HASH_SIZE);
}

void dag_iter_topo(merkle_dag_t *dag, dag_iter_fn fn, void *ctx) {
    size_t count = dag_count(dag);
    if (count == 0) return;

    dag_node_t **nodes = malloc(count * sizeof(dag_node_t *));
    if (!nodes) return;

    // Collect all nodes, mark depths as uncomputed
    size_t i = 0;
    dag_node_t *node, *tmp;
    HASH_ITER(hh, dag->nodes, node, tmp) {
        node->depth = UINT32_MAX;
        nodes[i++] = node;
    }

    // Recompute depths from actual parent structure
    for (size_t j = 0; j < count; j++) {
        recompute_depth(nodes[j], dag);
    }

    // Sort: depth ascending (roots first), hash for deterministic tiebreak
    qsort(nodes, count, sizeof(dag_node_t *), compare_nodes);

    for (size_t j = 0; j < count; j++) {
        fn(nodes[j], ctx);
    }

    free(nodes);
}