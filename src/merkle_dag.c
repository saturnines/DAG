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

    // Single contiguous arena allocation with framing header.
    // Layout: [key_len:4][value_len:4][parent_count:4][key][value][parents]
    size_t parents_size = parent_count * DAG_HASH_SIZE;
    size_t total = 4 + 4 + 4 + key_len + value_len + parents_size;

    uint8_t *block = arena_alloc(dag->arena, total);
    if (!block) return NULL;

    // now allocate node from slab
    dag_node_t *node = ring_slab_alloc(dag->slab);
    if (!node) return NULL;  // arena bytes leaked, reclaimed on reset

    // Write header
    uint32_t klen32 = (uint32_t)key_len;
    uint32_t vlen32 = (uint32_t)value_len;
    uint32_t pcount32 = parent_count;
    memcpy(block,     &klen32,   4);
    memcpy(block + 4, &vlen32,   4);
    memcpy(block + 8, &pcount32, 4);

    // Write data and set node pointers into the block
    uint8_t *p = block + 12;

    memcpy(p, key, key_len);
    node->key = p;
    node->key_len = key_len;
    p += key_len;

    memcpy(p, value, value_len);
    node->value = p;
    node->value_len = value_len;
    p += value_len;

    if (parent_count > 0) {
        memcpy(p, parents, parents_size);
        node->parents = p;
    } else {
        node->parents = NULL;
    }
    node->parent_count = parent_count;

    // copy hash
    memcpy(node->hash, hash, DAG_HASH_SIZE);

    // Depth recomputed at sort time in dag_iter_topo()
    node->depth = 0;

    // Track parent references and update tips
    for (uint32_t i = 0; i < parent_count; i++) {
        const uint8_t *parent_hash = parents + (i * DAG_HASH_SIZE);

        hash_set_entry_t *ref;
        HASH_FIND(hh, dag->referenced_as_parent, parent_hash, DAG_HASH_SIZE, ref);
        if (!ref) {
            ref = malloc(sizeof(hash_set_entry_t));
            if (ref) {
                memcpy(ref->hash, parent_hash, DAG_HASH_SIZE);
                HASH_ADD(hh, dag->referenced_as_parent, hash, DAG_HASH_SIZE, ref);
            }
        }

        dag_node_t *par = dag_find(dag, parent_hash);
        if (par) {
            dag_node_t *in_tips;
            HASH_FIND(hh_tips, dag->tips, par->hash, DAG_HASH_SIZE, in_tips);
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
    size_t max = *count;  // caller sets max capacity
    size_t i = 0;
    dag_node_t *node, *tmp;
    HASH_ITER(hh_tips, dag->tips, node, tmp) {
        if (i >= max) break;
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

static int hash_in_set(const uint8_t *hash, const uint8_t *set, size_t set_count) {
    for (size_t i = 0; i < set_count; i++) {
        if (memcmp(hash, set + (i * DAG_HASH_SIZE), DAG_HASH_SIZE) == 0) {
            return 1;
        }
    }
    return 0;
}

void dag_iter_topo_excluding(merkle_dag_t *dag, dag_iter_fn fn, void *ctx,
                              const uint8_t *exclude, size_t excl_count) {
    if (!exclude || excl_count == 0) {
        dag_iter_topo(dag, fn, ctx);
        return;
    }

    size_t count = dag_count(dag);
    if (count == 0) return;

    dag_node_t **nodes = malloc(count * sizeof(dag_node_t *));
    if (!nodes) return;

    size_t i = 0;
    dag_node_t *node, *tmp;
    HASH_ITER(hh, dag->nodes, node, tmp) {
        node->depth = UINT32_MAX;
        nodes[i++] = node;
    }

    for (size_t j = 0; j < count; j++) {
        recompute_depth(nodes[j], dag);
    }

    qsort(nodes, count, sizeof(dag_node_t *), compare_nodes);

    for (size_t j = 0; j < count; j++) {
        if (!hash_in_set(nodes[j]->hash, exclude, excl_count)) {
            fn(nodes[j], ctx);
        }
    }

    free(nodes);
}

// Note: maybe add a per-block checksum or a trailing magic word.

merkle_dag_t *dag_create_durable(size_t max_nodes, size_t arena_size,
                                  const char *arena_path) {
    merkle_dag_t *dag = malloc(sizeof(merkle_dag_t));
    if (!dag) return NULL;

    dag->slab = ring_slab_create(sizeof(dag_node_t), max_nodes);
    if (!dag->slab) {
        free(dag);
        return NULL;
    }

    dag->arena = arena_create_mmap(arena_size, arena_path);
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


int dag_recover_from_arena(merkle_dag_t *dag) {
    if (!dag || !dag->arena || !dag->arena->is_mmap) return 0;

    uint8_t *mem = (uint8_t *)dag->arena->memory;
    size_t cap = dag->arena->capacity;
    size_t offset = 0;
    int count = 0;

    while (offset + 12 <= cap) {
        uint8_t *block = mem + offset;

        uint32_t klen, vlen, pcount;
        memcpy(&klen, block, 4);
        memcpy(&vlen, block + 4, 4);
        memcpy(&pcount, block + 8, 4);

        // Zero header means end of data (arena was zeroed past used)
        if (klen == 0 && vlen == 0 && pcount == 0) break;

        // Sanity checks
        size_t parents_size = pcount * DAG_HASH_SIZE;
        size_t total = 12 + klen + vlen + parents_size;
        size_t aligned = (total + 7) & ~7;

        if (offset + total > cap) break;  // truncated entry
        if (klen > 1024 * 1024 || vlen > 16 * 1024 * 1024) break;  // corrupt

        uint8_t *key = block + 12;
        uint8_t *value = key + klen;
        uint8_t *parents = (pcount > 0) ? value + vlen : NULL;

        // dag_add computes hash and deduplicates.
        // It will try to arena_alloc — but the data is already in the
        // arena from the mmap. We need to reconstruct without double-allocating.
        dag_add(dag, key, klen, value, vlen, parents, pcount);
        count++;

        offset += aligned;
    }

    // Set arena->used to the end of what we walked, so new allocs
    // append after recovered data.
    dag->arena->used = offset;

    return count;
}

int dag_msync(merkle_dag_t *dag, size_t offset, size_t len) {
    if (!dag || !dag->arena) return -1;
    return arena_msync(dag->arena, offset, len);
}