#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "merkle_dag.h"
#include "dag_key_index.h"
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

// ============================================================================
// Lifecycle
// ============================================================================

merkle_dag_t *dag_create(size_t max_nodes, size_t arena_size) {
    merkle_dag_t *dag = malloc(sizeof(merkle_dag_t));
    if (!dag) return NULL;

    dag->pool = node_pool_create(sizeof(dag_node_t), max_nodes);
    if (!dag->pool) {
        free(dag);
        return NULL;
    }

    dag->arena = arena_create(arena_size);
    if (!dag->arena) {
        node_pool_destroy(dag->pool);
        free(dag);
        return NULL;
    }

    dag->nodes = NULL;
    dag->tips = NULL;
    dag->referenced_as_parent = NULL;
    dag->key_index = NULL;
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

    key_index_clear(dag);
    node_pool_destroy(dag->pool);
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

    key_index_clear(dag);
    node_pool_reset(dag->pool);
    arena_reset(dag->arena);
}

// ============================================================================
// Selective Removal
// ============================================================================

size_t dag_remove_by_hashes(merkle_dag_t *dag,
                            const uint8_t *hashes, size_t count) {
    if (!dag || !hashes || count == 0) return 0;

    size_t removed = 0;

    /* Phase 1: Build set of hashes being removed (for O(1) lookup) */
    hash_set_entry_t *remove_set = NULL;
    for (size_t i = 0; i < count; i++) {
        hash_set_entry_t *e = malloc(sizeof(hash_set_entry_t));
        if (!e) continue;
        memcpy(e->hash, hashes + (i * DAG_HASH_SIZE), DAG_HASH_SIZE);
        e->refcount = 0;
        HASH_ADD(hh, remove_set, hash, DAG_HASH_SIZE, e);
    }

    /* Phase 2: Remove nodes, fix parent refcounts + tips incrementally.
     * Also track which key_index entries need re-evaluation. */

    for (size_t i = 0; i < count; i++) {
        const uint8_t *hash = hashes + (i * DAG_HASH_SIZE);

        dag_node_t *node;
        HASH_FIND(hh, dag->nodes, hash, DAG_HASH_SIZE, node);
        if (!node) continue;

        /* Check if this node is the key_index winner for its key */
        key_index_entry_t *ki;
        HASH_FIND(hh, dag->key_index, node->key, node->key_len, ki);
        if (ki && ki->winner == node) {
            /* Mark as dirty — winner is being removed, needs re-eval.
             * Set winner to NULL so we can detect it in phase 3. */
            ki->winner = NULL;
        }

        /* Remove from tips */
        dag_node_t *in_tips;
        HASH_FIND(hh_tips, dag->tips, hash, DAG_HASH_SIZE, in_tips);
        if (in_tips) {
            HASH_DELETE(hh_tips, dag->tips, in_tips);
        }

        /* Decrement parent refcounts.  If a parent's refcount hits 0
         * and the parent is still in the DAG (and not being removed),
         * it becomes a new tip. */
        for (uint32_t j = 0; j < node->parent_count; j++) {
            const uint8_t *parent_hash = node->parents + (j * DAG_HASH_SIZE);

            hash_set_entry_t *ref;
            HASH_FIND(hh, dag->referenced_as_parent, parent_hash,
                      DAG_HASH_SIZE, ref);
            if (!ref) continue;

            ref->refcount--;
            if (ref->refcount == 0) {
                HASH_DELETE(hh, dag->referenced_as_parent, ref);
                free(ref);

                /* Parent might become a tip if it's still in the DAG
                 * and not being removed in this batch */
                hash_set_entry_t *in_remove;
                HASH_FIND(hh, remove_set, parent_hash, DAG_HASH_SIZE, in_remove);
                if (!in_remove) {
                    dag_node_t *parent_node;
                    HASH_FIND(hh, dag->nodes, parent_hash, DAG_HASH_SIZE, parent_node);
                    if (parent_node) {
                        dag_node_t *already_tip;
                        HASH_FIND(hh_tips, dag->tips, parent_hash,
                                  DAG_HASH_SIZE, already_tip);
                        if (!already_tip) {
                            HASH_ADD(hh_tips, dag->tips, hash,
                                     DAG_HASH_SIZE, parent_node);
                        }
                    }
                }
            }
        }

        HASH_DELETE(hh, dag->nodes, node);
        node_pool_free(dag->pool, node);
        removed++;
    }

    /* Cleanup remove set */
    {
        hash_set_entry_t *e, *etmp;
        HASH_ITER(hh, remove_set, e, etmp) {
            HASH_DELETE(hh, remove_set, e);
            free(e);
        }
    }

    if (removed == 0) return 0;

    /* Fast path: DAG is now empty */
    if (HASH_COUNT(dag->nodes) == 0) {
        HASH_CLEAR(hh_tips, dag->tips);

        hash_set_entry_t *ref, *tmp;
        HASH_ITER(hh, dag->referenced_as_parent, ref, tmp) {
            HASH_DELETE(hh, dag->referenced_as_parent, ref);
            free(ref);
        }

        key_index_clear(dag);
        node_pool_reset(dag->pool);
        arena_reset(dag->arena);
        return removed;
    }

    /* Phase 3: Fix key_index entries whose winners were removed.
     * Walk remaining nodes ONCE, updating only affected keys. */
    {
        dag_node_t *n, *ntmp;
        HASH_ITER(hh, dag->nodes, n, ntmp) {
            if (n->leader_seq == 0) continue;

            key_index_entry_t *ki;
            HASH_FIND(hh, dag->key_index, n->key, n->key_len, ki);
            if (ki && ki->winner == NULL) {
                /* This key's winner was removed — this node is a candidate */
                ki->winner = n;
            } else if (ki && ki->winner != NULL
                       && ki->winner != n
                       && dag_node_wins(n, ki->winner)) {
                /* Only re-evaluate entries that had their winner removed,
                 * but also update if we find a better winner */
                /* winner is non-NULL here so it's already been set by
                 * a previous node in this loop — just check if n is better */
                ki->winner = n;
            }
        }

        /* Remove key_index entries that still have NULL winner
         * (no remaining node has that key with leader_seq > 0) */
        key_index_entry_t *ki, *kitmp;
        HASH_ITER(hh, dag->key_index, ki, kitmp) {
            if (ki->winner == NULL) {
                HASH_DEL(dag->key_index, ki);
                free(ki);
            }
        }
    }

    return removed;
}

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

    uint8_t hash[DAG_HASH_SIZE];
    compute_hash(hash, key, key_len, value, value_len, parents, parent_count);

    dag_node_t *existing;
    HASH_FIND(hh, dag->nodes, hash, DAG_HASH_SIZE, existing);
    if (existing) return existing;

    /* Single contiguous arena allocation with framing header.
     * Layout: [key_len:4][value_len:4][parent_count:4][key][value][parents] */
    size_t parents_size = parent_count * DAG_HASH_SIZE;
    size_t total = 4 + 4 + 4 + key_len + value_len + parents_size;

    uint8_t *block = arena_alloc(dag->arena, total);
    if (!block) return NULL;

    dag_node_t *node = node_pool_alloc(dag->pool);
    if (!node) return NULL;

    /* Write header */
    uint32_t klen32 = (uint32_t)key_len;
    uint32_t vlen32 = (uint32_t)value_len;
    uint32_t pcount32 = parent_count;
    memcpy(block,     &klen32,   4);
    memcpy(block + 4, &vlen32,   4);
    memcpy(block + 8, &pcount32, 4);

    /* Write data and set node pointers into the block */
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

    memcpy(node->hash, hash, DAG_HASH_SIZE);

    /* ---- Track parent references and update tips ---- */

    for (uint32_t i = 0; i < parent_count; i++) {
        const uint8_t *parent_hash = parents + (i * DAG_HASH_SIZE);

        hash_set_entry_t *ref;
        HASH_FIND(hh, dag->referenced_as_parent, parent_hash, DAG_HASH_SIZE, ref);
        if (!ref) {
            ref = malloc(sizeof(hash_set_entry_t));
            if (ref) {
                memcpy(ref->hash, parent_hash, DAG_HASH_SIZE);
                ref->refcount = 1;
                HASH_ADD(hh, dag->referenced_as_parent, hash, DAG_HASH_SIZE, ref);
            }
        } else {
            ref->refcount++;
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

    /* ---- Add to nodes table ---- */

    HASH_ADD(hh, dag->nodes, hash, DAG_HASH_SIZE, node);

    /* ---- Add to tips if not already referenced as parent ---- */

    hash_set_entry_t *already_parent;
    HASH_FIND(hh, dag->referenced_as_parent, hash, DAG_HASH_SIZE, already_parent);
    if (!already_parent) {
        HASH_ADD(hh_tips, dag->tips, hash, DAG_HASH_SIZE, node);
    }

    /* ---- Eager depth computation + key index ---- */

    if (parent_count == 0) {
        node->depth = 0;
        key_index_update(dag, node);
    } else if (dag_parents_complete(dag, node)) {
        uint32_t max_depth = 0;
        for (uint32_t i = 0; i < parent_count; i++) {
            dag_node_t *par = dag_find(dag, parents + (i * DAG_HASH_SIZE));
            if (par && par->depth + 1 > max_depth) {
                max_depth = par->depth + 1;
            }
        }
        node->depth = max_depth;
        key_index_update(dag, node);
    } else {
        /*
         * Fix #8: Use UINT32_MAX sentinel for "depth unresolved"
         * instead of 0.  Depth 0 is valid for root nodes, so using
         * it as a sentinel caused the fix-up loop to skip real
         * orphans whose parents happened to also be orphans at
         * depth 0.  UINT32_MAX matches the convention in
         * recompute_depth() for topo sort.
         */
        node->depth = UINT32_MAX;
    }

    return node;
}

// ============================================================================
// Lookup
// ============================================================================

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

// ============================================================================
// Tips
// ============================================================================

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
    size_t max = *count;
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

// ============================================================================
// Topo Sort — leader_seq primary, no depth recomputation
// ============================================================================

static uint32_t ensure_depth(dag_node_t *node, merkle_dag_t *dag) {
    if (node->depth != UINT32_MAX) return node->depth;

    uint32_t max_pd = 0;
    for (uint32_t i = 0; i < node->parent_count; i++) {
        dag_node_t *par = dag_find(dag, node->parents + (i * DAG_HASH_SIZE));
        if (par) {
            uint32_t pd = ensure_depth(par, dag);
            if (pd != UINT32_MAX && pd + 1 > max_pd)
                max_pd = pd + 1;
        }
    }
    node->depth = max_pd;
    return max_pd;
}

static int compare_nodes_fast(const void *a, const void *b) {
    dag_node_t *na = *(dag_node_t **)a;
    dag_node_t *nb = *(dag_node_t **)b;

    if (na->leader_seq > 0 && nb->leader_seq > 0) {
        if (na->leader_seq < nb->leader_seq) return -1;
        if (na->leader_seq > nb->leader_seq) return 1;
        return 0;
    }
    if (na->leader_seq > 0) return -1;
    if (nb->leader_seq > 0) return 1;

    if (na->depth < nb->depth) return -1;
    if (na->depth > nb->depth) return 1;
    return memcmp(na->hash, nb->hash, DAG_HASH_SIZE);
}

void dag_iter_topo(merkle_dag_t *dag, dag_iter_fn fn, void *ctx) {
    size_t count = dag_count(dag);
    if (count == 0) return;

    dag_node_t **nodes = malloc(count * sizeof(dag_node_t *));
    if (!nodes) return;

    size_t i = 0;
    dag_node_t *node, *tmp;
    HASH_ITER(hh, dag->nodes, node, tmp) {
        if (node->depth == UINT32_MAX)
            ensure_depth(node, dag);
        nodes[i++] = node;
    }

    qsort(nodes, count, sizeof(dag_node_t *), compare_nodes_fast);

    for (size_t j = 0; j < count; j++)
        fn(nodes[j], ctx);

    free(nodes);
}

typedef struct {
    uint8_t         hash[DAG_HASH_SIZE];
    UT_hash_handle  hh;
} excl_entry_t;

void dag_iter_topo_excluding(merkle_dag_t *dag, dag_iter_fn fn, void *ctx,
                              const uint8_t *exclude, size_t excl_count) {
    if (!exclude || excl_count == 0) {
        dag_iter_topo(dag, fn, ctx);
        return;
    }

    size_t total = dag_count(dag);
    if (total == 0) return;

    excl_entry_t *excl_set = NULL;
    for (size_t i = 0; i < excl_count; i++) {
        excl_entry_t *e = malloc(sizeof(excl_entry_t));
        if (!e) continue;
        memcpy(e->hash, exclude + (i * DAG_HASH_SIZE), DAG_HASH_SIZE);
        HASH_ADD(hh, excl_set, hash, DAG_HASH_SIZE, e);
    }

    dag_node_t **nodes = malloc(total * sizeof(dag_node_t *));
    if (!nodes) goto cleanup;

    size_t count = 0;
    dag_node_t *node, *tmp;
    HASH_ITER(hh, dag->nodes, node, tmp) {
        excl_entry_t *found = NULL;
        HASH_FIND(hh, excl_set, node->hash, DAG_HASH_SIZE, found);
        if (found) continue;
        if (node->depth == UINT32_MAX)
            ensure_depth(node, dag);
        nodes[count++] = node;
    }

    qsort(nodes, count, sizeof(dag_node_t *), compare_nodes_fast);

    for (size_t j = 0; j < count; j++)
        fn(nodes[j], ctx);

    free(nodes);

cleanup:
    {
        excl_entry_t *e, *etmp;
        HASH_ITER(hh, excl_set, e, etmp) {
            HASH_DELETE(hh, excl_set, e);
            free(e);
        }
    }
}

// ============================================================================
// Durable DAG (mmap-backed)
// ============================================================================

merkle_dag_t *dag_create_durable(size_t max_nodes, size_t arena_size,
                                  const char *arena_path) {
    merkle_dag_t *dag = malloc(sizeof(merkle_dag_t));
    if (!dag) return NULL;

    dag->pool = node_pool_create(sizeof(dag_node_t), max_nodes);
    if (!dag->pool) {
        free(dag);
        return NULL;
    }

    dag->arena = arena_create_mmap(arena_size, arena_path);
    if (!dag->arena) {
        node_pool_destroy(dag->pool);
        free(dag);
        return NULL;
    }

    dag->nodes = NULL;
    dag->tips = NULL;
    dag->referenced_as_parent = NULL;
    dag->key_index = NULL;
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

        if (klen == 0 && vlen == 0 && pcount == 0) break;

        size_t parents_size = pcount * DAG_HASH_SIZE;
        size_t total = 12 + klen + vlen + parents_size;
        size_t aligned = (total + 7) & ~7;  // matches arena_alloc 8-byte alignment

        if (offset + total > cap) break;
        if (klen > 1024 * 1024 || vlen > 16 * 1024 * 1024) break;

        uint8_t *key = block + 12;
        uint8_t *value = key + klen;
        uint8_t *parents = (pcount > 0) ? value + vlen : NULL;

        dag_add(dag, key, klen, value, vlen, parents, pcount);
        count++;

        offset += aligned;
    }

    dag->arena->used = offset;

    return count;
}

int dag_msync(merkle_dag_t *dag, size_t offset, size_t len) {
    if (!dag || !dag->arena) return -1;
    return arena_msync(dag->arena, offset, len);
}