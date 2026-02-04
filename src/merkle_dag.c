#include <stdlib.h>
#include <string.h>
#include "merkle_dag.h"

#include <stdio.h>

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
    return dag;
}

void dag_destroy(merkle_dag_t *dag) {
    if (!dag) return;
    HASH_CLEAR(hh, dag->nodes);
    HASH_CLEAR(hh_tips, dag->tips);
    ring_slab_destroy(dag->slab);
    arena_destroy(dag->arena);
    free(dag);
}

void dag_reset(merkle_dag_t *dag) {
    HASH_CLEAR(hh, dag->nodes);
    HASH_CLEAR(hh_tips, dag->tips);
    ring_slab_reset(dag->slab);
    arena_reset(dag->arena);
}

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

    // copy key
    node->key = arena_alloc(dag->arena, key_len);
    if (!node->key) return NULL;
    memcpy(node->key, key, key_len);
    node->key_len = key_len;

    // copy value
    node->value = arena_alloc(dag->arena, value_len);
    if (!node->value) return NULL;
    memcpy(node->value, value, value_len);
    node->value_len = value_len;

    // copy parents
    node->parent_count = parent_count;
    if (parent_count > 0) {
        node->parents = arena_alloc(dag->arena, parent_count * DAG_HASH_SIZE);
        if (!node->parents) return NULL;
        memcpy(node->parents, parents, parent_count * DAG_HASH_SIZE);
    } else {
        node->parents = NULL;
    }

    // compute depth
    node->depth = 0;
    for (uint32_t i = 0; i < parent_count; i++) {
        dag_node_t *p = dag_find(dag, parents + (i * DAG_HASH_SIZE));
        if (p) {
            if (p->depth + 1 > node->depth) {
                node->depth = p->depth + 1;
            }
            dag_node_t *in_tips;
            HASH_FIND(hh_tips, dag->tips, p->hash, DAG_HASH_SIZE, in_tips);
            if (in_tips) {
                size_t before = HASH_COUNT(dag->tips);
                HASH_DELETE(hh_tips, dag->tips, in_tips);
                size_t after = HASH_COUNT(dag->tips);
            }
        }
    }

    // add to nodes table
    HASH_ADD(hh, dag->nodes, hash, DAG_HASH_SIZE, node);
    HASH_ADD(hh_tips, dag->tips, hash, DAG_HASH_SIZE, node);

    dag_node_t *dbg_iter, *dbg_tmp;
    HASH_ITER(hh_tips, dag->tips, dbg_iter, dbg_tmp) {
        printf("  tip node: %p\n", (void*)dbg_iter);
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
    return HASH_CNT(hh_tips, dag->tips);  // NOT HASH_COUNT
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

    // Collect all tip hashes
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

    // Sort for deterministic order
    qsort(tip_hashes, count, DAG_HASH_SIZE, compare_hashes);

    // Hash sorted tips
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

    // Sort for deterministic order
    qsort(out, i, DAG_HASH_SIZE, compare_hashes);
}


size_t dag_count(merkle_dag_t *dag) {
    return HASH_COUNT(dag->nodes);
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

    size_t i = 0;
    dag_node_t *node, *tmp;
    HASH_ITER(hh, dag->nodes, node, tmp) {
        nodes[i++] = node;
    }

    qsort(nodes, count, sizeof(dag_node_t *), compare_nodes);

    for (size_t i = 0; i < count; i++) {
        fn(nodes[i], ctx);
    }

    free(nodes);
}