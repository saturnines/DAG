#include <stdlib.h>
#include <string.h>
#include "merkle_dag.h"

// rem to use SHA256
static void compute_hash(uint8_t *out,
                         const uint8_t *key, size_t key_len,
                         const uint8_t *value, size_t value_len,
                         const uint8_t *parents, uint32_t parent_count) {

}

merkle_dag_t *dag_create(size_t max_nodes, size_t arena_size) {
    return NULL;
}

void dag_destroy(merkle_dag_t *dag) {

}

void dag_reset(merkle_dag_t *dag) {

}

dag_node_t *dag_add(merkle_dag_t *dag,
                    const uint8_t *key, size_t key_len,
                    const uint8_t *value, size_t value_len,
                    const uint8_t *parents, uint32_t parent_count) {
    return NULL;
}

dag_node_t *dag_find(merkle_dag_t *dag, const uint8_t *hash) {
    return NULL;
}

bool dag_has(merkle_dag_t *dag, const uint8_t *hash) {
    return false;
}

bool dag_parents_complete(merkle_dag_t *dag, dag_node_t *node) {
    return false;
}

size_t dag_tip_count(merkle_dag_t *dag) {
    return 0;
}

void dag_get_tips(merkle_dag_t *dag, uint8_t *out, size_t *count) {

}

void dag_root_hash(merkle_dag_t *dag, uint8_t *out) {

}

size_t dag_count(merkle_dag_t *dag) {
    return 0;
}

void dag_iter_topo(merkle_dag_t *dag, dag_iter_fn fn, void *ctx) {

}