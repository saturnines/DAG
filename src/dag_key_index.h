#ifndef DAG_KEY_INDEX_H
#define DAG_KEY_INDEX_H

#include "merkle_dag.h"
#include <string.h>
#include <stdlib.h>

/* ---- Type ---- */

typedef struct key_index_entry {
    void       *key;
    size_t      key_len;
    dag_node_t *winner;
    UT_hash_handle hh;
} key_index_entry_t;

/* ---- Compare: same rule as compare_nodes in topo sort ---- */

static inline int dag_node_wins(dag_node_t *candidate, dag_node_t *current) {
    if (candidate->depth > current->depth) return 1;
    if (candidate->depth == current->depth &&
        memcmp(candidate->hash, current->hash, DAG_HASH_SIZE) > 0) return 1;
    return 0;
}

/* ---- Update index for one node ---- */

static inline void key_index_update(merkle_dag_t *dag, dag_node_t *node) {
    key_index_entry_t *entry;
    HASH_FIND(hh, dag->key_index, node->key, node->key_len, entry);

    if (!entry) {
        entry = malloc(sizeof(key_index_entry_t));
        if (!entry) return;
        entry->key = node->key;
        entry->key_len = node->key_len;
        entry->winner = node;
        HASH_ADD_KEYPTR(hh, dag->key_index, entry->key, entry->key_len, entry);
        return;
    }

    if (dag_node_wins(node, entry->winner)) {
        entry->winner = node;
    }
}

/* ---- O(1) read ---- */

static inline dag_node_t *dag_get_latest(merkle_dag_t *dag,
                                          const uint8_t *key, size_t key_len) {
    key_index_entry_t *entry;
    HASH_FIND(hh, dag->key_index, key, key_len, entry);
    return entry ? entry->winner : NULL;
}

/* ---- Cleanup ---- */

static inline void key_index_clear(merkle_dag_t *dag) {
    key_index_entry_t *entry, *tmp;
    HASH_ITER(hh, dag->key_index, entry, tmp) {
        HASH_DEL(dag->key_index, entry);
        free(entry);
    }
    dag->key_index = NULL;
}

#endif /* DAG_KEY_INDEX_H */