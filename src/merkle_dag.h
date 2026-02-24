#ifndef DAG_MERKLE_DAG_H
#define DAG_MERKLE_DAG_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "uthash.h"
#include "node_pool.h"
#include "arena.h"



#define DAG_HASH_SIZE 32

typedef struct dag_node {
    uint8_t  hash[DAG_HASH_SIZE];   // H(key || value || parents)
    uint8_t *key;                    // arena allocated
    size_t   key_len;
    uint8_t *value;                  // arena allocated
    size_t   value_len;
    uint8_t *parents;                // arena allocated, array of 32-byte hashes
    uint32_t parent_count;
    uint32_t depth;                  // max(parent depths) + 1, for topo sort
    uint64_t leader_seq;        // Leader-assigned total order (§4): (term << 32) | counter
    UT_hash_handle hh;               // for nodes table
    UT_hash_handle hh_tips;          // for tips table
} dag_node_t;

typedef struct {
    uint8_t hash[DAG_HASH_SIZE];
    UT_hash_handle hh;
} hash_set_entry_t;

typedef struct key_index_entry key_index_entry_t;

typedef struct {
    dag_node_t  *nodes;
    dag_node_t  *tips;
    hash_set_entry_t *referenced_as_parent;
    key_index_entry_t *key_index;
    node_pool_t *pool;
    arena_t     *arena;
} merkle_dag_t;


// lifecycle
merkle_dag_t *dag_create(size_t max_nodes, size_t arena_size);
void          dag_destroy(merkle_dag_t *dag);
void          dag_reset(merkle_dag_t *dag);

// write path
dag_node_t   *dag_add(merkle_dag_t *dag,
                      const uint8_t *key, size_t key_len,
                      const uint8_t *value, size_t value_len,
                      const uint8_t *parents, uint32_t parent_count);

// lookup
dag_node_t   *dag_find(merkle_dag_t *dag, const uint8_t *hash);
bool          dag_has(merkle_dag_t *dag, const uint8_t *hash);

// causal completeness
bool          dag_parents_complete(merkle_dag_t *dag, dag_node_t *node);

// tips
size_t        dag_tip_count(merkle_dag_t *dag);
// Copy tip hashes into `out`,  Output is sorted by hash for deterministic ordering.
void          dag_get_tips(merkle_dag_t *dag, uint8_t *out, size_t *count);
void          dag_root_hash(merkle_dag_t *dag, uint8_t *out);

// iteration for commit
size_t        dag_count(merkle_dag_t *dag);
typedef void (*dag_iter_fn)(dag_node_t *node, void *ctx);
void          dag_iter_topo(merkle_dag_t *dag, dag_iter_fn fn, void *ctx);

// Durable arena backed by mmap'd file at `arena_path`.
// Slab remains volatile — rebuilt on recovery.
merkle_dag_t *dag_create_durable(size_t max_nodes, size_t arena_size,
                                  const char *arena_path);

// Walk the mmap'd arena, reconstruct hash tables and pool.
// Call on startup before Raft. Returns number of nodes recovered.
int dag_recover_from_arena(merkle_dag_t *dag);

// Msync the arena range written by the last dag_add.
// No-op if arena is not mmap-backed.
int dag_msync(merkle_dag_t *dag, size_t offset, size_t len);

/**
 * Iterate in topo order, skipping nodes whose hashes appear in the
 * exclusion set.  Used by propose to skip unconfirmed leader writes.
 *
 * @param dag       The DAG
 * @param fn        Callback per node
 * @param ctx       User context
 * @param exclude   Flat buffer of 32-byte hashes to skip
 * @param excl_count Number of hashes in exclude
 */
void          dag_iter_topo_excluding(merkle_dag_t *dag, dag_iter_fn fn, void *ctx,
                                      const uint8_t *exclude, size_t excl_count);


size_t dag_remove_by_hashes(merkle_dag_t *dag,
                            const uint8_t *hashes, size_t count);


size_t dag_collect_hashes(merkle_dag_t *dag, uint8_t *out, size_t max_count);

#endif // DAG_MERKLE_DAG_H