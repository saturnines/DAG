#ifndef DAG_SERIAL_H
#define DAG_SERIAL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "merkle_dag.h"

/*
 * Node wire format:
 *   [klen:4][vlen:4][parent_count:4][leader_seq:8][key:klen][value:vlen][parents:32*parent_count]
 *
 * Hash is NOT serialized, recomputed on deserialize (content-addressed).
 *
 * Batch wire format:
 *   [count:4][node1][node2]...[nodeN]
 *
 * Nodes are in topological order (depth ascending, hash tiebreaker).
 */

#define DAG_SERIAL_NODE_HEADER_SIZE 20   // klen + vlen + parent_count

// Single node serialization
ssize_t dag_node_serialize(dag_node_t *node, uint8_t *buf, size_t cap);
ssize_t dag_node_serialized_size(dag_node_t *node);

// Single node deserialization (adds to DAG)
dag_node_t *dag_node_deserialize(merkle_dag_t *dag, const uint8_t *buf, size_t len, size_t *consumed);

// Batch serialization (entire DAG in topo order)
ssize_t dag_serialize_batch(merkle_dag_t *dag, uint8_t *buf, size_t cap);
ssize_t dag_batch_serialized_size(merkle_dag_t *dag);

/**
 * Serialize DAG batch excluding nodes in the exclusion set.
 * Used by leader to skip unconfirmed writes when proposing.
 *
 * @param dag        The DAG
 * @param buf        Output buffer
 * @param cap        Buffer capacity
 * @param exclude    Flat buffer of 32-byte hashes to skip
 * @param excl_count Number of hashes in exclude
 * @return           Bytes written, or negative on error
 */
ssize_t dag_serialize_batch_excluding(merkle_dag_t *dag, uint8_t *buf, size_t cap,
                                       const uint8_t *exclude, size_t excl_count,
                                       uint32_t max_count,
                                       uint8_t *out_hashes, size_t *out_hash_count);

// Batch deserialization (into fresh or existing DAG)
int dag_deserialize_batch(merkle_dag_t *dag, const uint8_t *buf, size_t len);

#endif // DAG_SERIAL_H