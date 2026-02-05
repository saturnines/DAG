#ifndef GOSSIP_H
#define GOSSIP_H

#include <stdint.h>
#include <stddef.h>
#include "merkle_dag.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Message Types
// ============================================================================

#define GOSSIP_SYNC       30  // { root_hash[32] }
#define GOSSIP_NEED_TIPS  31  // { } (empty)
#define GOSSIP_TIPS       32  // { count:4, hashes[count][32] }
#define GOSSIP_NEED_NODES 33  // { count:4, hashes[count][32] }
#define GOSSIP_NODES      34  // { count:4, serialized_nodes[] }

// ============================================================================
// Types
// ============================================================================

typedef struct gossip gossip_t;

/**
 * Send callback - called when gossip needs to send a message
 *
 * @param ctx       User context (e.g., network handle)
 * @param to_peer   Destination peer ID
 * @param msg_type  GOSSIP_* message type
 * @param data      Message payload
 * @param len       Payload length
 */
typedef void (*gossip_send_fn)(void *ctx, int to_peer, uint8_t msg_type,
                                const uint8_t *data, size_t len);

/**
 * Peer selection callback - called to pick a random peer
 *
 * @param ctx       User context
 * @return          Peer ID to sync with, or -1 if no peers
 */
typedef int (*gossip_pick_peer_fn)(void *ctx);

/**
 * Gossip configuration
 */
typedef struct {
    int node_id;                    // This node's ID
    merkle_dag_t *dag;              // DAG to sync
    gossip_pick_peer_fn pick_peer;  // Peer selection callback
    void *pick_peer_ctx;            // Context for pick_peer
} gossip_config_t;

// ============================================================================
// Lifecycle
// ============================================================================

/**
 * Create gossip instance
 *
 * @param cfg  Configuration
 * @return     Gossip handle, or NULL on error
 */
gossip_t *gossip_create(const gossip_config_t *cfg);

/**
 * Destroy gossip instance
 */
void gossip_destroy(gossip_t *g);

// ============================================================================
// Protocol
// ============================================================================

/**
 * Periodic tick - initiate sync with random peer
 *
 * Call this every ~50-100ms.
 *
 * @param g     Gossip handle
 * @param send  Send callback
 * @param ctx   Context passed to send callback
 */
void gossip_tick(gossip_t *g, gossip_send_fn send, void *ctx);

/**
 * Handle incoming gossip message
 *
 * @param g         Gossip handle
 * @param from_peer Source peer ID
 * @param msg_type  GOSSIP_* message type
 * @param data      Message payload
 * @param len       Payload length
 * @param send      Send callback for replies
 * @param ctx       Context passed to send callback
 */
void gossip_recv(gossip_t *g, int from_peer, uint8_t msg_type,
                 const uint8_t *data, size_t len,
                 gossip_send_fn send, void *ctx);

// ============================================================================
// Stats (optional, for debugging)
// ============================================================================

typedef struct {
    uint64_t syncs_sent;
    uint64_t syncs_recv;
    uint64_t nodes_sent;
    uint64_t nodes_recv;
    uint64_t already_synced;  // SYNC received, roots matched
} gossip_stats_t;

/**
 * Get gossip statistics
 */
void gossip_get_stats(gossip_t *g, gossip_stats_t *stats);

/**
 * Reset gossip statistics
 */
void gossip_reset_stats(gossip_t *g);

#ifdef __cplusplus
}
#endif

#endif // GOSSIP_H