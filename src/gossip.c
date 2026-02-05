/**
 * gossip.c - Anti-entropy gossip protocol for Merkle DAG
 */

#include <stdlib.h>
#include <string.h>
#include "gossip.h"
#include "dag_serial.h"

// ============================================================================
// Internal State
// ============================================================================

struct gossip {
    int node_id;
    merkle_dag_t *dag;
    gossip_pick_peer_fn pick_peer;
    void *pick_peer_ctx;
    gossip_stats_t stats;
};

// ============================================================================
// Lifecycle
// ============================================================================

gossip_t *gossip_create(const gossip_config_t *cfg) {
    if (!cfg || !cfg->dag) {
        return NULL;
    }

    gossip_t *g = calloc(1, sizeof(gossip_t));
    if (!g) return NULL;

    g->node_id = cfg->node_id;
    g->dag = cfg->dag;
    g->pick_peer = cfg->pick_peer;
    g->pick_peer_ctx = cfg->pick_peer_ctx;

    return g;
}

void gossip_destroy(gossip_t *g) {
    free(g);
}

// ============================================================================
// Protocol: Tick
// ============================================================================

void gossip_tick(gossip_t *g, gossip_send_fn send, void *ctx) {
    if (!g || !send || !g->pick_peer) return;

    // Pick a random peer
    int peer = g->pick_peer(g->pick_peer_ctx);
    if (peer < 0) return;  // No peers

    // Send our root hash
    uint8_t root[DAG_HASH_SIZE];
    dag_root_hash(g->dag, root);

    send(ctx, peer, GOSSIP_SYNC, root, DAG_HASH_SIZE);
    g->stats.syncs_sent++;
}

// ============================================================================
// Protocol: Message Handlers
// ============================================================================

static void handle_sync(gossip_t *g, int from, const uint8_t *data, size_t len,
                        gossip_send_fn send, void *ctx) {
    if (len < DAG_HASH_SIZE) return;

    g->stats.syncs_recv++;

    // Compare roots
    uint8_t my_root[DAG_HASH_SIZE];
    dag_root_hash(g->dag, my_root);

    if (memcmp(my_root, data, DAG_HASH_SIZE) == 0) {
        // Already in sync
        g->stats.already_synced++;
        return;
    }

    // Roots differ, request their tips
    send(ctx, from, GOSSIP_NEED_TIPS, NULL, 0);


    size_t tip_count = dag_tip_count(g->dag);
    if (tip_count > 0) {
        size_t buf_size = 4 + (tip_count * DAG_HASH_SIZE);
        uint8_t *buf = malloc(buf_size);
        if (buf) {
            uint32_t count32 = (uint32_t)tip_count;
            memcpy(buf, &count32, 4);
            dag_get_tips(g->dag, buf + 4, &tip_count);
            send(ctx, from, GOSSIP_TIPS, buf, buf_size);
            free(buf);
        }
    }
}

static void handle_need_tips(gossip_t *g, int from,
                              gossip_send_fn send, void *ctx) {
    size_t tip_count = dag_tip_count(g->dag);
    if (tip_count == 0) {
        // Empty DAG, send empty tips
        uint32_t zero = 0;
        send(ctx, from, GOSSIP_TIPS, (uint8_t*)&zero, 4);
        return;
    }

    // Allocate buffer: count + hashes
    size_t buf_size = 4 + (tip_count * DAG_HASH_SIZE);
    uint8_t *buf = malloc(buf_size);
    if (!buf) return;

    // Write count
    uint32_t count32 = (uint32_t)tip_count;
    memcpy(buf, &count32, 4);

    // Write tip hashes
    dag_get_tips(g->dag, buf + 4, &tip_count);

    send(ctx, from, GOSSIP_TIPS, buf, buf_size);
    free(buf);
}

static void handle_tips(gossip_t *g, int from, const uint8_t *data, size_t len,
                        gossip_send_fn send, void *ctx) {
    if (len < 4) return;

    uint32_t count;
    memcpy(&count, data, 4);

    if (count == 0) return;  // Empty DAG on peer
    if (len < 4 + count * DAG_HASH_SIZE) return;  // Malformed

    const uint8_t *hashes = data + 4;

    // Find tips we don't have
    uint8_t *need = malloc(4 + count * DAG_HASH_SIZE);
    if (!need) return;

    uint32_t need_count = 0;
    uint8_t *need_hashes = need + 4;

    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *hash = hashes + (i * DAG_HASH_SIZE);
        if (!dag_has(g->dag, hash)) {
            memcpy(need_hashes + (need_count * DAG_HASH_SIZE), hash, DAG_HASH_SIZE);
            need_count++;
        }
    }

    if (need_count > 0) {
        memcpy(need, &need_count, 4);
        send(ctx, from, GOSSIP_NEED_NODES, need, 4 + need_count * DAG_HASH_SIZE);
    }

    free(need);
}

static void handle_need_nodes(gossip_t *g, int from, const uint8_t *data, size_t len,
                               gossip_send_fn send, void *ctx) {
    if (len < 4) return;

    uint32_t count;
    memcpy(&count, data, 4);

    if (count == 0) return;
    if (len < 4 + count * DAG_HASH_SIZE) return;

    const uint8_t *hashes = data + 4;

    // Collect requested nodes
    // Buffer: count + serialized nodes
    size_t buf_cap = 4 + (count * 1024);  // Estimate
    uint8_t *buf = malloc(buf_cap);
    if (!buf) return;

    uint32_t found = 0;
    size_t offset = 4;  // Leave room for count

    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *hash = hashes + (i * DAG_HASH_SIZE);
        dag_node_t *node = dag_find(g->dag, hash);

        if (node) {
            ssize_t need = dag_node_serialized_size(node);
            if (need < 0) continue;

            // Grow buffer if needed
            if (offset + need > buf_cap) {
                buf_cap = (offset + need) * 2;
                uint8_t *new_buf = realloc(buf, buf_cap);
                if (!new_buf) {
                    free(buf);
                    return;
                }
                buf = new_buf;
            }

            ssize_t wrote = dag_node_serialize(node, buf + offset, buf_cap - offset);
            if (wrote > 0) {
                offset += wrote;
                found++;
            }
        }
    }

    if (found > 0) {
        memcpy(buf, &found, 4);
        send(ctx, from, GOSSIP_NODES, buf, offset);
        g->stats.nodes_sent += found;
    }

    free(buf);
}

static void handle_nodes(gossip_t *g, int from, const uint8_t *data, size_t len,
                         gossip_send_fn send, void *ctx) {
    if (len < 4) return;

    uint32_t count;
    memcpy(&count, data, 4);

    if (count == 0) return;

    const uint8_t *p = data + 4;
    size_t remaining = len - 4;

    // Track hashes of missing parents
    uint8_t *missing = malloc(count * DAG_HASH_SIZE * 4);  // Worst case: 4 parents per node
    uint32_t missing_count = 0;

    for (uint32_t i = 0; i < count; i++) {
        size_t consumed = 0;
        dag_node_t *node = dag_node_deserialize(g->dag, p, remaining, &consumed);

        if (node) {
            g->stats.nodes_recv++;

            // Check for missing parents
            for (uint32_t j = 0; j < node->parent_count; j++) {
                const uint8_t *parent_hash = node->parents + (j * DAG_HASH_SIZE);
                if (!dag_has(g->dag, parent_hash)) {
                    // Add to missing list if not already there
                    int already = 0;
                    for (uint32_t k = 0; k < missing_count; k++) {
                        if (memcmp(missing + k * DAG_HASH_SIZE, parent_hash, DAG_HASH_SIZE) == 0) {
                            already = 1;
                            break;
                        }
                    }
                    if (!already && missing) {
                        memcpy(missing + missing_count * DAG_HASH_SIZE, parent_hash, DAG_HASH_SIZE);
                        missing_count++;
                    }
                }
            }
        }

        if (consumed == 0) break;  // Parse error
        p += consumed;
        remaining -= consumed;
    }

    // Request missing parents
    if (missing_count > 0 && missing) {
        size_t req_size = 4 + missing_count * DAG_HASH_SIZE;
        uint8_t *req = malloc(req_size);
        if (req) {
            memcpy(req, &missing_count, 4);
            memcpy(req + 4, missing, missing_count * DAG_HASH_SIZE);
            send(ctx, from, GOSSIP_NEED_NODES, req, req_size);
            free(req);
        }
    }

    free(missing);
}

// dispatch
void gossip_recv(gossip_t *g, int from_peer, uint8_t msg_type,
                 const uint8_t *data, size_t len,
                 gossip_send_fn send, void *ctx) {
    if (!g) return;

    switch (msg_type) {
        case GOSSIP_SYNC:
            handle_sync(g, from_peer, data, len, send, ctx);
            break;
        case GOSSIP_NEED_TIPS:
            handle_need_tips(g, from_peer, send, ctx);
            break;
        case GOSSIP_TIPS:
            handle_tips(g, from_peer, data, len, send, ctx);
            break;
        case GOSSIP_NEED_NODES:
            handle_need_nodes(g, from_peer, data, len, send, ctx);
            break;
        case GOSSIP_NODES:
            handle_nodes(g, from_peer, data, len, send, ctx);
            break;
        default:
            break;
    }
}

// ============================================================================
// Stats
// ============================================================================

void gossip_get_stats(gossip_t *g, gossip_stats_t *stats) {
    if (g && stats) {
        *stats = g->stats;
    }
}

void gossip_reset_stats(gossip_t *g) {
    if (g) {
        memset(&g->stats, 0, sizeof(g->stats));
    }
}