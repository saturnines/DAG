#include <string.h>
#include "dag_serial.h"

ssize_t dag_node_serialized_size(dag_node_t *node) {
    if (!node) return -1;
    return DAG_SERIAL_NODE_HEADER_SIZE 
         + node->key_len 
         + node->value_len 
         + (node->parent_count * DAG_HASH_SIZE);
}

ssize_t dag_node_serialize(dag_node_t *node, uint8_t *buf, size_t cap) {
    if (!node) return -1;
    
    ssize_t needed = dag_node_serialized_size(node);
    if (needed < 0) return -1;
    
    if (!buf || cap < (size_t)needed) {
        return -needed;  // Return negative of needed size
    }
    
    uint8_t *p = buf;
    
    // Key length
    uint32_t klen = (uint32_t)node->key_len;
    memcpy(p, &klen, 4);
    p += 4;
    
    // Value length
    uint32_t vlen = (uint32_t)node->value_len;
    memcpy(p, &vlen, 4);
    p += 4;
    
    // Parent count
    uint32_t pcount = node->parent_count;
    memcpy(p, &pcount, 4);
    p += 4;
    
    // Key
    if (node->key_len > 0) {
        memcpy(p, node->key, node->key_len);
        p += node->key_len;
    }
    
    // Value
    if (node->value_len > 0) {
        memcpy(p, node->value, node->value_len);
        p += node->value_len;
    }
    
    // Parents
    if (node->parent_count > 0) {
        memcpy(p, node->parents, node->parent_count * DAG_HASH_SIZE);
        p += node->parent_count * DAG_HASH_SIZE;
    }
    
    return needed;
}

dag_node_t *dag_node_deserialize(merkle_dag_t *dag, const uint8_t *buf, size_t len, size_t *consumed) {
    if (!dag || !buf || len < DAG_SERIAL_NODE_HEADER_SIZE) {
        return NULL;
    }
    
    const uint8_t *p = buf;
    
    // Read header
    uint32_t klen, vlen, pcount;
    memcpy(&klen, p, 4);  p += 4;
    memcpy(&vlen, p, 4);  p += 4;
    memcpy(&pcount, p, 4); p += 4;
    
    // Validate lengths
    size_t needed = DAG_SERIAL_NODE_HEADER_SIZE + klen + vlen + (pcount * DAG_HASH_SIZE);
    if (len < needed) {
        return NULL;
    }
    
    // Extract pointers
    const uint8_t *key = (klen > 0) ? p : NULL;
    p += klen;
    
    const uint8_t *value = (vlen > 0) ? p : NULL;
    p += vlen;
    
    const uint8_t *parents = (pcount > 0) ? p : NULL;
    p += pcount * DAG_HASH_SIZE;
    
    // Add to DAG (handles dedup, hash computation)
    dag_node_t *node = dag_add(dag, key, klen, value, vlen, parents, pcount);
    
    if (consumed) {
        *consumed = needed;
    }
    
    return node;
}

// Helper for batch serialization - collects nodes in topo order
typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t written;
    int error;
} serialize_ctx_t;

static void serialize_one(dag_node_t *node, void *ctx) {
    serialize_ctx_t *s = (serialize_ctx_t *)ctx;
    
    if (s->error) return;
    
    ssize_t needed = dag_node_serialized_size(node);
    if (needed < 0 || s->written + (size_t)needed > s->cap) {
        s->error = 1;
        return;
    }
    
    ssize_t wrote = dag_node_serialize(node, s->buf + s->written, s->cap - s->written);
    if (wrote < 0) {
        s->error = 1;
        return;
    }
    
    s->written += (size_t)wrote;
}

// Helper for size calculation
typedef struct {
    size_t total;
} size_ctx_t;

static void sum_size(dag_node_t *node, void *ctx) {
    size_ctx_t *s = (size_ctx_t *)ctx;
    ssize_t sz = dag_node_serialized_size(node);
    if (sz > 0) {
        s->total += (size_t)sz;
    }
}

ssize_t dag_batch_serialized_size(merkle_dag_t *dag) {
    if (!dag) return -1;
    
    size_t count = dag_count(dag);
    if (count == 0) return 4;  // Just the count field
    
    size_ctx_t ctx = { .total = 4 };  // Start with count field
    dag_iter_topo(dag, sum_size, &ctx);
    
    return (ssize_t)ctx.total;
}

ssize_t dag_serialize_batch(merkle_dag_t *dag, uint8_t *buf, size_t cap) {
    if (!dag) return -1;
    
    size_t count = dag_count(dag);
    
    // Need at least 4 bytes for count
    if (!buf || cap < 4) {
        ssize_t needed = dag_batch_serialized_size(dag);
        return (needed > 0) ? -needed : -4;
    }
    
    // Write count
    uint32_t count32 = (uint32_t)count;
    memcpy(buf, &count32, 4);
    
    if (count == 0) {
        return 4;
    }
    
    // Serialize nodes in topo order
    serialize_ctx_t ctx = {
        .buf = buf + 4,
        .cap = cap - 4,
        .written = 0,
        .error = 0
    };
    
    dag_iter_topo(dag, serialize_one, &ctx);
    
    if (ctx.error) {
        return -(ssize_t)(4 + ctx.written + 1024);  // Estimate needed
    }
    
    return (ssize_t)(4 + ctx.written);
}

int dag_deserialize_batch(merkle_dag_t *dag, const uint8_t *buf, size_t len) {
    if (!dag || !buf || len < 4) {
        return -1;
    }
    
    // Read count
    uint32_t count;
    memcpy(&count, buf, 4);
    
    if (count == 0) {
        return 0;
    }
    
    const uint8_t *p = buf + 4;
    size_t remaining = len - 4;
    
    for (uint32_t i = 0; i < count; i++) {
        size_t consumed = 0;
        dag_node_t *node = dag_node_deserialize(dag, p, remaining, &consumed);
        
        if (!node) {
            return -1;  // Deserialize failed
        }
        
        p += consumed;
        remaining -= consumed;
    }
    
    return (int)count;
}

// ============================================================================
// Selective batch serialization (Item 3: only drain confirmed writes)
// ============================================================================

typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   written;
    uint32_t count;
    int      error;
} serialize_excl_ctx_t;

static void serialize_one_counting(dag_node_t *node, void *ctx) {
    serialize_excl_ctx_t *s = (serialize_excl_ctx_t *)ctx;
    if (s->error) return;

    ssize_t needed = dag_node_serialized_size(node);
    if (needed < 0 || s->written + (size_t)needed > s->cap) {
        s->error = 1;
        return;
    }

    ssize_t wrote = dag_node_serialize(node, s->buf + s->written,
                                        s->cap - s->written);
    if (wrote < 0) {
        s->error = 1;
        return;
    }

    s->written += (size_t)wrote;
    s->count++;
}

ssize_t dag_serialize_batch_excluding(merkle_dag_t *dag, uint8_t *buf, size_t cap,
                                       const uint8_t *exclude, size_t excl_count) {
    if (!dag) return -1;
    if (!buf || cap < 4) return -4;

    if (!exclude || excl_count == 0) {
        return dag_serialize_batch(dag, buf, cap);
    }

    // Reserve 4 bytes for count — we'll patch it after iterating
    serialize_excl_ctx_t ctx = {
        .buf = buf + 4,
        .cap = cap - 4,
        .written = 0,
        .count = 0,
        .error = 0,
    };

    dag_iter_topo_excluding(dag, serialize_one_counting, &ctx, exclude, excl_count);

    if (ctx.error) {
        return -(ssize_t)(4 + ctx.written + 1024);
    }

    // Patch count
    memcpy(buf, &ctx.count, 4);

    return (ssize_t)(4 + ctx.written);
}