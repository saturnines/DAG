#ifndef DAG_NODE_POOL_H
#define DAG_NODE_POOL_H

#include <stddef.h>
#include <stdbool.h>


typedef struct node_pool node_pool_t;

node_pool_t *node_pool_create(size_t slot_size, size_t slot_count);
void         node_pool_destroy(node_pool_t *pool);
void        *node_pool_alloc(node_pool_t *pool);
void         node_pool_free(node_pool_t *pool, void *ptr);
void         node_pool_reset(node_pool_t *pool);
size_t       node_pool_count(const node_pool_t *pool);
bool         node_pool_empty(const node_pool_t *pool);
size_t       node_pool_capacity(const node_pool_t *pool);

#endif // DAG_NODE_POOL_H