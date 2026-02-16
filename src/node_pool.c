#include <stdlib.h>
#include <string.h>
#include "node_pool.h"


typedef struct free_node {
    struct free_node *next;
} free_node_t;

struct node_pool {
    void   *memory;      // Contiguous block of slot_count * slot_size bytes
    size_t  slot_size;
    size_t  slot_count;
    size_t  bump;        // Next never-allocated slot index
    size_t  used;        // Number of currently allocated slots
    free_node_t *free_list;  // Head of freed-slot list
};

node_pool_t *node_pool_create(size_t slot_size, size_t slot_count) {
    if (slot_size < sizeof(free_node_t) || slot_count == 0) {
        return NULL;
    }

    node_pool_t *pool = malloc(sizeof(node_pool_t));
    if (!pool) return NULL;

    pool->memory = malloc(slot_size * slot_count);
    if (!pool->memory) {
        free(pool);
        return NULL;
    }

    pool->slot_size = slot_size;
    pool->slot_count = slot_count;
    pool->bump = 0;
    pool->used = 0;
    pool->free_list = NULL;

    return pool;
}

void node_pool_destroy(node_pool_t *pool) {
    if (!pool) return;
    free(pool->memory);
    free(pool);
}

void *node_pool_alloc(node_pool_t *pool) {
    if (!pool) return NULL;

    void *ptr;

    if (pool->free_list) {
        // Pop from freelist
        ptr = pool->free_list;
        pool->free_list = pool->free_list->next;
    } else if (pool->bump < pool->slot_count) {
        // Bump allocate
        ptr = (char *)pool->memory + (pool->bump * pool->slot_size);
        pool->bump++;
    } else {
        return NULL;  // Pool exhausted
    }

    memset(ptr, 0, pool->slot_size);
    pool->used++;
    return ptr;
}

void node_pool_free(node_pool_t *pool, void *ptr) {
    if (!pool || !ptr) return;

    // Sanity check: ptr must be within our memory block
    char *base = (char *)pool->memory;
    char *p = (char *)ptr;
    if (p < base || p >= base + (pool->slot_count * pool->slot_size)) {
        return;  // Not our pointer
    }

    // Push onto freelist
    free_node_t *node = (free_node_t *)ptr;
    node->next = pool->free_list;
    pool->free_list = node;
    pool->used--;
}

void node_pool_reset(node_pool_t *pool) {
    if (!pool) return;
    pool->bump = 0;
    pool->used = 0;
    pool->free_list = NULL;
}

size_t node_pool_count(const node_pool_t *pool) {
    return pool ? pool->used : 0;
}

bool node_pool_empty(const node_pool_t *pool) {
    return pool ? pool->used == 0 : true;
}

size_t node_pool_capacity(const node_pool_t *pool) {
    return pool ? pool->slot_count : 0;
}