#ifndef DAG_RING_SLAB_H
#define DAG_RING_SLAB_H

#include <stddef.h>
#include <stdbool.h>

typedef struct {
    void *memory;
    size_t slot_size;
    size_t slot_count;
    size_t head; // next to consume
    size_t tail; // next to produce
} ring_slab_t;

// api

ring_slab_t *ring_slab_create(size_t slot_size, size_t slot_count);
void ring_slab_destroy(ring_slab_t *ring);
void *ring_slab_push(ring_slab_t *ring);    // alloc at tail
void ring_slab_pop(ring_slab_t *ring);      // free from head
void *ring_slab_head(const ring_slab_t *ring);    // peek head
size_t ring_slab_count(const ring_slab_t *ring);
bool ring_slab_full(const ring_slab_t *ring);
bool ring_slab_empty(const ring_slab_t *ring);
void ring_slab_reset(ring_slab_t *ring);


// may be used for DAG traversal:
void *ring_slab_at(const ring_slab_t *ring, size_t index);  // access by offset from head
size_t ring_slab_capacity(const ring_slab_t *ring);         // returns slot_count


#endif //DAG_RING_SLAB_H