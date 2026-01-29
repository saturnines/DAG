#include <stdlib.h>
#include "ring_slab.h"


ring_slab_t *ring_slab_create(size_t slot_size, size_t slot_count) {

    if (slot_size == 0 || slot_count == 0) {
        return NULL;
    }

    ring_slab_t *ring = malloc(sizeof(ring_slab_t));
    if (!ring) {
        return NULL;
    }

    ring->memory = malloc(slot_size * slot_count);
    if (!ring->memory) {
        free(ring);  // clean up the struct we already allocated
        return NULL;
    }

    ring->slot_size = slot_size;
    ring->slot_count = slot_count;
    ring->head = 0;
    ring->tail = 0;
    return ring;
}

void ring_slab_destroy(ring_slab_t *ring) {
    if (ring == NULL) return;
    free(ring->memory);
    free(ring);
}


size_t ring_slab_count(const ring_slab_t *ring) {
    return (ring->tail - ring->head + ring->slot_count) % ring->slot_count;
}

bool ring_slab_empty(const ring_slab_t *ring) {
    return ring->head == ring->tail;
}

bool ring_slab_full(const ring_slab_t *ring) {
    return (ring->tail + 1) % ring->slot_count == ring->head;
}

size_t ring_slab_capacity(const ring_slab_t *ring) {
    return ring->slot_count;
}

void ring_slab_reset(ring_slab_t *ring) {
    ring->head = 0;
    ring->tail = 0;
}

void *ring_slab_head(const ring_slab_t *ring) {
    return NULL
}

void *ring_slab_at(const ring_slab_t *ring, size_t index) {
    return NULL
}

void ring_slab_pop(ring_slab_t *ring) {
    return NULL
}