#ifndef DAG_ARENA_H
#define DAG_ARENA_H

#include <stddef.h>

typedef struct {
    void *memory;
    size_t capacity;
    size_t used;
} arena_t;

// api

arena_t *arena_create(size_t capacity);
void     arena_destroy(arena_t *arena);
void    *arena_alloc(arena_t *arena, size_t size);
void     arena_reset(arena_t *arena);

// diagnostics
size_t   arena_used(const arena_t *arena);
size_t   arena_remaining(const arena_t *arena);

#endif // DAG_ARENA_H