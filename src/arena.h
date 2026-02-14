#ifndef DAG_ARENA_H
#define DAG_ARENA_H

#include <stddef.h>
#include <stdbool.h>

typedef struct {
    void  *memory;
    size_t capacity;
    size_t used;
    int    fd;        // -1 if anonymous (malloc-backed)
    bool   is_mmap;
} arena_t;

// Anonymous (volatile) arena — existing behavior
arena_t *arena_create(size_t capacity);

// File-backed (durable) arena — mmap(MAP_SHARED, fd)
// Creates or opens the file. On open, restores `used` from file size.
arena_t *arena_create_mmap(size_t capacity, const char *path);

void     arena_destroy(arena_t *arena);
void    *arena_alloc(arena_t *arena, size_t size);
void     arena_reset(arena_t *arena);

// Flush dirty pages to disk. No-op on anonymous arenas.
int      arena_msync(arena_t *arena, size_t offset, size_t len);

// diagnostics
size_t   arena_used(const arena_t *arena);
size_t   arena_remaining(const arena_t *arena);

#endif // DAG_ARENA_H