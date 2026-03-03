#include <stdlib.h>
#include <string.h>
#include "arena.h"


arena_t *arena_create(size_t capacity) {
    if (!capacity) return NULL;

    arena_t *arena = malloc(sizeof(arena_t));
    if (!arena) return NULL;

    arena->memory = malloc(capacity);
    if (!arena->memory) {
        free(arena);
        return NULL;
    }

    arena->capacity = capacity;
    arena->used = 0;
    return arena;
}

void arena_destroy(arena_t *arena) {
    if (!arena) return;
    free(arena->memory);
    free(arena);
}
//
void *arena_alloc(arena_t *arena, size_t size) {
    size = (size + 7) & ~7;  // 8-byte align
    if (size > arena_remaining(arena)) {
        return NULL;
    }

    void *ptr = (char *)arena->memory + arena->used;
    arena->used += size;
    return ptr;
}

void arena_reset(arena_t *arena) {
    arena->used = 0;
}

size_t arena_used(const arena_t *arena) {
    return arena->used;
}

size_t arena_remaining(const arena_t *arena) {
    return arena->capacity - arena->used;
}