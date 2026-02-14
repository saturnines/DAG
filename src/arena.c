#include <stdlib.h>
#include <string.h>
#include "arena.h"


#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>


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
    arena->fd = -1;
    arena->is_mmap = false;
    return arena;
}

arena_t *arena_create_mmap(size_t capacity, const char *path) {
    if (!capacity || !path) return NULL;

    arena_t *arena = malloc(sizeof(arena_t));
    if (!arena) return NULL;

    // Open or create the backing file
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        free(arena);
        return NULL;
    }

    // Check existing file size for recovery
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        free(arena);
        return NULL;
    }

    // Extend file to full capacity if needed
    if ((size_t)st.st_size < capacity) {
        if (ftruncate(fd, (off_t)capacity) < 0) {
            close(fd);
            free(arena);
            return NULL;
        }
    }

    void *mem = mmap(NULL, capacity, PROT_READ | PROT_WRITE,
                     MAP_SHARED, fd, 0);
    if (mem == MAP_FAILED) {
        close(fd);
        free(arena);
        return NULL;
    }

    arena->memory = mem;
    arena->capacity = capacity;
    arena->fd = fd;
    arena->is_mmap = true;

    // Recovery: if file had data, used is restored by the caller
    // (dag_recover_from_arena walks the content and sets this).
    // Fresh file starts at 0.
    arena->used = 0;

    return arena;
}

void arena_destroy(arena_t *arena) {
    if (!arena) return;

    if (arena->is_mmap) {
        munmap(arena->memory, arena->capacity);
        if (arena->fd >= 0) close(arena->fd);
    } else {
        free(arena->memory);
    }

    free(arena);
}

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

    // For mmap: zero the pages so recovery doesn't see ghosts.
    // madvise(DONTNEED) drops dirty pages without writeback —
    // next access gets zeroed pages from the filesystem.
    if (arena->is_mmap) {
        madvise(arena->memory, arena->capacity, MADV_DONTNEED);
    }
}

int arena_msync(arena_t *arena, size_t offset, size_t len) {
    if (!arena->is_mmap) return 0;  // no-op for volatile arenas
    if (len == 0) return 0;

    // Page-align the range
    size_t page_size = 4096;
    size_t start = (offset / page_size) * page_size;
    size_t end = ((offset + len + page_size - 1) / page_size) * page_size;
    if (end > arena->capacity) end = arena->capacity;

    return msync((char *)arena->memory + start, end - start, MS_SYNC);
}

size_t arena_used(const arena_t *arena) {
    return arena->used;
}

size_t arena_remaining(const arena_t *arena) {
    return arena->capacity - arena->used;
}