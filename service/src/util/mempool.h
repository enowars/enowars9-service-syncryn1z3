#pragma once

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <util/error.h>

#define UTIL_MEMPOOL_GUARD_LENGTH 65536

struct util_mempool;

struct util_mempool_item_descriptor {
    struct util_mempool *mempool;
};

struct util_mempool {
    struct util_mempool_item_descriptor *start;
    struct util_mempool_item_descriptor *end;

    struct util_mempool_item_descriptor *head;
    struct util_mempool_item_descriptor *tail;

    int descriptor_unit_item_length;
};

static inline int util_mempool_setup(struct util_mempool *mempool, short length, int count) {
    int aligned_item_length = sizeof(struct util_mempool_item_descriptor) + length;
    if (length % sizeof(struct util_mempool_item_descriptor)) {
        aligned_item_length += sizeof(struct util_mempool_item_descriptor) - (length % sizeof(struct util_mempool_item_descriptor));
    }

    const int total_length = aligned_item_length * count + UTIL_MEMPOOL_GUARD_LENGTH;
    mempool->descriptor_unit_item_length = aligned_item_length / sizeof(struct util_mempool_item_descriptor);

    void *buffer = malloc(total_length);
    if (!buffer) {
        perror("Failed to allocate mempool");
        return -1;
    }
    
    mempool->start = (struct util_mempool_item_descriptor *)(buffer + UTIL_MEMPOOL_GUARD_LENGTH);
    mempool->end = mempool->start + count * mempool->descriptor_unit_item_length;

    for (struct util_mempool_item_descriptor *descriptor = mempool->start; descriptor < mempool->end; descriptor += mempool->descriptor_unit_item_length) {
        descriptor->mempool = mempool;
    }

    mempool->head = mempool->start;
    mempool->tail = mempool->start;

    return 0;
}

static inline int util_mempool_cleanup(struct util_mempool *mempool) {
    free((void *)mempool->start - UTIL_MEMPOOL_GUARD_LENGTH);

    return 0;
}

static inline void *util_mempool_get(struct util_mempool *mempool) {
    struct util_mempool_item_descriptor *descriptor = mempool->head + mempool->descriptor_unit_item_length;

    if (descriptor == mempool->end) {
        descriptor = mempool->start;
    }

    
    if (descriptor == mempool->tail) {
        return NULL;
    }

    mempool->head = descriptor;

    return (void *)(descriptor + 1);
}

static inline void util_mempool_put(void *item) {
    struct util_mempool_item_descriptor *descriptor = ((struct util_mempool_item_descriptor *)item) - 1;
    struct util_mempool *mempool = descriptor->mempool;

    mempool->tail += mempool->descriptor_unit_item_length;

    if (mempool->tail == mempool->end) {
        mempool->tail = mempool->start;
    }

    if (mempool->tail != descriptor) {
        util_error(ENOTRECOVERABLE, "Mempool put operation called out of order");
        exit(-1);
    }
}
