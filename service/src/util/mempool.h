#pragma once

#include <stdlib.h>
#include <stdio.h>

struct util_mempool;

struct util_mempool_item_descriptor {
    struct util_mempool *mempool;
};

struct util_mempool {
    struct util_mempool_item_descriptor *start;
    struct util_mempool_item_descriptor *end;

    struct util_mempool_item_descriptor *head;
    struct util_mempool_item_descriptor *tail;

    int descriptor_unit_item_size;
};

static inline int util_mempool_setup(struct util_mempool *mempool, int size, int count) {
    int aligned_item_size = sizeof(struct util_mempool_item_descriptor) + size;
    if (size % sizeof(struct util_mempool_item_descriptor)) {
        aligned_item_size += sizeof(struct util_mempool_item_descriptor) - (size % sizeof(struct util_mempool_item_descriptor));
    }

    const int total_size = aligned_item_size * count;
    mempool->descriptor_unit_item_size = aligned_item_size / sizeof(struct util_mempool_item_descriptor);

    mempool->start = (struct util_mempool_item_descriptor *)malloc(total_size);

    if (!mempool->start) {
        perror("Failed to allocate mempool");
        return -1;
    }

    mempool->end = mempool->start + count * mempool->descriptor_unit_item_size;

    for (struct util_mempool_item_descriptor *descriptor = mempool->start; descriptor < mempool->end; descriptor += mempool->descriptor_unit_item_size) {
        descriptor->mempool = mempool;
    }

    mempool->head = mempool->start;
    mempool->tail = mempool->start;

    return 0;
}

static inline int util_mempool_cleanup(struct util_mempool *mempool) {
    free(mempool->start);

    return 0;
}

static inline void *util_mempool_get(struct util_mempool *mempool) {
    struct util_mempool_item_descriptor *descriptor = mempool->head + mempool->descriptor_unit_item_size;

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

    mempool->tail += mempool->descriptor_unit_item_size;

    if (mempool->tail == mempool->end) {
        mempool->tail = mempool->start;
    }

    if (mempool->tail != descriptor) {
        perror("Mempool put operation called out of order");
        exit(-1);
    }
}
