#pragma once

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdatomic.h>

struct util_ring {
    void **buffer;

    atomic_int head;
    atomic_int tail;

    int length;
};

static inline int util_ring_setup(struct util_ring *ring, int length) {
    ring->buffer = (void **)malloc(sizeof(void *) * length);
    
    if (!ring->buffer) {
        perror("Failed to allocate ring");
        return -ENOMEM;
    }

    ring->length = length;

    atomic_init(&ring->head, 0);
    atomic_init(&ring->tail, 0);

    return 0;
}

static inline int util_ring_cleanup(struct util_ring *ring) {
    free(ring->buffer);

    return 0;
}

static inline void *util_ring_get(struct util_ring *ring) {
    void *result;

    int tail = atomic_load_explicit(&ring->tail, memory_order_relaxed);
    int head = atomic_load_explicit(&ring->head, memory_order_acquire);

    if (tail == head) {
        return NULL;
    }

    result = ring->buffer[tail];
    atomic_store_explicit(&ring->tail, (tail + 1) % ring->length, memory_order_release);
    
    return result;
}

static inline int util_ring_put(struct util_ring *ring, void* item) {
    int head = atomic_load_explicit(&ring->head, memory_order_relaxed);
    int next_head = (head + 1) % ring->length;

    int tail = atomic_load_explicit(&ring->tail, memory_order_acquire);

    if (next_head == tail) {
        return -ENOMEM;
    }

    ring->buffer[head] = item;
    atomic_store_explicit(&ring->head, next_head, memory_order_release);

    return 0;
}

