#pragma once

#include <stdint.h>

static inline __attribute__((always_inline)) uint64_t util_get_time() {
    uint64_t tsc;

    asm volatile ("rdtsc" : "=a" (tsc));

    return tsc;
}
