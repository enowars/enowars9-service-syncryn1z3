#pragma once

#include <stdint.h>

static inline __attribute__((always_inline)) uint64_t util_get_time() {
    register uint32_t tsc_high;
    register uint32_t tsc_low;
    register uint64_t tsc;

    asm volatile ("rdtsc" : "=d"(tsc_high), "=a"(tsc_low));

    tsc = (((uint64_t)tsc_high) << 32) | ((uint64_t)tsc_low);

    return tsc;
}
