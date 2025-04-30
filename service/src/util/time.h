#pragma once

#include <bits/time.h>
#include <stdint.h>
#include <time.h>

static inline __attribute__((always_inline)) uint64_t util_get_time_kernel() {
    int ret;
    struct timespec now;

    ret = clock_gettime(CLOCK_MONOTONIC, &now);

    return now.tv_sec * 1000000000 + now.tv_nsec;
}

static inline __attribute__((always_inline)) uint64_t util_get_time_tsc() {
    register uint32_t tsc_high;
    register uint32_t tsc_low;
    register uint64_t tsc;

    asm volatile ("rdtsc" : "=d"(tsc_high), "=a"(tsc_low));

    tsc = (((uint64_t)tsc_high) << 32) | ((uint64_t)tsc_low);

    // TODO: adjust for CPU frequency
    return tsc;
}

static inline __attribute__((always_inline)) uint64_t util_get_time_ns() {
    return util_get_time_kernel();
}
