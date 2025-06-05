#pragma once

#include <bits/time.h>
#include <stdint.h>
#include <time.h>

static inline uint64_t util_get_time_ns() {
    int ret;
    struct timespec now;

    ret = clock_gettime(CLOCK_MONOTONIC, &now);

    return now.tv_sec * 1000000000 + now.tv_nsec;
}
