#pragma once

#include <stdlib.h>
#include <string.h>

#define GUARD_LENGTH 32768

static void *util_safe_malloc(int length) {
    void *result;

    // Allocate with guards
    result = malloc(length + 2 * GUARD_LENGTH);
    if (!result) {
        return result;
    }

    memset(result, 0, length + 2 * GUARD_LENGTH);

    return result + GUARD_LENGTH;
}

static inline void util_safe_free(void *pointer) {
    free(pointer - GUARD_LENGTH);
}
