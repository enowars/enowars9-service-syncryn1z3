#pragma once

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

static inline int util_error(int error, const char *format, ...) {
    int ret;
    va_list va_args;

    va_start(va_args, format);

    if (error < 0) {
        error = -error;
    }

    ret = vfprintf(stderr, format, va_args);
    if (ret < 0) {
        return ret;
    }

    ret = fprintf(stderr, ": %s\n", strerror(error));
    if (ret < 0) {
        return ret;
    }

    return 0;
}
