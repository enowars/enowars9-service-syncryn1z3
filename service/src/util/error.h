#pragma once

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

static inline int util_error_int(int error) {
    if (error < 0) {
        error = -error;
    }

    return error;
}

static inline char *util_error_str(int error) {
    return strerror(util_error_int(error));
}

static inline int util_error(int error, const char *format, ...) {
    int ret;
    va_list va_args;

    va_start(va_args, format);

    ret = vfprintf(stderr, format, va_args);
    if (ret < 0) {
        return ret;
    }

    ret = fprintf(stderr, ": %s\n", util_error_str(error));
    if (ret < 0) {
        return ret;
    }

    return 0;
}
