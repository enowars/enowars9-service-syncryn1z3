#include <string.h>

char __attribute__((section(".ext"))) *strcpy(char *dst, const char *src) {
    register char *p = dst;

    while (*src) {
        *p = *src;
        ++src;
        ++p;
    }

    *p = '\0';

    return dst;
}
