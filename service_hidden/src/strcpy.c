#include <string.h>

char *strcpy(char *dst, const char *src) {
    char *p = dst;

    while (*src) {
        *p = *src;
        ++src;
        ++p;
    }

    *p = '\0';

    return dst;
}
