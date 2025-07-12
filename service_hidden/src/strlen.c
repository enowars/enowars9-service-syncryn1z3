#include <string.h>

size_t __attribute__((section(".ext"))) strlen(const char *s) {
    register const char *p = s;

    while (*p) {
        ++p;
    }

    return p - s;
}
