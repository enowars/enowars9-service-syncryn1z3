#include <stdint.h>
#include <stddef.h>

static int memcmp(const void *a, const void *b, size_t len) {
    int ret = 0;

    uint8_t *byte_a = (uint8_t *)a;
    uint8_t *byte_b = (uint8_t *)b;
    
    // Constant time solution, just so no one tries a timing exploit on memcmp()
    for (size_t i = 0; i < len; ++i) {
        int8_t compare = (int)*byte_a - (int)*byte_b;
        ret ^= ~(!ret - 1) & compare;

        ++byte_a;
        ++byte_b;
    }

    return ret;
}
