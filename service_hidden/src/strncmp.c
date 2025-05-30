#include <stdint.h>
#include <time.h>

#define CHARACTER_SLEEP_TIME 2500

static inline __attribute__((always_inline)) uint64_t get_time() {
    int ret;
    struct timespec now;

    ret = clock_gettime(CLOCK_MONOTONIC, &now);

    return now.tv_sec * 1000000000 + now.tv_nsec;
}

int strncmp(const char *a, const char *b, size_t len) {
    int i;
    int ret;

    uint64_t start_time = get_time();
    
    for (i = 0; i < len; ++i) {
        ret = (int)*a - (int)*b;

        if (ret) {
            goto end;
        }

        if (*a == '\0' || *b == '\0') {
            goto end;
        }

        ++a;
        ++b;
    }

    ret = 0;

end:
    uint64_t target_time = start_time + i * CHARACTER_SLEEP_TIME;

    while (1) {
        uint64_t current_time = get_time();

        if (current_time >= target_time) {
            break;
        }
    }

    return ret;
}
