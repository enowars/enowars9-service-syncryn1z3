#include <stdint.h>
#include <time.h>

#define CHARACTER_SLEEP_TIME 0x1000 // 4096 cycles / ~0.9us @ 2.3GHz

static inline uint64_t __attribute__((always_inline)) _rdtsc() {
    register uint32_t hi;
    register uint32_t lo;

    __asm__ volatile ("rdtsc": "=a"(lo), "=d"(hi));

    return ((uint64_t)hi << 32) | lo;
}

static inline void _() {
    register uint64_t t1;
    register uint64_t t2;

    t1 = _rdtsc();

    do {
        t2 = _rdtsc();
    } while (t2 - t1 < CHARACTER_SLEEP_TIME);
}

int strncmp(const char *a, const char *b, size_t len) {
    register int ret;
    
    for (int i = 0; i < len; ++i) {
        _();

        register int reg_a = *a;
        register int reg_b = *b;

        ret = reg_a - reg_b;

        if (ret) {
            return ret;
        }

        if (reg_a == 0 || reg_b == 0) {
            return ret;
        }

        ++a;
        ++b;
    }

    ret = 0;

    return ret;
}
