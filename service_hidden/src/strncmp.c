#include <stdint.h>
#include <time.h>

#define CHARACTER_SLEEP_TIME 2500

static int load_char(const char *c) {
    __asm__ volatile ("mov %0, %%eax" : : "r"(0xB) : "%eax");
    __asm__ __volatile__("cpuid");

    return *c;
}

int strncmp(const char *a, const char *b, size_t len) {
    int ret;
    
    for (int i = 0; i < len; ++i) {
        register int reg_a;
        register int reg_b;
        
        reg_a = load_char(a);
        reg_b = load_char(b);

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
