#include <stdint.h>
#include <stdbool.h>

int __attribute__((section(".ext"))) strcmp(const char *a, const char *b) {
    register int ret;
    
    while (true) {
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
}
