#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/user.h>

#define CHARACTER_SLEEP_TIME 0x1000 // 4096 cycles / ~0.9us @ 2.3GHz

static inline uint64_t __attribute__((always_inline)) _rdtsc() {
    register uint32_t hi;
    register uint32_t lo;

    __asm__ volatile("rdtsc": "=a"(lo), "=d"(hi));

    return ((uint64_t)hi << 32) | lo;
}

int __attribute__((section(".ext"))) strncmp(const char *a, const char *b, size_t len) {
    register int ret = 0;
    
    while (true) {
        __asm__ volatile("1:");  

        if (!len) {
            return ret;
        }

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
        --len;

        // Will be overwritten on load
        __asm__ volatile("injection:"); 
        __asm__ volatile("jmp 1b");

        register uint64_t t1;
        register uint64_t t2;

        t1 = _rdtsc();

        // Slow down each iteration
        do {
            t2 = _rdtsc();
        } while (t2 - t1 < CHARACTER_SLEEP_TIME);
    }
}

static inline void *__attribute__((always_inline)) _page_down(void *p) {
    return (void *)((uint64_t)p & PAGE_MASK);
}

int _init() {
    int ret;

    // Overwrite unconditional jump with NOPs
    __asm__ volatile("lea injection(%rip), %rax");
    __asm__ volatile("movw $0x9090, (%rax)");

    // Remove write permission
    ret = mprotect(_page_down((void *)(&strncmp)), PAGE_SIZE, PROT_READ | PROT_EXEC);
    if (ret) {
        exit(ret);
    }

    return 0;
}

void _fini() {
    return;
}
