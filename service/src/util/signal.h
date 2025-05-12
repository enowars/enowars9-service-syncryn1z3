#pragma once

#include <signal.h>
#include <stdio.h>

static inline int util_block_signals() {
    int ret;

    sigset_t set;
    
    sigfillset(&set);

    ret = sigprocmask(SIG_BLOCK, &set, NULL);
    if (ret) {                                           
        perror("sigprocmask failed");                                                  
        return ret;
    }

    return 0;
}

static inline int util_wait_for_exit() {
    int ret;

    sigset_t set;
    int signal;

    sigemptyset(&set);
    //sigaddset(&set, SIGINT); // Disabled for debugging
    sigaddset(&set, SIGTERM);

    ret = sigprocmask(SIG_BLOCK, &set, NULL);
    if (ret) {                                           
        perror("sigprocmask failed");                                                  
        return ret;
    }

    ret = sigwait(&set, &signal);
    if (ret) {                                           
        perror("sigwait failed");                                                  
        return ret;
    }

    return 0;
}
