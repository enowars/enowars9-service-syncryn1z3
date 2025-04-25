#pragma once

#include <signal.h>
#include <stdio.h>

static inline int util_wait_for_exit() {
    int ret;

    sigset_t set;
    int signal;

    sigemptyset(&set);

    ret = sigaddset(&set, SIGINT);
    if (ret) {                                           
        perror("sigaddset failed");                                                  
        return ret;
    }

    ret = sigwait(&set, &signal);
    if (ret) {                                           
        perror("sigwait failed");                                                  
        return ret;
    }

    return 0;
}
