#include "ptp/ptp_peer.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>

#include <ptp/ptp.h>
#include <ptp/ptp_coding.h>
#include <ptp/ptp_tasks.h>
#include <common/common_types.h>
#include <util/signal.h>
#include <util/time.h>
#include <util/ring.h>
#include <util/mempool.h>

static void *thread_worker(void *arg) {
    int ret;

    struct ptp_state *state = (struct ptp_state *)arg;

    int timer_fd;
    int epoll_fd;

    struct itimerspec timer_spec;
    struct epoll_event events[2];

    util_block_signals();

    ret = clock_gettime(CLOCK_MONOTONIC, &timer_spec.it_value);
    if (ret) {
        perror("clock_gettime failed");
        return NULL;
    }

    timer_spec.it_interval.tv_sec = state->config->task_interval_s;
    timer_spec.it_interval.tv_nsec = 0;

    timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (timer_fd < 0) {
        perror("timerfd_create failed");
        exit(EXIT_FAILURE);
    }

    ret = timerfd_settime(timer_fd, TFD_TIMER_ABSTIME, &timer_spec, NULL);
    if (ret){
        perror("timerfd_settime failed");
        exit(EXIT_FAILURE);
    }

    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1 failed");
        exit(EXIT_FAILURE);
    }

    events[0].events = EPOLLIN;
    events[0].data.fd = timer_fd;

    ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &events[0]);
    if (ret) {
        perror("epoll_ctl for timer fd failed");
        exit(EXIT_FAILURE);
    }

    events[1].events = EPOLLIN;
    events[1].data.fd = state->event_fd;

    ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, state->event_fd, &events[1]);
    if (ret) {
        perror("epoll_ctl for event fd failed");
        exit(EXIT_FAILURE);
    }

    while (!state->exit_flag) {
        ret = epoll_wait(epoll_fd, events, 2, 100);
        if (ret < 0) {
            perror("epoll_wait failed");
            continue;
        }

        const int event_count = ret;

        for (int i = 0; i < event_count; ++i) {
            if (events[i].data.fd == timer_fd) {
                uint64_t elapsed_time_s;

                ret = read(timer_fd, &elapsed_time_s, sizeof(elapsed_time_s));
                if (ret != sizeof(elapsed_time_s)) {
                    perror("read on timer fd failed");
                    continue;
                }

                ptp_run_cyclic_tasks(state, elapsed_time_s);
            } else if (events[i].data.fd == state->event_fd) {
                uint64_t value;

                ret = read(state->event_fd, &value, sizeof(value));
                if (ret != sizeof(value)) {
                    perror("read on event fd failed");
                    continue;
                }

                ptp_run_acyclic_tasks(state);
            }
        }
        
    }

    ret = close(epoll_fd);
    if (ret) {
        perror("Failed to close epoll fd");
    }

    ret = close(timer_fd);
    if (ret) {
        perror("Failed to close timer fd");
    }

    return NULL;
}

int ptp_setup(struct ptp_state *state, struct ptp_config *config) {
    int ret;

    memset(state, 0, sizeof(*state));
    state->config = config;

    ret = util_ring_setup(&state->tx_ring, COMMON_RING_SIZE);
    if (ret) {
        return ret;
    }

    ret = util_ring_setup(&state->rx_ring, COMMON_RING_SIZE);
    if (ret) {
        return ret;
    }

    ret = util_mempool_setup(&state->mempool, sizeof(struct common_message_info), COMMON_MEMPOOL_SIZE);
    if (ret) {
        return ret; 
    }

    ret = ptp_peer_db_setup(&state->peer_db, state->config->peer_db_filename);
    if (ret) {
        return ret; 
    }

    return 0;
}
    
int ptp_cleanup(struct ptp_state *state) {
    int ret;

    ret = util_ring_cleanup(&state->tx_ring);
    if (ret) {
        return ret;
    }

    ret = util_ring_cleanup(&state->rx_ring);
    if (ret) {
        return ret;
    }

    ret = util_mempool_cleanup(&state->mempool);
    if (ret) {
        return ret;
    }

    ret = ptp_peer_db_cleanup(&state->peer_db);
    if (ret) {
        return ret; 
    }

    return 0;
}

int ptp_start(struct ptp_state *state) {
    int ret;

    state->event_fd = eventfd(0, EFD_SEMAPHORE);
    if (state->event_fd < 0) {
        perror("eventfd failed");
        return state->event_fd;
    }

    state->exit_flag = false;

    ret = pthread_create(&state->thread, NULL, thread_worker, (void *)state);
    if (ret) {
        perror("pthread_create failed");
        return ret;
    }

    return 0;
}

int ptp_stop(struct ptp_state *state) {
    int ret;

    state->exit_flag = true;

    ret = pthread_join(state->thread, NULL);
    if (ret) {
        perror("pthread_join failed");
        return ret;
    }

    ret = close(state->event_fd);
    if (ret) {
        perror("close for event fd failed");
        return ret;
    }

    return 0;
}

int ptp_enqueue_message(void *user_ptr, struct common_message_info *info) {
    int ret;
    struct ptp_state *state = (struct ptp_state *)user_ptr;

    info->timestamp = util_get_time_ns();

    ret = util_ring_put(&state->rx_ring, info);
    if (ret) {
        return ret;
    }

    // Wakeup worker thread
    const uint64_t message_increment = 1;
    ret = write(state->event_fd, &message_increment, sizeof(message_increment));
    if (ret != sizeof(message_increment)) {
        goto out;
    }

    return 0;

out:
    util_mempool_put(info);
    return ret;
}

int ptp_dequeue_message(void *user_ptr, struct common_message_info **info) {
    struct ptp_state *state = (struct ptp_state *)user_ptr;

    *info = util_ring_get(&state->tx_ring);
    if (!(*info)) {
        return -ENODATA;
    }

    (*info)->timestamp = util_get_time_ns();

    return 0;
}
