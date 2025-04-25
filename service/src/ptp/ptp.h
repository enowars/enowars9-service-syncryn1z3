#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#include <common/common_types.h>
#include <util/ring.h>
#include <util/mempool.h>

struct ptp_config {
    uint64_t task_interval_nsec;
};

struct ptp_state {
    struct ptp_config *config;

    pthread_t thread;
    volatile bool exit_flag;

    int event_fd;

    struct util_ring tx_ring;
    struct util_ring rx_ring;

    struct util_mempool mempool;
};

int ptp_setup(struct ptp_state *state);
int ptp_cleanup(struct ptp_state *state);

int ptp_start(struct ptp_state *state);
int ptp_stop(struct ptp_state *state);

int ptp_enqueue_message(void *user_ptr, struct common_message_info *info);
int ptp_dequeue_message(void *user_ptr, struct common_message_info **info);
