#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <stdlib.h>

#include <util/ring.h>
#include <util/mempool.h>

struct ptp_config {
};

struct ptp_state {
    struct ptp_config *config;

    pthread_t thread;
    volatile bool exit_flag;

    struct util_ring ring;

    struct util_mempool send_mempool;
    struct util_mempool receive_mempool;
};

int ptp_setup(struct ptp_state *state);
int ptp_cleanup(struct ptp_state *state);

int ptp_start(struct ptp_state *state);
int ptp_stop(struct ptp_state *state);

int ptp_enqueue_message(void *user_ptr, uint8_t *buffer, size_t length);
int ptp_dequeue_message(void *user_ptr, uint8_t **buffer, size_t *length);
