#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#include <ptp/ptp_tasks.h>
#include <ptp/ptp_decoded.h>
#include <ptp/ptp_peer.h>
#include <common/common_types.h>
#include <util/ring.h>
#include <util/mempool.h>

struct ptp_config {
    struct ptp_decoded_port_id port_id;
    uint16_t clock_priority;
    struct ptp_decoded_clock_quality clock_quality;

    uint64_t task_interval_s;
    uint64_t peer_expiration_time_s;

    uint64_t log_announce_interval;
    uint64_t log_sync_interval;

    const char *peer_db_filename;
};

struct ptp_state {
    struct ptp_config *config;

    pthread_t thread;
    volatile bool exit_flag;

    int event_fd;

    struct util_ring tx_ring;
    struct util_ring rx_ring;

    struct util_mempool mempool;

    struct ptp_peer_db peer_db;

    struct ptp_tasks tasks;
};

int ptp_setup(struct ptp_state *state, struct ptp_config *config);
int ptp_cleanup(struct ptp_state *state);

int ptp_start(struct ptp_state *state);
int ptp_stop(struct ptp_state *state);

int ptp_enqueue_message(void *user_ptr, struct common_message_info *info);
int ptp_dequeue_message(void *user_ptr, struct common_message_info **info);
