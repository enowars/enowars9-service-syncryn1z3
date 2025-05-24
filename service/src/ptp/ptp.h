#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#include <ptp/protocol/ptp_protocol.h>
#include <ptp/tasks/ptp_tasks.h>
#include <ptp/port/ptp_port.h>
#include <common/common_types.h>
#include <util/ring.h>
#include <util/mempool.h>

#define PTP_MAX_RESPONSES 4

struct ptp_config {
    uint16_t clock_priority;
    struct ptp_decoded_clock_quality clock_quality;

    const char *port_db_filename;
};

struct ptp_state {
    struct ptp_config *config;

    int event_fd;

    struct util_ring tx_ring;

    struct common_message_info *request;
    struct common_message_info *reponses[PTP_MAX_RESPONSES]; // TODO: move into extra file
    int num_responses;

    struct util_mempool mempool;

    struct ptp_port_db port_db;
};

int ptp_setup(struct ptp_state *state, struct ptp_config *config);
int ptp_cleanup(struct ptp_state *state);

int ptp_enqueue_message(void *user_ptr, struct common_message_info *info);
int ptp_dequeue_message(void *user_ptr, struct common_message_info **info);
