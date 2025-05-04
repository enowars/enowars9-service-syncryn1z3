#pragma once

#include <stdint.h>

struct ptp_state;

struct ptp_task {
    uint64_t last_trigger_time_s;
};

struct ptp_tasks {
    uint64_t logical_time_s;

    struct {
        struct {
            struct ptp_task task;
        } announce;

        struct {
            struct ptp_task task;
        } sync;
    } cyclic;

    struct {
        struct {
            struct ptp_task task;
        } handle_message;
    } acyclic;
};

static inline int ptp_try_run_task(struct ptp_tasks *tasks, struct ptp_task *task, uint64_t log_target_interval) {
    if (task->last_trigger_time_s + (1 << log_target_interval) > tasks->logical_time_s) {
        return -1;
    }

    task->last_trigger_time_s = tasks->logical_time_s;

    return 0;
}

int ptp_run_acyclic_tasks(struct ptp_state *state);
int ptp_run_cyclic_tasks(struct ptp_state *state, uint64_t elapsed_time);
