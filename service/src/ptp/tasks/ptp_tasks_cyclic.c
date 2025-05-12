#include <error.h>

#include <ptp/ptp.h>
#include <ptp/ptp_defaults.h>
#include <ptp/ptp_helper.h>
#include <ptp/protocol/ptp_protocol.h>
#include <ptp/tasks/ptp_tasks.h>
#include <ptp/peer/ptp_peer.h>
#include <common/common_types.h>
#include <string.h>
#include <util/mempool.h>
#include <util/time.h>

static int ptp_send_announce(void *user_ptr, struct ptp_peer *peer) {
    int ret;
    struct ptp_state *state = user_ptr;

    if (!(peer->subscriptions & PTP_PEER_SUBSCRIPTION_ANNOUNCE)) {
        return 0;
    }
    
    struct common_message_info *info;
    ret = ptp_get_and_init_message(state, &info, COMMON_PORT_TYPE_EVENT, 0); // TODO: set correct port
    if (ret) {
        return ret;
    }

    memcpy(&info->address.address, &peer->address, sizeof(info->address.address));
    info->address.length = sizeof(info->address.address);

    info->message.type = PTP_MESSAGE_TYPE_ANNOUNCE;
    info->message.sequence_id = state->tasks.cyclic.announce.sequence_id++;
    info->message.log_message_interval = state->config->log_announce_interval;

    info->message.payload.announce.timestamp = util_get_time_ns();
    info->message.payload.announce.grandmaster_priority = state->config->clock_priority;
    memcpy(&info->message.payload.announce.grandmaster_clock_quality, &state->config->clock_quality, sizeof(state->config->clock_quality));
    memcpy(&info->message.payload.announce.grandmaster_id, &state->config->clock_id, sizeof(state->config->clock_id));
    info->message.payload.announce.steps_removed = 0;
    info->message.payload.announce.time_source = PTP_TIME_SOURCE_INTERNAL_OSCILLATOR;

    ret = ptp_encode_and_enqueue_message(state, info);
    if (ret) {
        goto out;
    }
    
    return 0;

out:
    util_mempool_put(info);
    return ret;
}

static int ptp_send_sync(void *user_ptr, struct ptp_peer *peer) {
    int ret;
    struct ptp_state *state = user_ptr;

    if (!(peer->subscriptions & PTP_PEER_SUBSCRIPTION_SYNC)) {
        return 0;
    }
    
    struct common_message_info *info;
    ret = ptp_get_and_init_message(state, &info, COMMON_PORT_TYPE_EVENT, 0); // TODO: set correct port
    if (ret) {
        return ret;
    }

    memcpy(&info->address.address, &peer->address, sizeof(info->address.address));
    info->address.length = sizeof(info->address.address);

    info->message.type = PTP_MESSAGE_TYPE_SYNC;
    info->message.sequence_id = state->tasks.cyclic.sync.sequence_id++;
    info->message.log_message_interval = state->config->log_sync_interval;

    info->message.payload.event.timestamp = util_get_time_ns();

    ret = ptp_encode_and_enqueue_message(state, info);
    if (ret) {
        goto out;
    }
    
    return 0;

out:
    util_mempool_put(info);
    return ret;
}

static int ptp_task_announce(struct ptp_state *state) {
    int ret;

    ret = ptp_try_run_task(&state->tasks, &state->tasks.cyclic.announce.task, state->config->log_announce_interval);
    if (ret) {
        return 0;
    }
    
    ret = ptp_peer_db_get_active(&state->peer_db, state->tasks.logical_time_s, ptp_send_announce, state);

    return ret;
}

static int ptp_task_sync(struct ptp_state *state) {   
    int ret;

    ret = ptp_try_run_task(&state->tasks, &state->tasks.cyclic.sync.task, state->config->log_sync_interval);
    if (ret) {
        return 0;
    }

    ret = ptp_peer_db_get_active(&state->peer_db, state->tasks.logical_time_s, ptp_send_sync, state);

    return ret;
}

int ptp_run_cyclic_tasks(struct ptp_state *state, uint64_t elapsed_time_s) {
    int ret;

    state->tasks.logical_time_s += elapsed_time_s;

    ret = ptp_task_announce(state);
    if (ret) {
        error(0, -ret, "Failed to run announce task");
        return ret;
    }

    ret = ptp_task_sync(state);
    if (ret) {
        error(0, -ret, "Failed to run sync task");
        return ret;
    }

    return 0;
}
