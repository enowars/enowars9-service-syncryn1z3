#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <ptp/ptp.h>
#include <ptp/ptp_helper.h>
#include <ptp/protocol/ptp_protocol.h>
#include <ptp/tasks/ptp_tasks.h>
#include <common/common_types.h>
#include <util/error.h>
#include <util/time.h>
#include <util/ring.h>
#include <util/mempool.h>

int ptp_setup(struct ptp_state *state, struct ptp_config *config) {
    int ret;

    memset(state, 0, sizeof(*state));
    state->config = config;

    ret = util_ring_setup(&state->rx_ring, COMMON_RING_SIZE);
    if (ret) {
        return ret;
    }

    ret = util_ring_setup(&state->tx_ring, COMMON_RING_SIZE);
    if (ret) {
        return ret;
    }

    ret = util_mempool_setup(&state->mempool, sizeof(struct common_message_info), COMMON_MEMPOOL_SIZE);
    if (ret) {
        return ret; 
    }

    return 0;
}
    
int ptp_cleanup(struct ptp_state *state) {
    int ret;

    ret = util_ring_cleanup(&state->rx_ring);
    if (ret) {
        return ret;
    }

    ret = util_ring_cleanup(&state->tx_ring);
    if (ret) {
        return ret;
    }

    ret = util_mempool_cleanup(&state->mempool);
    if (ret) {
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

    ret = ptp_handle_message(state);
    if (ret) {
        util_error(ret, "Failure in message handling");
        return ret;
    }

    return 0;
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
