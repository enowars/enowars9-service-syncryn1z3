#include <error.h>

#include <ptp/ptp.h>
#include <ptp/ptp_tasks.h>
#include <common/common_types.h>
#include <util/ring.h>
#include <util/mempool.h>

static int ptp_handle_message(struct ptp_state *state) {   
    int ret;
    struct common_message_info *info;

    info = util_ring_get(&state->rx_ring);
    if (!info) {
        return -1;
    }
    
    ret = ptp_decode_message(&info->message, info->buffer.data, info->buffer.length);
    if (ret) {
        goto out;
    }

    ret = 0;

out:
    util_mempool_put(info);
    return ret;
}

int ptp_run_acyclic_tasks(struct ptp_state *state) {
    int ret;

    ret = ptp_handle_message(state);
    if (ret) {
        error(0, -ret, "Failed to run handle message task");
        return ret;
    }

    return 0;
}
