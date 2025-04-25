#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <error.h>

#include <ptp/ptp.h>
#include <ptp/ptp_coding.h>
#include <common/common_types.h>
#include <util/ring.h>
#include <util/mempool.h>

static int ptp_send_announce(struct ptp_state *state) {   
    int ret;
    
    struct common_message_info *info = util_mempool_get(&state->mempool);
    if (!info) {
        return -ENOMEM;
    }

    memset(&info->message, 0, sizeof(info->message));
    info->message.type = PTP_MESSAGE_TYPE_ANNOUNCE;
    info->message.sdo_id = ptp_sdo_id;
    info->message.domain = ptp_domain;

    ret = ptp_encode_message(info->buffer.data, &info->message, COMMON_BUFFER_SIZE);
    if (ret < 0) {
        goto out;
    }

    info->buffer.length = ret;

    memcpy(&info->address.address, &ptp_default_address, sizeof(ptp_default_address));
    info->address.length = sizeof(ptp_default_address);

    info->timestamp = 3;

    ret = util_ring_put(&state->tx_ring, info);
    if (ret) {
        goto out;
    }

    return 0;

out:
    util_mempool_put(info);
    return ret;
}

int ptp_run_cyclic_tasks(struct ptp_state *state) {
    int ret;

    ret = ptp_send_announce(state);
    if (ret) {
        error(0, -ret, "Failed to send announcement");
        return ret;
    }

    return 0;
}
