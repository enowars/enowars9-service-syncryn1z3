#pragma once

#include <string.h>
#include <errno.h>

#include <ptp/ptp.h>
#include <ptp/ptp_decoded.h>
#include <ptp/ptp_constants.h>
#include <common/common_types.h>
#include <util/ring.h>
#include <util/mempool.h>

static int ptp_get_and_init_message(struct ptp_state *state, struct common_message_info **info) {
    *info = (struct common_message_info *)util_mempool_get(&state->mempool);
    if (!info) {
        return -ENOMEM;
    }

    memset(&(*info)->message, 0, sizeof((*info)->message));

    (*info)->message.sdo_id = ptp_sdo_id;
    (*info)->message.domain = ptp_domain;

    return 0;
}

static int ptp_encode_and_enqueue_message(struct ptp_state *state, struct common_message_info *info) {
    int ret;

    ret = ptp_encode_message(info->buffer.data, &info->message, COMMON_BUFFER_SIZE);
    if (ret < 0) {
        return ret;
    }

    info->buffer.length = ret;

    memcpy(&info->address.address, &ptp_default_address, sizeof(ptp_default_address));
    info->address.length = sizeof(ptp_default_address);

    info->timestamp = 3;

    ret = util_ring_put(&state->tx_ring, info);
    if (ret) {
        return ret;
    }

    return 0;
}
