#pragma once

#include <endian.h>
#include <string.h>
#include <errno.h>

#include <ptp/ptp.h>
#include <ptp/protocol/ptp_constants.h>
#include <ptp/protocol/ptp_decoded.h>
#include <ptp/protocol/ptp_protocol.h>
#include <common/common_types.h>
#include <sys/socket.h>
#include <util/ring.h>
#include <util/mempool.h>

static int ptp_get_and_init_message(struct ptp_state *state, struct common_message_info **info, enum common_port_type port_type) {
    *info = (struct common_message_info *)util_mempool_get(&state->mempool);
    if (!info) {
        return -ENOMEM;
    }

    // Possible vuln if ommited
    memset(&(*info)->message, 0, sizeof((*info)->message));

    (*info)->message.sdo_id = ptp_sdo_id;
    (*info)->message.domain = ptp_domain;
    (*info)->message.log_message_interval = 0x7f;

    memcpy(&(*info)->message.port_id, &state->config->port_id, sizeof(state->config->port_id));

    return 0;
}

static int ptp_encode_and_enqueue_message(struct ptp_state *state, struct common_message_info *info) {
    int ret;

    ret = ptp_encode_message(info->buffer.data, &info->message, COMMON_BUFFER_SIZE);
    if (ret < 0) {
        return ret;
    }

    info->buffer.length = ret;

    ret = util_ring_put(&state->tx_ring, info);
    if (ret) {
        return ret;
    }

    return 0;
}

static void ptp_set_default_address(struct common_message_info *info, enum common_port_type port_type) {
    info->address.address.sin_addr.s_addr = ptp_default_address;
    info->address.address.sin_family = AF_INET;

    switch (port_type) {
        case COMMON_PORT_TYPE_EVENT: {
            info->address.address.sin_port = htobe16(ptp_default_event_port);
            break;
        }

        case COMMON_PORT_TYPE_GENERAL: {
            info->address.address.sin_port = htobe16(ptp_default_general_port);
            break;
        }
    }

    info->address.length = sizeof(info->address.address);
}
