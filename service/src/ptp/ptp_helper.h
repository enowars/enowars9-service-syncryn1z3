#pragma once

#include <endian.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <ptp/ptp.h>
#include <ptp/ptp_defaults.h>
#include <ptp/protocol/ptp_constants.h>
#include <ptp/protocol/ptp_decoded.h>
#include <ptp/protocol/ptp_protocol.h>
#include <ptp/security/ptp_security.h>
#include <common/common_types.h>
#include <sys/socket.h>
#include <util/ring.h>
#include <util/mempool.h>

static int ptp_get_and_init_message(struct ptp_state *state, struct common_message_info **info, enum common_port_type port_type, uint16_t port) {
    *info = (struct common_message_info *)util_mempool_get(&state->mempool);
    if (!info) {
        return -ENOMEM;
    }

    // Possible vuln if ommited
    memset(&(*info)->message, 0, sizeof((*info)->message));

    (*info)->message.sdo_id = ptp_sdo_id;
    (*info)->message.domain = ptp_domain;
    (*info)->message.log_message_interval = 0x7f;

    memcpy(&(*info)->message.port_id.clock_id, &state->config->clock_id, sizeof(state->config->clock_id));
    (*info)->message.port_id.port = port;

    return 0;
}

static int ptp_encode_and_enqueue_message(struct ptp_state *state, struct common_message_info *info) {
    int ret;

    ret = ptp_encode_message(info->buffer.data, &info->message, COMMON_BUFFER_SIZE);
    if (ret < 0) {
        return ret;
    }

    info->buffer.length = ret;

    ret = ptp_security_complete_auth_tlvs(state, info);
    if (ret < 0) {
        return ret;
    }

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

static inline enum ptp_management_error_id ptp_management_error_id(int error) {
    // Correctly handle negative return codes
    if (error < 0) {
        error = -error;
    }

    // Fallback to general error if we overshoot assigned range 
    if (error > 0x1FFF) {
        error = 1;
    }

    return PTP_MANAGEMENT_ERROR_ID_IMPLEMENTATION_SPECIFIC + error;
}

static inline enum ptp_management_action ptp_managment_response_action(enum ptp_management_action request_action) {
    switch (request_action) {
        case PTP_MANAGEMENT_ACTION_GET:
        case PTP_MANAGEMENT_ACTION_SET: {
            return PTP_MANAGEMENT_ACTION_RESPONSE;
        }

        case PTP_MANAGEMENT_ACTION_COMMAND: {
            return PTP_MANAGEMENT_ACTION_ACKNOWLEDGE;
        }

        default: {
            return 0; // TODO: Hide this better
        }
    }
}
