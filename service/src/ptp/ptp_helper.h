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

static int ptp_get_and_init_message(struct ptp_state *state, struct common_message_info **info, enum common_port_type port_type, struct ptp_decoded_port_id port_id) {
    *info = (struct common_message_info *)util_mempool_get(&state->mempool);
    if (!info) {
        return -ENOMEM;
    }

    // Possible vuln if ommited
    memset(&(*info)->message, 0, sizeof((*info)->message));

    (*info)->message.sdo_id = ptp_sdo_id;
    (*info)->message.domain = ptp_domain;
    (*info)->message.log_message_interval = 0x7f;

    (*info)->message.port_id.clock_id = port_id.clock_id;
    (*info)->message.port_id.port = port_id.port;

    (*info)->port_type = port_type;

    return 0;
}

static int ptp_encode_and_enqueue_message(struct ptp_state *state, struct common_message_info *info) {
    int ret;

    ret = ptp_encode_message(info->buffer.data, &info->message, COMMON_BUFFER_SIZE);
    if (ret < 0) {
        goto out;
    }

    info->buffer.length = ret;

    ret = ptp_security_complete_auth_tlvs(state, info);
    if (ret < 0) {
        goto out;
    }

    ret = util_ring_put(&state->tx_ring, info);
    if (ret) {
        goto out;
    }

    return 0;

out:
    util_mempool_put(info);
    return ret;
}

static struct ptp_decoded_tlv *ptp_add_tlv(struct ptp_decoded_message *message) {
    struct ptp_decoded_tlv *result;

    if (message->tlv_count >= PTP_MAX_TLV_COUNT) {
        return NULL;
    }

    result = &message->tlvs[message->tlv_count++];
    
    return result;
}

// TODO: move to web interface
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

static inline int ptp_compare_port_id(struct ptp_decoded_port_id port_id_a, struct ptp_decoded_port_id port_id_b) {
    if (port_id_a.clock_id != port_id_b.clock_id || port_id_a.port != port_id_b.port) {
        return -1;
    }

    return 0;
}
