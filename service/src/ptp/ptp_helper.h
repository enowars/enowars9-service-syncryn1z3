#pragma once

#include <endian.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <db/db.h>
#include <ptp/ptp.h>
#include <ptp/ptp_defaults.h>
#include <ptp/protocol/ptp_constants.h>
#include <ptp/protocol/ptp_decoded.h>
#include <ptp/protocol/ptp_protocol.h>
#include <ptp/security/ptp_security.h>
#include <common/common_types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <util/ring.h>
#include <util/mempool.h>
#include <util/time.h>

static int ptp_get_and_init_response(struct ptp_state *state, struct common_transaction_info *transaction, enum common_port_type port_type, enum ptp_message_type type, struct ptp_decoded_port_id port_id, uint16_t sequence_id) {
    int ret;
    
    transaction->response = (struct common_message_info *)util_mempool_get(&state->mempool);
    if (!transaction->response) {
        return -ENOMEM;
    }

    transaction->response->port_type = port_type;
    transaction->response->buffer.length = 0;

    memcpy(&transaction->response->address, &transaction->request->address, sizeof(transaction->request->address));
    transaction->response->address.length = sizeof(transaction->response->address.address);

    memset(&transaction->response->message, 0, sizeof(transaction->response->message));

    transaction->response->message.type = type;
    transaction->response->message.sequence_id = sequence_id;
    transaction->response->message.sdo_id = ptp_sdo_id;
    transaction->response->message.domain = ptp_domain;
    transaction->response->message.log_message_interval = 0x7f;
    transaction->response->message.flags = PTP_FLAG_UNICAST;
    memcpy(&transaction->response->message.port_id, &port_id, sizeof(port_id));

    ret = util_ring_put(&state->tx_ring, transaction->response);
    if (ret) {
        goto out;
    }

    return 0;

out:
    util_mempool_put(transaction->response);
    return ret;
}

static int ptp_finalize_message(struct ptp_state *state, struct common_message_info *info) {
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

    return 0;
}

static struct ptp_decoded_tlv *ptp_add_tlv(struct ptp_decoded_message *message) {
    struct ptp_decoded_tlv *result;

    if (message->tlv_count >= PTP_MAX_TLV_COUNT) {
        return NULL;
    }

    result = &message->tlvs[message->tlv_count++];
    
    return result;
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

static inline int ptp_compare_port_id(struct ptp_decoded_port_id port_id_a, struct ptp_decoded_port_id port_id_b) {
    if (port_id_a.clock_id != port_id_b.clock_id || port_id_a.port != port_id_b.port) {
        return -1;
    }

    return 0;
}

static inline uint64_t ptp_get_port_time(struct ptp_state *state, struct ptp_decoded_port_id port_id) {
    int ret;
    struct db_entry *entry;

    ret = db_get(state->config->db_state, &entry, port_id);
    if (ret) {
        return 0;
    }

    return util_get_time_ns() + entry->offset;
}
