#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <ptp/ptp.h>
#include <ptp/ptp_defaults.h>
#include <ptp/ptp_helper.h>
#include <ptp/protocol/ptp_constants.h>
#include <ptp/protocol/ptp_protocol.h>
#include <ptp/security/ptp_security.h>
#include <ptp/tasks/ptp_tasks.h>
#include <db/db.h>
#include <common/common_types.h>
#include <util/time.h>
#include <util/mempool.h>

static int ptp_send_sync(struct ptp_state *state, struct common_message_info *request, struct ptp_decoded_port_id port_id) {
    int ret;
    struct common_transaction_info transaction;

    transaction.request = request;

    ret = ptp_get_and_init_response(state, &transaction, COMMON_PORT_TYPE_EVENT, PTP_MESSAGE_TYPE_SYNC, port_id, transaction.request->message.sequence_id);
    if (ret) {
        return ret;
    }

    transaction.response->message.flags &= ~PTP_FLAG_TWO_STEP;
    transaction.response->message.payload.event.timestamp = util_get_time_ns();

    ret = ptp_finalize_message(state, transaction.response);
    if (ret) {
        util_error(ret, "Failed to finalize sync message");
    }
    
    return ret;
}

static int ptp_send_announce(struct ptp_state *state, struct common_message_info *request, struct ptp_decoded_port_id port_id) {
    int ret;
    struct common_transaction_info transaction;
    struct db_entry *entry;
    struct ptp_decoded_tlv *tlv;

    transaction.request = request;

    ret = db_get(state->config->db_state, &entry, port_id);
    if (ret) {
        return ret;
    }

    ret = ptp_get_and_init_response(state, &transaction, COMMON_PORT_TYPE_EVENT, PTP_MESSAGE_TYPE_ANNOUNCE, port_id, transaction.request->message.sequence_id);
    if (ret) {
        return ret;
    }

    transaction.response->message.payload.announce.timestamp = ptp_get_port_time(state, port_id);
    transaction.response->message.payload.announce.grandmaster_priority = state->config->clock_priority;
    memcpy(&transaction.response->message.payload.announce.grandmaster_clock_quality, &state->config->clock_quality, sizeof(state->config->clock_quality));
    transaction.response->message.payload.announce.grandmaster_id = port_id.clock_id;
    transaction.response->message.payload.announce.steps_removed = 0;
    transaction.response->message.payload.announce.time_source = PTP_TIME_SOURCE_INTERNAL_OSCILLATOR;

    tlv = ptp_add_tlv(&transaction.response->message);
    if (!tlv) {
        return -EMSGSIZE;
    }

    tlv->type = PTP_TLV_TYPE_ALTERNATE_TIME_OFFSET_INDICATOR;
    tlv->payload.alternate_time_offset_indicator.key = 0;
    tlv->payload.alternate_time_offset_indicator.current_offset = entry->offset / 1000000000;
    tlv->payload.alternate_time_offset_indicator.jump_seconds = 0;
    tlv->payload.alternate_time_offset_indicator.time_of_next_jump = 0;
    tlv->payload.alternate_time_offset_indicator.display_name[0] = '\0';

    ret = ptp_finalize_message(state, transaction.response);
    if (ret) {
        util_error(ret, "Failed to finalize announce message");
    }
    
    return ret;
}

static int ptp_add_management_error_tlv_va(struct ptp_state *state, struct common_transaction_info *transaction, enum ptp_management_error_id error_id, enum ptp_management_id id, const char *format, va_list va_args) {
    int ret;
    struct ptp_decoded_tlv *tlv;

    transaction->response->message.type = PTP_MESSAGE_TYPE_MANAGEMENT;

    tlv = ptp_add_tlv(&transaction->response->message);
    if (!tlv) {
        return -EMSGSIZE;
    }

    tlv->type = PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS;
    tlv->payload.management_error_status.error_id = error_id;
    tlv->payload.management_error_status.id = id;

    ret = vsnprintf(tlv->payload.management_error_status.display_data, PTP_MANAGEMENT_ERROR_DISPLAY_DATA_SIZE, format, va_args);
    if (ret < 0) {
        return ret;
    }
    
    return 0;
}

static inline int ptp_add_management_error_tlv(struct ptp_state *state, struct common_transaction_info *transaction, enum ptp_management_error_id error_id, enum ptp_management_id id, const char *format, ...) {
    va_list va_args;
    va_start(va_args, format);

    return ptp_add_management_error_tlv_va(state, transaction, error_id, id, format, va_args); 
}

static int ptp_add_management_error_message_va(struct ptp_state *state, struct common_message_info *request, enum ptp_management_error_id error_id, enum ptp_management_id id, const char *format, va_list va_args) {
    int ret;
    struct common_transaction_info transaction;

    transaction.request = request;

    ret = ptp_get_and_init_response(state, &transaction, transaction.request->port_type, PTP_MESSAGE_TYPE_MANAGEMENT, ptp_default_port_id, transaction.request->message.sequence_id);
    if (ret) {
        return ret;
    }

    memset(&transaction.response->message.payload.management, 0, sizeof(transaction.response->message.payload.management));
    memcpy(&transaction.response->message.payload.management.target_port_id, &transaction.request->message.port_id, sizeof(transaction.request->message.port_id));
    
    ret = ptp_add_management_error_tlv_va(state, &transaction, error_id, id, format, va_args);
    if (ret) {
        return ret;
    }

    ret = ptp_finalize_message(state, transaction.response);
    if (ret) {
        util_error(ret, "Failed to finalize error message");
    }
    
    return ret;
}

static inline int ptp_add_management_error_message(struct ptp_state *state, struct common_message_info *request, enum ptp_management_error_id error_id, enum ptp_management_id id, const char *format, ...) {
    va_list va_args;
    va_start(va_args, format);

    return ptp_add_management_error_message_va(state, request, error_id, id, format, va_args); 
}

static int ptp_handle_management_user_description_get(struct ptp_state *state, struct common_transaction_info *transaction, struct ptp_decoded_tlv *request_tlv) {
    int ret;
    struct db_entry *entry;
    struct common_message_info *response;
    struct ptp_decoded_tlv *tlv;

    ret = db_get(state->config->db_state, &entry, transaction->request->message.payload.management.target_port_id);
    if (ret) {
        return ptp_add_management_error_tlv(state, transaction, PTP_MANAGEMENT_ERROR_ID_UNPOPULATED, PTP_MANAGEMENT_ID_USER_DESCRIPTION, "No such port");
    }

    ret = ptp_security_check_auth(state, transaction->request, request_tlv, transaction->request->message.payload.management.target_port_id);
    if (ret) {
        return ptp_add_management_error_tlv(state, transaction, ptp_management_error_id(ret), PTP_MANAGEMENT_ID_NULL, "Access denied");
    }

    transaction->response->message.payload.management.action = PTP_MANAGEMENT_ACTION_RESPONSE;

    tlv = ptp_add_tlv(&transaction->response->message);
    if (!tlv) {
        return -EMSGSIZE;
    }

    tlv->type = PTP_TLV_TYPE_MANAGEMENT;
    tlv->payload.management.id = PTP_MANAGEMENT_ID_USER_DESCRIPTION;

    if (entry->user_description_length < PTP_USER_DESCRIPTION_SIZE) {
        tlv->payload.management.payload.user_description.length = entry->user_description_length;
    } else {
        tlv->payload.management.payload.user_description.length = PTP_USER_DESCRIPTION_SIZE;
    }
    
    memcpy(tlv->payload.management.payload.user_description.data, entry->user_description, entry->user_description_length);

    return 0;
}

static int ptp_handle_management_time_get(struct ptp_state *state, struct common_transaction_info *transaction, struct ptp_decoded_tlv *request_tlv) {
    struct db_entry *entry;
    struct ptp_decoded_tlv *tlv;

    transaction->response->message.payload.management.action = PTP_MANAGEMENT_ACTION_RESPONSE;

    tlv = ptp_add_tlv(&transaction->response->message);
    if (!tlv) {
        return -EMSGSIZE;
    }

    tlv->type = PTP_TLV_TYPE_MANAGEMENT;
    tlv->payload.management.id = PTP_MANAGEMENT_ID_TIME;

    // Timestamp itself is very accurate, but the peer is not able to calculate the propagation delay
    tlv->payload.management.payload.time = ptp_get_port_time(state, transaction->request->message.payload.management.target_port_id);

    return 0;
}

static int ptp_handle_tlv_request_unicast(struct ptp_state *state, struct common_transaction_info *transaction, struct ptp_decoded_tlv *request_tlv) {
    int ret;
    struct ptp_decoded_tlv *tlv;
    int (*send_function)(struct ptp_state *, struct common_message_info *, struct ptp_decoded_port_id);

    ret = ptp_security_check_auth(state, transaction->request, request_tlv, transaction->request->message.payload.management.target_port_id);
    if (ret) {
        return ptp_add_management_error_message(state, transaction->request, ptp_management_error_id(ret), PTP_MANAGEMENT_ID_NULL, "Access denied");
    }

    switch (request_tlv->payload.request_unicast.type) {
        case PTP_MESSAGE_TYPE_SYNC: {
            send_function = ptp_send_sync;
            break;
        }
        
        case PTP_MESSAGE_TYPE_ANNOUNCE: {
            send_function = ptp_send_announce;
            break;
        }

        default: {
            return -EINVAL;
        }
    }

    tlv = ptp_add_tlv(&transaction->response->message);
    if (!tlv) {
        return -EMSGSIZE;
    }

    tlv->type = PTP_TLV_TYPE_GRANT_UNICAST_TRANSMISSION;
    tlv->payload.grant_unicast.duration = 0; // No duration as we only send one packet
    tlv->payload.grant_unicast.log_message_interval = 0;
    tlv->payload.grant_unicast.flags = PTP_TLV_UNICAST_FLAG_MAINTAIN_REQUEST;

    return send_function(state, transaction->request, transaction->request->message.payload.signaling.target_port_id);
}

static int ptp_handle_tlv_management(struct ptp_state *state, struct common_transaction_info *transaction, struct ptp_decoded_tlv *tlv) {
    switch (tlv->payload.management.id) {
        case PTP_MANAGEMENT_ID_USER_DESCRIPTION: {
            if (transaction->request->message.payload.management.action == PTP_MANAGEMENT_ACTION_GET) {
                return ptp_handle_management_user_description_get(state, transaction, tlv);
            }

            break;
        }

        case PTP_MANAGEMENT_ID_TIME: {
            if (transaction->request->message.payload.management.action == PTP_MANAGEMENT_ACTION_GET) {
                return ptp_handle_management_time_get(state, transaction, tlv);
            }

            break;
        }

        default: {
            return ptp_add_management_error_tlv(state, transaction, PTP_MANAGEMENT_ERROR_ID_NOT_SUPPORTED, tlv->payload.management.id, "Management ID not supported");
        }
    }

    return ptp_add_management_error_tlv(state, transaction, PTP_MANAGEMENT_ERROR_ID_NOT_SUPPORTED, tlv->payload.management.id, "Unsupported action");
}

static int ptp_handle_message_delay_request(struct ptp_state *state, struct common_message_info *request) {
    int ret;
    struct common_transaction_info transaction;

    transaction.request = request;

    if (transaction.request->port_type != COMMON_PORT_TYPE_EVENT) {
        return -EINVAL;
    }

    // This should be COMMON_PORT_TYPE_GENERAL, but that creates problems with NAT
    ret = ptp_get_and_init_response(state, &transaction, COMMON_PORT_TYPE_EVENT, PTP_MESSAGE_TYPE_DELAY_RESPONSE, transaction.request->message.payload.event.port_id, transaction.request->message.sequence_id);
    if (ret) {
        return ret;
    }

    transaction.response->message.payload.event.timestamp = transaction.request->timestamp;
    memcpy(&transaction.response->message.payload.event.port_id, &transaction.request->message.port_id, sizeof(transaction.request->message.port_id));

    ret = ptp_finalize_message(state, transaction.response);
    if (ret) {
        util_error(ret, "Failed to finalize delay response message");
    }

    return ret;
}

static int ptp_handle_message_signaling(struct ptp_state *state, struct common_message_info *request) {
    int ret;
    struct common_transaction_info transaction;

    transaction.request = request;

    if (transaction.request->port_type != COMMON_PORT_TYPE_EVENT) {
        return -EINVAL;
    }

    // This should be COMMON_PORT_TYPE_GENERAL, but that creates problems with NAT
    ret = ptp_get_and_init_response(state, &transaction, COMMON_PORT_TYPE_EVENT, PTP_MESSAGE_TYPE_SIGNALING, transaction.request->message.payload.signaling.target_port_id, transaction.request->message.sequence_id);
    if (ret) {
        return ret;
    }

    transaction.response->message.payload.event.timestamp = transaction.request->timestamp;
    memcpy(&transaction.response->message.payload.signaling.target_port_id, &transaction.request->message.port_id, sizeof(transaction.request->message.port_id));

    // Handle supported TLVs
    for (int i = 0; i < transaction.request->message.tlv_count; ++i) {
        struct ptp_decoded_tlv *tlv = &transaction.request->message.tlvs[i];

        switch (tlv->type) {
            case PTP_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION: {
                ret = ptp_handle_tlv_request_unicast(state, &transaction, tlv);
                if (ret) {
                    return ret;
                }

                break;
            }

            default: {
                continue;
            }
        }
    }

    ret = ptp_finalize_message(state, transaction.response);
    if (ret) {
        util_error(ret, "Failed to finalize delay response message");
    }

    return ret;
} 

static int ptp_handle_message_management(struct ptp_state *state, struct common_message_info *request) {
    int ret;
    struct common_transaction_info transaction;

    transaction.request = request;

    if (transaction.request->port_type != COMMON_PORT_TYPE_GENERAL) {
        return -EINVAL;
    }

    ret = ptp_get_and_init_response(state, &transaction, COMMON_PORT_TYPE_GENERAL, PTP_MESSAGE_TYPE_MANAGEMENT, transaction.request->message.payload.management.target_port_id, transaction.request->message.sequence_id);
    if (ret) {
        return ret;
    }

    memset(&transaction.response->message.payload.management, 0, sizeof(transaction.response->message.payload.management));
    memcpy(&transaction.response->message.payload.management.target_port_id, &transaction.request->message.port_id, sizeof(transaction.request->message.port_id));

    // Handle supported TLVs
    for (int i = 0; i < transaction.request->message.tlv_count; ++i) {
        struct ptp_decoded_tlv *tlv = &transaction.request->message.tlvs[i];

        switch (tlv->type) {
            case PTP_TLV_TYPE_MANAGEMENT: {
                ret = ptp_handle_tlv_management(state, &transaction, tlv);
                if (ret) {
                    goto out;
                }

                break;
            }

            default: {
                continue;
            }
        }
    }

    ret = ptp_security_add_auth_tlv(state, transaction.response);
    if (ret) {
        goto out;
    }

out:
    ret = ptp_finalize_message(state, transaction.response);
    if (ret) {
        util_error(ret, "Failed to finalize management message");
    }

    return 0;
}

int ptp_handle_message(struct ptp_state *state) {   
    int ret;
    struct common_message_info *request;

    request = util_ring_get(&state->rx_ring);
    if (!request) {
        return -ENODATA;
    }
    
    ret = ptp_decode_message(&request->message, request->buffer.data, request->buffer.length);
    if (ret) {
        goto out;
    }

    switch (request->message.type) {
        case PTP_MESSAGE_TYPE_SYNC:
        case PTP_MESSAGE_TYPE_DELAY_RESPONSE:
        case PTP_MESSAGE_TYPE_ANNOUNCE: {
            // Ignore, we are running in master-only mode
            break;
        }

        case PTP_MESSAGE_TYPE_DELAY_REQUEST: {
            ret = ptp_handle_message_delay_request(state, request);
            break;
        }

        case PTP_MESSAGE_TYPE_SIGNALING: {
            ret = ptp_handle_message_signaling(state, request);
            break;
        }
    
        case PTP_MESSAGE_TYPE_MANAGEMENT: {
            ret = ptp_handle_message_management(state, request);
            break;
        }

        default: {
            ret = -EINVAL;
            break;
        }
    }

out:
    if (ret) {
        ret = ptp_add_management_error_message(state, request, PTP_MANAGEMENT_ERROR_ID_GENERAL, PTP_MANAGEMENT_ID_NULL, "General error");
    }

    util_mempool_put(request);
    return ret;
}
