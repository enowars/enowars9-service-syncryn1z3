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
#include <ptp/port/ptp_port.h>
#include <ptp/tasks/ptp_tasks.h>
#include <common/common_types.h>
#include <util/time.h>
#include <util/mempool.h>

static int ptp_send_sync(struct ptp_state *state, struct common_message_info *request, struct ptp_decoded_port_id port_id) {
    int ret;
    
    struct common_message_info *response;
    ret = ptp_get_and_init_message(state, &response, COMMON_PORT_TYPE_EVENT, port_id);
    if (ret) {
        return ret;
    }

    memcpy(&response->address.address, &request->address.address, sizeof(response->address.address));
    response->address.length = sizeof(response->address.address);

    response->message.type = PTP_MESSAGE_TYPE_SYNC;
    response->message.sequence_id = request->message.sequence_id;
    response->message.log_message_interval = 0;

    response->message.payload.event.timestamp = util_get_time_ns();
    
    return 0;
}

static int ptp_send_announce(struct ptp_state *state, struct common_message_info *request, struct ptp_decoded_port_id port_id) {
    int ret;

    struct common_message_info *response;
    ret = ptp_get_and_init_message(state, &response, COMMON_PORT_TYPE_EVENT, port_id);
    if (ret) {
        return ret;
    }

    memcpy(&response->address.address, &request->address.address, sizeof(response->address.address));
    response->address.length = sizeof(response->address.address);

    response->message.type = PTP_MESSAGE_TYPE_ANNOUNCE;
    response->message.sequence_id = request->message.sequence_id;
    response->message.log_message_interval = 0;

    response->message.payload.announce.timestamp = util_get_time_ns();
    response->message.payload.announce.grandmaster_priority = state->config->clock_priority;
    memcpy(&response->message.payload.announce.grandmaster_clock_quality, &state->config->clock_quality, sizeof(state->config->clock_quality));
    response->message.payload.announce.grandmaster_id = port_id.clock_id;
    response->message.payload.announce.steps_removed = 0;
    response->message.payload.announce.time_source = PTP_TIME_SOURCE_INTERNAL_OSCILLATOR;
    
    return 0;
}

static int ptp_management_error(struct ptp_state *state, struct common_transaction_info *transaction, enum ptp_management_error_id error_id, enum ptp_management_id id, const char *format, ...) {
    int ret;
    va_list va_args;
    struct ptp_decoded_tlv *tlv;

    va_start(va_args, format);

    transaction->response->message.type = PTP_MESSAGE_TYPE_MANAGEMENT;

    tlv = ptp_add_tlv(&transaction->response->message);
    if (!tlv) {
        return -EMSGSIZE;
    }

    tlv->type = PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS;
    tlv->payload.management_error_status.error_id = error_id;
    tlv->payload.management_error_status.id = id;

    ret = vsnprintf(tlv->payload.management_error_status.display_data, PTP_USER_DESCRIPTION_SIZE, format, va_args);
    if (ret < 0) {
        return ret;
    }
    
    return 0;
}

static int ptp_handle_management_user_description_get(struct ptp_state *state, struct common_transaction_info *transaction, struct ptp_decoded_tlv *request_tlv) {
    int ret;
    struct ptp_port_entry *entry;
    struct common_message_info *response;
    struct ptp_decoded_tlv *tlv;

    ret = ptp_port_db_get(&state->port_db, &entry, transaction->request->message.payload.management.target_port_id);
    if (ret) {
        return ptp_management_error(state, transaction, PTP_MANAGEMENT_ERROR_ID_UNPOPULATED, PTP_MANAGEMENT_ID_USER_DESCRIPTION, "No such port");
    }

    ret = ptp_security_check_auth(state, transaction->request, request_tlv, transaction->request->message.payload.management.target_port_id);
    if (ret) {
        return ptp_management_error(state, transaction, ptp_management_error_id(ret), PTP_MANAGEMENT_ID_NULL, "Access denied");
    }

    transaction->response->message.payload.management.action = PTP_MANAGEMENT_ACTION_RESPONSE;

    tlv = ptp_add_tlv(&transaction->response->message);
    if (!tlv) {
        return -EMSGSIZE;
    }

    tlv->type = PTP_TLV_TYPE_MANAGEMENT;
    tlv->payload.management.id = PTP_MANAGEMENT_ID_USER_DESCRIPTION;
    strncpy(tlv->payload.management.payload.user_description, entry->user_description, PTP_USER_DESCRIPTION_SIZE);

    return 0;
}

static int ptp_handle_management_time_get(struct ptp_state *state, struct common_transaction_info *transaction, struct ptp_decoded_tlv *request_tlv) {
    struct ptp_port_entry *entry;
    struct ptp_decoded_tlv *tlv;

    transaction->response->message.payload.management.action = PTP_MANAGEMENT_ACTION_RESPONSE;

    tlv = ptp_add_tlv(&transaction->response->message);
    if (!tlv) {
        return -EMSGSIZE;
    }

    tlv->type = PTP_TLV_TYPE_MANAGEMENT;
    tlv->payload.management.id = PTP_MANAGEMENT_ID_TIME;

    tlv->payload.management.payload.time = util_get_time_ns();

    return 0;
}

static int ptp_handle_management_port_claim(struct ptp_state *state, struct common_transaction_info *transaction, struct ptp_decoded_tlv *request_tlv) {
    int ret;
    struct ptp_port_entry entry;
    struct ptp_decoded_tlv *tlv;

    entry.port_id.clock_id = transaction->request->message.payload.management.target_port_id.clock_id;
    entry.port_id.port = transaction->request->message.payload.management.target_port_id.port;
    entry.active = true;
    entry.authentication_policy = request_tlv->payload.management.payload.port_claim.authentication_policy;
    strncpy(entry.secret, request_tlv->payload.management.payload.port_claim.port_secret, PTP_PORT_SECRET_SIZE);
    strncpy(entry.user_description, request_tlv->payload.management.payload.port_claim.user_description, PTP_USER_DESCRIPTION_SIZE);

    ret = ptp_port_db_set(&state->port_db, &entry);
    if (ret) {
        return ptp_management_error(state, transaction, PTP_MANAGEMENT_ERROR_ID_NOT_SETABLE, PTP_MANAGEMENT_ID_IMPLEMENTATION_SPECIFIC_PORT_CLAIM, "Port already claimed");
    }

    transaction->response->message.payload.management.action = PTP_MANAGEMENT_ACTION_ACKNOWLEDGE;

    // Send values back
    tlv = ptp_add_tlv(&transaction->response->message);
    if (!tlv) {
        return -EMSGSIZE;
    }

    tlv->type = PTP_TLV_TYPE_MANAGEMENT;
    memcpy(&tlv->payload.management, &request_tlv->payload.management, sizeof(request_tlv->payload.management));
    
    return 0;
}

static int ptp_handle_tlv_request_unicast(struct ptp_state *state, struct common_transaction_info *transaction, struct ptp_decoded_tlv *request_tlv) {
    struct ptp_decoded_tlv *tlv;
    int (*send_function)(struct ptp_state *, struct common_message_info *, struct ptp_decoded_port_id);

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

        case PTP_MANAGEMENT_ID_IMPLEMENTATION_SPECIFIC_PORT_CLAIM: {
            if (transaction->request->message.payload.management.action == PTP_MANAGEMENT_ACTION_COMMAND) {
                return ptp_handle_management_port_claim(state, transaction, tlv);
            }

            break;
        }

        default: {
            return ptp_management_error(state, transaction, PTP_MANAGEMENT_ERROR_ID_NOT_SUPPORTED, tlv->payload.management.id, "Management ID not supported");
        }
    }

    return ptp_management_error(state, transaction, PTP_MANAGEMENT_ERROR_ID_NOT_SUPPORTED, tlv->payload.management.id, "Unsupported action");
}

static int ptp_handle_message_delay_request(struct ptp_state *state, struct common_transaction_info *transaction) {
    if (transaction->request->port_type != COMMON_PORT_TYPE_EVENT) {
        return -EINVAL;
    }

    transaction->response->message.type = PTP_MESSAGE_TYPE_DELAY_RESPONSE;
    memcpy(&transaction->response->message.port_id, &transaction->request->message.payload.event.port_id, sizeof(transaction->request->message.payload.event.port_id));

    transaction->response->message.payload.event.timestamp = transaction->request->timestamp;
    memcpy(&transaction->response->message.payload.event.port_id, &transaction->request->message.port_id, sizeof(transaction->request->message.port_id));    

    return 0;
}

static int ptp_handle_message_signaling(struct ptp_state *state, struct common_transaction_info *transaction) {
    int ret;

    if (transaction->request->port_type != COMMON_PORT_TYPE_GENERAL) {
        return -EINVAL;
    }

    transaction->response->message.type = PTP_MESSAGE_TYPE_SIGNALING;
    memcpy(&transaction->response->message.port_id, &transaction->request->message.payload.signaling.target_port_id, sizeof(transaction->request->message.payload.signaling.target_port_id));

    memcpy(&transaction->response->message.payload.signaling.target_port_id, &transaction->request->message.port_id, sizeof(transaction->request->message.port_id));    

    // Handle supported TLVs
    for (int i = 0; i < transaction->request->message.tlv_count; ++i) {
        struct ptp_decoded_tlv *tlv = &transaction->request->message.tlvs[i];

        switch (tlv->type) {
            case PTP_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION: {
                ret = ptp_handle_tlv_request_unicast(state, transaction, tlv);
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

    return 0;
} 

static int ptp_handle_message_management(struct ptp_state *state, struct common_transaction_info *transaction) {
    int ret;

    if (transaction->request->port_type != COMMON_PORT_TYPE_GENERAL) {
        return ptp_management_error(state, transaction, PTP_MANAGEMENT_ERROR_ID_WRONG_VALUE, PTP_MANAGEMENT_ID_NULL, "Management message received on wrong port");
    }

    transaction->response->message.type = PTP_MESSAGE_TYPE_MANAGEMENT;
    memcpy(&transaction->response->message.port_id, &transaction->request->message.payload.management.target_port_id, sizeof(transaction->request->message.payload.management.target_port_id));

    memset(&transaction->response->message.payload.management, 0, sizeof(transaction->response->message.payload.management));
    memcpy(&transaction->response->message.payload.management.target_port_id, &transaction->request->message.port_id, sizeof(transaction->request->message.port_id));

    // Handle supported TLVs
    for (int i = 0; i < transaction->request->message.tlv_count; ++i) {
        struct ptp_decoded_tlv *tlv = &transaction->request->message.tlvs[i];

        switch (tlv->type) {
            case PTP_TLV_TYPE_MANAGEMENT: {
                ret = ptp_handle_tlv_management(state, transaction, tlv);
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

    ret = ptp_security_add_auth_tlv(state, transaction->response);
    if (ret) {
        return ret;
    }

    return 0;
} 

int ptp_handle_message(struct ptp_state *state) {   
    int ret;
    struct common_transaction_info transaction;

    transaction.request = state->request;
    if (!transaction.request) {
        return -ENODATA;
    }

    ret = ptp_get_and_init_message(state, &transaction.response, COMMON_PORT_TYPE_GENERAL, ptp_default_port_id);
    if (ret) {
        return ret;
    }
    
    ret = ptp_decode_message(&transaction.request->message, transaction.request->buffer.data, transaction.request->buffer.length);
    if (ret) {
        goto err;
    }

    memcpy(&transaction.response->address, &transaction.request->address, sizeof(transaction.request->address));
    
    transaction.response->message.sequence_id = transaction.request->message.sequence_id;
    transaction.response->message.flags = PTP_FLAG_UNICAST;

    switch (transaction.request->message.type) {
        case PTP_MESSAGE_TYPE_DELAY_REQUEST: {
            ret = ptp_handle_message_delay_request(state, &transaction);
            break;
        }

        case PTP_MESSAGE_TYPE_SIGNALING: {
            ret = ptp_handle_message_signaling(state, &transaction);
            break;
        }
    
        case PTP_MESSAGE_TYPE_MANAGEMENT: {
            ret = ptp_handle_message_management(state, &transaction);
            break;
        }

        default: {
            ret = -EINVAL;
            break;
        }
    }

err:
    if (ret) {
        ret = ptp_management_error(state, &transaction, PTP_MANAGEMENT_ERROR_ID_GENERAL, PTP_MANAGEMENT_ID_NULL, "General error");
        if (ret) {
            goto out;
        }
    }

out:
    util_mempool_put(transaction.request);
    return ret;
}
