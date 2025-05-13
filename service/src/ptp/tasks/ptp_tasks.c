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
#include <util/ring.h>
#include <util/mempool.h>

static int ptp_send_sync(struct ptp_state *state, struct common_message_info *request) {
    int ret;
    
    struct common_message_info *response;
    ret = ptp_get_and_init_message(state, &response, COMMON_PORT_TYPE_EVENT, 0); // TODO: set correct port
    if (ret) {
        return ret;
    }

    memcpy(&response->address.address, &request->address.address, sizeof(response->address.address));
    response->address.length = sizeof(response->address.address);

    response->message.type = PTP_MESSAGE_TYPE_SYNC;
    response->message.sequence_id = request->message.sequence_id;
    response->message.log_message_interval = 0;

    response->message.payload.event.timestamp = util_get_time_ns();

    ret = ptp_encode_and_enqueue_message(state, response);
    if (ret) {
        goto out;
    }
    
    return 0;

out:
    util_mempool_put(response);
    return ret;
}

static int ptp_send_announce(struct ptp_state *state, struct common_message_info *request) {
    int ret;

    struct common_message_info *response;
    ret = ptp_get_and_init_message(state, &response, COMMON_PORT_TYPE_EVENT, 0); // TODO: set correct port
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
    memcpy(&response->message.payload.announce.grandmaster_id, &state->config->clock_id, sizeof(state->config->clock_id));
    response->message.payload.announce.steps_removed = 0;
    response->message.payload.announce.time_source = PTP_TIME_SOURCE_INTERNAL_OSCILLATOR;

    ret = ptp_encode_and_enqueue_message(state, response);
    if (ret) {
        goto out;
    }
    
    return 0;

out:
    util_mempool_put(response);
    return ret;
}

static int ptp_management_error(struct ptp_state *state, struct common_message_info *request, enum ptp_management_error_id error_id, enum ptp_management_id id, const char *format, ...) {
    int ret;
    va_list va_args;
    struct common_message_info *response;

    va_start(va_args, format);

    ret = ptp_get_and_init_message(state, &response, COMMON_PORT_TYPE_GENERAL, request->message.payload.management.target_port_id.port);
    if (ret) {
        return ret;
    }

    memcpy(&response->address, &request->address, sizeof(request->address));

    response->message.type = PTP_MESSAGE_TYPE_MANAGEMENT;
    response->message.sequence_id = request->message.sequence_id;
    response->message.flags = PTP_FLAG_UNICAST;

    response->message.payload.management.action = ptp_managment_response_action(request->message.payload.management.action);
    response->message.payload.management.starting_boundary_hops = 0;
    response->message.payload.management.boundary_hops = 0;
    memcpy(&response->message.payload.management.target_port_id, &request->message.port_id, sizeof(request->message.port_id));

    response->message.tlvs[0].type = PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS;
    response->message.tlvs[0].payload.management_error_status.error_id = error_id;
    response->message.tlvs[0].payload.management_error_status.id = id;

    ret = vsnprintf(response->message.tlvs[0].payload.management_error_status.display_data, PTP_USER_DESCRIPTION_SIZE, format, va_args);
    if (ret < 0) {
        return ret;
    }

    response->message.tlv_count = 1;

    ret = ptp_security_add_auth_tlv(state, response);
    if (ret) {
        goto out;
    }

    ret = ptp_encode_and_enqueue_message(state, response);
    if (ret) {
        goto out;
    }
    
    return 0;

out:
    util_mempool_put(response);
    return ret;
}

static int ptp_handle_management_user_description_get(struct ptp_state *state, struct common_message_info *request) {
    int ret;
    struct ptp_port_entry entry;
    struct common_message_info *response;

    entry.port = request->message.payload.management.target_port_id.port;
    ret = ptp_port_db_get(&state->port_db, &entry);
    if (ret) {
        return ret;
    }

    ret = ptp_get_and_init_message(state, &response, COMMON_PORT_TYPE_GENERAL, request->message.payload.management.target_port_id.port);
    if (ret) {
        return ret;
    }

    memcpy(&response->address, &request->address, sizeof(request->address));

    response->message.type = PTP_MESSAGE_TYPE_MANAGEMENT;
    response->message.sequence_id = request->message.sequence_id;
    response->message.flags = PTP_FLAG_UNICAST;

    response->message.payload.management.action = PTP_MANAGEMENT_ACTION_RESPONSE;
    response->message.payload.management.starting_boundary_hops = 0;
    response->message.payload.management.boundary_hops = 0;
    memcpy(&response->message.payload.management.target_port_id, &request->message.port_id, sizeof(request->message.port_id));

    response->message.tlvs[0].type = PTP_TLV_TYPE_MANAGEMENT;
    response->message.tlvs[0].payload.management.id = PTP_MANAGEMENT_ID_USER_DESCRIPTION;
    strncpy(response->message.tlvs[0].payload.management.payload.user_description, entry.user_description, PTP_USER_DESCRIPTION_SIZE);

    response->message.tlv_count = 1;

    ret = ptp_encode_and_enqueue_message(state, response);
    if (ret) {
        goto out;
    }
    
    return 0;

out:
    util_mempool_put(response);
    return ret;
}

static int ptp_handle_management_port_claim(struct ptp_state *state, struct common_message_info *request, struct ptp_decoded_management_tlv *tlv) {
    int ret;
    struct ptp_port_entry entry;
    struct common_message_info *response;

    entry.port = request->message.payload.management.target_port_id.port;
    entry.active = true;
    strncpy(entry.secret, tlv->payload.port_claim.port_secret, PTP_PORT_SECRET_SIZE);
    strncpy(entry.user_description, tlv->payload.port_claim.user_description, PTP_USER_DESCRIPTION_SIZE);

    ret = ptp_port_db_set(&state->port_db, &entry);
    if (ret) {
        return ret;
    }

    ret = ptp_get_and_init_message(state, &response, COMMON_PORT_TYPE_GENERAL, request->message.payload.management.target_port_id.port);
    if (ret) {
        return ret;
    }

    memcpy(&response->address, &request->address, sizeof(request->address));

    response->message.type = PTP_MESSAGE_TYPE_MANAGEMENT;
    response->message.sequence_id = request->message.sequence_id;
    response->message.flags = PTP_FLAG_UNICAST;

    response->message.payload.management.action = PTP_MANAGEMENT_ACTION_ACKNOWLEDGE;
    response->message.payload.management.starting_boundary_hops = 0;
    response->message.payload.management.boundary_hops = 0;
    memcpy(&response->message.payload.management.target_port_id, &request->message.port_id, sizeof(request->message.port_id));

    // Send values back
    response->message.tlvs[0].type = PTP_TLV_TYPE_MANAGEMENT;
    memcpy(&response->message.tlvs[0].payload, tlv, sizeof(*tlv));

    response->message.tlv_count = 1;

    ret = ptp_encode_and_enqueue_message(state, response);
    if (ret) {
        goto out;
    }
    
    return 0;

out:
    util_mempool_put(response);
    return ret;
}

static int ptp_handle_tlv_request_unicast(struct ptp_state *state, struct common_message_info *request, struct ptp_decoded_request_unicast_transmission_tlv *tlv) {
    int ret;
    struct common_message_info *response;
    int (*send_function)(struct ptp_state *, struct common_message_info *);

    switch (tlv->type) {
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

    // Build response
    ret = ptp_get_and_init_message(state, &response, COMMON_PORT_TYPE_GENERAL, request->message.payload.signaling.target_port_id.port);
    if (ret) {
        return ret;
    }

    memcpy(&response->address, &request->address, sizeof(request->address));

    response->message.type = PTP_MESSAGE_TYPE_SIGNALING;
    response->message.sequence_id = request->message.sequence_id;
    response->message.flags = PTP_FLAG_UNICAST;

    memcpy(&response->message.payload.signaling.target_port_id, &request->message.port_id, sizeof(request->message.port_id));

    response->message.tlvs[0].type = PTP_TLV_TYPE_GRANT_UNICAST_TRANSMISSION;
    response->message.tlvs[0].payload.grant_unicast.duration = 0; // No duration as we only send one packet
    response->message.tlvs[0].payload.grant_unicast.log_message_interval = 0;
    response->message.tlvs[0].payload.grant_unicast.flags = PTP_TLV_UNICAST_FLAG_MAINTAIN_REQUEST;

    response->message.tlv_count = 1;

    ret = ptp_encode_and_enqueue_message(state, response);
    if (ret) {
        goto out;
    }

    ret = send_function(state, request);
    if (ret) {
        return ret;
    }
    
    return 0;

out:
    util_mempool_put(response);
    return ret;
}

static int ptp_handle_tlv_management(struct ptp_state *state, struct common_message_info *request, struct ptp_decoded_management_tlv *tlv) {
    int ret;

    switch (tlv->id) {
        case PTP_MANAGEMENT_ID_USER_DESCRIPTION: {
            if (request->message.payload.management.action == PTP_MANAGEMENT_ACTION_GET) {
                ret = ptp_handle_management_user_description_get(state, request);
                if (ret) {
                    return ret;
                }
            } else {
                ret = ptp_management_error(state, request, PTP_MANAGEMENT_ERROR_ID_NOT_SUPPORTED, tlv->id, "Action not supported");
                if (ret) {
                    return ret;
                }
            }

            break;
        }

        case PTP_MANAGEMENT_ID_IMPLEMENTATION_SPECIFIC_PORT_CLAIM: {
            if (request->message.payload.management.action == PTP_MANAGEMENT_ACTION_COMMAND) {
                ret = ptp_handle_management_port_claim(state, request, tlv);
                if (ret) {
                    return ret;
                }
            } else {
                ret = ptp_management_error(state, request, PTP_MANAGEMENT_ERROR_ID_NOT_SUPPORTED, tlv->id, "Action not supported");
                if (ret) {
                    return ret;
                }
            }

            break;
        }

        default: {
            ret = ptp_management_error(state, request, PTP_MANAGEMENT_ERROR_ID_NOT_SUPPORTED, tlv->id, "Management ID not supported");
            if (ret) {
                return ret;
            }
        }
    }

    return 0;
}

static int ptp_handle_message_delay_request(struct ptp_state *state, struct common_message_info *request) {
    int ret;
    struct common_message_info *response;

    if (request->port_type != COMMON_PORT_TYPE_EVENT) {
        return -EINVAL;
    }

    ret = ptp_get_and_init_message(state, &response, COMMON_PORT_TYPE_EVENT, request->message.payload.event.port_id.port);
    if (ret) {
        return ret;
    }

    memcpy(&response->address, &request->address, sizeof(request->address));

    response->message.type = PTP_MESSAGE_TYPE_DELAY_RESPONSE;
    response->message.sequence_id = request->message.sequence_id;
    response->message.flags = PTP_FLAG_UNICAST;

    response->message.payload.event.timestamp = request->timestamp;
    memcpy(&response->message.payload.event.port_id, &request->message.port_id, sizeof(request->message.port_id));    

    ret = ptp_encode_and_enqueue_message(state, response);
    if (ret) {
        goto out;
    }
    
    return 0;

out:
    util_mempool_put(response);
    return ret;
}

static int ptp_handle_message_signaling(struct ptp_state *state, struct common_message_info *request) {
    int ret;
    
    if (request->port_type != COMMON_PORT_TYPE_GENERAL) {
        return -EINVAL;
    }

    ret = memcmp(&request->message.payload.signaling.target_port_id.clock_id, &state->config->clock_id, sizeof(state->config->clock_id));
    if (ret) {
        return -EINVAL;
    }

    // Handle supported TLVs
    for (int i = 0; i < request->message.tlv_count; ++i) {
        struct ptp_decoded_tlv *tlv = &request->message.tlvs[i];

        switch (tlv->type) {
            case PTP_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION: {
                ret = ptp_handle_tlv_request_unicast(state, request, &tlv->payload.request_unicast);
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

static int ptp_handle_message_management(struct ptp_state *state, struct common_message_info *request) {
    int ret;
    
    if (request->port_type != COMMON_PORT_TYPE_GENERAL) {
        return -EINVAL;
    }

    ret = memcmp(&request->message.payload.management.target_port_id.clock_id, &state->config->clock_id, sizeof(state->config->clock_id));
    if (ret) {
        return -EINVAL;
    }

    // Only require authetication on management messages
    ret = ptp_security_check_auth(state, request, request->message.payload.management.target_port_id.port);
    if (ret) {
        ret = ptp_management_error(state, request, ptp_management_error_id(ret), PTP_MANAGEMENT_ID_NULL, "Authentication fail");
        if (ret) {
            return ret;
        }
    }

    // Handle supported TLVs
    for (int i = 0; i < request->message.tlv_count; ++i) {
        struct ptp_decoded_tlv *tlv = &request->message.tlvs[i];

        switch (tlv->type) {
            case PTP_TLV_TYPE_MANAGEMENT: {
                if (!tlv->authenticated) {
                    continue;
                }

                ret = ptp_handle_tlv_management(state, request, &tlv->payload.management);
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

int ptp_handle_message(struct ptp_state *state) {   
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

    switch (info->message.type) {
        case PTP_MESSAGE_TYPE_DELAY_REQUEST: {
            ret = ptp_handle_message_delay_request(state, info);
            break;
        }

        case PTP_MESSAGE_TYPE_SIGNALING: {
            ret = ptp_handle_message_signaling(state, info);
            break;
        }
    
        case PTP_MESSAGE_TYPE_MANAGEMENT: {
            ret = ptp_handle_message_management(state, info);
            break;
        }

        default: {
            ret = -EINVAL;
            break;
        }
    }

out:
    util_mempool_put(info);
    return ret;
}
