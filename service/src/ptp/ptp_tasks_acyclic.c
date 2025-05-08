#include <errno.h>
#include <error.h>

#include <ptp/ptp.h>
#include <ptp/ptp_constants.h>
#include <ptp/ptp_tasks.h>
#include <ptp/ptp_helper.h>
#include <ptp/ptp_peer.h>
#include <common/common_types.h>
#include <string.h>
#include <util/ring.h>
#include <util/mempool.h>

static int ptp_handle_message_delay_request(struct ptp_state *state, struct common_message_info *request) {
    int ret;
    struct common_message_info *response;

    if (request->port_type != COMMON_PORT_TYPE_EVENT) {
        return -EINVAL;
    }

    ret = ptp_get_and_init_message(state, &response, COMMON_PORT_TYPE_EVENT);
    if (ret) {
        return ret;
    }

    response->message.type = PTP_MESSAGE_TYPE_DELAY_RESPONSE;

    response->message.payload.event.timestamp = request->timestamp;
    response->message.sequence_id = request->message.sequence_id;
    response->message.flags = PTP_FLAG_UNICAST;
    memcpy(&response->message.payload.event.port_id, &request->message.port_id, sizeof(request->message.port_id));

    memcpy(&response->address, &request->address, sizeof(request->address));

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

    ret = memcmp(&request->message.payload.signaling.target_port_id, &state->config->port_id, sizeof(state->config->port_id));
    if (ret) {
        return -EINVAL;
    }

    // Handle TLVs
    for (int i = 0; i < request->message.tlv_count; ++i) {
        struct ptp_decoded_tlv *tlv = &request->message.tlvs[i];

        switch (tlv->type) {
            case PTP_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION: {
                struct ptp_peer peer;

                memcpy(&peer.port_id, &request->message.port_id, sizeof(peer.port_id));
                memcpy(&peer.address, &request->address, sizeof(peer.address));
                peer.expiration = state->tasks.logical_time_s + state->config->peer_expiration_time_s;
        
                // TODO: add message type

                ptp_peer_db_add(&state->peer_db, &peer);
                break;
            }

            case PTP_TLV_TYPE_CANCEL_UNICAST_TRANSMISSION: {

                break;
            }

            default: {
                return -EINVAL;
            }
        }
    }

    return 0;
} 

static int ptp_handle_message_management(struct ptp_state *state, struct common_message_info *request) {
    return 0;
} 

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

int ptp_run_acyclic_tasks(struct ptp_state *state) {
    int ret;

    ret = ptp_handle_message(state);
    if (ret) {
        error(0, -ret, "Failed to run handle message task");
        return ret;
    }

    return 0;
}
