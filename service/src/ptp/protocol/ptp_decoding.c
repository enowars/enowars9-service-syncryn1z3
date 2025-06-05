#include <errno.h>
#include <endian.h>
#include <stdint.h>
#include <string.h>

#include <ptp/protocol/ptp_constants.h>
#include <ptp/protocol/ptp_decoded.h>
#include <ptp/protocol/ptp_encoded.h>
#include <ptp/protocol/ptp_protocol.h>

static void ptp_decode_port_id(struct ptp_decoded_port_id *output, struct ptp_encoded_port_id *input) {
    output->clock_id = be64toh(input->clock_id);
    output->port = be16toh(input->port);
}

static void ptp_decode_timestamp(ptp_decoded_timestamp_t *output, struct ptp_encoded_timestamp *input) {
    const uint64_t seconds = (((uint64_t)be16toh(input->seconds_high)) << 32) | be32toh(input->seconds_low);
    const uint64_t nanoseconds = be32toh(input->nanoseconds);

    *output = seconds * 1000000000UL + nanoseconds;
}

static void ptp_decode_clock_quality(struct ptp_decoded_clock_quality *output, struct ptp_encoded_clock_quality *input) {
    output->clock_class = input->clock_class;
    output->clock_accuracy = (enum ptp_clock_accuracy)input->clock_accuracy;
    output->offset_scaled_log_variance = be16toh(input->offset_scaled_log_variance);
}

static int ptp_decode_payload(struct ptp_decoded_message *output, uint8_t **input, const uint8_t *tail) {
    uint8_t *head = *input;

    switch (output->type) {
        case PTP_MESSAGE_TYPE_SYNC: {
            struct ptp_encoded_sync_message *payload = (struct ptp_encoded_sync_message *)head;
            head += sizeof(struct ptp_encoded_sync_message);

            if (head > tail) {
                return -EMSGSIZE;
            }

            ptp_decode_timestamp(&output->payload.event.timestamp, &payload->origin_timestamp);
            
            break;
        }

        case PTP_MESSAGE_TYPE_DELAY_REQUEST: {
            struct ptp_encoded_delay_request_message *payload = (struct ptp_encoded_delay_request_message *)head;
            head += sizeof(struct ptp_encoded_delay_request_message);

            if (head > tail) {
                return -EMSGSIZE;
            }

            ptp_decode_timestamp(&output->payload.event.timestamp, &payload->origin_timestamp);
            
            break;
        }

        case PTP_MESSAGE_TYPE_PDELAY_REQUEST: {
            struct ptp_encoded_pdelay_request_message *payload = (struct ptp_encoded_pdelay_request_message *)head;
            head += sizeof(struct ptp_encoded_pdelay_request_message);

            if (head > tail) {
                return -EMSGSIZE;
            }

            ptp_decode_timestamp(&output->payload.event.timestamp, &payload->origin_timestamp);
            
            break;
        }

        case PTP_MESSAGE_TYPE_PDELAY_RESPONSE: {
            struct ptp_encoded_pdelay_response_message *payload = (struct ptp_encoded_pdelay_response_message *)head;
            head += sizeof(struct ptp_encoded_pdelay_response_message);

            if (head > tail) {
                return -EMSGSIZE;
            }

            ptp_decode_timestamp(&output->payload.event.timestamp, &payload->receive_timestamp);
            ptp_decode_port_id(&output->payload.event.port_id, &payload->requesting_port_id);
            
            break;
        }

        case PTP_MESSAGE_TYPE_FOLLOW_UP: {
            struct ptp_encoded_pdelay_response_message *payload = (struct ptp_encoded_pdelay_response_message *)head;
            head += sizeof(struct ptp_encoded_pdelay_response_message);

            if (head > tail) {
                return -EMSGSIZE;
            }

            ptp_decode_timestamp(&output->payload.event.timestamp, &payload->receive_timestamp);
            ptp_decode_port_id(&output->payload.event.port_id, &payload->requesting_port_id);
            
            break;
        }

        case PTP_MESSAGE_TYPE_DELAY_RESPONSE: {
            struct ptp_encoded_delay_response_message *payload = (struct ptp_encoded_delay_response_message *)head;
            head += sizeof(struct ptp_encoded_delay_response_message);

            if (head > tail) {
                return -EMSGSIZE;
            }

            ptp_decode_timestamp(&output->payload.event.timestamp, &payload->receive_timestamp);
            ptp_decode_port_id(&output->payload.event.port_id, &payload->requesting_port_id);
            
            break;
        }

        case PTP_MESSAGE_TYPE_PDELAY_RESPONSE_FOLLOW_UP: {
            struct ptp_encoded_pdelay_response_follow_up_message *payload = (struct ptp_encoded_pdelay_response_follow_up_message *)head;
            head += sizeof(struct ptp_encoded_pdelay_response_follow_up_message);

            if (head > tail) {
                return -EMSGSIZE;
            }

            ptp_decode_timestamp(&output->payload.event.timestamp, &payload->receive_timestamp);
            ptp_decode_port_id(&output->payload.event.port_id, &payload->requesting_port_id);
            
            break;
        }

        case PTP_MESSAGE_TYPE_ANNOUNCE: {
            struct ptp_encoded_announce_message *payload = (struct ptp_encoded_announce_message *)head;
            head += sizeof(struct ptp_encoded_announce_message);

            if (head > tail) {
                return -EMSGSIZE;
            }

            ptp_decode_timestamp(&output->payload.announce.timestamp, &payload->origin_timestamp);
            output->payload.announce.current_utc_offset = be16toh(payload->current_utc_offset);

            output->payload.announce.grandmaster_priority = (((uint16_t)payload->grandmaster_priority_1) << 8) | payload->grandmaster_priority_2;
            ptp_decode_clock_quality(&output->payload.announce.grandmaster_clock_quality, &payload->grandmaster_clock_quality);
            output->payload.announce.grandmaster_id = be64toh(payload->grandmaster_id);

            output->payload.announce.steps_removed = be16toh(payload->steps_removed);
            output->payload.announce.time_source = (enum ptp_time_source)payload->time_source;
            
            break;
        }

        case PTP_MESSAGE_TYPE_SIGNALING: {
            struct ptp_encoded_signaling_message *payload = (struct ptp_encoded_signaling_message *)head;
            head += sizeof(struct ptp_encoded_signaling_message);

            if (head > tail) {
                return -EMSGSIZE;
            }

            ptp_decode_port_id(&output->payload.signaling.target_port_id, &payload->target_port_id);
            
            break;
        }

        case PTP_MESSAGE_TYPE_MANAGEMENT: {
            struct ptp_encoded_management_message *payload = (struct ptp_encoded_management_message *)head;
            head += sizeof(struct ptp_encoded_management_message);

            if (head > tail) {
                return -EMSGSIZE;
            }

            ptp_decode_port_id(&output->payload.management.target_port_id, &payload->target_port_id);

            output->payload.management.starting_boundary_hops = payload->starting_boundary_hops;
            output->payload.management.boundary_hops = payload->boundary_hops;
            output->payload.management.action = (enum ptp_management_action)payload->action;
            
            break;
        }

        default: {
            return -EINVAL;
        }
    }

    *input = head;

    return 0;
}

static int ptp_decode_management_tlv(struct ptp_decoded_management_tlv *output, uint8_t **input, uint8_t *const tlv_tail) {
    uint8_t *head = *input;

    struct ptp_encoded_management_tlv *payload = (struct ptp_encoded_management_tlv *)head;
    head += sizeof(struct ptp_encoded_management_tlv);

    if (head > tlv_tail) {
        return -EMSGSIZE;
    }

    output->id = (enum ptp_management_id)be16toh(payload->management_id);

    switch (output->id) {
        case PTP_MANAGEMENT_ID_USER_DESCRIPTION: {
            struct ptp_encoded_text_header *string_header = (struct ptp_encoded_text_header *)head;
            head += sizeof(*string_header);

            if (string_header->length > PTP_USER_DESCRIPTION_SIZE) {
                return -EMSGSIZE;
            }

            if (head + string_header->length > tlv_tail) {
                return -EMSGSIZE;
            }

            output->payload.user_description.length = string_header->length;
            memcpy(output->payload.user_description.data, head, string_header->length);

            break;
        }

        case PTP_MANAGEMENT_ID_TIME: {
            struct ptp_encoded_management_tlv_time *header = (struct ptp_encoded_management_tlv_time *)head;
            head += sizeof(*header);

            if (head > tlv_tail) {
                return -EMSGSIZE;
            }

            ptp_decode_timestamp(&output->payload.time, &header->current_time);

            break;
        }

        default: {
            return -EINVAL;
        }
    }

    return 0;
}

static int ptp_decode_management_error_status_tlv(struct ptp_decoded_management_error_status_tlv *output, uint8_t **input, uint8_t *const tlv_tail) {
    uint8_t *head = *input;

    struct ptp_encoded_management_error_status_tlv *payload = (struct ptp_encoded_management_error_status_tlv *)head;
    head += sizeof(struct ptp_encoded_management_error_status_tlv);

    if (head > tlv_tail) {
        return -EMSGSIZE;
    }

    output->error_id = (enum ptp_management_error_id)be16toh(payload->management_error_id);
    output->id = (enum ptp_management_id)be16toh(payload->management_id);

    struct ptp_encoded_text_header *string_header = (struct ptp_encoded_text_header *)head;
    head += sizeof(*string_header);

    if (string_header->length > PTP_MANAGEMENT_ERROR_DISPLAY_DATA_SIZE) {
        return -EMSGSIZE;
    }

    if (head + string_header->length > tlv_tail) {
        return -EMSGSIZE;
    }

    strncpy(output->display_data, (char *)head, string_header->length);
    output->display_data[PTP_MANAGEMENT_ERROR_DISPLAY_DATA_SIZE] = '\0';

    return 0;
}

static int ptp_decode_tlv(struct ptp_decoded_tlv *output, uint8_t **input, uint8_t *const tail) {
    int ret;
    uint8_t *head = *input;

    struct ptp_encoded_tlv_header *header = (struct ptp_encoded_tlv_header *)head;
    
    output->type = (enum ptp_tlv_type)be16toh(header->type);
    output->authenticated = false;

    const short length = be16toh(header->length);

    head += sizeof(struct ptp_encoded_tlv_header);
    uint8_t *const tlv_tail = head + length;

    if (head > tail || tlv_tail > tail) {
        return -EMSGSIZE;
    }

    switch (output->type) {
        case PTP_TLV_TYPE_MANAGEMENT: {
            ret = ptp_decode_management_tlv(&output->payload.management, &head, tlv_tail);
            if (ret) {
                return ret;
            }

            break;
        }

        case PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS: {
            ret = ptp_decode_management_error_status_tlv(&output->payload.management_error_status, &head, tlv_tail);
            if (ret) {
                return ret;
            }

            break;
        }

        case PTP_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION: {
            struct ptp_encoded_request_unicast_transmission_tlv *payload = (struct ptp_encoded_request_unicast_transmission_tlv *)head;
            head += sizeof(struct ptp_encoded_request_unicast_transmission_tlv);

            if (head > tlv_tail) {
                return -EMSGSIZE;
            }

            output->payload.request_unicast.type = (enum ptp_message_type)((payload->message_type & PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_MASK) >> PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_SHIFT);
            output->payload.request_unicast.log_message_interval = payload->log_message_interval;
            output->payload.request_unicast.duration = be32toh(payload->duration);

            break;
        }

        case PTP_TLV_TYPE_GRANT_UNICAST_TRANSMISSION: {
            struct ptp_encoded_grant_unicast_transmission_tlv *payload = (struct ptp_encoded_grant_unicast_transmission_tlv *)head;
            head += sizeof(struct ptp_encoded_grant_unicast_transmission_tlv);

            if (head > tlv_tail) {
                return -EMSGSIZE;
            }

            output->payload.grant_unicast.type = (enum ptp_message_type)((payload->message_type & PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_MASK) >> PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_SHIFT);
            output->payload.grant_unicast.log_message_interval = payload->log_message_interval;
            output->payload.grant_unicast.duration = be32toh(payload->duration);
            output->payload.grant_unicast.flags = (enum ptp_tlv_unicast_flag)((payload->flags & PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_MASK) >> PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_SHIFT);

            break;
        }

        case PTP_TLV_TYPE_CANCEL_UNICAST_TRANSMISSION: {
            struct ptp_encoded_cancel_unicast_transmission_tlv *payload = (struct ptp_encoded_cancel_unicast_transmission_tlv *)head;
            head += sizeof(struct ptp_encoded_cancel_unicast_transmission_tlv);

            if (head > tlv_tail) {
                return -EMSGSIZE;
            }

            output->payload.cancel_unicast.type = (enum ptp_message_type)((payload->message_type_flags & PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_MASK) >> PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_SHIFT);
            output->payload.cancel_unicast.flags = (enum ptp_tlv_unicast_flag)((payload->message_type_flags & PTP_ENCODED_MESSAGE_TLV_UNICAST_FLAGS_MASK) >> PTP_ENCODED_MESSAGE_TLV_UNICAST_FLAGS_SHIFT);

            break;
        }

        case PTP_TLV_TYPE_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION: {
            struct ptp_encoded_acknowledge_cancel_unicast_transmission_tlv *payload = (struct ptp_encoded_acknowledge_cancel_unicast_transmission_tlv *)head;
            head += sizeof(struct ptp_encoded_acknowledge_cancel_unicast_transmission_tlv);

            if (head > tlv_tail) {
                return -EMSGSIZE;
            }

            output->payload.acknowledge_cancel_unicast.type = (enum ptp_message_type)((payload->message_type_flags & PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_MASK) >> PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_SHIFT);
            output->payload.acknowledge_cancel_unicast.flags = (enum ptp_tlv_unicast_flag)((payload->message_type_flags & PTP_ENCODED_MESSAGE_TLV_UNICAST_FLAGS_MASK) >> PTP_ENCODED_MESSAGE_TLV_UNICAST_FLAGS_SHIFT);

            break;
        }

        case PTP_TLV_TYPE_ALTERNATE_TIME_OFFSET_INDICATOR: {
            struct ptp_encoded_alternate_time_offset_indicator_tlv *payload = (struct ptp_encoded_alternate_time_offset_indicator_tlv *)head;
            head += sizeof(struct ptp_encoded_alternate_time_offset_indicator_tlv);

            if (head > tlv_tail) {
                return -EMSGSIZE;
            }

            output->payload.alternate_time_offset_indicator.key = payload->key;
            output->payload.alternate_time_offset_indicator.current_offset = be32toh(payload->current_offset);
            output->payload.alternate_time_offset_indicator.jump_seconds = be32toh(payload->jump_seconds);
            output->payload.alternate_time_offset_indicator.time_of_next_jump = ((uint64_t)be16toh(payload->time_of_next_jump_high) << 32) | (uint64_t)be32toh(payload->time_of_next_jump_low);

            struct ptp_encoded_text_header *string_header = (struct ptp_encoded_text_header *)head;
            head += sizeof(*string_header);

            if (string_header->length > PTP_DISPLAY_NAME_SIZE) {
                return -EMSGSIZE;
            }

            if (head + string_header->length > tlv_tail) {
                return -EMSGSIZE;
            }

            strncpy(output->payload.alternate_time_offset_indicator.display_name, (char *)head, string_header->length);
            output->payload.alternate_time_offset_indicator.display_name[string_header->length] = '\0';

            break;
        }

        case PTP_TLV_TYPE_PAD: {
            output->payload.pad.length = length;

            break;
        }

        case PTP_TLV_TYPE_AUTHENTICATION: {
            struct ptp_encoded_authetication_tlv *payload = (struct ptp_encoded_authetication_tlv *)head;
            head += sizeof(struct ptp_encoded_authetication_tlv);

            if (head > tlv_tail) {
                return -EMSGSIZE;
            }

            output->payload.authentication.policy = (enum ptp_authentication_policy)payload->policy;
            output->payload.authentication.parameter_indicator = payload->parameter_indicator;
            output->payload.authentication.key_id = be32toh(payload->key_id);

            output->payload.authentication.icv = head;
            output->payload.authentication.icv_length = tlv_tail - head;

            break;
        }

        default: {
            return -EINVAL;
        }
    }

    head = tlv_tail;
    *input = head;

    return 0;
}

int ptp_decode_message(struct ptp_decoded_message *output, uint8_t *input, short length) {
    int ret;

    uint8_t *head = input;
    uint8_t *const tail = input + length;

    struct ptp_encoded_message_header *header = (struct ptp_encoded_message_header *)head;
    head += sizeof(struct ptp_encoded_message_header);

    if (head > tail) {
        return -EMSGSIZE;
    }

    output->type = (header->major_sdo_id_type & PTP_ENCODED_MESSAGE_HEADER_TYPE_MASK) >> PTP_ENCODED_MESSAGE_HEADER_TYPE_SHIFT;
    output->sequence_id = be16toh(header->sequence_id);
    output->authenticated = false;

    output->sdo_id = ((uint16_t)((header->major_sdo_id_type & PTP_ENCODED_MESSAGE_HEADER_MAJOR_SDO_ID_MASK) >> PTP_ENCODED_MESSAGE_HEADER_MAJOR_SDO_ID_SHIFT) << 8) | header->minor_sdo_id;
    output->domain = header->domain;

    ptp_decode_port_id(&output->port_id, &header->port_id);

    output->flags = le16toh(header->flags);
    output->correction = be64toh(header->correction);
    output->control = header->control;

    output->log_message_interval = header->log_message_interval;

    ret = ptp_decode_payload(output, &head, tail);
    if (ret < 0) {
        return ret;
    }

    for (output->tlv_count = 0; output->tlv_count < PTP_MAX_TLV_COUNT; ++output->tlv_count) {
        if (head >= tail) {
            break;
        }

        ret = ptp_decode_tlv(&output->tlvs[output->tlv_count], &head, tail);
        if (ret < 0) {
            return ret;
        }
    }
    
    return 0;
}
