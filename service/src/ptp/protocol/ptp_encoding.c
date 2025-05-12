#include <endian.h>
#include <stdint.h>
#include <string.h>

#include <ptp/protocol/ptp_encoded.h>
#include <ptp/protocol/ptp_protocol.h>

static void ptp_encode_port_id(struct ptp_encoded_port_id *output, struct ptp_decoded_port_id *input) {
    memcpy(output->clock_id, input->clock_id, sizeof(input->clock_id));
    output->port = htobe16(input->port);
}

static void ptp_encode_timestamp(struct ptp_encoded_timestamp *output, ptp_decoded_timestamp_t input) {
    const uint64_t seconds = input / 1000000000UL;

    output->seconds_high = htobe16((seconds % 0xffff00000000) >> 32);
    output->seconds_low = htobe32(seconds & 0xffffffff);
    output->nanoseconds = htobe32(input % 1000000000UL);
}

static void ptp_encode_clock_quality(struct ptp_encoded_clock_quality *output, struct ptp_decoded_clock_quality *input) {
    output->clock_class = input->clock_class;
    output->clock_accuracy = (uint8_t)input->clock_accuracy;
    output->offset_scaled_log_variance = htobe16(input->offset_scaled_log_variance);
}

static int ptp_encode_payload(uint8_t **output, struct ptp_decoded_message *input, const uint8_t *tail) {
    uint8_t *head = *output;

    switch (input->type) {
        case PTP_MESSAGE_TYPE_SYNC: {
            struct ptp_encoded_sync_message *payload = (struct ptp_encoded_sync_message *)head;
            head += sizeof(struct ptp_encoded_sync_message);

            if (head > tail) {
                return -1;
            }

            ptp_encode_timestamp(&payload->origin_timestamp, input->payload.event.timestamp);
            
            break;
        }

        case PTP_MESSAGE_TYPE_DELAY_REQUEST: {
            struct ptp_encoded_delay_request_message *payload = (struct ptp_encoded_delay_request_message *)head;
            head += sizeof(struct ptp_encoded_delay_request_message);

            if (head > tail) {
                return -1;
            }

            ptp_encode_timestamp(&payload->origin_timestamp, input->payload.event.timestamp);
            
            break;
        }

        case PTP_MESSAGE_TYPE_PDELAY_REQUEST: {
            struct ptp_encoded_pdelay_request_message *payload = (struct ptp_encoded_pdelay_request_message *)head;
            head += sizeof(struct ptp_encoded_pdelay_request_message);

            if (head > tail) {
                return -1;
            }

            ptp_encode_timestamp(&payload->origin_timestamp, input->payload.event.timestamp);
            
            break;
        }

        case PTP_MESSAGE_TYPE_PDELAY_RESPONSE: {
            struct ptp_encoded_pdelay_response_message *payload = (struct ptp_encoded_pdelay_response_message *)head;
            head += sizeof(struct ptp_encoded_pdelay_response_message);

            if (head > tail) {
                return -1;
            }

            ptp_encode_timestamp(&payload->receive_timestamp, input->payload.event.timestamp);
            ptp_encode_port_id(&payload->requesting_port_id, &input->payload.event.port_id);
            
            break;
        }

        case PTP_MESSAGE_TYPE_FOLLOW_UP: {
            struct ptp_encoded_pdelay_response_message *payload = (struct ptp_encoded_pdelay_response_message *)head;
            head += sizeof(struct ptp_encoded_pdelay_response_message);

            if (head > tail) {
                return -1;
            }

            ptp_encode_timestamp(&payload->receive_timestamp, input->payload.event.timestamp);
            ptp_encode_port_id(&payload->requesting_port_id, &input->payload.event.port_id);
            
            break;
        }

        case PTP_MESSAGE_TYPE_DELAY_RESPONSE: {
            struct ptp_encoded_delay_response_message *payload = (struct ptp_encoded_delay_response_message *)head;
            head += sizeof(struct ptp_encoded_delay_response_message);

            if (head > tail) {
                return -1;
            }

            ptp_encode_timestamp(&payload->receive_timestamp, input->payload.event.timestamp);
            ptp_encode_port_id(&payload->requesting_port_id, &input->payload.event.port_id);
            
            break;
        }

        case PTP_MESSAGE_TYPE_PDELAY_RESPONSE_FOLLOW_UP: {
            struct ptp_encoded_pdelay_response_follow_up_message *payload = (struct ptp_encoded_pdelay_response_follow_up_message *)head;
            head += sizeof(struct ptp_encoded_pdelay_response_follow_up_message);

            if (head > tail) {
                return -1;
            }

            ptp_encode_timestamp(&payload->receive_timestamp, input->payload.event.timestamp);
            ptp_encode_port_id(&payload->requesting_port_id, &input->payload.event.port_id);
            
            break;
        }

        case PTP_MESSAGE_TYPE_ANNOUNCE: {
            struct ptp_encoded_announce_message *payload = (struct ptp_encoded_announce_message *)head;
            head += sizeof(struct ptp_encoded_announce_message);

            if (head > tail) {
                return -1;
            }

            ptp_encode_timestamp(&payload->origin_timestamp, input->payload.announce.timestamp);
            payload->current_utc_offset = htobe16(input->payload.announce.current_utc_offset);

            payload->grandmaster_priority_1 = (input->payload.announce.grandmaster_priority & 0xff00) >> 8;
            payload->grandmaster_priority_2 = input->payload.announce.grandmaster_priority & 0xff;
            ptp_encode_clock_quality(&payload->grandmaster_clock_quality, &input->payload.announce.grandmaster_clock_quality);
            memcpy(payload->grandmaster_id, input->payload.announce.grandmaster_id, sizeof(input->payload.announce.grandmaster_id));

            payload->steps_removed = htobe16(input->payload.announce.steps_removed);
            payload->time_source = (uint8_t)input->payload.announce.time_source;
            
            break;
        }

        case PTP_MESSAGE_TYPE_SIGNALING: {
            struct ptp_encoded_signaling_message *payload = (struct ptp_encoded_signaling_message *)head;
            head += sizeof(struct ptp_encoded_signaling_message);

            if (head > tail) {
                return -1;
            }

            ptp_encode_port_id(&payload->target_port_id, &input->payload.signaling.target_port_id);
            
            break;
        }

        case PTP_MESSAGE_TYPE_MANAGEMENT: {
            struct ptp_encoded_management_message *payload = (struct ptp_encoded_management_message *)head;
            head += sizeof(struct ptp_encoded_management_message);

            if (head > tail) {
                return -1;
            }

            ptp_encode_port_id(&payload->target_port_id, &input->payload.management.target_port_id);

            payload->starting_boundary_hops = input->payload.management.starting_boundary_hops;
            payload->boundary_hops = input->payload.management.boundary_hops;
            payload->action = (uint8_t)input->payload.management.action;
            
            break;
        }

        default: {
            return -1;
        }
    }

    *output = head;

    return 0;
}   

static int ptp_encode_management_tlv(uint8_t **output, struct ptp_decoded_management_tlv *input, uint8_t *const tail) {
    uint8_t *head = *output;

    struct ptp_encoded_management_tlv *payload = (struct ptp_encoded_management_tlv *)head;
    head += sizeof(struct ptp_encoded_management_tlv);

    if (head > tail) {
        return -1;
    }

    payload->management_id = htobe16((uint16_t)input->id);

    switch (input->id) {
        case PTP_MANAGEMENT_ID_USER_DESCRIPTION: {
            uint8_t *string_head = head;
            int total_length = 0;

            struct ptp_encoded_text_header *header = (struct ptp_encoded_text_header *)string_head;
            string_head += sizeof(*header);

            if (string_head > tail) {
                return -1;
            }

            header->length = strnlen(input->payload.user_description, PTP_USER_DESCRIPTION_SIZE);
            total_length += sizeof(*header) + header->length;
            int actual_length = total_length + (total_length & 0x1); // Add padding to get 2-byte alignment

            if (head + actual_length > tail) {
                return -1;
            }

            memcpy((char *)string_head, input->payload.user_description, header->length);

            head += actual_length;

            break;
        }

        case PTP_MANAGEMENT_ID_IMPLEMENTATION_SPECIFIC_PORT_CLAIM: {
            uint8_t *string_head = head;
            int total_length = 0;

            struct ptp_encoded_text_header *header = (struct ptp_encoded_text_header *)string_head;
            string_head += sizeof(*header);

            if (string_head > tail) {
                return -1;
            }

            header->length = strnlen(input->payload.port_claim.port_secret, PTP_PORT_SECRET_SIZE);
            header->length = header->length;
            total_length += sizeof(*header) + header->length;

            if (string_head + header->length > tail) {
                return -1;
            }

            memcpy((char *)string_head, input->payload.port_claim.port_secret, header->length);

            string_head += header->length;

            header = (struct ptp_encoded_text_header *)string_head;
            string_head += sizeof(*header);

            if (string_head > tail) {
                return -1;
            }

            header->length = strnlen(input->payload.port_claim.user_description, PTP_USER_DESCRIPTION_SIZE);
            total_length += sizeof(*header) + header->length;
            int actual_length = total_length + (total_length & 0x1); // Add padding to get 2-byte alignment

            if (head + actual_length > tail) {
                return -1;
            }

            memcpy((char *)string_head, input->payload.port_claim.user_description, header->length);

            head += total_length;

            break;
        }

        default: {
            return -1;
        }
    }

    *output = head;

    return 0;
}

static int ptp_encode_management_error_status_tlv(uint8_t **output, struct ptp_decoded_management_error_status_tlv *input, uint8_t *const tail) {
    uint8_t *head = *output;

    struct ptp_encoded_management_error_status_tlv *payload = (struct ptp_encoded_management_error_status_tlv *)head;
    head += sizeof(struct ptp_encoded_management_error_status_tlv);

    if (head > tail) {
        return -1;
    }

    payload->management_error_id = htobe16((uint16_t)input->error_id);
    payload->management_id = htobe16((uint16_t)input->id);

    struct ptp_encoded_text_header *header = (struct ptp_encoded_text_header *)head;
    head += sizeof(*header);

    if (head > tail) {
        return -1;
    }

    header->length = strnlen(input->display_data, PTP_MANAGEMENT_ERROR_DISPLAY_DATA_SIZE);
    int actual_length = header->length + (~header->length & 0x1); // Add padding to get 2-byte alignment

    if (head + actual_length > tail) {
        return -1;
    }

    memcpy((char *)head, input->display_data, header->length);

    head += actual_length;
    *output = head;

    return 0;
}

static int ptp_encode_tlv(uint8_t **output, struct ptp_decoded_tlv *input, uint8_t *const tail) {
    int ret;
    uint8_t *head = *output;

    struct ptp_encoded_tlv_header *header = (struct ptp_encoded_tlv_header *)head;
    
    header->type = htobe16((uint16_t)input->type);

    head += sizeof(struct ptp_encoded_tlv_header);

    if (head > tail) {
        return -1;
    }

    switch (input->type) {
        case PTP_TLV_TYPE_MANAGEMENT: {
            ret = ptp_encode_management_tlv(&head, &input->payload.management, tail);
            if (ret) {
                return ret;
            }

            break;
        }

        case PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS: {
            ret = ptp_encode_management_error_status_tlv(&head, &input->payload.management_error_status, tail);
            if (ret) {
                return ret;
            }

            break;
        }

        case PTP_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION: {
            struct ptp_encoded_request_unicast_transmission_tlv *payload = (struct ptp_encoded_request_unicast_transmission_tlv *)head;
            head += sizeof(struct ptp_encoded_request_unicast_transmission_tlv);

            if (head > tail) {
                return -1;
            }

            payload->message_type = (input->payload.request_unicast.type << PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_SHIFT) & PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_MASK;
            payload->log_message_interval = input->payload.request_unicast.log_message_interval;
            payload->duration = htobe32(input->payload.request_unicast.duration);

            break;
        }

        case PTP_TLV_TYPE_GRANT_UNICAST_TRANSMISSION: {
            struct ptp_encoded_grant_unicast_transmission_tlv *payload = (struct ptp_encoded_grant_unicast_transmission_tlv *)head;
            head += sizeof(struct ptp_encoded_grant_unicast_transmission_tlv);

            if (head > tail) {
                return -1;
            }

            payload->message_type = (input->payload.grant_unicast.type << PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_SHIFT) & PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_MASK;
            payload->log_message_interval = input->payload.grant_unicast.log_message_interval;
            payload->duration = htobe32(input->payload.grant_unicast.duration);
            payload->flags = (input->payload.grant_unicast.flags << PTP_ENCODED_MESSAGE_TLV_UNICAST_FLAGS_SHIFT) & PTP_ENCODED_MESSAGE_TLV_UNICAST_FLAGS_MASK;

            break;
        }

        case PTP_TLV_TYPE_CANCEL_UNICAST_TRANSMISSION: {
            struct ptp_encoded_cancel_unicast_transmission_tlv *payload = (struct ptp_encoded_cancel_unicast_transmission_tlv *)head;
            head += sizeof(struct ptp_encoded_cancel_unicast_transmission_tlv);

            if (head > tail) {
                return -1;
            }

            payload->message_type_flags = (input->payload.cancel_unicast.type << PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_SHIFT) & PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_MASK;
            payload->message_type_flags |= (input->payload.cancel_unicast.flags << PTP_ENCODED_MESSAGE_TLV_UNICAST_FLAGS_SHIFT) & PTP_ENCODED_MESSAGE_TLV_UNICAST_FLAGS_MASK;

            break;
        }

        case PTP_TLV_TYPE_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION: {
            struct ptp_encoded_acknowledge_cancel_unicast_transmission_tlv *payload = (struct ptp_encoded_acknowledge_cancel_unicast_transmission_tlv *)head;
            head += sizeof(struct ptp_encoded_acknowledge_cancel_unicast_transmission_tlv);

            if (head > tail) {
                return -1;
            }

            payload->message_type_flags = (input->payload.acknowledge_cancel_unicast.type << PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_SHIFT) & PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_MASK;
            payload->message_type_flags |= (input->payload.acknowledge_cancel_unicast.flags << PTP_ENCODED_MESSAGE_TLV_UNICAST_FLAGS_SHIFT) & PTP_ENCODED_MESSAGE_TLV_UNICAST_FLAGS_MASK;

            break;
        }

        case PTP_TLV_TYPE_PAD: {
            head += input->payload.pad.length;

            if (head > tail) {
                return -1;
            }

            break;
        }

        case PTP_TLV_TYPE_AUTHENTICATION: {
            struct ptp_encoded_authetication_tlv *payload = (struct ptp_encoded_authetication_tlv *)head;
            head += sizeof(struct ptp_encoded_authetication_tlv);

            if (head + input->payload.authentication.icv_length > tail) {
                return -1;
            }

            payload->spp = input->payload.authentication.spp;
            payload->security_parameter_indicatior = input->payload.authentication.security_parameter_indicatior;
            payload->key_id = htobe32(input->payload.authentication.key_id);

            // ICV is generated by ptp_security_complete_auth_tlvs()

            head += input->payload.authentication.icv_length;

            break;
        }

        default: {
            return -1;
        }
    }

    header->length = htobe16(head - (uint8_t *)(header + 1));
    *output = head;

    return 0;
}

int ptp_encode_message(uint8_t *output, struct ptp_decoded_message *input, int length) {
    int ret;

    uint8_t *head = output;
    uint8_t *const tail = output + length;

    struct ptp_encoded_message_header *header = (struct ptp_encoded_message_header *)head;
    head += sizeof(struct ptp_encoded_message_header);

    if (head > tail) {
        return -1;
    }

    header->major_sdo_id_type = ((input->type << PTP_ENCODED_MESSAGE_HEADER_TYPE_SHIFT) & PTP_ENCODED_MESSAGE_HEADER_TYPE_MASK) | (((input->sdo_id & 0xf00) >> 8) << PTP_ENCODED_MESSAGE_HEADER_MAJOR_SDO_ID_SHIFT);
    header->version = ptp_version;
    header->sequence_id = htobe16(input->sequence_id);

    header->minor_sdo_id = input->sdo_id & 0xff;
    header->domain = input->domain;

    ptp_encode_port_id(&header->port_id, &input->port_id);

    header->flags = htole16(input->flags);
    header->correction = htobe64(input->correction);
    header->control = input->control;

    header->log_message_interval = input->log_message_interval;

    ret = ptp_encode_payload(&head, input, tail);
    if (ret < 0) {
        return ret;
    }

    for (int i = 0; i < input->tlv_count; ++i) {
        ret = ptp_encode_tlv(&head, &input->tlvs[i], tail);
        if (ret < 0) {
            return ret;
        }
    }

    const int actual_length = head - output;
    header->length = htobe16(actual_length);
    
    return actual_length;
}
