#include <endian.h>
#include <string.h>

#include <ptp/ptp_coding.h>

static void ptp_encode_port_id(struct ptp_encoded_port_id *output, struct ptp_decoded_port_id *input) {
    output->clock_id = be64toh(input->clock_id);
    output->port = be16toh(input->port);
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
            payload->grandmaster_identity = htobe64(input->payload.announce.grandmaster_identity);

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

static int ptp_encode_tlv(uint8_t **output, struct ptp_decoded_tlv *input, uint8_t *const tail) {
    uint8_t *head = *output;

    struct ptp_encoded_tlv_header *header = (struct ptp_encoded_tlv_header *)head;
    
    header->type = htobe16((uint16_t)input->type);

    head += sizeof(struct ptp_encoded_tlv_header);

    if (head > tail) {
        return -1;
    }

    switch (input->type) {
        case PTP_TLV_TYPE_MANAGEMENT: {
            struct ptp_encoded_management_tlv *payload = (struct ptp_encoded_management_tlv *)head;
            head += sizeof(struct ptp_encoded_management_tlv);

            if (head + input->payload.management.data_length > tail) {
                return -1;
            }

            payload->management_id = htobe16((uint16_t)input->payload.management.id);
            memcpy(head, input->payload.management.data, input->payload.management.data_length);

            head += input->payload.management.data_length;

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

            // TODO: generate ICV

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
