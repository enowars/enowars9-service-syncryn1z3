#include <endian.h>

#include <ptp/ptp_parse.h>

static void ptp_parse_port_id(struct ptp_port_id *destination, struct ptp_port_id *source) {
    destination->clock_id = be64toh(source->clock_id);
    destination->port = be16toh(source->port);
}

static void ptp_parse_timestamp(uint64_t *destination, struct ptp_timestamp *source) {
    const uint64_t seconds = (((uint64_t)be16toh(source->seconds_high)) << 32) | be32toh(source->seconds_low);
    const uint64_t nanoseconds = be32toh(source->nanoseconds);

    *destination = seconds * 1000000000UL + nanoseconds;
}

static void ptp_parse_clock_quality(struct ptp_parsed_clock_quality *destination, struct ptp_clock_quality *source) {
    destination->clock_class = source->clock_class;
    destination->clock_accuracy = (enum ptp_clock_accuracy)source->clock_accuracy;
    destination->offset_scaled_log_variance = be16toh(source->offset_scaled_log_variance);
}

static int ptp_parse_payload(struct ptp_parsed_message *result, uint8_t **buffer, const uint8_t *tail) {
    uint8_t *head = *buffer;

    switch (result->type) {
        case PTP_MESSAGE_TYPE_SYNC: {
            struct ptp_sync_message *payload = (struct ptp_sync_message *)head;
            head += sizeof(struct ptp_sync_message);

            if (head > tail) {
                return -1;
            }

            ptp_parse_timestamp(&result->payload.event.timestamp, &payload->origin_timestamp);
            
            break;
        }

        case PTP_MESSAGE_TYPE_DELAY_REQUEST: {
            struct ptp_delay_request_message *payload = (struct ptp_delay_request_message *)head;
            head += sizeof(struct ptp_delay_request_message);

            if (head > tail) {
                return -1;
            }

            ptp_parse_timestamp(&result->payload.event.timestamp, &payload->origin_timestamp);
            
            break;
        }

        case PTP_MESSAGE_TYPE_PDELAY_REQUEST: {
            struct ptp_pdelay_request_message *payload = (struct ptp_pdelay_request_message *)head;
            head += sizeof(struct ptp_pdelay_request_message);

            if (head > tail) {
                return -1;
            }

            ptp_parse_timestamp(&result->payload.event.timestamp, &payload->origin_timestamp);
            
            break;
        }

        case PTP_MESSAGE_TYPE_PDELAY_RESPONSE: {
            struct ptp_pdelay_response_message *payload = (struct ptp_pdelay_response_message *)head;
            head += sizeof(struct ptp_pdelay_response_message);

            if (head > tail) {
                return -1;
            }

            ptp_parse_timestamp(&result->payload.event.timestamp, &payload->receive_timestamp);
            ptp_parse_port_id(&result->payload.event.port_id, &payload->requesting_port_id);
            
            break;
        }

        case PTP_MESSAGE_TYPE_FOLLOW_UP: {
            struct ptp_pdelay_response_message *payload = (struct ptp_pdelay_response_message *)head;
            head += sizeof(struct ptp_pdelay_response_message);

            if (head > tail) {
                return -1;
            }

            ptp_parse_timestamp(&result->payload.event.timestamp, &payload->receive_timestamp);
            ptp_parse_port_id(&result->payload.event.port_id, &payload->requesting_port_id);
            
            break;
        }

        case PTP_MESSAGE_TYPE_DELAY_RESPONSE: {
            struct ptp_delay_response_message *payload = (struct ptp_delay_response_message *)head;
            head += sizeof(struct ptp_delay_response_message);

            if (head > tail) {
                return -1;
            }

            ptp_parse_timestamp(&result->payload.event.timestamp, &payload->receive_timestamp);
            ptp_parse_port_id(&result->payload.event.port_id, &payload->requesting_port_id);
            
            break;
        }

        case PTP_MESSAGE_TYPE_PDELAY_RESPONSE_FOLLOW_UP: {
            struct ptp_pdelay_response_follow_up_message *payload = (struct ptp_pdelay_response_follow_up_message *)head;
            head += sizeof(struct ptp_pdelay_response_follow_up_message);

            if (head > tail) {
                return -1;
            }

            ptp_parse_timestamp(&result->payload.event.timestamp, &payload->receive_timestamp);
            ptp_parse_port_id(&result->payload.event.port_id, &payload->requesting_port_id);
            
            break;
        }

        case PTP_MESSAGE_TYPE_ANNOUNCE: {
            struct ptp_announce_message *payload = (struct ptp_announce_message *)head;
            head += sizeof(struct ptp_announce_message);

            if (head > tail) {
                return -1;
            }

            ptp_parse_timestamp(&result->payload.announce.timestamp, &payload->origin_timestamp);
            result->payload.announce.current_utc_offset = be16toh(payload->current_utc_offset);

            result->payload.announce.grandmaster_priority = (((uint16_t)payload->grandmaster_priority_1) << 8) | payload->grandmaster_priority_2;
            ptp_parse_clock_quality(&result->payload.announce.grandmaster_clock_quality, &payload->grandmaster_clock_quality);
            result->payload.announce.grandmaster_identity = be64toh(payload->grandmaster_identity);

            result->payload.announce.steps_removed = be16toh(payload->steps_removed);
            result->payload.announce.time_source = (enum ptp_time_source)payload->time_source;
            
            break;
        }

        case PTP_MESSAGE_TYPE_SIGNALING: {
            struct ptp_signaling_message *payload = (struct ptp_signaling_message *)head;
            head += sizeof(struct ptp_signaling_message);

            if (head > tail) {
                return -1;
            }

            ptp_parse_port_id(&result->payload.signaling.target_port_id, &payload->target_port_id);
            
            break;
        }

        case PTP_MESSAGE_TYPE_MANAGEMENT: {
            struct ptp_management_message *payload = (struct ptp_management_message *)head;
            head += sizeof(struct ptp_management_message);

            if (head > tail) {
                return -1;
            }

            ptp_parse_port_id(&result->payload.management.target_port_id, &payload->target_port_id);

            result->payload.management.starting_boundary_hops = payload->starting_boundary_hops;
            result->payload.management.boundary_hops = payload->boundary_hops;
            result->payload.management.action = (enum ptp_management_action)payload->action;
            
            break;
        }

        default: {
            return -1;
        }
    }

    *buffer = head;

    return 0;
}

static int ptp_parse_tlv(struct ptp_parsed_tlv *result, uint8_t **buffer, uint8_t *const tail) {
    uint8_t *head = *buffer;

    struct ptp_tlv_header *header = (struct ptp_tlv_header *)head;
    
    result->type = (enum ptp_tlv_type)be16toh(header->type);
    const int length = be16toh(header->length);

    head += sizeof(struct ptp_tlv_header);

    uint8_t *const tlv_tail = head + length;

    if (head > tail) {
        return -1;
    }

    switch (result->type) {
        case PTP_TLV_TYPE_MANAGEMENT: {
            struct ptp_management_tlv *payload = (struct ptp_management_tlv *)head;
            head += sizeof(struct ptp_management_tlv);

            if (head > tail || head > tlv_tail) {
                return -1;
            }

            result->payload.management.id = (enum ptp_management_id)be16toh(payload->management_id);

            result->payload.management.data = head;
            result->payload.management.data_length = tlv_tail - head;

            break;
        }

        case PTP_TLV_TYPE_PAD: {
            break;
        }

        case PTP_TLV_TYPE_AUTHENTICATION: {
            struct ptp_authetication_tlv *payload = (struct ptp_authetication_tlv *)head;
            head += sizeof(struct ptp_authetication_tlv);

            if (head > tail || head > tlv_tail) {
                return -1;
            }

            result->payload.authentication.spp = payload->spp;
            result->payload.authentication.security_parameter_indicatior = payload->security_parameter_indicatior;
            result->payload.authentication.key_id = be32toh(payload->key_id);

            result->payload.authentication.icv = head;
            result->payload.authentication.icv_length = tlv_tail - head;

            break;
        }

        default: {
            return -1;
        }
    }

    head = tlv_tail;
    *buffer = head;

    return 0;
}

int ptp_parse_message(struct ptp_parsed_message *result, uint8_t *buffer, size_t length) {
    int ret;

    uint8_t *head = buffer;
    uint8_t *const tail = buffer + length;

    struct ptp_message_header *header = (struct ptp_message_header *)head;
    head += sizeof(struct ptp_message_header);

    if (head > tail) {
        return -1;
    }

    result->type = (header->major_sdo_id_type & PTP_MESSAGE_HEADER_TYPE_MASK) >> PTP_MESSAGE_HEADER_TYPE_SHIFT;
    result->sequence_id = be16toh(header->sequence_id);

    result->sdo_id = ((uint16_t)((header->major_sdo_id_type & PTP_MESSAGE_HEADER_MAJOR_SDO_ID_MASK) >> PTP_MESSAGE_HEADER_MAJOR_SDO_ID_SHIFT) << 8) | header->minor_sdo_id;
    result->domain = header->domain;

    ptp_parse_port_id(&result->port_id, &header->port_id);

    result->flags = be16toh(header->flags);
    result->correction = be64toh(header->correction);
    result->control = header->control;

    result->log_message_interval = header->log_message_interval;

    ret = ptp_parse_payload(result, &head, tail);
    if (ret < 0) {
        return ret;
    }

    for (result->tlv_count = 0; result->tlv_count < PTP_MAX_TLV_COUNT; ++result->tlv_count) {
        if (head >= tail) {
            break;
        }

        ret = ptp_parse_tlv(&result->tlvs[result->tlv_count], &head, tail);
        if (ret < 0) {
            return ret;
        }
    }
    
    return 0;
}
