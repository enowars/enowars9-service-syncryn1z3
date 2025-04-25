#pragma once

#include <stdint.h>
#include <stdlib.h>

#include <ptp/ptp_protocol.h>

#define PTP_MAX_TLV_COUNT 8


/*
    General types
*/

struct ptp_parsed_clock_quality {
    uint8_t clock_class;
    enum ptp_clock_accuracy clock_accuracy;
    uint16_t offset_scaled_log_variance;
};


/*
    TLVs
*/

struct ptp_parsed_management_tlv {
    enum ptp_management_id id;

    void *data;
    size_t data_length;  
};

struct ptp_parsed_authentication_tlv {
    uint8_t spp;
    uint8_t security_parameter_indicatior;
    uint32_t key_id;

    void *icv;
    size_t icv_length;    
};

struct ptp_parsed_tlv {
    enum ptp_tlv_type type;

    union {
        struct ptp_parsed_management_tlv management;
        struct ptp_parsed_authentication_tlv authentication;
    } payload;
};


/*
    Messages
*/

struct ptp_parsed_event_message {
    uint64_t timestamp;
    struct ptp_port_id port_id;
};

struct ptp_parsed_announce_message {
    uint64_t timestamp;
    uint16_t current_utc_offset;

    uint16_t grandmaster_priority;
    struct ptp_parsed_clock_quality grandmaster_clock_quality;
    ptp_clock_id_t grandmaster_identity;

    uint16_t steps_removed;
    enum ptp_time_source time_source;
};

struct ptp_parsed_signaling_message {
    struct ptp_port_id target_port_id;
};

struct ptp_parsed_management_message {
    struct ptp_port_id target_port_id;
    enum ptp_management_action action;

    uint8_t starting_boundary_hops;
    uint8_t boundary_hops;
};

struct ptp_parsed_message {
    enum ptp_message_type type;
    uint16_t sequence_id;

    uint16_t sdo_id;
    uint8_t domain;

    struct ptp_port_id port_id;

    uint16_t flags;
    uint64_t correction;    
    uint8_t control;

    uint8_t log_message_interval;

    union {
        struct ptp_parsed_event_message event;
        struct ptp_parsed_announce_message announce;
        struct ptp_parsed_signaling_message signaling;
        struct ptp_parsed_management_message management;
    } payload;

    struct ptp_parsed_tlv tlvs[PTP_MAX_TLV_COUNT];
    int tlv_count;
};

int ptp_parse_message(struct ptp_parsed_message *result, uint8_t *buffer, size_t length);
