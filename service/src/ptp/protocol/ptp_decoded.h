#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <ptp/protocol/ptp_constants.h>

#define PTP_MAX_TLV_COUNT 20

#define PTP_DISPLAY_NAME_SIZE 10
#define PTP_USER_DESCRIPTION_SIZE 128
#define PTP_PORT_SECRET_SIZE 64
#define PTP_MANAGEMENT_ERROR_DISPLAY_DATA_SIZE 50

/*
    General types
*/

struct ptp_decoded_port_id {
    uint64_t clock_id;
    uint16_t port;
};

typedef uint64_t ptp_decoded_timestamp_t;

struct ptp_decoded_clock_quality {
    enum ptp_clock_class clock_class;
    enum ptp_clock_accuracy clock_accuracy;
    uint16_t offset_scaled_log_variance;
};


/*
    TLVs
*/

union ptp_decoded_management_tlv_payload {
    struct {
        short length;
        uint8_t data[PTP_USER_DESCRIPTION_SIZE];
    } user_description;
    
    ptp_decoded_timestamp_t time;
};

struct ptp_decoded_management_tlv {
    enum ptp_management_id id;
    union ptp_decoded_management_tlv_payload payload; 
};

struct ptp_decoded_management_error_status_tlv {
    enum ptp_management_error_id error_id;
    enum ptp_management_id id;
    char display_data[PTP_MANAGEMENT_ERROR_DISPLAY_DATA_SIZE + 1]; 
};

struct ptp_decoded_request_unicast_transmission_tlv {
    enum ptp_message_type type;
    uint8_t log_message_interval;
    uint32_t duration;
};

struct ptp_decoded_grant_unicast_transmission_tlv {
    enum ptp_message_type type;
    uint8_t log_message_interval;
    uint32_t duration;
    enum ptp_tlv_unicast_flag flags;
};

struct ptp_decoded_cancel_unicast_transmission_tlv {
    enum ptp_message_type type;
    enum ptp_tlv_unicast_flag flags;
};

struct ptp_decoded_acknowledge_cancel_unicast_transmission_tlv {
    enum ptp_message_type type;
    enum ptp_tlv_unicast_flag flags;
};

struct ptp_decoded_alternate_time_offset_indicator_tlv {
    uint8_t key;
    int32_t current_offset;
    int32_t jump_seconds;
    uint64_t time_of_next_jump;
    char display_name[PTP_DISPLAY_NAME_SIZE + 1];
};

struct ptp_decoded_pad_tlv {
    uint16_t length;  
};

struct ptp_decoded_authentication_tlv {
    enum ptp_authentication_policy policy;
    uint8_t parameter_indicator;
    uint32_t key_id;

    uint8_t *icv;
    short icv_length;    
};

struct ptp_decoded_tlv {
    enum ptp_tlv_type type;
    bool authenticated;

    union {
        struct ptp_decoded_management_tlv management;
        struct ptp_decoded_management_error_status_tlv management_error_status;
        struct ptp_decoded_request_unicast_transmission_tlv request_unicast;
        struct ptp_decoded_grant_unicast_transmission_tlv grant_unicast;
        struct ptp_decoded_cancel_unicast_transmission_tlv cancel_unicast;
        struct ptp_decoded_acknowledge_cancel_unicast_transmission_tlv acknowledge_cancel_unicast;
        struct ptp_decoded_alternate_time_offset_indicator_tlv alternate_time_offset_indicator;
        struct ptp_decoded_pad_tlv pad;
        struct ptp_decoded_authentication_tlv authentication;
    } payload;
};


/*
    Messages
*/

struct ptp_decoded_event_message {
    ptp_decoded_timestamp_t timestamp;
    struct ptp_decoded_port_id port_id;
};

struct ptp_decoded_announce_message {
    ptp_decoded_timestamp_t timestamp;
    uint16_t current_utc_offset;

    uint16_t grandmaster_priority;
    struct ptp_decoded_clock_quality grandmaster_clock_quality;
    uint64_t grandmaster_id;

    uint16_t steps_removed;
    enum ptp_time_source time_source;
};

struct ptp_decoded_signaling_message {
    struct ptp_decoded_port_id target_port_id;
};

struct ptp_decoded_management_message {
    struct ptp_decoded_port_id target_port_id;
    enum ptp_management_action action;

    uint8_t starting_boundary_hops;
    uint8_t boundary_hops;
};

struct ptp_decoded_message {
    enum ptp_message_type type;
    uint16_t sequence_id;
    bool authenticated;

    uint16_t sdo_id;
    uint8_t domain;

    struct ptp_decoded_port_id port_id;

    uint16_t flags;
    uint64_t correction;
    uint8_t control;

    uint8_t log_message_interval;

    union {
        struct ptp_decoded_event_message event;
        struct ptp_decoded_announce_message announce;
        struct ptp_decoded_signaling_message signaling;
        struct ptp_decoded_management_message management;
    } payload;

    struct ptp_decoded_tlv tlvs[PTP_MAX_TLV_COUNT];
    int tlv_count;
};
