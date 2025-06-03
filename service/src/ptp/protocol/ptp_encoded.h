#pragma once

#include <stdint.h>

#include <ptp/protocol/ptp_constants.h>

/*
    Shifts and masks
*/

#define PTP_ENCODED_MESSAGE_HEADER_TYPE_MASK 0x0f
#define PTP_ENCODED_MESSAGE_HEADER_TYPE_SHIFT 0
#define PTP_ENCODED_MESSAGE_HEADER_MAJOR_SDO_ID_MASK 0xf0
#define PTP_ENCODED_MESSAGE_HEADER_MAJOR_SDO_ID_SHIFT 4
#define PTP_ENCODED_MESSAGE_TLV_UNICAST_FLAGS_MASK 0x03
#define PTP_ENCODED_MESSAGE_TLV_UNICAST_FLAGS_SHIFT 0
#define PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_MASK 0xf0
#define PTP_ENCODED_MESSAGE_TLV_UNICAST_TYPE_SHIFT 4
#define PTP_MANAGEMENT_ACTION_MASK 0x1f
#define PTP_MANAGEMENT_ACTION_SHIFT 0

#define PTP_MESSAGE_ALIGNMENT 16


/*
    General types
*/

struct ptp_encoded_port_id {
    uint64_t clock_id;
    uint16_t port;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_port_id) == 10);

struct ptp_encoded_timestamp {
    uint16_t seconds_high;
    uint32_t seconds_low;
    uint32_t nanoseconds;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_timestamp) == 10);

struct ptp_encoded_clock_quality {
    uint8_t clock_class;
    uint8_t clock_accuracy;
    uint16_t offset_scaled_log_variance;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_clock_quality) == 4);

struct ptp_encoded_text_header {
    uint8_t length;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_text_header) == 1);

/*
    Messages
*/

struct ptp_encoded_message_header {
    uint8_t major_sdo_id_type;
    uint8_t version;
    uint16_t length;
    uint8_t domain;
    uint8_t minor_sdo_id;
    uint16_t flags;
    uint64_t correction;
    uint32_t type_specific;
    struct ptp_encoded_port_id port_id;
    uint16_t sequence_id;
    uint8_t control;
    uint8_t log_message_interval;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_message_header) == 34);

struct ptp_encoded_sync_message {
    struct ptp_encoded_timestamp origin_timestamp;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_sync_message) == 10);

struct ptp_encoded_delay_request_message {
    struct ptp_encoded_timestamp origin_timestamp;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_delay_request_message) == 10);

struct ptp_encoded_follow_up_message {
    struct ptp_encoded_timestamp origin_timestamp;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_follow_up_message) == 10);

struct ptp_encoded_delay_response_message {
    struct ptp_encoded_timestamp receive_timestamp;
    struct ptp_encoded_port_id requesting_port_id;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_delay_response_message) == 20);

struct ptp_encoded_pdelay_request_message {
    struct ptp_encoded_timestamp origin_timestamp;
    uint8_t reserved[10];
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_pdelay_request_message) == 20);

struct ptp_encoded_pdelay_response_message {
    struct ptp_encoded_timestamp receive_timestamp;
    struct ptp_encoded_port_id requesting_port_id;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_pdelay_response_message) == 20);

struct ptp_encoded_pdelay_response_follow_up_message {
    struct ptp_encoded_timestamp receive_timestamp;
    struct ptp_encoded_port_id requesting_port_id;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_pdelay_response_follow_up_message) == 20);

struct ptp_encoded_announce_message {
    struct ptp_encoded_timestamp origin_timestamp;
    uint16_t current_utc_offset;
    uint8_t reserved;
    uint8_t grandmaster_priority_1;
    struct ptp_encoded_clock_quality grandmaster_clock_quality;
    uint8_t grandmaster_priority_2;
    uint64_t grandmaster_id;
    uint16_t steps_removed;
    uint8_t time_source;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_announce_message) == 30);

struct ptp_encoded_signaling_message {
    struct ptp_encoded_port_id target_port_id;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_signaling_message) == 10);

struct ptp_encoded_management_message {
    struct ptp_encoded_port_id target_port_id;
    uint8_t starting_boundary_hops;
    uint8_t boundary_hops;
    uint8_t action;
    uint8_t reserved;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_management_message) == 14);


/*
    TLVs
*/

struct ptp_encoded_tlv_header {
    uint16_t type;
    uint16_t length;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_tlv_header) == 4);

struct ptp_encoded_management_tlv {
    uint16_t management_id;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_management_tlv) == 2);

struct ptp_encoded_management_error_status_tlv {
    uint16_t management_error_id;
    uint16_t management_id;
    uint8_t reserved[4];
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_management_error_status_tlv) == 8);

struct ptp_encoded_request_unicast_transmission_tlv {
    uint8_t message_type;
    uint8_t log_message_interval;
    uint32_t duration;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_request_unicast_transmission_tlv) == 6);

struct ptp_encoded_grant_unicast_transmission_tlv {
    uint8_t message_type;
    uint8_t log_message_interval;
    uint32_t duration;
    int8_t reserved;
    int8_t flags;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_grant_unicast_transmission_tlv) == 8);

struct ptp_encoded_cancel_unicast_transmission_tlv {
    uint8_t message_type_flags;
    uint8_t reserved;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_cancel_unicast_transmission_tlv) == 2);

struct ptp_encoded_acknowledge_cancel_unicast_transmission_tlv {
    uint8_t message_type_flags;
    uint8_t reserved;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_acknowledge_cancel_unicast_transmission_tlv) == 2);

struct ptp_encoded_alternate_time_offset_indicator_tlv {
    uint8_t key;
    int32_t current_offset;
    int32_t jump_seconds;
    uint16_t time_of_next_jump_high;
    uint32_t time_of_next_jump_low;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_alternate_time_offset_indicator_tlv) == 15);

struct ptp_encoded_authetication_tlv {
    uint8_t policy;
    uint8_t parameter_indicator;
    uint32_t key_id;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_authetication_tlv) == 6);

struct ptp_encoded_management_tlv_time {
    struct ptp_encoded_timestamp current_time;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_encoded_management_tlv_time) == 10);
