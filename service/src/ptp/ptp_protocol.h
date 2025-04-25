#pragma once

#include <stdint.h>

/*
    Shifts and masks
*/

#define PTP_MESSAGE_HEADER_TYPE_MASK 0x0f
#define PTP_MESSAGE_HEADER_TYPE_SHIFT 0
#define PTP_MESSAGE_HEADER_MAJOR_SDO_ID_MASK 0xf0
#define PTP_MESSAGE_HEADER_MAJOR_SDO_ID_SHIFT 4
#define PTP_MANAGEMENT_ACTION_MASK 0x1f
#define PTP_MANAGEMENT_ACTION_SHIFT 0


/*
    Constants
*/

#define PTP_DEFAULT_UDP_PORT 319

enum ptp_message_type {
    PTP_MESSAGE_TYPE_SYNC = 0x0,
    PTP_MESSAGE_TYPE_DELAY_REQUEST = 0x1,
    PTP_MESSAGE_TYPE_PDELAY_REQUEST = 0x2,
    PTP_MESSAGE_TYPE_PDELAY_RESPONSE = 0x3,
    PTP_MESSAGE_TYPE_FOLLOW_UP = 0x8,
    PTP_MESSAGE_TYPE_DELAY_RESPONSE = 0x9,
    PTP_MESSAGE_TYPE_PDELAY_RESPONSE_FOLLOW_UP = 0xa,
    PTP_MESSAGE_TYPE_ANNOUNCE = 0xb,
    PTP_MESSAGE_TYPE_SIGNALING = 0xc,
    PTP_MESSAGE_TYPE_MANAGEMENT = 0xd,
};

enum ptp_tlv_type {
    PTP_TLV_TYPE_MANAGEMENT = 0x1,
    PTP_TLV_TYPE_MANAGEMENT_ERROR_STATUS = 0x2,
    PTP_TLV_TYPE_ORGANIZATION_EXTENSION = 0x3,
    PTP_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION = 0x4,
    PTP_TLV_TYPE_GRANT_UNICAST_TRANSMISSION = 0x5,
    PTP_TLV_TYPE_CANCEL_UNICAST_TRANSMISSION = 0x6,
    PTP_TLV_TYPE_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION = 0x7,
    PTP_TLV_TYPE_PATH_TRACE = 0x8,
    PTP_TLV_TYPE_ALTERNATE_TIME_OFFSET_INDICATOR = 0x9,
    PTP_TLV_TYPE_ORGANIZATION_EXTENSION_PROPAGATE = 0x4000,
    PTP_TLV_TYPE_ENHANCED_ACCURACY_METRICS = 0x4001,
    PTP_TLV_TYPE_ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE = 0x8000,
    PTP_TLV_TYPE_L1_SYNC = 0x8001,
    PTP_TLV_TYPE_PORT_COMMUNICATION_AVAILABILITY = 0x8002,
    PTP_TLV_TYPE_PROTOCOL_ADDRESS = 0x8003,
    PTP_TLV_TYPE_SLAVE_RX_SYNC_TIMING_DATA = 0x8004,
    PTP_TLV_TYPE_SLAVE_RX_SYNC_COMPUTED_DATA = 0x8005,
    PTP_TLV_TYPE_SLAVE_TX_EVENT_TIMESTAMPS = 0x8006,
    PTP_TLV_TYPE_CUMULATIVE_RATE_RATIO = 0x8007,
    PTP_TLV_TYPE_PAD = 0x8008,
    PTP_TLV_TYPE_AUTHENTICATION = 0x8009,
};

enum ptp_flag {
    PTP_FLAG_ALTERNATE_MASTER = 1 << 0,
    PTP_FLAG_TWO_STEP = 1 << 1,
    PTP_FLAG_UNICAST = 1 << 2,
    PTP_FLAG_PROFILE_SPECIFIC_1 = 1 << 5,
    PTP_FLAG_PROFILE_SPECIFIC_2 = 1 << 6,
    PTP_FLAG_LEAP_61 = 1 << 8,
    PTP_FLAG_LEAP_59 = 1 << 9,
    PTP_FLAG_TIMESCALE = 1 << 10,
    PTP_FLAG_CURRENT_UTC_OFFSET_VALID = 1 << 11,
    PTP_FLAG_TIME_TRACABLE = 1 << 12,
    PTP_FLAG_FREQUENCY_TRACABLE = 1 << 13,
    PTP_FLAG_SYNCHRONIZATION_UNCERTAIN = 1 << 14,
};

enum ptp_management_action {
    PTP_MANAGEMENT_ACTION_GET = 0x0,
    PTP_MANAGEMENT_ACTION_SET = 0x1,
    PTP_MANAGEMENT_ACTION_RESPONSE = 0x2,
    PTP_MANAGEMENT_ACTION_COMMAND = 0x3,
    PTP_MANAGEMENT_ACTION_ACKNOWLEDGE = 0x4,
};

enum ptp_management_id {
    PTP_MANAGEMENT_ID_NULL = 0x0, 
    PTP_MANAGEMENT_ID_CLOCK_DESCRIPTION = 0x1,
    PTP_MANAGEMENT_ID_USER_DESCRIPTION = 0x2,
    PTP_MANAGEMENT_ID_SAVE_IN_NON_VOLATILE_STORAGE = 0x3,
    PTP_MANAGEMENT_ID_RESET_NON_VOLATILE_STORAGE = 0x4,
    PTP_MANAGEMENT_ID_INITIALIZE = 0x5,
    PTP_MANAGEMENT_ID_FAULT_LOG = 0x6,
    PTP_MANAGEMENT_ID_FAULT_LOG_RESET = 0x7,
    PTP_MANAGEMENT_ID_DEFAULT_DATA_SET = 0x2000,
    PTP_MANAGEMENT_ID_CURRENT_DATA_SET = 0x2001,
    PTP_MANAGEMENT_ID_PARENT_DATA_SET = 0x2002,
    PTP_MANAGEMENT_ID_TIME_PROPERTIES_DATA_SET = 0x2003,
    PTP_MANAGEMENT_ID_PORT_DATA_SET = 0x2004,
    PTP_MANAGEMENT_ID_PRIORITY1 = 0x2005,
    PTP_MANAGEMENT_ID_PRIORITY2 = 0x2006,
    PTP_MANAGEMENT_ID_DOMAIN = 0x2007,
    PTP_MANAGEMENT_ID_SLAVE_ONLY = 0x2008,
    PTP_MANAGEMENT_ID_LOG_ANNOUNCE_INTERVAL = 0x2009,
    PTP_MANAGEMENT_ID_ANNOUNCE_RECEIPT_TIMEOUT = 0x200A,
    PTP_MANAGEMENT_ID_LOG_SYNC_INTERVAL = 0x200B,
    PTP_MANAGEMENT_ID_VERSION_NUMBER = 0x200C,
    PTP_MANAGEMENT_ID_ENABLE_PORT = 0x200D,
    PTP_MANAGEMENT_ID_DISABLE_PORT = 0x200E,
    PTP_MANAGEMENT_ID_TIME = 0x200F,
    PTP_MANAGEMENT_ID_CLOCK_ACCURACY = 0x2010,
    PTP_MANAGEMENT_ID_UTC_PROPERTIES = 0x2011,
    PTP_MANAGEMENT_ID_TRACEABILITY_PROPERTIES = 0x2012,
    PTP_MANAGEMENT_ID_TIMESCALE_PROPERTIES = 0x2013,
    PTP_MANAGEMENT_ID_UNICAST_NEGOTIATION_ENABLE = 0x2014,
    PTP_MANAGEMENT_ID_PATH_TRACE_LIST = 0x2015,
    PTP_MANAGEMENT_ID_PATH_TRACE_ENABLE = 0x2016,
    PTP_MANAGEMENT_ID_GRANDMASTER_CLUSTER_TABLE = 0x2017,
    PTP_MANAGEMENT_ID_UNICAST_MASTER_TABLE = 0x2018,
    PTP_MANAGEMENT_ID_UNICAST_MASTER_MAX_TABLE_SIZE = 0x2019,
    PTP_MANAGEMENT_ID_ACCEPTABLE_MASTER_TABLE = 0x201A,
    PTP_MANAGEMENT_ID_ACCEPTABLE_MASTER_TABLE_ENABLED = 0x201B,
    PTP_MANAGEMENT_ID_ACCEPTABLE_MASTER_MAX_TABLE_SIZE = 0x201C,
    PTP_MANAGEMENT_ID_ALTERNATE_MASTER = 0x201D,
    PTP_MANAGEMENT_ID_ALTERNATE_TIME_OFFSET_ENABLE = 0x201E,
    PTP_MANAGEMENT_ID_ALTERNATE_TIME_OFFSET_NAME = 0x201F,
    PTP_MANAGEMENT_ID_ALTERNATE_TIME_OFFSET_MAX_KEY = 0x2020,
    PTP_MANAGEMENT_ID_ALTERNATE_TIME_OFFSET_PROPERTIES = 0x2021,
    PTP_MANAGEMENT_ID_EXTERNAL_PORT_CONFIGURATION_ENABLED = 0x3000,
    PTP_MANAGEMENT_ID_MASTER_ONLY = 0x3001,
    PTP_MANAGEMENT_ID_HOLDOVER_UPGRADE_ENABLE = 0x3002,
    PTP_MANAGEMENT_ID_EXT_PORT_CONFIG_PORT_DATA_SET = 0x3003,
    PTP_MANAGEMENT_ID_TRANSPARENT_CLOCK_DEFAULT_DATA_SET = 0x4000,
    PTP_MANAGEMENT_ID_TRANSPARENT_CLOCK_PORT_DATA_SET = 0x4001,
    PTP_MANAGEMENT_ID_PRIMARY_DOMAIN = 0x4002,
    PTP_MANAGEMENT_ID_DELAY_MECHANISM = 0x6000,
    PTP_MANAGEMENT_ID_LOG_MIN_PDELAY_REQ_INTERVAL = 0x6001,
};

enum ptp_clock_accuracy {
    PTP_CLOCK_ACCURACY_1_PS = 0x17,
    PTP_CLOCK_ACCURACY_2_5_PS,
    PTP_CLOCK_ACCURACY_10_PS,
    PTP_CLOCK_ACCURACY_25_PS,
    PTP_CLOCK_ACCURACY_100_PS,
    PTP_CLOCK_ACCURACY_250_PS,
    PTP_CLOCK_ACCURACY_1_NS,
    PTP_CLOCK_ACCURACY_2_5_NS,
    PTP_CLOCK_ACCURACY_10_NS,
    PTP_CLOCK_ACCURACY_25_NS,
    PTP_CLOCK_ACCURACY_100_NS,
    PTP_CLOCK_ACCURACY_250_NS,
    PTP_CLOCK_ACCURACY_1_US,
    PTP_CLOCK_ACCURACY_2_5_US,
    PTP_CLOCK_ACCURACY_10_US,
    PTP_CLOCK_ACCURACY_25_US,
    PTP_CLOCK_ACCURACY_100_US,
    PTP_CLOCK_ACCURACY_250_US,
    PTP_CLOCK_ACCURACY_1_MS,
    PTP_CLOCK_ACCURACY_2_5_MS,
    PTP_CLOCK_ACCURACY_10_MS,
    PTP_CLOCK_ACCURACY_25_MS,
    PTP_CLOCK_ACCURACY_100_MS,
    PTP_CLOCK_ACCURACY_250_MS,
    PTP_CLOCK_ACCURACY_1_S,
    PTP_CLOCK_ACCURACY_10_S,
    PTP_CLOCK_ACCURACY_GT_10_S,
};

enum ptp_time_source {
    PTP_TIME_SOURCE_ATOMIC_CLOCK = 0x10,
    PTP_TIME_SOURCE_GNSS = 0x20,
    PTP_TIME_SOURCE_TERRESTRIAL_RADIO = 0x30,
    PTP_TIME_SOURCE_SERIAL_TIME_CODE = 0x39,
    PTP_TIME_SOURCE_PTP = 0x40,
    PTP_TIME_SOURCE_NTP = 0x50,
    PTP_TIME_SOURCE_HAND_SET = 0x60,
    PTP_TIME_SOURCE_OTHER = 0x90,
    PTP_TIME_SOURCE_INTERNAL_OSCILLATOR= 0xa0,
};


/*
    General types
*/

typedef uint64_t ptp_clock_id_t;

struct ptp_port_id {
    ptp_clock_id_t clock_id;
    uint16_t port;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_port_id) == 10);

struct ptp_timestamp {
    uint16_t seconds_high;
    uint32_t seconds_low;
    uint32_t nanoseconds;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_timestamp) == 10);

struct ptp_clock_quality {
    uint8_t clock_class;
    uint8_t clock_accuracy;
    uint16_t offset_scaled_log_variance;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_clock_quality) == 4);


/*
    Messages
*/

struct ptp_message_header {
    uint8_t major_sdo_id_type;
    uint8_t version;
    uint16_t length;
    uint8_t domain;
    uint8_t minor_sdo_id;
    uint16_t flags;
    uint64_t correction;
    uint32_t type_specific;
    struct ptp_port_id port_id;
    uint16_t sequence_id;
    uint8_t control;
    uint8_t log_message_interval;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_message_header) == 34);

struct ptp_sync_message {
    struct ptp_timestamp origin_timestamp;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_sync_message) == 10);

struct ptp_delay_request_message {
    struct ptp_timestamp origin_timestamp;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_delay_request_message) == 10);

struct ptp_follow_up_message {
    struct ptp_timestamp origin_timestamp;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_follow_up_message) == 10);

struct ptp_delay_response_message {
    struct ptp_timestamp receive_timestamp;
    struct ptp_port_id requesting_port_id;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_delay_response_message) == 20);

struct ptp_pdelay_request_message {
    struct ptp_timestamp origin_timestamp;
    uint8_t reserved[10];
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_pdelay_request_message) == 20);

struct ptp_pdelay_response_message {
    struct ptp_timestamp receive_timestamp;
    struct ptp_port_id requesting_port_id;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_pdelay_response_message) == 20);

struct ptp_pdelay_response_follow_up_message {
    struct ptp_timestamp receive_timestamp;
    struct ptp_port_id requesting_port_id;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_pdelay_response_follow_up_message) == 20);

struct ptp_announce_message {
    struct ptp_timestamp origin_timestamp;
    uint16_t current_utc_offset;
    uint8_t reserved;
    uint8_t grandmaster_priority_1;
    struct ptp_clock_quality grandmaster_clock_quality;
    uint8_t grandmaster_priority_2;
    ptp_clock_id_t grandmaster_identity;
    uint16_t steps_removed;
    uint8_t time_source;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_announce_message) == 30);

struct ptp_signaling_message {
    struct ptp_port_id target_port_id;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_signaling_message) == 10);

struct ptp_management_message {
    struct ptp_port_id target_port_id;
    uint8_t starting_boundary_hops;
    uint8_t boundary_hops;
    uint8_t action;
    uint8_t reserved;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_management_message) == 14);


/*
    TLVs
*/

struct ptp_tlv_header {
    uint16_t type;
    uint16_t length;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_tlv_header) == 4);

struct ptp_management_tlv {
    uint16_t management_id;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_management_tlv) == 2);

struct ptp_authetication_tlv {
    uint8_t spp;
    uint8_t security_parameter_indicatior;
    uint32_t key_id;
} __attribute__((packed, aligned(1)));

_Static_assert(sizeof(struct ptp_authetication_tlv) == 6);
