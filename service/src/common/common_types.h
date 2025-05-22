#pragma once

#include <stdint.h>
#include <arpa/inet.h>

#include <ptp/protocol/ptp_protocol.h>

#define COMMON_RING_SIZE 8
#define COMMON_MEMPOOL_SIZE 8
#define COMMON_BUFFER_SIZE 1472

enum common_port_type {
    COMMON_PORT_TYPE_EVENT = 0,
    COMMON_PORT_TYPE_GENERAL = 1
};

struct common_message_info {
    struct {
        struct sockaddr_in address;
        socklen_t length;
    } address;

    enum common_port_type port_type;
    uint64_t timestamp;

    struct {
        uint8_t data[COMMON_BUFFER_SIZE];
        short length;
    } buffer;

    struct ptp_decoded_message message;
};

struct common_transaction_info {
    struct common_message_info *request;
    struct common_message_info *response;
};
