#pragma once

#include <stdint.h>
#include <arpa/inet.h>

#include <ptp/ptp_coding.h>

#define COMMON_RING_SIZE 8
#define COMMON_MEMPOOL_SIZE 8
#define COMMON_BUFFER_SIZE 1500

enum common_port_type {
    COMMON_PORT_TYPE_EVENT = 0,
    COMMON_PORT_TYPE_MANAGEMENT = 1
};

struct common_message_info {
    struct ptp_decoded_message message;

    struct {
        uint8_t data[COMMON_BUFFER_SIZE];
        int length;
    } buffer;

    struct {
        struct sockaddr_in address;
        socklen_t length;
    } address;

    enum common_port_type port_type;

    uint64_t timestamp;
};
