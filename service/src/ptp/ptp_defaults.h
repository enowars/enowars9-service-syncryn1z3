#pragma once

#include <stdint.h>
#include <arpa/inet.h>


/*
    Defaults
*/

static const in_addr_t ptp_default_address = 0x810100e0; // 224.0.1.129
static const uint16_t ptp_default_event_port = 319;
static const uint16_t ptp_default_general_port = 320;
