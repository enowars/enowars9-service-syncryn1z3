#pragma once

#include <stdint.h>
#include <arpa/inet.h>

#include <ptp/protocol/ptp_decoded.h>


/*
    Defaults
*/

static const uint16_t ptp_default_event_port = 319;
static const uint16_t ptp_default_general_port = 320;

static const struct ptp_decoded_port_id ptp_default_port_id = {
    .clock_id = 0xffffffffffffffff,
    .port = 0xffff,
};
