#pragma once

#include <stdint.h>

#include <ptp/protocol/ptp_decoded.h>

int ptp_encode_message(uint8_t *output, struct ptp_decoded_message *input, short length);
int ptp_decode_message(struct ptp_decoded_message *output, uint8_t *input, short length);
