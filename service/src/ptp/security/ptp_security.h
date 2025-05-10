#pragma once

#include <stdint.h>
#include <arpa/inet.h>

#include <common/common_types.h>
#include <ptp/ptp.h>
#include <ptp/protocol/ptp_decoded.h>

/**
 * @brief Add a yet incomplete authentication TLV to the message
 * @details After serializing the message one needs to call ptp_security_complete_auth_tlvs() for the TLV to be valid
 */
int ptp_security_add_auth_tlv(struct ptp_state *state, struct common_message_info *info, uint32_t key_id);

/**
 * @brief Complete authentication TLVs of an already serialized message
 */
int ptp_security_complete_auth_tlvs(struct ptp_state *state, struct common_message_info *info);

/**
 * @brief Validate all authentication TLVs and mark the message contents accordingly
 */
int ptp_security_check_auth(struct ptp_state *state, struct common_message_info *info);
