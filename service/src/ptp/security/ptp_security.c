#include <errno.h>
#include <string.h>
#include <stdint.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <ptp/ptp.h>
#include <ptp/port/ptp_port.h>
#include <ptp/protocol/ptp_decoded.h>
#include <ptp/security/ptp_security.h>

#define PTP_HMAC_128_SIZE 16

int ptp_security_add_auth_tlv(struct ptp_state *state, struct common_message_info *info) {
    const int index = info->message.tlv_count++;

    // Check that we have enough room to add TLV
    if (info->message.tlv_count > PTP_MAX_TLV_COUNT) {
        --info->message.tlv_count;
        return -ENOMEM;
    }

    info->message.tlvs[index].type = PTP_TLV_TYPE_AUTHENTICATION;
    info->message.tlvs[index].payload.authentication.spp = 0; // Only a single SA exists
    info->message.tlvs[index].payload.authentication.security_parameter_indicatior = 0; // No optional field supported
    info->message.tlvs[index].payload.authentication.key_id = info->message.port_id.port; // Reuse unique port
    info->message.tlvs[index].payload.authentication.icv_length = PTP_HMAC_128_SIZE; // Constant ICV length

    return 0;
}

int ptp_security_complete_auth_tlvs(struct ptp_state *state, struct common_message_info *info) {
    int ret;

    // Decode the message again to get access to the ICV pointer
    ret = ptp_decode_message(&info->message, info->buffer.data, info->buffer.length);
    if (ret) {
        return ret;
    }

    for (int i = 0; i < info->message.tlv_count; ++i) {
        struct ptp_decoded_tlv *tlv = &info->message.tlvs[i];

        if (tlv->type != PTP_TLV_TYPE_AUTHENTICATION) {
            continue;
        }

        struct ptp_port_entry entry;
        entry.port = info->message.port_id.port;
        ret = ptp_port_db_get(&state->port_db, &entry);
        if (ret) {
            return ret;
        }

        const uint8_t *data = (const uint8_t *)info->buffer.data;
        const unsigned int data_length = tlv->payload.authentication.icv - data;
        uint8_t icv[EVP_MAX_MD_SIZE];
        unsigned int icv_length;

        // Calculate ICV
        HMAC(EVP_sha256(), entry.secret, PTP_SECURITY_SECRET_LENTH, data, data_length, icv, &icv_length);

        // Truncate to 128 bits
        memcpy(tlv->payload.authentication.icv, icv, PTP_HMAC_128_SIZE);
    }

    return 0;
}

int ptp_security_check_auth(struct ptp_state *state, struct common_message_info *info, uint16_t port) {
    int ret;
    bool authenticated = false;
    
    for (int i = info->message.tlv_count - 1; i >= 0; --i) {
        struct ptp_decoded_tlv *tlv = &info->message.tlvs[i];

        if (tlv->type != PTP_TLV_TYPE_AUTHENTICATION) {
            tlv->authenticated = authenticated;
            continue;
        }

        struct ptp_port_entry entry;
        entry.port = port;
        ret = ptp_port_db_get(&state->port_db, &entry);
        if (ret) {
            return ret;
        }

        const uint8_t *data = (const uint8_t *)info->buffer.data;
        const unsigned int data_length = tlv->payload.authentication.icv - data;
        uint8_t icv[EVP_MAX_MD_SIZE];
        unsigned int icv_length;

        // Calculate ICV
        HMAC(EVP_sha256(), entry.secret, PTP_SECURITY_SECRET_LENTH, data, data_length, icv, &icv_length);

        // Truncate to 128 bits and compare
        ret = memcmp(tlv->payload.authentication.icv, icv, PTP_HMAC_128_SIZE);
        if (ret) {
            return ret; // Vulnerability: correct byte gets leaked
        }

        authenticated = true;
        tlv->authenticated = true;
    }

    info->message.authenticated = authenticated;

    return 0;
}
