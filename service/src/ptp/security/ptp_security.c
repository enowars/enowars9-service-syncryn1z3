#include <errno.h>
#include <string.h>
#include <stdint.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <ptp/protocol/ptp_decoded.h>
#include <ptp/security/ptp_security.h>

#define PTP_HMAC_128_SIZE 16

static const char key[] = "password"; // TODO: Implement custom keys

int ptp_security_add_auth_tlv(struct ptp_state *state, struct common_message_info *info, uint32_t key_id) {
    const int index = info->message.tlv_count++;

    // Check that we have enough room to add TLV
    if (info->message.tlv_count > PTP_MAX_TLV_COUNT) {
        --info->message.tlv_count;
        return -ENOMEM;
    }

    info->message.tlvs[index].type = PTP_TLV_TYPE_AUTHENTICATION;
    info->message.tlvs[index].payload.authentication.spp = 0; // Only a single SA exists
    info->message.tlvs[index].payload.authentication.security_parameter_indicatior = 0; // No optional field supported
    info->message.tlvs[index].payload.authentication.key_id = key_id;
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

        const uint8_t *data = (const uint8_t *)info->buffer.data;
        const unsigned int data_length = tlv->payload.authentication.icv - data;
        uint8_t icv[EVP_MAX_MD_SIZE];
        unsigned int icv_length;

        // Calculate ICV
        HMAC(EVP_sha256(), key, sizeof(key), data, data_length, icv, &icv_length);

        // Truncate to 128 bits
        memcpy(tlv->payload.authentication.icv, icv, PTP_HMAC_128_SIZE);
    }

    return 0;
}

int ptp_security_check_auth(struct ptp_state *state, struct common_message_info *info) {
    int ret;
    bool authenticated = false;
    
    for (int i = info->message.tlv_count - 1; i > 0; --i) {
        struct ptp_decoded_tlv *tlv = &info->message.tlvs[i];

        if (tlv->type != PTP_TLV_TYPE_AUTHENTICATION) {
            tlv->authenticated = authenticated;
        }

        const uint8_t *data = (const uint8_t *)info->buffer.data;
        const unsigned int data_length = tlv->payload.authentication.icv - data;
        uint8_t icv[EVP_MAX_MD_SIZE];
        unsigned int icv_length;

        // Calculate ICV
        HMAC(EVP_sha256(), key, sizeof(key), data, data_length, icv, &icv_length);

        // Truncate to 128 bits and compare
        ret = memcmp(tlv->payload.authentication.icv, icv, PTP_HMAC_128_SIZE);
        if (ret) {
            return ret; // Vulnerability: correct byte gets leaked
        }

        authenticated = true;
        tlv->authenticated = true;
    }

    return 0;
}
