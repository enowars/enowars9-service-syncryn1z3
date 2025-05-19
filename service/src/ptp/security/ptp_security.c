#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <ptp/ptp.h>
#include <ptp/port/ptp_port.h>
#include <ptp/protocol/ptp_decoded.h>
#include <ptp/security/ptp_security.h>

#define PTP_MAX_ICV_LENGTH 100
#define PTP_HMAC_128_SIZE 16

_Static_assert(PTP_MAX_ICV_LENGTH >= PTP_PORT_SECRET_SIZE);
_Static_assert(PTP_MAX_ICV_LENGTH >= EVP_MAX_MD_SIZE);

_Static_assert(PTP_HMAC_128_SIZE <= EVP_MAX_MD_SIZE);

static int ptp_compute_icv_plain(uint8_t *icv, struct ptp_port_entry *entry) {
    // Plaintext password
    strncpy((char *)icv, entry->secret, PTP_PORT_SECRET_SIZE);

    return strnlen(entry->secret, PTP_PORT_SECRET_SIZE);
}

static int ptp_compute_icv_hmac_128(uint8_t *icv, struct common_message_info *info, struct ptp_decoded_authentication_tlv *tlv, struct ptp_port_entry *entry) {
    int ret;

    const uint8_t *data = (const uint8_t *)info->buffer.data;
    const unsigned int data_length = tlv->icv - data;
    unsigned int icv_length;

    // Calculate ICV
    HMAC(EVP_sha256(), entry->secret, PTP_PORT_SECRET_SIZE, data, data_length, icv, &icv_length);

    return PTP_HMAC_128_SIZE;
}

static int ptp_compute_icv(uint8_t *icv, struct common_message_info *info, struct ptp_decoded_authentication_tlv *tlv, struct ptp_port_entry *entry) {
    switch (tlv->policy) {
        case PTP_AUTHENTICATION_POLICY_PLAIN: {
            return ptp_compute_icv_plain(icv, entry);
        }

        case PTP_AUTHENTICATION_POLICY_HMAC_128: {
            return ptp_compute_icv_hmac_128(icv, info, tlv, entry);
        }

        default: {
            return -EINVAL;
        }
    }
}

int ptp_security_add_auth_tlv(struct ptp_state *state, struct common_message_info *info) {
    const int index = info->message.tlv_count++;

    // Check that we have enough room to add TLV
    if (info->message.tlv_count > PTP_MAX_TLV_COUNT) {
        --info->message.tlv_count;
        return -ENOMEM;
    }

    info->message.tlvs[index].type = PTP_TLV_TYPE_AUTHENTICATION;
    info->message.tlvs[index].payload.authentication.policy = PTP_AUTHENTICATION_POLICY_HMAC_128;
    info->message.tlvs[index].payload.authentication.parameter_indicator = 0; // No optional field supported
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

        uint8_t icv[PTP_MAX_ICV_LENGTH];
        ret = ptp_compute_icv(icv, info, &tlv->payload.authentication, &entry);
        if (ret < 0) {
            return ret;
        }

        const int icv_length = ret;

        // Truncate to 128 bits
        memcpy(tlv->payload.authentication.icv, icv, icv_length);
    }

    return 0;
}

int ptp_security_check_auth(struct ptp_state *state, struct common_message_info *info, uint16_t port) {
    int ret;
    bool authenticated = false;

    struct ptp_port_entry entry;
    entry.port = port;
    ret = ptp_port_db_get(&state->port_db, &entry);
    if (ret) {
        return ret;
    }

    // Only require authentication on active ports
    authenticated = !entry.active;
    
    for (int i = info->message.tlv_count - 1; i >= 0; --i) {
        struct ptp_decoded_tlv *tlv = &info->message.tlvs[i];

        if (tlv->type != PTP_TLV_TYPE_AUTHENTICATION) {
            tlv->authenticated = authenticated;
            continue;
        }

        if (tlv->payload.authentication.policy != entry.authentication_policy) {
            return -EINVAL;
        }

        uint8_t icv[PTP_MAX_ICV_LENGTH];
        ret = ptp_compute_icv(icv, info, &tlv->payload.authentication, &entry);
        if (ret < 0) {
            return ret;
        }

        const int icv_length = ret;

        // Truncate to 128 bits and compare
        ret = memcmp(tlv->payload.authentication.icv, icv, icv_length);
        if (ret) {
            return ret; // Vulnerability: correct byte gets leaked
        }

        authenticated = true;
        tlv->authenticated = true;
    }

    info->message.authenticated = authenticated;

    return 0;
}
