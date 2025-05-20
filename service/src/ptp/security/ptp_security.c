#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <ptp/ptp.h>
#include <ptp/ptp_helper.h>
#include <ptp/port/ptp_port.h>
#include <ptp/protocol/ptp_decoded.h>
#include <ptp/security/ptp_security.h>

#define PTP_MAX_ICV_LENGTH 100
#define PTP_HMAC_128_SIZE 16

static inline int ptp_compute_icv_plain(uint8_t *icv, struct ptp_port_entry *entry) {
    // Plaintext password
    strncpy((char *)icv, entry->secret, PTP_PORT_SECRET_SIZE);

    return strnlen(entry->secret, PTP_PORT_SECRET_SIZE);
}

static inline int ptp_compute_icv_hmac_128(uint8_t *icv, struct common_message_info *info, struct ptp_decoded_authentication_tlv *tlv, struct ptp_port_entry *entry) {
    int ret;

    const uint8_t *data = (const uint8_t *)info->buffer.data;
    const unsigned int data_length = tlv->icv - data;
    uint8_t icv_temp[EVP_MAX_MD_SIZE];
    unsigned int icv_length;

    // Calculate ICV
    HMAC(EVP_sha256(), entry->secret, PTP_PORT_SECRET_SIZE, data, data_length, icv_temp, &icv_length);

    // Truncate to 128 bits
    memcpy(icv, icv_temp, PTP_HMAC_128_SIZE);

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

static inline int ptp_check_icv_plain(uint8_t *icv, struct ptp_port_entry *entry) {
    int ret;

    // Compare plaintext password
    ret = strncmp((char *)icv, entry->secret, PTP_HMAC_128_SIZE);
    if (ret) {
        return -EPERM;
    }

    return 0;
}

static inline int ptp_check_icv_hmac_128(uint8_t *icv, struct common_message_info *info, struct ptp_decoded_authentication_tlv *tlv, struct ptp_port_entry *entry) {
    int ret;

    const uint8_t *data = (const uint8_t *)info->buffer.data;
    const unsigned int data_length = tlv->icv - data;
    uint8_t icv_temp[EVP_MAX_MD_SIZE];
    unsigned int icv_length;

    // Calculate ICV
    HMAC(EVP_sha256(), entry->secret, PTP_PORT_SECRET_SIZE, data, data_length, icv_temp, &icv_length);

    // Compare 128 bits
    ret = memcmp(icv, icv_temp, PTP_HMAC_128_SIZE);
    if (ret) {
        return ret; //-EPERM; TODO: move vuln into web interface
    }

    return 0;
}

static int ptp_check_icv(uint8_t *icv, struct common_message_info *info, struct ptp_decoded_authentication_tlv *tlv, struct ptp_port_entry *entry) {
    switch (tlv->policy) {
        case PTP_AUTHENTICATION_POLICY_PLAIN: {
            return ptp_check_icv_plain(icv, entry);
        }

        case PTP_AUTHENTICATION_POLICY_HMAC_128: {
            return ptp_check_icv_hmac_128(icv, info, tlv, entry);
        }

        default: {
            return -EINVAL;
        }
    }
}

int ptp_security_add_auth_tlv(struct ptp_state *state, struct common_message_info *info) {
    struct ptp_decoded_tlv *tlv = ptp_add_tlv(&info->message);

    if (!tlv) {
        return -ENOMEM;
    }

    tlv->type = PTP_TLV_TYPE_AUTHENTICATION;
    tlv->payload.authentication.policy = PTP_AUTHENTICATION_POLICY_HMAC_128;
    tlv->payload.authentication.parameter_indicator = 0; // No optional field supported
    tlv->payload.authentication.key_id = info->message.port_id.port; // Reuse unique port
    tlv->payload.authentication.icv_length = PTP_HMAC_128_SIZE; // Constant ICV length

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

        struct ptp_port_entry *entry;
        ret = ptp_port_db_get(&state->port_db, &entry, info->message.port_id);
        if (ret) {
            return ret;
        }

        ret = ptp_compute_icv(tlv->payload.authentication.icv, info, &tlv->payload.authentication, entry);
        if (ret < 0) {
            return ret;
        }
    }

    return 0;
}

int ptp_security_check_auth(struct ptp_state *state, struct common_message_info *info, struct ptp_decoded_tlv *tlv, struct ptp_decoded_port_id port_id) {
    int ret;

    // This TLV was already checked
    if (tlv->authenticated) {
        return 0;
    }

    struct ptp_port_entry *entry;
    ret = ptp_port_db_get(&state->port_db, &entry, port_id);
    if (ret) {
        return ret;
    }
    
    // Skip to next auth TLV
    while (++tlv <= &info->message.tlvs[info->message.tlv_count]) {
        if (tlv->type == PTP_TLV_TYPE_AUTHENTICATION) {
            goto check;
        }
    }

    // No auth TLV found
    return -ENODATA;
    
check:
    if (tlv->payload.authentication.policy != entry->authentication_policy) {
        return -EINVAL;
    }

    ret = ptp_check_icv(tlv->payload.authentication.icv, info, &tlv->payload.authentication, entry);
    if (ret < 0) {
        return ret;
    }

    // Mark all previous TLVs
    do {
        tlv->authenticated = true;
    } while (tlv-- >= info->message.tlvs);

    info->message.authenticated = true;

    return 0;
}
