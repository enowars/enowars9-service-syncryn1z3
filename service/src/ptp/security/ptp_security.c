#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <ptp/ptp.h>
#include <ptp/ptp_helper.h>
#include <ptp/protocol/ptp_decoded.h>
#include <ptp/security/ptp_security.h>
#include <db/db.h>

#define PTP_MAX_ICV_LENGTH 64
#define PTP_HMAC_128_SIZE 16

static inline int ptp_compute_icv_none(struct ptp_decoded_authentication_tlv *tlv) {
    tlv->icv[0] = '\0';

    return 0;
}

static inline int ptp_compute_icv_plain(struct ptp_decoded_authentication_tlv *tlv, struct db_entry *entry) {
    char *icv = (char *)tlv->icv;

    // Plaintext password
    strncpy(icv, entry->secret, PTP_PORT_SECRET_SIZE);

    return strnlen(entry->secret, PTP_PORT_SECRET_SIZE);
}

static inline int ptp_compute_icv_hmac_128(struct common_message_info *info, struct ptp_decoded_authentication_tlv *tlv, struct db_entry *entry) {
    int ret;

    uint8_t *icv = tlv->icv;
    uint8_t icv_temp[EVP_MAX_MD_SIZE];
    unsigned int icv_length;
    const uint8_t *data = (const uint8_t *)info->buffer.data;
    const unsigned int data_length = icv - data;

    // Calculate ICV
    HMAC(EVP_sha256(), entry->secret, strnlen(entry->secret, PTP_PORT_SECRET_SIZE), data, data_length, icv_temp, &icv_length);

    // Truncate to 128 bits
    memcpy(icv, icv_temp, PTP_HMAC_128_SIZE);

    return PTP_HMAC_128_SIZE;
}

static int ptp_compute_icv(struct common_message_info *info, struct ptp_decoded_authentication_tlv *tlv, struct db_entry *entry) {
    switch (entry->authentication_policy) {
        case PTP_AUTHENTICATION_POLICY_NONE: {
            return ptp_compute_icv_none(tlv);
        }

        case PTP_AUTHENTICATION_POLICY_PLAIN: {
            return ptp_compute_icv_plain(tlv, entry);
        }

        case PTP_AUTHENTICATION_POLICY_HMAC_128: {
            return ptp_compute_icv_hmac_128(info, tlv, entry);
        }

        default: {
            return -EINVAL;
        }
    }
}

static inline int ptp_check_icv_plain(struct ptp_decoded_authentication_tlv *tlv, struct db_entry *entry) {
    int ret;

    char *icv = (char *)tlv->icv;

    // Compare plaintext password
    ret = strncmp((char *)icv, entry->secret, PTP_MAX_ICV_LENGTH);
    if (ret) {
        return -EPERM;
    }

    return 0;
}

static inline int ptp_check_icv_hmac_128(struct common_message_info *info, struct ptp_decoded_authentication_tlv *tlv, struct db_entry *entry) {
    int ret;

    uint8_t *icv = tlv->icv;
    uint8_t icv_temp[EVP_MAX_MD_SIZE];
    unsigned int icv_length;
    const uint8_t *data = (const uint8_t *)info->buffer.data;
    const unsigned int data_length = icv - data;

    // Calculate ICV
    HMAC(EVP_sha256(), entry->secret, strnlen(entry->secret, PTP_PORT_SECRET_SIZE), data, data_length, icv_temp, &icv_length);

    ret = memcmp(icv, icv_temp, tlv->icv_length);
    if (ret) {
        return -EPERM;
    }

    return 0;
}

static int ptp_check_icv(struct common_message_info *info, struct ptp_decoded_authentication_tlv *tlv, struct db_entry *entry) {
    switch (entry->authentication_policy) {
        case PTP_AUTHENTICATION_POLICY_PLAIN: {
            return ptp_check_icv_plain(tlv, entry);
        }

        case PTP_AUTHENTICATION_POLICY_HMAC_128: {
            return ptp_check_icv_hmac_128(info, tlv, entry);
        }

        default: {
            return -EINVAL;
        }
    }
}

int ptp_security_add_auth_tlv(struct ptp_state *state, struct common_message_info *info) {
    int ret;

    struct db_entry *entry;
    ret = db_get(state->config->db_state, &entry, info->message.port_id);
    if (ret) {
        return ret;
    }

    // This would be a little too easy, huh?
    if (entry->authentication_policy == PTP_AUTHENTICATION_POLICY_PLAIN) {
        return 0;
    }

    struct ptp_decoded_tlv *tlv = ptp_add_tlv(&info->message);
    if (!tlv) {
        return -EMSGSIZE;
    }

    tlv->type = PTP_TLV_TYPE_AUTHENTICATION;
    tlv->payload.authentication.policy = entry->authentication_policy;
    tlv->payload.authentication.parameter_indicator = 0; // No optional field supported
    tlv->payload.authentication.key_id = 0;
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

        struct db_entry *entry;
        ret = db_get(state->config->db_state, &entry, info->message.port_id);
        if (ret) {
            return ret;
        }

        ret = ptp_compute_icv(info, &tlv->payload.authentication, entry);
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

    struct db_entry *entry;
    ret = db_get(state->config->db_state, &entry, port_id);
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
    if (entry->authentication_policy != PTP_AUTHENTICATION_POLICY_NONE) {
        if (tlv->payload.authentication.policy != entry->authentication_policy) {
            return -EINVAL;
        }

        ret = ptp_check_icv(info, &tlv->payload.authentication, entry);
        if (ret) {
            return ret;
        }
    }

    // Mark all previous TLVs
    do {
        tlv->authenticated = true;
    } while (tlv-- >= info->message.tlvs);

    info->message.authenticated = true;

    return 0;
}
