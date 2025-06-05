#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

int util_base64_encode(char *output, const uint8_t *input, short output_length, short input_length) {
    int ret;
    BIO *bio;
    BIO *b64;
    BUF_MEM *buffer_pointer;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, input_length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_pointer);

    if (buffer_pointer->length > output_length) {
        ret = -EMSGSIZE;
        goto out;
    }

    memcpy(output, buffer_pointer->data, buffer_pointer->length);
    output[buffer_pointer->length] = '\0';

    ret = buffer_pointer->length;

out:
    BIO_free_all(bio);

    return ret;
}

int util_base64_decode(uint8_t *output, const char *input, short output_length) {
    int ret;
    BIO *bio;
    BIO *b64;

    // Ceiling division
    const int max_decoded_length = (strlen(input) / 4) * 3;
    if (max_decoded_length > output_length) {
        return -EMSGSIZE;
    }

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf((void *)input, -1);
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    ret = BIO_read(bio, output, max_decoded_length);

    BIO_free_all(bio);

    return ret;
}
