// gcc -c skynet_proto.c -o skynet_proto.o -lcrypto

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "skynet.h"

static void print_openssl_error(void) {
    unsigned long err = ERR_get_error();
    char err_str[256];
    ERR_error_string_n(err, err_str, sizeof(err_str));
    fprintf(stderr, "OpenSSL error: %s\n", err_str);
}

void skynet_init(SkyNetMessage *msg, SkyNetMessageType type, uint32_t node_id, uint32_t npg_id, uint8_t qos) {
    memset(msg, 0, sizeof(SkyNetMessage));
    msg->version = SKYNET_VERSION;
    msg->type = type;
    msg->npg_id = npg_id;
    msg->node_id = node_id;
    msg->qos = qos;
    msg->hop_count = 0;
    msg->timestamp = 0; /* Set by caller */
    if (RAND_bytes(msg->iv, 16) != 1) {
        fprintf(stderr, "Error: Failed to generate random IV\n");
        print_openssl_error();
    }
}

void skynet_set_data(SkyNetMessage *msg, const uint8_t *data, uint16_t data_length, const uint8_t *aes_key, const uint8_t *hmac_key) {
    if (!msg || !aes_key || !hmac_key) {
        fprintf(stderr, "Error: Null pointer in skynet_set_data\n");
        return;
    }
    if (data_length > SKYNET_MAX_PAYLOAD - 16) { /* Reserve 16 bytes for GCM tag */
        fprintf(stderr, "Error: Payload too large: %u > %u\n", data_length, SKYNET_MAX_PAYLOAD - 16);
        return;
    }

    /* Encrypt payload with AES-256-GCM */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        print_openssl_error();
        return;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, msg->iv) != 1) {
        print_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int outlen = 0, finallen = 0;
    uint8_t outbuf[SKYNET_MAX_PAYLOAD];
    if (data && data_length > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, data, data_length) != 1) {
            print_openssl_error();
            EVP_CIPHER_CTX_free(ctx);
            return;
        }
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf + outlen, &finallen) != 1) {
        print_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    msg->payload_len = outlen + finallen;
    if (msg->payload_len > SKYNET_MAX_PAYLOAD - 16) {
        fprintf(stderr, "Error: Encrypted payload too large: %u\n", msg->payload_len);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    memcpy(msg->payload, outbuf, msg->payload_len);

    /* Append 16-byte GCM tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, msg->payload + msg->payload_len) != 1) {
        print_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    msg->payload_len += 16; /* Include tag in payload length */
    EVP_CIPHER_CTX_free(ctx);

    /* Compute HMAC-SHA256 */
    uint32_t data_len = 1 + 1 + 4 + 4 + 4 + 8 + 1 + 1 + 16 + 2 + msg->payload_len;
    if (data_len > SKYNET_MAX_PAYLOAD + 32) {
        fprintf(stderr, "Error: HMAC data length too large: %u\n", data_len);
        return;
    }

    uint8_t *hmac_data = malloc(data_len);
    if (!hmac_data) {
        fprintf(stderr, "Error: Memory allocation failed for HMAC\n");
        return;
    }

    size_t offset = 0;
    hmac_data[offset++] = msg->version;
    hmac_data[offset++] = msg->type;
    *(uint32_t *)(hmac_data + offset) = htonl(msg->npg_id); offset += 4;
    *(uint32_t *)(hmac_data + offset) = htonl(msg->node_id); offset += 4;
    *(uint32_t *)(hmac_data + offset) = htonl(msg->seq_no); offset += 4;
    *(uint64_t *)(hmac_data + offset) = htobe64(msg->timestamp); offset += 8;
    hmac_data[offset++] = msg->qos;
    hmac_data[offset++] = msg->hop_count;
    memcpy(hmac_data + offset, msg->iv, 16); offset += 16;
    *(uint16_t *)(hmac_data + offset) = htons(msg->payload_len); offset += 2;
    memcpy(hmac_data + offset, msg->payload, msg->payload_len); offset += msg->payload_len;

    if (offset != data_len) {
        fprintf(stderr, "Error: HMAC data length mismatch: %zu != %u\n", offset, data_len);
        free(hmac_data);
        return;
    }

    unsigned int hmac_len;
    if (!HMAC(EVP_sha256(), hmac_key, 32, hmac_data, data_len, msg->hmac, &hmac_len) || hmac_len != 32) {
        fprintf(stderr, "Error: HMAC computation failed\n");
        free(hmac_data);
        return;
    }
    free(hmac_data);
}

int skynet_serialize(const SkyNetMessage *msg, uint8_t *buffer, size_t buffer_size) {
    if (!msg || !buffer) {
        fprintf(stderr, "Error: Null pointer in skynet_serialize\n");
        return -1;
    }

    if (msg->payload_len > SKYNET_MAX_PAYLOAD) {
        fprintf(stderr, "Error: Invalid payload length: %u > %u\n", msg->payload_len, SKYNET_MAX_PAYLOAD);
        return -1;
    }

    size_t required_size = 1 + 1 + 4 + 4 + 4 + 8 + 1 + 1 + 16 + 2 + msg->payload_len + 32 + 4;
    if (buffer_size < required_size) {
        fprintf(stderr, "Error: Buffer too small: %zu < %zu\n", buffer_size, required_size);
        return -1;
    }

    size_t offset = 0;
    buffer[offset++] = msg->version;
    buffer[offset++] = msg->type;
    *(uint32_t *)(buffer + offset) = htonl(msg->npg_id); offset += 4;
    *(uint32_t *)(buffer + offset) = htonl(msg->node_id); offset += 4;
    *(uint32_t *)(buffer + offset) = htonl(msg->seq_no); offset += 4;
    *(uint64_t *)(buffer + offset) = htobe64(msg->timestamp); offset += 8;
    buffer[offset++] = msg->qos;
    buffer[offset++] = msg->hop_count;
    memcpy(buffer + offset, msg->iv, 16); offset += 16;
    *(uint16_t *)(buffer + offset) = htons(msg->payload_len); offset += 2;
    memcpy(buffer + offset, msg->payload, msg->payload_len); offset += msg->payload_len;
    memcpy(buffer + offset, msg->hmac, 32); offset += 32;
    *(uint32_t *)(buffer + offset) = htonl(msg->crc); offset += 4;

    return (int)offset;
}

int skynet_deserialize(SkyNetMessage *msg, const uint8_t *buffer, size_t buffer_size) {
    if (!msg || !buffer) {
        fprintf(stderr, "Error: Null pointer in skynet_deserialize\n");
        return -1;
    }

    size_t min_size = 1 + 1 + 4 + 4 + 4 + 8 + 1 + 1 + 16 + 2 + 32 + 4;
    if (buffer_size < min_size) {
        fprintf(stderr, "Error: Buffer too small for deserialization: %zu < %zu\n", buffer_size, min_size);
        return -1;
    }

    size_t offset = 0;
    msg->version = buffer[offset++];
    msg->type = buffer[offset++];
    msg->npg_id = ntohl(*(uint32_t *)(buffer + offset)); offset += 4;
    msg->node_id = ntohl(*(uint32_t *)(buffer + offset)); offset += 4;
    msg->seq_no = ntohl(*(uint32_t *)(buffer + offset)); offset += 4;
    msg->timestamp = be64toh(*(uint64_t *)(buffer + offset)); offset += 8;
    msg->qos = buffer[offset++];
    msg->hop_count = buffer[offset++];
    memcpy(msg->iv, buffer + offset, 16); offset += 16;
    msg->payload_len = ntohs(*(uint16_t *)(buffer + offset)); offset += 2;

    if (msg->payload_len > SKYNET_MAX_PAYLOAD || offset + msg->payload_len + 32 + 4 > buffer_size) {
        fprintf(stderr, "Error: Invalid payload length or buffer overrun: payload_len=%u, buffer_size=%zu\n",
                msg->payload_len, buffer_size);
        return -1;
    }

    memcpy(msg->payload, buffer + offset, msg->payload_len); offset += msg->payload_len;
    memcpy(msg->hmac, buffer + offset, 32); offset += 32;
    msg->crc = ntohl(*(uint32_t *)(buffer + offset)); offset += 4;

    return 0;
}

void skynet_print(const SkyNetMessage *msg) {
    printf("SkyNetMessage: version=%u, type=%u, npg_id=%u, node_id=%x, "
           "seq_no=%u, timestamp=%lu, qos=%u, hop_count=%u, payload_len=%u\n",
           msg->version, msg->type, msg->npg_id, msg->node_id,
           msg->seq_no, msg->timestamp, msg->qos, msg->hop_count, msg->payload_len);
}

int skynet_verify_hmac(const SkyNetMessage *msg, const uint8_t *hmac_key) {
    if (!msg || !hmac_key) {
        fprintf(stderr, "Error: Null pointer in skynet_verify_hmac\n");
        return -1;
    }

    unsigned char computed_hmac[32];
    uint32_t data_len = 1 + 1 + 4 + 4 + 4 + 8 + 1 + 1 + 16 + 2 + msg->payload_len;
    if (data_len > SKYNET_MAX_PAYLOAD + 32) {
        fprintf(stderr, "Error: HMAC data length too large: %u\n", data_len);
        return -1;
    }

    uint8_t *data = malloc(data_len);
    if (!data) {
        fprintf(stderr, "Error: Memory allocation failed for HMAC verification\n");
        return -1;
    }

    size_t offset = 0;
    data[offset++] = msg->version;
    data[offset++] = msg->type;
    *(uint32_t *)(data + offset) = htonl(msg->npg_id); offset += 4;
    *(uint32_t *)(data + offset) = htonl(msg->node_id); offset += 4;
    *(uint32_t *)(data + offset) = htonl(msg->seq_no); offset += 4;
    *(uint64_t *)(data + offset) = htobe64(msg->timestamp); offset += 8;
    data[offset++] = msg->qos;
    data[offset++] = msg->hop_count;
    memcpy(data + offset, msg->iv, 16); offset += 16;
    *(uint16_t *)(data + offset) = htons(msg->payload_len); offset += 2;
    memcpy(data + offset, msg->payload, msg->payload_len); offset += msg->payload_len;

    if (offset != data_len) {
        fprintf(stderr, "Error: HMAC data length mismatch: %zu != %u\n", offset, data_len);
        free(data);
        return -1;
    }

    unsigned int hmac_len;
    if (!HMAC(EVP_sha256(), hmac_key, 32, data, data_len, computed_hmac, &hmac_len) || hmac_len != 32) {
        fprintf(stderr, "Error: HMAC verification computation failed\n");
        free(data);
        return -1;
    }

    free(data);
    return memcmp(msg->hmac, computed_hmac, 32) == 0 ? 0 : -1;
}

int skynet_decrypt_payload(SkyNetMessage *msg, const uint8_t *aes_key) {
    if (!msg || !aes_key) {
        fprintf(stderr, "Error: Null pointer in skynet_decrypt_payload\n");
        return -1;
    }

    if (msg->payload_len < 16) { /* Need at least 16 bytes for GCM tag */
        fprintf(stderr, "Error: Payload too short for GCM tag: %u\n", msg->payload_len);
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        print_openssl_error();
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, msg->iv) != 1) {
        print_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, msg->payload + msg->payload_len - 16) != 1) {
        print_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int outlen = 0, finallen = 0;
    uint8_t outbuf[SKYNET_MAX_PAYLOAD];
    if (EVP_DecryptUpdate(ctx, outbuf, &outlen, msg->payload, msg->payload_len - 16) != 1) {
        print_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptFinal_ex(ctx, outbuf + outlen, &finallen) != 1) {
        print_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (outlen + finallen > SKYNET_MAX_PAYLOAD) {
        fprintf(stderr, "Error: Decrypted payload too large: %d\n", outlen + finallen);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    memcpy(msg->payload, outbuf, outlen + finallen);
    msg->payload_len = outlen + finallen;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

uint32_t fnv1a_32(const void *data, size_t len) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t hash = FNV_OFFSET_BASIS_32;
    for (size_t i = 0; i < len; ++i) {
        hash ^= bytes[i];
        hash *= FNV_PRIME_32;
    }
    return hash;
}
