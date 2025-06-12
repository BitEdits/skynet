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
    msg->timestamp = 0; /* Set by caller or during serialization */
    RAND_bytes(msg->iv, 16); /* Random IV for AES-GCM */
}

void skynet_set_data(SkyNetMessage *msg, const uint8_t *data, uint16_t data_length, const uint8_t *aes_key, const uint8_t *hmac_key) {
    if (data_length > SKYNET_MAX_PAYLOAD) {
        fprintf(stderr, "Error: Payload too large: %u > %u\n", data_length, SKYNET_MAX_PAYLOAD);
        return;
    }

    /* Encrypt payload */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        print_openssl_error();
        return;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key, msg->iv) != 1) {
        print_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    int outlen, finallen;
    uint8_t outbuf[SKYNET_MAX_PAYLOAD];
    if (EVP_EncryptUpdate(ctx, outbuf, &outlen, data, data_length) != 1) {
        print_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    if (EVP_EncryptFinal_ex(ctx, outbuf + outlen, &finallen) != 1) {
        print_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    msg->payload_len = outlen + finallen;
    memcpy(msg->payload, outbuf, msg->payload_len);
    EVP_CIPHER_CTX_free(ctx);

    /* Compute HMAC-SHA256 */
    uint32_t data_len = 1 + 1 + 4 + 4 + 4 + 8 + 1 + 1 + 16 + 2 + msg->payload_len;
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
    memcpy(hmac_data + offset, msg->payload, msg->payload_len);
    HMAC(EVP_sha256(), hmac_key, 32, hmac_data, data_len, msg->hmac, NULL);
    free(hmac_data);
}

int skynet_serialize(const SkyNetMessage *msg, uint8_t *buffer, size_t buffer_size) {
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
    return offset;
}

int skynet_deserialize(SkyNetMessage *msg, const uint8_t *buffer, size_t buffer_size) {
    size_t min_size = 1 + 1 + 4 + 4 + 4 + 8 + 1 + 1 + 16 + 2 + 32 + 4;
    if (buffer_size < min_size) {
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
    if (msg->payload_len > SKYNET_MAX_PAYLOAD || offset + msg->payload_len + 36 > buffer_size) {
        return -1;
    }
    memcpy(msg->payload, buffer + offset, msg->payload_len); offset += msg->payload_len;
    memcpy(msg->hmac, buffer + offset, 32); offset += 32;
    msg->crc = ntohl(*(uint32_t *)(buffer + offset)); offset += 4;
    return 0;
}

void skynet_print(const SkyNetMessage *msg) {
    printf("SkyNetMessage: version=%u, type=%u, npg_id=%u, node_id=%u, "
           "seq_no=%u, timestamp=%lu, qos=%u, hop_count=%u, payload_len=%u, payload=%s\n",
           msg->version, msg->type, msg->npg_id, msg->node_id,
           msg->seq_no, msg->timestamp, msg->qos, msg->hop_count, msg->payload_len, msg->payload);
}

int skynet_verify_hmac(const SkyNetMessage *msg, const uint8_t *hmac_key) {
    unsigned char computed_hmac[32];
    uint32_t data_len = 1 + 1 + 4 + 4 + 4 + 8 + 1 + 1 + 16 + 2 + msg->payload_len;
    uint8_t *data = malloc(data_len);
    if (!data) {
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
    memcpy(data + offset, msg->payload, msg->payload_len);
    HMAC(EVP_sha256(), hmac_key, 32, data, data_len, computed_hmac, NULL);
    free(data);
    return memcmp(msg->hmac, computed_hmac, 32) == 0 ? 0 : -1;
}

int skynet_decrypt_payload(SkyNetMessage *msg, const uint8_t *aes_key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        print_openssl_error();
        return -1;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key, msg->iv) != 1) {
        print_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int outlen, finallen;
    uint8_t outbuf[SKYNET_MAX_PAYLOAD];
    if (EVP_DecryptUpdate(ctx, outbuf, &outlen, msg->payload, msg->payload_len) != 1) {
        print_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_DecryptFinal_ex(ctx, outbuf + outlen, &finallen) != 1) {
        print_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    memcpy(msg->payload, outbuf, outlen + finallen);
    msg->payload_len = outlen + finallen;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

