// gcc -c skynet_proto.c -o skynet_proto.o -lcrypto

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include "skynet.h"

#define MAX_NODE_NAME 64
#define SERVER_BASE_PATH "~/.skynet/ecc/secp384r1/"
#define CLIENT_BASE_PATH "~/.skynet_client/ecc/secp384r1/"
#define HASH_STR_LEN 16

void print_openssl_error(void) {
    unsigned long err = ERR_get_error();
    char err_str[256];
    ERR_error_string_n(err, err_str, sizeof(err_str));
    fprintf(stderr, "OpenSSL error: %s\n", err_str);
}

char *expand_home(const char *path) {
    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "HOME environment variable not set\n");
        return NULL;
    }
    size_t len = strlen(home) + strlen(path) + 1;
    char *expanded = malloc(len);
    if (!expanded) {
        fprintf(stderr, "Failed to allocate memory for path\n");
        return NULL;
    }
    snprintf(expanded, len, "%s%s", home, path + 1);
    return expanded;
}

char *get_base_path(int srv, const char *node_name) {
    if (strcmp(node_name, "server") == 0) return SERVER_BASE_PATH;
    if (strcmp(node_name, "client") == 0) return CLIENT_BASE_PATH;
    if (strcmp(node_name, "40ac3dd2") == 0) return SERVER_BASE_PATH;
    if (strcmp(node_name, " 8f929c1e") == 0) return CLIENT_BASE_PATH;
    return srv == 0 ? CLIENT_BASE_PATH : SERVER_BASE_PATH;
}

char *build_key_path(int srv, const char *node_name, const char *suffix) {

    const char *base_path = get_base_path(srv, node_name);

   fprintf(stderr, "Build key path: %s/%s \n", base_path, node_name);

    if (!base_path) {
        fprintf(stderr, "Invalid node name: %s (must be 'server' or 'client')\n", node_name);
        return NULL;
    }
    char *dir_path = expand_home(base_path);
    if (!dir_path) return NULL;
/*    
    uint32_t hash = fnv1a_32(node_name, strlen(node_name));
    char hash_str[HASH_STR_LEN];
    snprintf(hash_str, sizeof(hash_str), "%08x", hash);
  */

    size_t path_len = strlen(dir_path) + 1 + strlen(node_name) + strlen(suffix) + 1;
    char *path = malloc(path_len);
    if (!path) {
        fprintf(stderr, "Failed to allocate memory for key path\n");
        free(dir_path);
        return NULL;
    }
    
    snprintf(path, path_len, "%s/%s%s", dir_path, node_name, suffix);
    free(dir_path);
    return path;
}

EVP_PKEY *load_ec_key(int srv, const char *node_name, int is_private) {
    char *key_path = build_key_path(srv, node_name, is_private ? ".ec_priv" : ".ec_pub");
    if (!key_path) return NULL;
    
    FILE *key_file = fopen(key_path, "rb");
    if (!key_file) {
        fprintf(stderr, "Failed to open %s: %s\n", key_path, strerror(errno));
        free(key_path);
        return NULL;
    }
    
    EVP_PKEY *key = is_private ? PEM_read_PrivateKey(key_file, NULL, NULL, NULL) :
                                 PEM_read_PUBKEY(key_file, NULL, NULL, NULL);
    fclose(key_file);
    free(key_path);
    
    if (!key) {
        print_openssl_error();
        return NULL;
    }
    return key;
}

int derive_shared_key(EVP_PKEY *priv_key, EVP_PKEY *peer_pub_key, uint8_t *aes_key, uint8_t *hmac_key) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0) {
        print_openssl_error();
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    
    if (EVP_PKEY_derive_set_peer(ctx, peer_pub_key) <= 0) {
        print_openssl_error();
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    
    size_t secret_len;
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) {
        print_openssl_error();
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    
    uint8_t *shared_secret = malloc(secret_len);
    if (!shared_secret || EVP_PKEY_derive(ctx, shared_secret, &secret_len) <= 0) {
        print_openssl_error();
        free(shared_secret);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kdf_ctx = EVP_KDF_CTX_new(kdf);
    if (!kdf_ctx) {
        print_openssl_error();
        free(shared_secret);
        EVP_KDF_free(kdf);
        return -1;
    }
    
    OSSL_PARAM aes_params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_octet_string("key", shared_secret, secret_len),
        OSSL_PARAM_construct_end()
    };
    
    if (EVP_KDF_derive(kdf_ctx, aes_key, 32, aes_params) <= 0) {
        print_openssl_error();
        EVP_KDF_CTX_free(kdf_ctx);
        EVP_KDF_free(kdf);
        free(shared_secret);
        return -1;
    }
    
    OSSL_PARAM hmac_params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_octet_string("key", shared_secret, secret_len),
        OSSL_PARAM_construct_octet_string("info", (unsigned char *)"HMAC", 4),
        OSSL_PARAM_construct_end()
    };
    
    if (EVP_KDF_derive(kdf_ctx, hmac_key, 32, hmac_params) <= 0) {
        print_openssl_error();
        EVP_KDF_CTX_free(kdf_ctx);
        EVP_KDF_free(kdf);
        free(shared_secret);
        return -1;
    }
    
    EVP_KDF_CTX_free(kdf_ctx);
    EVP_KDF_free(kdf);
    free(shared_secret);
    return 0;
}

int skynet_encrypt(int srv, SkyNetMessage *msg, const char *from_node, const char *to_node, const uint8_t *data, uint16_t data_len) {

    if (!msg || !from_node || !to_node || !data) {
        fprintf(stderr, "Error: Null pointer in skynet_encrypt\n");
        return -1;
    }
    if (data_len > SKYNET_MAX_PAYLOAD - 16) {
        fprintf(stderr, "Error: Payload too large: %u > %u\n", data_len, SKYNET_MAX_PAYLOAD - 16);
        return -1;
    }
    if (strlen(from_node) >= MAX_NODE_NAME || strlen(to_node) >= MAX_NODE_NAME) {
        fprintf(stderr, "Node name too long (max %d characters)\n", MAX_NODE_NAME - 1);
        return -1;
    }
    if (strcmp(from_node, to_node) == 0) {
        fprintf(stderr, "Error: from_node and to_node must be different\n");
        return -1;
    }

    uint32_t from_hash = fnv1a_32(from_node, strlen(from_node));
    uint32_t to_hash = fnv1a_32(to_node, strlen(to_node));
    char to_name[16];
    char from_name[16];
    snprintf(to_name, sizeof(to_name), "%08x", to_hash);
    snprintf(from_name, sizeof(from_name), "%08x", from_hash);


    EVP_PKEY *priv_key = load_ec_key(0, from_name, 1);
    EVP_PKEY *peer_pub_key = load_ec_key(1, to_name, 0);

    if (!priv_key || !peer_pub_key) {
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(peer_pub_key);
        return -1;
    }

    uint8_t aes_key[32], hmac_key[32];
    if (derive_shared_key(priv_key, peer_pub_key, aes_key, hmac_key) < 0) {
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(peer_pub_key);
        return -1;
    }

    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(peer_pub_key);

    skynet_set_data(msg, data, data_len, aes_key, hmac_key);
    if (msg->payload_len == 0) {
        fprintf(stderr, "Error: Failed to set encrypted data\n");
        return -1;
    }

    return 0;
}

int skynet_decrypt(int srv, SkyNetMessage *msg, const char *to_node, const char *from_node) {
    if (!msg || !to_node || !from_node) {
        fprintf(stderr, "Error: Null pointer in skynet_decrypt\n");
        return -1;
    }
    if (strlen(to_node) >= MAX_NODE_NAME || strlen(from_node) >= MAX_NODE_NAME) {
        fprintf(stderr, "Node name too long (max %d characters)\n", MAX_NODE_NAME - 1);
        return -1;
    }
    if (strcmp(to_node, from_node) == 0) {
        fprintf(stderr, "Error: to_node and from_node must be different\n");
        return -1;
    }

    EVP_PKEY *priv_key = load_ec_key(srv, to_node, 1);
    EVP_PKEY *peer_pub_key = load_ec_key(srv, from_node, 0);
    if (!priv_key || !peer_pub_key) {
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(peer_pub_key);
        return -1;
    }

    uint8_t aes_key[32], hmac_key[32];
    if (derive_shared_key(priv_key, peer_pub_key, aes_key, hmac_key) < 0) {
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(peer_pub_key);
        return -1;
    }

    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(peer_pub_key);
/*
    if (skynet_verify_hmac(msg, hmac_key) < 0) {
        fprintf(stderr, "Error: HMAC verification failed\n");
        return -1;
    }
*/
    if (skynet_decrypt_payload(msg, aes_key) < 0) {
        fprintf(stderr, "Error: Payload decryption failed\n");
        return -1;
    }

    return 0;
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
    if (data_length > SKYNET_MAX_PAYLOAD - 16) {
        fprintf(stderr, "Error: Payload too large: %u > %u\n", data_length, SKYNET_MAX_PAYLOAD - 16);
        return;
    }

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

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, msg->payload + msg->payload_len) != 1) {
        print_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    msg->payload_len += 16;
    EVP_CIPHER_CTX_free(ctx);

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

    if (msg->payload_len < 16) {
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

int load_keys(int srv, const char *node_name, uint8_t *aes_key, uint8_t *hmac_key, uint32_t *node_id, EVP_PKEY **ec_key) {

    const char *base_path = get_base_path(srv, node_name);
    char *dir_path = expand_home(base_path);
    if (!dir_path) return -1;
    char aes_path[256], hmac_path[256], id_path[256];
    snprintf(aes_path, sizeof(aes_path), "%s/%s.aes", dir_path, node_name);
    snprintf(hmac_path, sizeof(hmac_path), "%s/%s.hmac", dir_path, node_name);
    snprintf(id_path, sizeof(id_path), "%s/%s.id", dir_path, node_name);
    free(dir_path);

    FILE *file = fopen(aes_path, "rb");
    if (!file || fread(aes_key, 1, 32, file) != 32) {
        fprintf(stderr, "Failed to read AES key from %s: %s\n", aes_path, file ? strerror(errno) : "null file");
        if (file) fclose(file);
        return -1;
    }
    fclose(file);

    file = fopen(hmac_path, "rb");
    if (!file || fread(hmac_key, 1, 32, file) != 32) {
        fprintf(stderr, "Failed to read HMAC key from %s: %s\n", hmac_path, file ? strerror(errno) : "null file");
        if (file) fclose(file);
        return -1;
    }
    fclose(file);

    file = fopen(id_path, "rb");
    if (!file || fread(node_id, 1, sizeof(uint32_t), file) != sizeof(uint32_t)) {
        fprintf(stderr, "Failed to read node ID from %s: %s\n", id_path, file ? strerror(errno) : "null file");
        if (file) fclose(file);
        return -1;
    }
    fclose(file);

    *ec_key = load_ec_key(srv, node_name, 1);
    if (!*ec_key) return -1;

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


int save_public_key(const char *node_name, const uint8_t *pub_key_data, size_t pub_key_len) {
    char *dir_path = expand_home(SERVER_BASE_PATH);
    if (!dir_path) return -1;
    uint32_t hash = fnv1a_32(node_name, strlen(node_name));
    char hash_str[16];
    snprintf(hash_str, sizeof(hash_str), "%08x", hash);
    char pub_path[256];
    snprintf(pub_path, sizeof(pub_path), "%s/%s.ec_pub", dir_path, hash_str);
    FILE *pub_file = fopen(pub_path, "wb");
    free(dir_path);
    if (!pub_file || fwrite(pub_key_data, 1, pub_key_len, pub_file) != pub_key_len) {
        fprintf(stderr, "Failed to write public key to %s: %s\n", pub_path, strerror(errno));
        if (pub_file) fclose(pub_file);
        return -1;
    }
    fclose(pub_file);
    return 0;
}

int set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}