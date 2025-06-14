#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include "skynet.h"

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

char *base_path(int srv) {
    return srv == 0 ? CLIENT_BASE_PATH : SERVER_BASE_PATH;
}

char *build_key_path(int srv, const char *node_name, const char *suffix) {
    const char *basepath = base_path(srv);
    if (!basepath) {
        fprintf(stderr, "Invalid node name: %s (must be 'server' or 'client')\n", node_name);
        return NULL;
    }
    char *dir_path = expand_home(basepath);
    if (!dir_path) return NULL;

    size_t path_len = strlen(dir_path) + 1 + strlen(node_name) + strlen(suffix) + 1;
    char *path = malloc(path_len);
    if (!path) {
        fprintf(stderr, "Failed to allocate memory for key path\n");
        free(dir_path);
        return NULL;
    }
    snprintf(path, path_len, "%s%s%s", dir_path, node_name, suffix);
    free(dir_path);
    return path;
}

EVP_PKEY *load_ec_key(int srv, const char *node_name, int is_private) {
    char *key_path = build_key_path(srv, node_name, is_private ? ".ec_priv" : ".ec_pub");
    if (!key_path) return NULL;

//  fprintf(stderr, "%sDebug: Accessing keystore: %s.%s\n", GRAY, key_path, RESET);

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

    if (!key) print_openssl_error();
    return key;
}

int load_keys(int srv, const char *from_name, const char *to_name, EVP_PKEY **priv_key, EVP_PKEY **peer_pub_key) {
    *priv_key = load_ec_key(srv, from_name, 1);
    *peer_pub_key = load_ec_key(srv ^ 1, to_name, 0);
    if (!*priv_key || !*peer_pub_key) {
        EVP_PKEY_free(*priv_key);
        EVP_PKEY_free(*peer_pub_key);
        return -1;
    }
    return 0;
}

int derive_shared_key(EVP_PKEY *priv_key, EVP_PKEY *peer_pub_key, uint8_t *aes_key) {
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

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_octet_string("key", shared_secret, secret_len),
        OSSL_PARAM_construct_end()
    };

    if (EVP_KDF_derive(kdf_ctx, aes_key, AES_KEY_LEN, params) <= 0) {
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

int skynet_encrypt(int srv, SkyNetMessage *msg, uint32_t from_node, uint32_t to_node, const uint8_t *data, uint16_t data_len) {

    if (data_len > MAX_BUFFER - 16) {
        fprintf(stderr, "Error: Payload too large: %u > %u\n", data_len, MAX_BUFFER - 16);
        return -1;
    }

    char from_name[16], to_name[16];
    snprintf(to_name, 16, "%08x", to_node);
    snprintf(from_name, 16, "%08x", from_node);

    EVP_PKEY *priv_key = NULL, *peer_pub_key = NULL;
    if (load_keys(srv, from_name, to_name, &priv_key, &peer_pub_key) < 0) return -1;

    uint8_t aes_key[AES_KEY_LEN];
    if (derive_shared_key(priv_key, peer_pub_key, aes_key) < 0) {
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(peer_pub_key);
        return -1;
    }

    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(peer_pub_key);

    skynet_encrypt_payload(msg, data, data_len, aes_key);
    if (msg->payload_len == 0) {
        fprintf(stderr, "Error: Failed to set encrypted data\n");
        return -1;
    }

    return 0;
}

int skynet_decrypt(int srv, SkyNetMessage *msg, uint32_t to_node, uint32_t from_node) {

    if (!msg || !to_node || !from_node) {
        fprintf(stderr, "Error: Null pointer in skynet_decrypt\n");
        return -1;
    }

    char from_name[16], to_name[16];
    snprintf(to_name, 16, "%08x", to_node);
    snprintf(from_name, 16, "%08x", from_node);

    EVP_PKEY *priv_key = NULL, *peer_pub_key = NULL;
    if (load_keys(srv, to_name, from_name, &priv_key, &peer_pub_key) < 0) {
        fprintf(stderr, "Error: Load keys failed for decryption.\n");
        return -1;
    }

    uint8_t aes_key[AES_KEY_LEN];
    if (derive_shared_key(priv_key, peer_pub_key, aes_key) < 0) {
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(peer_pub_key);
        return -1;
    }

    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(peer_pub_key);

    if (skynet_decrypt_payload(msg, aes_key) < 0) {
        fprintf(stderr, "Error: Payload decryption failed from=%x to=%x\n", from_node, to_node);
        return -1;
    }

    return 0;
}

void skynet_init(SkyNetMessage *msg, SkyNetMessageType type, uint32_t node_id, uint32_t npg_id, uint8_t qos) {
    memset(msg, 0, sizeof(SkyNetMessage));
    msg->version = SKYNET_VERSION;
    msg->type = type & 0x0F;
    msg->qos = qos & 0x0F;
    msg->hop_count = 0;
    msg->npg_id = npg_id;
    msg->node_id = node_id;
    msg->seq_no = 0;
    if (RAND_bytes(msg->iv, 16) != 1) {
        fprintf(stderr, "Error: Failed to generate random IV\n");
        print_openssl_error();
    }
}

int skynet_serialize(const SkyNetMessage *msg, uint8_t *buffer, size_t buffer_size) {
    if (!msg || !buffer) {
        fprintf(stderr, "Error: Null pointer in skynet_serialize\n");
        return -1;
    }

    if (msg->payload_len > MAX_BUFFER) {
        fprintf(stderr, "Error: Invalid payload length: %u > %u\n", msg->payload_len, MAX_BUFFER);
        return -1;
    }

    size_t required_size = 2 + 4 + 4 + 4 + 16 + 2 + msg->payload_len;
    if (buffer_size < required_size) {
        fprintf(stderr, "Error: Buffer too small: %zu < %zu\n", buffer_size, required_size);
        return -1;
    }

    size_t offset = 0;
    buffer[offset++] = (msg->version << 4) | (msg->type & 0x0F);
    buffer[offset++] = (msg->qos << 4) | (msg->hop_count & 0x0F);
    *(uint32_t *)(buffer + offset) = htonl(msg->npg_id); offset += 4;
    *(uint32_t *)(buffer + offset) = htonl(msg->node_id); offset += 4;
    *(uint32_t *)(buffer + offset) = htonl(msg->seq_no); offset += 4;
    memcpy(buffer + offset, msg->iv, 16); offset += 16;
    *(uint16_t *)(buffer + offset) = htons(msg->payload_len); offset += 2;
    memcpy(buffer + offset, msg->payload, msg->payload_len); offset += msg->payload_len;

    return (int)offset;
}

int skynet_deserialize(SkyNetMessage *msg, const uint8_t *buffer, size_t buffer_size) {
    if (!msg || !buffer) {
        fprintf(stderr, "Error: Null pointer in skynet_deserialize\n");
        return -1;
    }

    size_t min_size = 2 + 4 + 4 + 4 + 16 + 2;
    if (buffer_size < min_size) {
        fprintf(stderr, "Error: Buffer too small for deserialization: %zu < %zu\n", buffer_size, min_size);
        return -1;
    }

    size_t offset = 0;
    msg->version = (buffer[offset] >> 4) & 0x0F;
    msg->type = buffer[offset++] & 0x0F;
    msg->qos = (buffer[offset] >> 4) & 0x0F;
    msg->hop_count = buffer[offset++] & 0x0F;
    msg->npg_id = ntohl(*(uint32_t *)(buffer + offset)); offset += 4;
    msg->node_id = ntohl(*(uint32_t *)(buffer + offset)); offset += 4;
    msg->seq_no = ntohl(*(uint32_t *)(buffer + offset)); offset += 4;
    memcpy(msg->iv, buffer + offset, 16); offset += 16;
    msg->payload_len = ntohs(*(uint16_t *)(buffer + offset)); offset += 2;

    if (msg->payload_len > MAX_BUFFER) {
        fprintf(stderr, "Error: Invalid payload length: %u > %u\n", msg->payload_len, MAX_BUFFER);
        return -1;
    }

    if (buffer_size < offset + msg->payload_len) {
        fprintf(stderr, "Error: Buffer too small for payload: %zu < %zu\n", buffer_size, offset + msg->payload_len);
        return -1;
    }

    memcpy(msg->payload, buffer + offset, msg->payload_len);
    return 0;
}

void skynet_print(const SkyNetMessage *msg) {
    printf("%sSkyNetMessage: version=%u, type=%u, npg_id=%u, node_id=%x, "
           "seq_no=%u, qos=%u, hop=%u, payload_len=%u%s\n", BLUE,
           msg->version, msg->type, msg->npg_id, msg->node_id,
           msg->seq_no, msg->qos, msg->hop_count, msg->payload_len, RESET);
}

void skynet_encrypt_payload(SkyNetMessage *msg, const uint8_t *data, uint16_t data_length, const uint8_t *aes_key) {
    if (!msg || !aes_key) {
        fprintf(stderr, "Error: Null pointer in skynet_encrypt_payload\n");
        return;
    }
    if (data_length > MAX_BUFFER - 16) {
        fprintf(stderr, "Error: Payload too large: %u > %u\n", data_length, MAX_BUFFER - 16);
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
    uint8_t outbuf[MAX_BUFFER];
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
    if (msg->payload_len > MAX_BUFFER - 16) {
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
    fprintf(stderr, "%sEncryption successful, from=%x, to=%x, size=%u.%s\n", YELLOW, msg->node_id, msg->npg_id, msg->payload_len, RESET);
}

int skynet_decrypt_payload(SkyNetMessage *msg, const uint8_t *aes_key) {
    if (!msg || !aes_key) {
        fprintf(stderr, "Error: Null pointer in skynet_decrypt_payload\n");
        return -1;
    }

    int outlen = 0, finallen = 0;
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
        fprintf(stderr, "Error: Failed to set GCM tag\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    uint8_t outbuf[MAX_BUFFER];
    if (EVP_DecryptUpdate(ctx, outbuf, &outlen, msg->payload, msg->payload_len - 16) != 1) {
        print_openssl_error();
        fprintf(stderr, "Error: DecryptUpdate with ciphertext failed\n");
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
    fprintf(stderr, "%sDecryption successful, from=%x, to=%x, size=%u.%s\n", YELLOW, msg->node_id, msg->npg_id, msg->payload_len, RESET);
    return 0;
}

uint32_t fnv1a_32(void *data, size_t len) {
    uint8_t *bytes = (uint8_t *)data;
    uint32_t hash = FNV_OFFSET_BASIS_32;
    for (size_t i = 0; i < len; ++i) {
        hash ^= bytes[i];
        hash *= FNV_PRIME_32;
    }
    return hash;
}

int save_public_key(int srv, char *node_name, const uint8_t *pub_key_data, size_t pub_key_len) {
    char *dir_path = expand_home(base_path(srv));
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

uint64_t get_time_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

void hex_dump(const char *label, const uint8_t *data, size_t len) {
    fprintf(stderr, "%s:\n", label);
    for (size_t i = 0; i < len; i++) { fprintf(stderr, "%02x ", data[i]); if (i % 32 == 31) fprintf(stderr, "\n"); }
    if (len % 32 != 0) fprintf(stderr, "\n");
}
