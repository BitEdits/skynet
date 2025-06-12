// gcc -o skynet_decrypt skynet_decrypt.c skynet_proto.c -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include "skynet.h"

#define MAX_NODE_NAME 64
#define MAX_BUFFER 1590
#define SERVER_BASE_PATH "~/.skynet/ecc/secp384r1/"
#define CLIENT_BASE_PATH "~/.skynet_client/ecc/secp384r1/"
#define HASH_STR_LEN 16

static void print_openssl_error(void) {
    unsigned long err = ERR_get_error();
    char err_str[256];
    ERR_error_string_n(err, err_str, sizeof(err_str));
    fprintf(stderr, "OpenSSL error: %s\n", err_str);
}

static char *expand_home(const char *path) {
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

static const char *get_base_path(const char *node_name) {
    if (strcmp(node_name, "server") == 0) return SERVER_BASE_PATH;
    if (strcmp(node_name, "client") == 0) return CLIENT_BASE_PATH;
    return NULL;
}

static char *build_key_path(const char *node_name, const char *suffix) {
    const char *base_path = get_base_path(node_name);
    if (!base_path) {
        fprintf(stderr, "Invalid node name: %s (must be 'server' or 'client')\n", node_name);
        return NULL;
    }
    char *dir_path = expand_home(base_path);
    if (!dir_path) return NULL;
    
    uint32_t hash = fnv1a_32(node_name, strlen(node_name));
    char hash_str[HASH_STR_LEN];
    snprintf(hash_str, sizeof(hash_str), "%08x", hash);
    
    size_t suffix_len = strlen(suffix);
    size_t hash_len = strlen(hash_str);
    size_t dir_len = strlen(dir_path);
    size_t path_len = dir_len + 1 + hash_len + suffix_len + 1; // +1 for '/', +1 for '\0'
    
    char *path = malloc(path_len);
    if (!path) {
        fprintf(stderr, "Failed to allocate memory for key path\n");
        free(dir_path);
        return NULL;
    }
    
    snprintf(path, path_len, "%s/%s%s", dir_path, hash_str, suffix);
    free(dir_path);
    return path;
}

static EVP_PKEY *load_ec_key(const char *node_name, int is_private) {
    char *key_path = build_key_path(node_name, is_private ? ".ec_priv" : ".ec_pub");
    if (!key_path) return NULL;
    fprintf(stderr, "Debug: Loading key from %s\n", key_path);
    
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
    fprintf(stderr, "Debug: Successfully loaded %s key for %s\n",
            is_private ? "private" : "public", node_name);
    return key;
}

static int derive_shared_key(EVP_PKEY *priv_key, EVP_PKEY *peer_pub_key, uint8_t *aes_key, uint8_t *hmac_key) {
    fprintf(stderr, "Debug: Deriving shared key\n");
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
    
    OSSL_PARAM aes_params[3] = {
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
    
    OSSL_PARAM hmac_params[4] = {
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
    fprintf(stderr, "Debug: Shared key derived successfully\n");
    return 0;
}

static uint8_t *read_encrypted_file(const char *filename, size_t *file_len) {
    fprintf(stderr, "Debug: Reading encrypted file %s\n", filename);
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open encrypted file %s: %s\n", filename, strerror(errno));
        return NULL;
    }
    
    if (fseek(file, 0, SEEK_END) != 0) {
        fprintf(stderr, "Failed to seek to end of file %s\n", filename);
        fclose(file);
        return NULL;
    }
    
    long file_size = ftell(file);
    if (file_size < 0) {
        fprintf(stderr, "Failed to get size of file %s\n", filename);
        fclose(file);
        return NULL;
    }
    
    if (file_size == 0) {
        fprintf(stderr, "Encrypted file %s is empty\n", filename);
        fclose(file);
        return NULL;
    }
    
    if (file_size > MAX_BUFFER) {
        fprintf(stderr, "Encrypted file too large (%ld bytes, max %d)\n", file_size, MAX_BUFFER);
        fclose(file);
        return NULL;
    }
    
    *file_len = (size_t)file_size;
    fprintf(stderr, "Debug: Encrypted file size: %zu bytes\n", *file_len);
    
    if (fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Failed to seek to start of file %s\n", filename);
        fclose(file);
        return NULL;
    }
    
    uint8_t *buffer = malloc(*file_len);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate memory for encrypted file\n");
        fclose(file);
        return NULL;
    }
    
    if (fread(buffer, 1, *file_len, file) != *file_len) {
        fprintf(stderr, "Failed to read encrypted file %s\n", filename);
        free(buffer);
        fclose(file);
        return NULL;
    }
    
    fclose(file);
    fprintf(stderr, "Debug: Successfully read %zu bytes from %s\n", *file_len, filename);
    return buffer;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <to_node_name> <from_node_name> <encrypted_file_name>\n", argv[0]);
        return 1;
    }

    const char *to_node_name = argv[1];
    const char *from_node_name = argv[2];
    const char *encrypted_file_name = argv[3];

    fprintf(stderr, "Debug: Starting decryption: to=%s, from=%s, file=%s\n",
            to_node_name, from_node_name, encrypted_file_name);

    if (strcmp(to_node_name, "server") != 0 && strcmp(to_node_name, "client") != 0) {
        fprintf(stderr, "Invalid to_node_name: %s (must be 'server' or 'client')\n", to_node_name);
        return 1;
    }
    
    if (strcmp(from_node_name, "server") != 0 && strcmp(from_node_name, "client") != 0) {
        fprintf(stderr, "Invalid from_node_name: %s (must be 'server' or 'client')\n", from_node_name);
        return 1;
    }
    
    if (strcmp(to_node_name, from_node_name) == 0) {
        fprintf(stderr, "to_node_name and from_node_name must be different\n");
        return 1;
    }
    
    if (strlen(to_node_name) >= MAX_NODE_NAME || strlen(from_node_name) >= MAX_NODE_NAME) {
        fprintf(stderr, "Node name too long (max %d characters)\n", MAX_NODE_NAME - 1);
        return 1;
    }

    EVP_PKEY *priv_key = load_ec_key(to_node_name, 1);
    EVP_PKEY *peer_pub_key = load_ec_key(from_node_name, 0);
    if (!priv_key || !peer_pub_key) {
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(peer_pub_key);
        return 1;
    }

    uint8_t aes_key[32], hmac_key[32];
    if (derive_shared_key(priv_key, peer_pub_key, aes_key, hmac_key) < 0) {
        EVP_PKEY_free(priv_key);
        EVP_PKEY_free(peer_pub_key);
        return 1;
    }
    
    EVP_PKEY_free(priv_key);
    EVP_PKEY_free(peer_pub_key);

    size_t file_len;
    uint8_t *encrypted_data = read_encrypted_file(encrypted_file_name, &file_len);
    if (!encrypted_data) {
        return 1;
    }

    SkyNetMessage msg;
    fprintf(stderr, "Debug: Deserializing message\n");
    if (skynet_deserialize(&msg, encrypted_data, file_len) < 0) {
        fprintf(stderr, "Failed to deserialize message\n");
        free(encrypted_data);
        return 1;
    }
    free(encrypted_data);

    fprintf(stderr, "Debug: Verifying HMAC\n");
    if (skynet_verify_hmac(&msg, hmac_key) < 0) {
        fprintf(stderr, "HMAC verification failed\n");
        return 1;
    }

    fprintf(stderr, "Debug: Decrypting payload\n");
    if (skynet_decrypt_payload(&msg, aes_key) < 0) {
        fprintf(stderr, "Failed to decrypt payload\n");
        return 1;
    }

    char out_path[256];
    snprintf(out_path, sizeof(out_path), "%s.dec", encrypted_file_name);
    FILE *out_file = fopen(out_path, "wb");
    if (!out_file || fwrite(msg.payload, 1, msg.payload_len, out_file) != msg.payload_len) {
        fprintf(stderr, "Failed to write decrypted payload to %s\n", out_path);
        if (out_file) fclose(out_file);
        return 1;
    }
    fclose(out_file);

    fprintf(stderr, "Debug: Decryption complete, output written to %s\n", out_path);
    return 0;
}
