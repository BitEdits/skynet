// gcc -o skynet_keygen skynet_keygen.c skynet_proto.c -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "skynet.h"

#define AES_KEY_LEN 32
#define HMAC_KEY_LEN 32
#define MAX_NODE_NAME 64
#define BASE_PATH_SERVER "~/.skynet/ecc/secp384r1/"
#define BASE_PATH_CLIENT "~/.skynet_client/ecc/secp384r1/"

static int create_dir(const char *path) {
    char *tmp = strdup(path);
    if (!tmp) return -1;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0700) < 0 && errno != EEXIST) {
                free(tmp);
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0700) < 0 && errno != EEXIST) {
        free(tmp);
        return -1;
    }
    free(tmp);
    return 0;
}

static int generate_keys(const char *node_name, int is_client) {
    const char *base_path = is_client ? BASE_PATH_CLIENT : BASE_PATH_SERVER;
    char *dir_path = expand_home(base_path);
    if (!dir_path) return -1;

    if (create_dir(dir_path) < 0) {
        fprintf(stderr, "Failed to create directory %s: %s\n", dir_path, strerror(errno));
        free(dir_path);
        return -1;
    }

    uint32_t hash = fnv1a_32(node_name, strlen(node_name));
    char hash_str[16];
    snprintf(hash_str, sizeof(hash_str), "%08x", hash);

    char aes_path[256], hmac_path[256], id_path[256], priv_path[256], pub_path[256];
    snprintf(priv_path, sizeof(priv_path), "%s/%s.ec_priv", dir_path, hash_str);
    snprintf(pub_path, sizeof(pub_path), "%s/%s.ec_pub", dir_path, hash_str);


    // Generate secp384r1 key pair
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp384r1);
    if (!ec_key || !EC_KEY_generate_key(ec_key)) {
        fprintf(stderr, "Failed to generate EC key pair\n");
        print_openssl_error();
        EC_KEY_free(ec_key);
        free(dir_path);
        return -1;
    }

    // Save private key
    FILE *priv_file = fopen(priv_path, "wb");
    if (!priv_file || !PEM_write_ECPrivateKey(priv_file, ec_key, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Failed to write private key to %s: %s\n", priv_path, strerror(errno));
        print_openssl_error();
        if (priv_file) fclose(priv_file);
        EC_KEY_free(ec_key);
        free(dir_path);
        return -1;
    }
    fclose(priv_file);

    // Save public key
    FILE *pub_file = fopen(pub_path, "wb");
    if (!pub_file || !PEM_write_EC_PUBKEY(pub_file, ec_key)) {
        fprintf(stderr, "Failed to write public key to %s: %s\n", pub_path, strerror(errno));
        print_openssl_error();
        if (pub_file) fclose(pub_file);
        EC_KEY_free(ec_key);
        free(dir_path);
        return -1;
    }
    fclose(pub_file);

    EC_KEY_free(ec_key);
    printf("Generated keys for node %s (hash: %s) in %s (ID: %u)\n", node_name, hash_str, dir_path);
    free(dir_path);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3 || (strcmp(argv[2], "--server") != 0 && strcmp(argv[2], "--client") != 0)) {
        fprintf(stderr, "Usage: %s <nodeName> [--server|--client]\n", argv[0]);
        return 1;
    }

    const char *node_name = argv[1];
    if (strlen(node_name) > MAX_NODE_NAME) {
        fprintf(stderr, "Node name too long (max %d characters)\n", MAX_NODE_NAME);
        return 1;
    }

    int is_client = strcmp(argv[2], "--client") == 0;
    if (generate_keys(node_name, is_client) < 0) {
        return 1;
    }

    return 0;
}
