// gcc -o skynet_keygen skynet_keygen.c skynet_proto.c -lcrypto
// skynet_keygen client --client
// skynet_keygen server --server

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
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include "skynet.h"

int create_dir(char *path) {
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

int generate_keys(char *node_name, int is_client) {
    char *base_path = is_client ? CLIENT_BASE_PATH : SERVER_BASE_PATH;
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

    char priv_path[256], pub_path[256];
    snprintf(priv_path, sizeof(priv_path), "%s/%s.ec_priv", dir_path, hash_str);
    snprintf(pub_path, sizeof(pub_path), "%s/%s.ec_pub", dir_path, hash_str);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0) {
        fprintf(stderr, "Failed to initialize key generation context\n");
        print_openssl_error();
        EVP_PKEY_CTX_free(pctx);
        free(dir_path);
        return -1;
    }

    // Set curve
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp384r1) <= 0) {
        fprintf(stderr, "Failed to set EC curve\n");
        print_openssl_error();
        EVP_PKEY_CTX_free(pctx);
        free(dir_path);
        return -1;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        fprintf(stderr, "Failed to generate EC key\n");
        print_openssl_error();
        EVP_PKEY_CTX_free(pctx);
        free(dir_path);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);

    // Save private key
    FILE *priv_file = fopen(priv_path, "wb");
    if (!priv_file || !PEM_write_PrivateKey(priv_file, pkey, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Failed to write private key to %s: %s\n", priv_path, strerror(errno));
        print_openssl_error();
        if (priv_file) fclose(priv_file);
        EVP_PKEY_free(pkey);
        free(dir_path);
        return -1;
    }
    fclose(priv_file);

    // Save public key
    FILE *pub_file = fopen(pub_path, "wb");
    if (!pub_file || !PEM_write_PUBKEY(pub_file, pkey)) {
        fprintf(stderr, "Failed to write public key to %s: %s\n", pub_path, strerror(errno));
        print_openssl_error();
        if (pub_file) fclose(pub_file);
        EVP_PKEY_free(pkey);
        free(dir_path);
        return -1;
    }
    fclose(pub_file);

    EVP_PKEY_free(pkey);
    printf("Generated keys for node %s (hash: %s) in %s\n", node_name, hash_str, dir_path);
    free(dir_path);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3 || (strcmp(argv[2], "--server") != 0 && strcmp(argv[2], "--client") != 0)) {
        fprintf(stderr, "Usage: %s <nodeName> [--server|--client]\n", argv[0]);
        return 1;
    }

    char *node_name = argv[1];
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
