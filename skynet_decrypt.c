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

    uint32_t from_node_hash = fnv1a_32(argv[1], strlen(argv[1]));
    uint32_t to_node_hash = fnv1a_32(argv[2], strlen(argv[2]));

    const char *encrypted_file_name = argv[3];
    size_t file_len;
    uint8_t *encrypted_data = read_encrypted_file(encrypted_file_name, &file_len);
    if (!encrypted_data) {
        return 1;
    }

    fprintf(stderr, "Debug: Starting decryption: to=%x, from=%x, file=%s\n",  to_node_hash, from_node_hash, encrypted_file_name);

    SkyNetMessage msg;

    fprintf(stderr, "Debug: Deserializing message with size %ld\n", file_len);
    if (skynet_deserialize(&msg, encrypted_data, file_len) < 0) {
        fprintf(stderr, "Failed to deserialize message\n");
        free(encrypted_data);
        return 1;
    }
    free(encrypted_data);

    skynet_decrypt(1, &msg, to_node_hash, from_node_hash);

    hex_dump("decrypt", (char *)&msg, 200);

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
