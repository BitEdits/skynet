// gcc -o skynet_encrypt skynet_encrypt.c skynet_proto.c -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include "skynet.h"

static uint8_t *read_payload_file(const char *filename, size_t *payload_len) {
    fprintf(stderr, "Debug: Reading payload file %s\n", filename);
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open payload file %s: %s\n", filename, strerror(errno));
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
        fprintf(stderr, "Payload file %s is empty\n", filename);
        fclose(file);
        return NULL;
    }

    if (file_size > SKYNET_MAX_PAYLOAD - 16) { /* Reserve 16 bytes for GCM tag */
        fprintf(stderr, "Payload file too large (%ld bytes, max %d)\n", file_size, SKYNET_MAX_PAYLOAD - 16);
        fclose(file);
        return NULL;
    }

    *payload_len = (size_t)file_size;
    fprintf(stderr, "Debug: Payload file size: %zu bytes\n", *payload_len);

    if (fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Failed to seek to start of file %s\n", filename);
        fclose(file);
        return NULL;
    }

    uint8_t *payload = malloc(*payload_len);
    if (!payload) {
        fprintf(stderr, "Failed to allocate memory for payload\n");
        fclose(file);
        return NULL;
    }

    if (fread(payload, 1, *payload_len, file) != *payload_len) {
        fprintf(stderr, "Failed to read payload file %s\n", filename);
        free(payload);
        fclose(file);
        return NULL;
    }

    fclose(file);
    fprintf(stderr, "Debug: Successfully read %zu bytes from %s\n", *payload_len, filename);
    return payload;
}

int main(int argc, char *argv[]) {
    srand(time(NULL)); /* Seed rand() for compatibility */
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <from_node_name> <to_node_name> <payload_file_name>\n", argv[0]);
        return 1;
    }

    uint32_t from_node_hash = fnv1a_32(argv[1], strlen(argv[1]));
    uint32_t to_node_hash = fnv1a_32(argv[2], strlen(argv[2]));

    char from_node_name[16];
    char to_node_name[16];

    snprintf(from_node_name, sizeof(from_node_name), "%08x", from_node_hash);
    snprintf(to_node_name, sizeof(to_node_name), "%08x", to_node_hash);

    const char *payload_file_name = argv[3];
    size_t payload_len;
    uint8_t *payload = read_payload_file(payload_file_name, &payload_len);
    if (!payload) {
        fprintf(stderr, "Error reading payload %s.\n", payload_file_name);
        return 1;
    }

    fprintf(stderr, "Debug: Starting encryption: from=%s, to=%s, file=%s\n", from_node_name, to_node_name, payload_file_name);

    SkyNetMessage msg;

    skynet_encrypt(0, &msg, from_node_hash, to_node_hash, payload, payload_len);

    hex_dump("encrypt", (char *)&msg, 200);

    uint8_t buffer[MAX_BUFFER];
    fprintf(stderr, "Debug: Serializing message\n");
    int len = skynet_serialize(&msg, buffer, MAX_BUFFER);
    if (len < 0) {
        fprintf(stderr, "Failed to serialize message\n");
        return 1;
    }

    char pub_path[256];
    snprintf(pub_path, sizeof(pub_path), "%s.sky", payload_file_name);
    FILE *pub_file = fopen(pub_path, "wb");

    if (!pub_file || fwrite(buffer, 1, len, pub_file) != len) {
        fprintf(stderr, "Failed to write encoded message to %s.\n", pub_path);
        if (pub_file) fclose(pub_file);
        return -1;
    }

    fflush(stdout);
    fprintf(stderr, "Debug: Encryption complete\n");
    return 0;
}
