// gcc -o skynet_client skynet_client.c skynet_proto.c -lcrypto
// skynet_client client

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include "skynet.h"

#define PORT 6566
#define NODE_ROLE_AIR_VEHICLE 3
#define TIME_SLOT_INTERVAL_US 1000
#define MESSAGE_LIMIT 10
#define SERVER_NAME "server"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <nodeName>\n", argv[0]);
        return 1;
    }
    const char *argname = argv[1];
    if (strlen(argname) > MAX_NODE_NAME) {
        fprintf(stderr, "Node name too long (max %d characters)\n", MAX_NODE_NAME);
        return 1;
    }

    char node_name[16];
    uint32_t node_id = fnv1a_32(argname, strlen(argname));
    snprintf(node_name, sizeof(node_name), "%08x", node_id);

    printf("Client: %s (hash: %x)\n", argname, node_id);

    EVP_PKEY *ec_key = NULL;
    if (load_private(0, node_name, &ec_key) < 0) {
        fprintf(stderr, "Failed to load client private key\n");
        return 1;
    }

    const char *topics[] = { "npg_control", "npg_pli", "npg_surveillance", "npg_chat",
                             "npg_c2", "npg_alerts", "npg_logistics", "npg_coord"};

    EVP_PKEY *topic_pub_keys[8] = {0};
    for (int i = 0; i < 8; i++) {
        uint32_t topic_hash = fnv1a_32(topics[i], strlen(topics[i]));
        char topic_name[16];
        snprintf(topic_name, sizeof(topic_name), "%08x", topic_hash);

        topic_pub_keys[i] = load_ec_key(0, topic_name, 0);
        if (!topic_pub_keys[i]) {
            fprintf(stderr, "Failed to load topic public key %s\n", topics[i]);
            EVP_PKEY_free(ec_key);
            for (int j = 0; j < i; j++) EVP_PKEY_free(topic_pub_keys[j]);
            return 1;
        }
    }

    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("Socket creation failed");
        EVP_PKEY_free(ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(topic_pub_keys[i]);
        return 1;
    }

    if (set_non_blocking(sock_fd) < 0) {
        perror("Set non-blocking failed");
        close(sock_fd);
        EVP_PKEY_free(ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(topic_pub_keys[i]);
        return 1;
    }

    int opt = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Set SO_REUSEADDR failed");
        close(sock_fd);
        EVP_PKEY_free(ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(topic_pub_keys[i]);
        return 1;
    }

    struct sockaddr_in npg_addrs[] = {
        { .sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr = { .s_addr = INADDR_ANY } },
        { .sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr = { .s_addr = INADDR_ANY } },
        { .sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr = { .s_addr = INADDR_ANY } },
        { .sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr = { .s_addr = INADDR_ANY } },
        { .sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr = { .s_addr = INADDR_ANY } },
        { .sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr = { .s_addr = INADDR_ANY } },
        { .sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr = { .s_addr = INADDR_ANY } },
        { .sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr = { .s_addr = INADDR_ANY } }
    };

    uint8_t npgs[] = { SKYNET_NPG_CONTROL, SKYNET_NPG_PLI, SKYNET_NPG_SURVEILLANCE, SKYNET_NPG_CHAT,
                       SKYNET_NPG_C2, SKYNET_NPG_ALERTS, SKYNET_NPG_LOGISTICS, SKYNET_NPG_COORD };

    for (size_t i = 0; i < sizeof(npgs) / sizeof(npgs[0]); i++) {
        char mcast_ip[16];
        snprintf(mcast_ip, sizeof(mcast_ip), "239.255.0.%d", npgs[i]);
        inet_pton(AF_INET, mcast_ip, &npg_addrs[i].sin_addr);
        struct ip_mreq mreq = { .imr_multiaddr = npg_addrs[i].sin_addr, .imr_interface.s_addr = INADDR_ANY };
        if (setsockopt(sock_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            fprintf(stderr, "Failed to join multicast group %s: %s\n", mcast_ip, strerror(errno));
        } else {
            printf("Joined multicast group %s (NPG %d)\n", mcast_ip, npgs[i]);
        }
    }

    uint8_t buffer[MAX_BUFFER];
    struct timespec last_slot_time;
    clock_gettime(CLOCK_MONOTONIC, &last_slot_time);
    uint32_t current_slot = 0;

    // Send key exchange message
    SkyNetMessage key_msg;
    skynet_init(&key_msg, SKYNET_MSG_KEY_EXCHANGE, node_id, SKYNET_NPG_CONTROL, SKYNET_QOS_C2);
    key_msg.seq_no = current_slot;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio || !PEM_write_bio_PUBKEY(bio, ec_key)) {
        fprintf(stderr, "Failed to write public key to BIO\n");
        BIO_free(bio);
        close(sock_fd);
        EVP_PKEY_free(ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(topic_pub_keys[i]);
        return 1;
    }
    char pub_key_data[512];
    long pub_key_len = BIO_read(bio, pub_key_data, sizeof(pub_key_data));
    BIO_free(bio);
    if (pub_key_len <= 0) {
        fprintf(stderr, "Failed to read public key from BIO\n");
        close(sock_fd);
        EVP_PKEY_free(ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(topic_pub_keys[i]);
        return 1;
    }

    uint32_t server_hash = fnv1a_32(SERVER_NAME, strlen(SERVER_NAME));
    if (skynet_encrypt(0, &key_msg, node_id, server_hash, (uint8_t *)pub_key_data, pub_key_len) < 0) {
        fprintf(stderr, "Failed to encrypt key exchange message\n");
        close(sock_fd);
        EVP_PKEY_free(ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(topic_pub_keys[i]);
        return 1;
    }

    int len = skynet_serialize(&key_msg, buffer, MAX_BUFFER);
    if (len < 0) {
        fprintf(stderr, "Failed to serialize key exchange message\n");
        close(sock_fd);
        EVP_PKEY_free(ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(topic_pub_keys[i]);
        return 1;
    }

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr = { .s_addr = INADDR_ANY }
    };
    char mcast_ip[16];
    snprintf(mcast_ip, sizeof(mcast_ip), "239.255.0.%d", SKYNET_NPG_CONTROL);
    inet_pton(AF_INET, mcast_ip, &server_addr.sin_addr);

    if (sendto(sock_fd, buffer, len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to send key exchange message");
        close(sock_fd);
        EVP_PKEY_free(ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(topic_pub_keys[i]);
        return 1;
    }
    printf("Sent key exchange message to server\n");

    // Request slot
    SkyNetMessage slot_msg;
    skynet_init(&slot_msg, SKYNET_MSG_SLOT_REQUEST, node_id, SKYNET_NPG_CONTROL, SKYNET_QOS_C2);
    slot_msg.seq_no = ++current_slot;

    if (skynet_encrypt(0, &slot_msg, node_id, server_hash, NULL, 0) < 0) {
        fprintf(stderr, "Failed to encrypt slot request message\n");
        close(sock_fd);
        EVP_PKEY_free(ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(topic_pub_keys[i]);
        return 1;
    }

    len = skynet_serialize(&slot_msg, buffer, MAX_BUFFER);
    if (len < 0) {
        fprintf(stderr, "Failed to serialize slot request message\n");
        close(sock_fd);
        EVP_PKEY_free(ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(topic_pub_keys[i]);
        return 1;
    }

    if (sendto(sock_fd, buffer, len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to send slot request message");
        close(sock_fd);
        EVP_PKEY_free(ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(topic_pub_keys[i]);
        return 1;
    }
    printf("Sent slot request message to server\n");

    // Main loop
    uint32_t message_count = 0;
    float position[3] = {0.0f, 0.0f, 0.0f};
    float velocity[3] = {0.0f, 0.0f, 0.0f};

    while (message_count < MESSAGE_LIMIT) {
        struct timespec current_time;
        clock_gettime(CLOCK_MONOTONIC, &current_time);
        int64_t elapsed_us = (current_time.tv_sec - last_slot_time.tv_sec) * 1000000 +
                             (current_time.tv_nsec - last_slot_time.tv_nsec) / 1000;

        if (elapsed_us >= TIME_SLOT_INTERVAL_US) {
            last_slot_time = current_time;
            current_slot = (current_slot + 1) % SKYNET_MAX_NODES;

            // Send status message
            SkyNetMessage status_msg;
            skynet_init(&status_msg, SKYNET_MSG_STATUS, node_id, SKYNET_NPG_PLI, SKYNET_QOS_PLI);
            status_msg.seq_no = current_slot;

            uint8_t status_data[24];
            memcpy(status_data, position, 3 * sizeof(float));
            memcpy(status_data + 3 * sizeof(float), velocity, 3 * sizeof(float));

            if (skynet_encrypt(0, &status_msg, node_id, fnv1a_32("npg_pli", strlen("npg_pli")), status_data, sizeof(status_data)) < 0) {
                fprintf(stderr, "Failed to encrypt status message\n");
                continue;
            }

            len = skynet_serialize(&status_msg, buffer, MAX_BUFFER);
            if (len < 0) {
                fprintf(stderr, "Failed to serialize status message\n");
                continue;
            }

            snprintf(mcast_ip, sizeof(mcast_ip), "239.255.0.%d", SKYNET_NPG_PLI);
            inet_pton(AF_INET, mcast_ip, &server_addr.sin_addr);

            if (sendto(sock_fd, buffer, len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    perror("Failed to send status message");
                }
                continue;
            }
            printf("Sent status message: pos=[%.1f, %.1f, %.1f], vel=[%.1f, %.1f, %.1f], seq=%u\n",
                   position[0], position[1], position[2], velocity[0], velocity[1], velocity[2], status_msg.seq_no);
            message_count++;

            // Simulate position and velocity updates
            position[0] += 0.1f;
            position[1] += 0.1f;
            position[2] += 0.1f;
            velocity[0] += 0.01f;
            velocity[1] += 0.01f;
            velocity[2] += 0.01f;
        }

        // Receive messages
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        ssize_t recv_len = recvfrom(sock_fd, buffer, MAX_BUFFER, 0, (struct sockaddr *)&addr, &addr_len);
        if (recv_len < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("recvfrom failed");
            }
            usleep(1000);
            continue;
        }

        SkyNetMessage msg;
        if (skynet_deserialize(&msg, buffer, recv_len) < 0) {
            fprintf(stderr, "Failed to deserialize received message\n");
            continue;
        }

        uint32_t topic_hash = 0;
        const char *topic = NULL;
        switch (msg.npg_id) {
            case SKYNET_NPG_CONTROL: topic = "npg_control"; break;
            case SKYNET_NPG_PLI: topic = "npg_pli"; break;
            case SKYNET_NPG_SURVEILLANCE: topic = "npg_surveillance"; break;
            case SKYNET_NPG_CHAT: topic = "npg_chat"; break;
            case SKYNET_NPG_C2: topic = "npg_c2"; break;
            case SKYNET_NPG_ALERTS: topic = "npg_alerts"; break;
            case SKYNET_NPG_LOGISTICS: topic = "npg_logistics"; break;
            case SKYNET_NPG_COORD: topic = "npg_coord"; break;
            default:
                fprintf(stderr, "Received message with unknown NPG ID: %u\n", msg.npg_id);
                continue;
        }
        topic_hash = fnv1a_32(topic, strlen(topic));

        if (skynet_decrypt(0, &msg, node_id, msg.node_id) < 0) {
            fprintf(stderr, "Failed to decrypt received message from node %u\n", msg.node_id);
            continue;
        }

        skynet_print(&msg);

        if (msg.type == SKYNET_MSG_KEY_EXCHANGE) {
            if (msg.payload_len > 0 && msg.payload_len <= MAX_BUFFER - 1) {
                if (save_public_key(0, SERVER_NAME, msg.payload, msg.payload_len) == 0) {
                    printf("Saved server's public key\n");
                }
            }
        } else if (msg.type == SKYNET_MSG_STATUS) {
            if (msg.payload_len >= 6 * sizeof(float)) {
                float pos[3], vel[3];
                memcpy(pos, msg.payload, 3 * sizeof(float));
                memcpy(vel, msg.payload + 3 * sizeof(float), 3 * sizeof(float));
                printf("Received status from node %u: pos=[%.1f, %.1f, %.1f], vel=[%.1f, %.1f, %.1f]\n",
                       msg.node_id, pos[0], pos[1], pos[2], vel[0], vel[1], vel[2]);
            }
        } else if (msg.type == SKYNET_MSG_CHAT) {
            if (msg.payload_len > 0 && msg.payload_len <= MAX_BUFFER - 1) {
                msg.payload[msg.payload_len] = '\0';
                printf("Received chat from node %u: %s\n", msg.node_id, (char *)msg.payload);
            }
        }

        usleep(1000);
    }

    close(sock_fd);
    EVP_PKEY_free(ec_key);
    for (int i = 0; i < 8; i++) EVP_PKEY_free(topic_pub_keys[i]);
    return 0;
}
