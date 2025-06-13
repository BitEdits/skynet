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
#define VEHICLE_TYPE VEHICLE_F_16_FALCON
#define NODE_ROLE NODE_ROLE_AIR_VEHICLE
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
    uint32_t seq_no = 0;

    SkyNetMessage msg; // Send initial key exchange with public key only
    skynet_init(&msg, SKYNET_MSG_KEY_EXCHANGE, node_id, SKYNET_NPG_CONTROL, SKYNET_QOS_C2);
    msg.seq_no = seq_no++;
    msg.timestamp = get_time_us();

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio || !PEM_write_bio_PUBKEY(bio, ec_key)) {
        fprintf(stderr, "Failed to serialize public key\n");
        print_openssl_error();
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
        fprintf(stderr, "Failed to read public key data\n");
        close(sock_fd);
        EVP_PKEY_free(ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(topic_pub_keys[i]);
        return 1;
    }

    skynet_encrypt(0, &msg, node_id, 0x40ac3dd2, (uint8_t *)pub_key_data, pub_key_len);

    skynet_print(&msg);
    int len = skynet_serialize(&msg, buffer, MAX_BUFFER);

    if (len > 0) {

        printf("SERIALIZED LEN: %d\n", len);
        hex_dump("SKY HEX DUMP", (char *)&msg, len);

        if (sendto(sock_fd, buffer, len, 0, (struct sockaddr *)&npg_addrs[0], sizeof(npg_addrs[0])) < 0) {
            perror("Send key exchange failed");
        } else {
            printf("Sent key exchange message on NPG %d, seq %u\n", SKYNET_NPG_CONTROL, msg.seq_no);
            skynet_print(&msg);
        }
    }

    struct timeval timeout = { 0, 1000 };
    fd_set read_fds;
    int message_count = 0;
    int server_joined = 0;

    while (message_count < MESSAGE_LIMIT) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed_us = (now.tv_sec - last_slot_time.tv_sec) * 1000000 +
                         (now.tv_nsec - last_slot_time.tv_nsec) / 1000;

        if (elapsed_us >= TIME_SLOT_INTERVAL_US) {
            current_slot = (current_slot + 1) % 1000;
            last_slot_time = now;

            if (current_slot % 10 == 0 && server_joined) {
                skynet_init(&msg, SKYNET_MSG_STATUS, node_id, SKYNET_NPG_PLI, SKYNET_QOS_PLI);
                msg.seq_no = seq_no++;
                float pli_data[6] = { 50.0f + message_count * 0.1f, 10.0f + message_count * 0.1f, 10000.0f,
                                      0.0f, 0.0f, 0.0f };
                uint8_t topic_key[32], topic_hmac_key[32];
                if (derive_shared_key(ec_key, topic_pub_keys[1], topic_key, topic_hmac_key) < 0) {
                    fprintf(stderr, "Failed to derive shared key for npg_pli\n");
                    continue;
                }
                skynet_set_data(&msg, (uint8_t *)pli_data, sizeof(pli_data), topic_key, topic_hmac_key);
                len = skynet_serialize(&msg, buffer, MAX_BUFFER);
                if (len > 0) {
                    if (sendto(sock_fd, buffer, len, 0, (struct sockaddr *)&npg_addrs[1], sizeof(npg_addrs[1])) < 0) {
                        perror("Send PLI failed");
                    } else {
                        printf("Sent PLI message on NPG %d, seq %u: pos=[%.1f, %.1f, %.1f]\n",
                               SKYNET_NPG_PLI, msg.seq_no, pli_data[0], pli_data[1], pli_data[2]);
                        skynet_print(&msg);
                    }
                }
            }

            if (current_slot % 10 == 0 && server_joined) {
                skynet_init(&msg, SKYNET_MSG_STATUS, node_id, SKYNET_NPG_SURVEILLANCE, SKYNET_QOS_PLI);
                msg.seq_no = seq_no++;
                char data[64];
                snprintf(data, sizeof(data), "Track: F-16, Lat:50.%d, Lon:10.%d, Alt:10000ft", message_count, message_count);
                uint8_t topic_key[32], topic_hmac_key[32];
                if (derive_shared_key(ec_key, topic_pub_keys[2], topic_key, topic_hmac_key) < 0) {
                    fprintf(stderr, "Failed to derive shared key for npg_surveillance\n");
                    continue;
                }
                skynet_set_data(&msg, (uint8_t *)data, strlen(data) + 1, topic_key, topic_hmac_key);
                len = skynet_serialize(&msg, buffer, MAX_BUFFER);
                if (len > 0) {
                    if (sendto(sock_fd, buffer, len, 0, (struct sockaddr *)&npg_addrs[2], sizeof(npg_addrs[2])) < 0) {
                        perror("Send surveillance failed");
                    } else {
                        printf("Sent surveillance message on NPG %d, seq %u: %s\n",
                               SKYNET_NPG_SURVEILLANCE, msg.seq_no, data);
                        skynet_print(&msg);
                        message_count++;
                    }
                }
            }
        }

        FD_ZERO(&read_fds);
        FD_SET(sock_fd, &read_fds);
        timeout.tv_sec = 0;
        timeout.tv_usec = 1000;
        int ready = select(sock_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (ready < 0) {
            perror("Select failed");
            continue;
        }

        if (ready > 0 && FD_ISSET(sock_fd, &read_fds)) {
            len = (int)recv(sock_fd, buffer, sizeof(buffer), 0);
            if (len < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    perror("recv");
                }
                continue;
            }
            SkyNetMessage rx_msg;
            if (skynet_deserialize(&rx_msg, buffer, sizeof(buffer)) == 0) {
                EVP_PKEY *dec_key = NULL;
                uint8_t dec_key_key[32], dec_hmac_key[32];
                if (rx_msg.npg_id == SKYNET_NPG_CONTROL) {
                    uint32_t hash = fnv1a_32(SERVER_NAME, strlen(SERVER_NAME));
                    char hash_str[16];
                    snprintf(hash_str, sizeof(hash_str), "%08x", hash);
                    printf("Control 1: %x\n", rx_msg.npg_id);
                    dec_key = load_ec_key(0, hash_str, 0);
                    if (!dec_key) continue;
                    if (derive_shared_key(ec_key, dec_key, dec_key_key, dec_hmac_key) < 0) {
                        EVP_PKEY_free(dec_key);
                        continue;
                    }
                } else {
                    printf("Control 2: %x\n", rx_msg.npg_id);
                    int topic_idx = -1;
                    switch (rx_msg.npg_id) {
                        case SKYNET_NPG_PLI: topic_idx = 1; break;
                        case SKYNET_NPG_SURVEILLANCE: topic_idx = 2; break;
                        case SKYNET_NPG_CHAT: topic_idx = 3; break;
                        case SKYNET_NPG_C2: topic_idx = 4; break;
                        case SKYNET_NPG_ALERTS: topic_idx = 5; break;
                        case SKYNET_NPG_LOGISTICS: topic_idx = 6; break;
                        case SKYNET_NPG_COORD: topic_idx = 7; break;
                        default: continue;
                    }
                    dec_key = topic_pub_keys[topic_idx];
                    if (!dec_key) continue;
                    if (derive_shared_key(ec_key, dec_key, dec_key_key, dec_hmac_key) < 0) {
                        continue;
                    }
                }
                if (skynet_verify_hmac(&rx_msg, dec_hmac_key) == 0 && skynet_decrypt_payload(&rx_msg, dec_key_key) == 0) {
                    printf("Received on NPG %u, seq %u: ", rx_msg.npg_id, rx_msg.seq_no);
                    skynet_print(&rx_msg);
                    if (rx_msg.type == SKYNET_MSG_KEY_EXCHANGE && rx_msg.npg_id == SKYNET_NPG_CONTROL && !server_joined) {
                        if (save_public_key(0, SERVER_NAME, rx_msg.payload, rx_msg.payload_len) == 0) {
                            printf("Saved server public key for %s\n", SERVER_NAME);
                            server_joined = 1;
                        }
                    } else if (rx_msg.type == SKYNET_MSG_WAYPOINT && rx_msg.npg_id == SKYNET_NPG_C2) {
                        float *waypoint = (float *)rx_msg.payload;
                        printf("Received waypoint: [%.1f, %.1f, %.1f]\n", waypoint[0], waypoint[1], waypoint[2]);
                    }
                }
                if (rx_msg.npg_id == SKYNET_NPG_CONTROL) EVP_PKEY_free(dec_key);
            }
        }
    }

    close(sock_fd);
    EVP_PKEY_free(ec_key);
    for (int i = 0; i < 8; i++) EVP_PKEY_free(topic_pub_keys[i]);
    return 0;
}
