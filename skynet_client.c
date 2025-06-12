// gcc -o skynet_client skynet_client.c -lcrypto

#define _GNU_SOURCE
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
#include "skynet.h"

#define PORT 6566                    /* SkyNet port */
#define MAX_BUFFER 1490              /* Max SkyNetMessage size */
#define NODE_ID 10002                /* Unique node ID (JU_ADDRESS equivalent) */
#define VEHICLE_TYPE VEHICLE_F_16_FALCON /* F-16 Falcon */
#define NODE_ROLE NODE_ROLE_AIR_VEHICLE  /* Air vehicle role */
#define TIME_SLOT_INTERVAL_US 1000   /* 1 ms TDMA slots */
#define MESSAGE_LIMIT 10             /* Number of surveillance messages to send */

/* Set socket to non-blocking mode */
int set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Generate random AES and HMAC keys (placeholder; use ECDH in production) */
void generate_keys(uint8_t *aes_key, uint8_t *hmac_key) {
    RAND_bytes(aes_key, 32);
    RAND_bytes(hmac_key, 32);
}

/* Main client function */
int main() {
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    if (set_non_blocking(sock_fd) < 0) {
        perror("Set non-blocking failed");
        close(sock_fd);
        return 1;
    }

    int opt = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Set SO_REUSEADDR failed");
        close(sock_fd);
        return 1;
    }

    /* Multicast addresses for NPGs */
    struct sockaddr_in npg_addrs[] = {
        { .sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr = { .s_addr = 0 } }, /* NPG 1: Control */
        { .sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr = { .s_addr = 0 } }, /* NPG 6: PLI */
        { .sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr = { .s_addr = 0 } }, /* NPG 7: Surveillance */
        { .sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr = { .s_addr = 0 } }, /* NPG 100: C2 */
        { .sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr = { .s_addr = 0 } }  /* NPG 101: Alerts */
    };
    uint8_t npgs[] = { SKYNET_NPG_CONTROL, SKYNET_NPG_PLI, SKYNET_NPG_SURVEILLANCE, SKYNET_NPG_C2, SKYNET_NPG_ALERTS };
    for (size_t i = 0; i < sizeof(npgs) / sizeof(npgs[i]); i++) {
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

    /* Placeholder keys (replace with ECDH) */
    uint8_t aes_key[32], hmac_key[32];
    generate_keys(aes_key, hmac_key);

    /* Send slot request message to join network */
    SkyNetMessage msg;
    skynet_init(&msg, SKYNET_MSG_SLOT_REQUEST, NODE_ID, SKYNET_NPG_CONTROL, SKYNET_QOS_C2);
    msg.seq_no = seq_no++;
    uint8_t slot_request_data[8] = { VEHICLE_TYPE, NODE_ROLE }; /* Include vehicle type and role */
    skynet_set_data(&msg, slot_request_data, sizeof(slot_request_data));
    int len = skynet_serialize(&msg, buffer, MAX_BUFFER);
    if (len > 0) {
        if (sendto(sock_fd, buffer, len, 0, (struct sockaddr *)&npg_addrs[0], sizeof(npg_addrs[0])) < 0) {
            perror("Send slot request failed");
        } else {
            printf("Sent slot request message on NPG %d, seq %u\n", SKYNET_NPG_CONTROL, msg.seq_no);
            skynet_print(&msg);
        }
    } else {
        printf("Serialization failed\n");
    }

    struct timeval timeout = { 0, 1000 };
    fd_set read_fds;
    int message_count = 0;

    while (message_count < MESSAGE_LIMIT) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed_us = (now.tv_sec - last_slot_time.tv_sec) * 1000000 +
                          (now.tv_nsec - last_slot_time.tv_nsec) / 1000;
        if (elapsed_us >= TIME_SLOT_INTERVAL_US) {
            current_slot = (current_slot + 1) % 1000; /* 1,000 slots/s */
            last_slot_time = now;

            /* Send PLI every 100 slots (100 ms, 10 Hz) */
            if (current_slot % 10 == 0) {
                skynet_init(&msg, SKYNET_MSG_STATUS, NODE_ID, SKYNET_NPG_PLI, SKYNET_QOS_PLI);
                msg.seq_no = seq_no++;
                float pli_data[6] = { 50.0f + message_count * 0.1f, 10.0f + message_count * 0.1f, 10000.0f, /* x, y, z */
                                      0.0f, 0.0f, 0.0f }; /* vx, vy, vz */
                skynet_set_data(&msg, (uint8_t *)pli_data, sizeof(pli_data));
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

            /* Send surveillance data every 100 slots (100 ms) */
            if (current_slot % 10 == 0) {
                skynet_init(&msg, SKYNET_MSG_STATUS, NODE_ID, SKYNET_NPG_SURVEILLANCE, SKYNET_QOS_PLI);
                msg.seq_no = seq_no++;
                char data[64];
                snprintf(data, sizeof(data), "Track: F-16, Lat:50.%d, Lon:10.%d, Alt:10000ft", message_count, message_count);
                skynet_set_data(&msg, (uint8_t *)data, strlen(data) + 1);
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
                } else {
                    printf("Serialization failed\n");
                }
            }
        }

        FD_ZERO(&read_fds);
        FD_SET(sock_fd, &read_fds);
        timeout.tv_usec = 1000;
        int ready = select(sock_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (ready < 0) {
            perror("Select failed");
            continue;
        }
        if (ready > 0 && FD_ISSET(sock_fd, &read_fds)) {
            len = recvfrom(sock_fd, buffer, MAX_BUFFER, 0, NULL, NULL);
            if (len < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    perror("Recvfrom failed");
                }
                continue;
            }
            SkyNetMessage rx_msg;
            if (skynet_deserialize(&rx_msg, buffer, len) >= 0) {
                if (skynet_verify_hmac(&rx_msg, hmac_key) == 0 && skynet_decrypt_payload(&rx_msg, aes_key) == 0) {
                    printf("Received on NPG %d, seq %u: ", rx_msg.npg_id, rx_msg.seq_no);
                    skynet_print(&rx_msg);
                    if (rx_msg.type == SKYNET_MSG_WAYPOINT && rx_msg.npg_id == SKYNET_NPG_C2) {
                        float *waypoint = (float *)rx_msg.payload;
                        printf("Received waypoint: [%.1f, %.1f, %.1f]\n", waypoint[0], waypoint[1], waypoint[2]);
                    }
                } else {
                    printf("Verification or decryption failed\n");
                }
            } else {
                printf("Deserialization failed\n");
            }
        }
    }

    close(sock_fd);
    return 0;
}
