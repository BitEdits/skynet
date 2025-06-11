// gcc -o f16 f16.c j-msg.c

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
#include "j-msg.h"

#define PORT 8080
#define MAX_BUFFER 1024
#define JU_ADDRESS 00002
#define INITIAL_NPG 1
#define SURVEILLANCE_NPG 7
#define DEFAULT_NET 0
#define TIME_SLOT_INTERVAL_US 7812 /* 7.8125 ms in microseconds */

/* Set socket to non-blocking mode */
int set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

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

    struct sockaddr_in initial_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT)
    };
    inet_pton(AF_INET, "239.255.0.1", &initial_addr.sin_addr);

    struct sockaddr_in surveillance_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT)
    };
    inet_pton(AF_INET, "239.255.0.7", &surveillance_addr.sin_addr);

    uint8_t buffer[MAX_BUFFER];
    struct timespec last_slot_time;
    clock_gettime(CLOCK_MONOTONIC, &last_slot_time);
    uint32_t current_slot = 0;

    /* Send initial entry message */
    JMessage msg;
    jmessage_init(&msg, J_MSG_INITIAL_ENTRY, JU_ADDRESS, INITIAL_NPG, DEFAULT_NET);
    msg.time_slot = current_slot; /* Set unique time_slot */
    int len = jmessage_serialize(&msg, buffer, MAX_BUFFER);
    if (len > 0) {
        if (sendto(sock_fd, buffer, len, 0, (struct sockaddr *)&initial_addr, sizeof(initial_addr)) < 0) {
            perror("Send initial entry failed");
        } else {
            printf("Sent initial entry message on NPG %d, slot %u\n", INITIAL_NPG, msg.time_slot);
        }
    } else {
        printf("Serialization failed\n");
    }

    struct timeval timeout = {0, 1000};
    fd_set read_fds;
    int message_count = 0;

    while (message_count < 10) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed_us = (now.tv_sec - last_slot_time.tv_sec) * 1000000 +
                          (now.tv_nsec - last_slot_time.tv_nsec) / 1000;
        if (elapsed_us >= TIME_SLOT_INTERVAL_US) {
            current_slot = (current_slot + 1) % TADIL_J_FRAME_SLOTS;
            last_slot_time = now;

            if (current_slot % 100 == 0) {
                jmessage_init(&msg, J_MSG_SURVEILLANCE, JU_ADDRESS, SURVEILLANCE_NPG, DEFAULT_NET);
                msg.time_slot = current_slot; /* Set unique time_slot */
                char data[64];
                snprintf(data, sizeof(data), "Track: F-16, Lat:50.%d, Lon:10.%d", message_count, message_count);
                jmessage_set_data(&msg, (uint8_t *)data, strlen(data) + 1);
                len = jmessage_serialize(&msg, buffer, MAX_BUFFER);
                if (len > 0) {
                    if (sendto(sock_fd, buffer, len, 0, (struct sockaddr *)&surveillance_addr, sizeof(surveillance_addr)) < 0) {
                        perror("Send surveillance failed");
                    } else {
                        jmessage_print(&msg);
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
            JMessage rx_msg;
            if (jmessage_deserialize(&rx_msg, buffer, len) >= 0) {
                printf("Received: ");
                jmessage_print(&rx_msg);
            } else {
                printf("Deserialization failed\n");
            }
        }
    }

    close(sock_fd);
    return 0;
}

