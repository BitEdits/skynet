#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include "j-msg.h"

#define PORT 8080
#define MAX_JUS 32
#define MAX_BUFFER 1024
#define JU_ADDRESS_BASE 00001
#define TIME_SLOT_INTERVAL_MS 100 /* Simplified for testing */
#define FRAME_DURATION_MS (TADIL_J_FRAME_SLOTS * TIME_SLOT_INTERVAL_MS)

/* JU State */
typedef struct {
    int sock_fd;                /* Client socket */
    uint32_t ju_address;        /* JU address */
    JURole role;                /* JU role */
    uint8_t subscribed_npgs[32]; /* Subscribed NPGs */
    uint32_t time_slots[16];    /* Assigned time slots */
    uint32_t slot_count;        /* Number of assigned slots */
    uint8_t in_buffer[MAX_BUFFER]; /* Input buffer */
    size_t in_buffer_len;       /* Length of data in input buffer */
    uint8_t out_buffer[MAX_BUFFER]; /* Output buffer */
    size_t out_buffer_len;      /* Length of data in output buffer */
    size_t out_buffer_sent;     /* Bytes already sent from output buffer */
} JUState;

/* Server State */
typedef struct {
    JUState jus[MAX_JUS];       /* Connected JUs */
    uint32_t ju_count;          /* Number of JUs */
    uint32_t current_slot;      /* Current time slot */
    int ntr_assigned;           /* NTR assigned flag */
} ServerState;

/* Set socket to non-blocking mode */
int set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Initialize server state */
void server_init(ServerState *state) {
    memset(state, 0, sizeof(ServerState));
    state->current_slot = 0;
    state->ntr_assigned = 0;
}

/* Add JU to server */
int add_ju(ServerState *state, int sock_fd) {
    if (state->ju_count >= MAX_JUS) {
        printf("Max JUs reached\n");
        return -1;
    }
    JUState *ju = &state->jus[state->ju_count];
    ju->sock_fd = sock_fd;
    ju->ju_address = JU_ADDRESS_BASE + state->ju_count;
    ju->role = JU_ROLE_NON_C2;
    ju->slot_count = 1;
    ju->time_slots[0] = state->ju_count * 100;
    ju->in_buffer_len = 0;
    ju->out_buffer_len = 0;
    ju->out_buffer_sent = 0;
    state->ju_count++;
    printf("Added JU %05o\n", ju->ju_address);
    return 0;
}

/* Subscribe JU to NPG */
void subscribe_npg(JUState *ju, uint8_t npg) {
    for (int i = 0; i < 32; i++) {
        if (ju->subscribed_npgs[i] == 0 || ju->subscribed_npgs[i] == npg) {
            ju->subscribed_npgs[i] = npg;
            printf("JU %05o subscribed to NPG %d\n", ju->ju_address, npg);
            break;
        }
    }
}

/* Queue message to JU's output buffer */
int queue_message(JUState *ju, const JMessage *msg) {
    uint8_t buffer[MAX_BUFFER];
    int len = jmessage_serialize(msg, buffer, MAX_BUFFER);
    if (len < 0) {
        printf("Serialization failed\n");
        return -1;
    }
    if (ju->out_buffer_len + len > MAX_BUFFER) {
        printf("Output buffer full for JU %05o\n", ju->ju_address);
        return -1;
    }
    memcpy(ju->out_buffer + ju->out_buffer_len, buffer, len);
    ju->out_buffer_len += len;
    return 0;
}

/* Broadcast message to subscribed JUs */
void broadcast_message(ServerState *state, const JMessage *msg) {
    for (uint32_t i = 0; i < state->ju_count; i++) {
        JUState *ju = &state->jus[i];
        for (int j = 0; j < 32 && ju->subscribed_npgs[j]; j++) {
            if (ju->subscribed_npgs[j] == msg->npg && ju->sock_fd > 0) {
                if (queue_message(ju, msg) == 0) {
                    printf("Queued broadcast to JU %05o, NPG %d\n", ju->ju_address, msg->npg);
                }
            }
        }
    }
}

/* Process control message */
void process_control(ServerState *state, JUState *ju, JMessage *msg) {
    if (msg->type == J_MSG_INITIAL_ENTRY) {
        subscribe_npg(ju, 1);
        subscribe_npg(ju, 7);
        if (!state->ntr_assigned) {
            ju->role = JU_ROLE_NTR;
            state->ntr_assigned = 1;
            subscribe_npg(ju, 4);
        }
        printf("JU %05o joined, role: %d\n", ju->ju_address, ju->role);
    } else if (msg->type == J_MSG_NETWORK_MANAGEMENT && ju->role == JU_ROLE_NTR) {
        printf("Network management from NTR %05o\n", ju->ju_address);
    }
}

/* Process client message */
void handle_message(ServerState *state, JUState *ju, JMessage *msg) {
    /* Allow messages in any slot for testing */
    printf("Received message from JU %05o, type: %d, NPG: %d\n", ju->ju_address, msg->type, msg->npg);

    switch (msg->type) {
        case J_MSG_INITIAL_ENTRY:
        case J_MSG_NETWORK_MANAGEMENT:
            process_control(state, ju, msg);
            break;
        case J_MSG_PPLI_C2:
        case J_MSG_PPLI_NON_C2:
        case J_MSG_SURVEILLANCE:
        case J_MSG_AIR_CONTROL:
        case J_MSG_WEAPONS_COORD:
        case J_MSG_FIGHTER_TO_FIGHTER:
        case J_MSG_ENGAGEMENT_COORD:
        case J_MSG_FREE_TEXT:
            broadcast_message(state, msg);
            jmessage_print(msg);
            break;
        default:
            printf("Unsupported message type: %d\n", msg->type);
    }
}

/* Process input buffer */
void process_input_buffer(ServerState *state, JUState *ju) {
    while (ju->in_buffer_len > 0) {
        JMessage msg;
        int consumed = jmessage_deserialize(&msg, ju->in_buffer, ju->in_buffer_len);
        if (consumed < 0) {
            break; /* Incomplete message */
        }
        handle_message(state, ju, &msg); /* Pass pointer to msg */
        memmove(ju->in_buffer, ju->in_buffer + consumed, ju->in_buffer_len - consumed);
        ju->in_buffer_len -= consumed;
    }
}

/* Process output buffer */
void process_output_buffer(JUState *ju) {
    if (ju->out_buffer_len <= ju->out_buffer_sent) {
        ju->out_buffer_len = 0;
        ju->out_buffer_sent = 0;
        return;
    }

    int bytes = send(ju->sock_fd, ju->out_buffer + ju->out_buffer_sent, ju->out_buffer_len - ju->out_buffer_sent, 0);
    if (bytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return; /* Try again later */
        }
        perror("Send failed");
        close(ju->sock_fd);
        ju->sock_fd = 0;
        ju->out_buffer_len = 0;
        ju->out_buffer_sent = 0;
    } else {
        ju->out_buffer_sent += bytes;
        printf("Sent %d bytes to JU %05o\n", bytes, ju->ju_address);
    }
}

int main() {
    ServerState state;
    server_init(&state);

    int server_sock;
    struct sockaddr_in server_addr;
    fd_set read_fds, write_fds;
    int max_fd;

    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    if (set_non_blocking(server_sock) < 0) {
        perror("Set non-blocking failed");
        exit(1);
    }

    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Setsockopt failed");
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(1);
    }

    if (listen(server_sock, 5) < 0) {
        perror("Listen failed");
        exit(1);
    }
    printf("Link 16 server listening on port %d...\n", PORT);

    struct timespec last_slot_time;
    clock_gettime(CLOCK_MONOTONIC, &last_slot_time);

    while (1) {
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        FD_SET(server_sock, &read_fds);
        max_fd = server_sock;

        for (uint32_t i = 0; i < state.ju_count; i++) {
            JUState *ju = &state.jus[i];
            if (ju->sock_fd > 0) {
                FD_SET(ju->sock_fd, &read_fds);
                if (ju->out_buffer_len > ju->out_buffer_sent) {
                    FD_SET(ju->sock_fd, &write_fds);
                }
                if (ju->sock_fd > max_fd) max_fd = ju->sock_fd;
            }
        }

        struct timeval timeout = {0, 1000}; /* 1ms timeout for responsiveness */
        int activity = select(max_fd + 1, &read_fds, &write_fds, NULL, &timeout);
        if (activity < 0) {
            perror("Select failed");
            continue;
        }

        /* Check for new connections */
        if (FD_ISSET(server_sock, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
            if (client_sock >= 0) {
                if (set_non_blocking(client_sock) < 0) {
                    perror("Set client non-blocking failed");
                    close(client_sock);
                } else if (add_ju(&state, client_sock) < 0) {
                    close(client_sock);
                }
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("Accept failed");
            }
        }

        /* Handle client I/O */
        for (uint32_t i = 0; i < state.ju_count; i++) {
            JUState *ju = &state.jus[i];
            if (ju->sock_fd <= 0) continue;

            /* Read data */
            if (FD_ISSET(ju->sock_fd, &read_fds)) {
                int bytes = recv(ju->sock_fd, ju->in_buffer + ju->in_buffer_len,
                                 MAX_BUFFER - ju->in_buffer_len, 0);
                if (bytes <= 0) {
                    if (bytes < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("Recv failed");
                    }
                    printf("JU %05o disconnected\n", ju->ju_address);
                    close(ju->sock_fd);
                    ju->sock_fd = 0;
                    ju->in_buffer_len = 0;
                    ju->out_buffer_len = 0;
                    ju->out_buffer_sent = 0;
                    continue;
                }
                ju->in_buffer_len += bytes;
                process_input_buffer(&state, ju);
            }

            /* Write data */
            if (FD_ISSET(ju->sock_fd, &write_fds)) {
                process_output_buffer(ju);
            }
        }

        /* Update TDMA slot */
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed_ms = (now.tv_sec - last_slot_time.tv_sec) * 1000 +
                          (now.tv_nsec - last_slot_time.tv_nsec) / 1000000;
        if (elapsed_ms >= TIME_SLOT_INTERVAL_MS) {
            state.current_slot = (state.current_slot + 1) % TADIL_J_FRAME_SLOTS;
            last_slot_time = now;
            printf("Advanced to slot %u\n", state.current_slot);
        }
    }

    close(server_sock);
    return 0;
}