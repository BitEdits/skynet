#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <time.h>
#include "j-msg.h"

#define PORT 8080
#define MAX_JUS 32
#define MAX_BUFFER 1024
#define JU_ADDRESS_BASE 00001
#define TIME_SLOT_INTERVAL_MS 7.8125
#define FRAME_DURATION_MS (TADIL_J_FRAME_SLOTS * TIME_SLOT_INTERVAL_MS)

/* JU State */
typedef struct {
    int sock_fd;                /* Client socket */
    uint32_t ju_address;        /* JU address */
    JURole role;                /* JU role */
    uint8_t subscribed_npgs[32]; /* Subscribed NPGs */
    uint32_t time_slots[16];    /* Assigned time slots */
    uint32_t slot_count;        /* Number of assigned slots */
} JUState;

/* Server State */
typedef struct {
    JUState jus[MAX_JUS];       /* Connected JUs */
    uint32_t ju_count;          /* Number of JUs */
    uint32_t current_slot;      /* Current time slot */
    int ntr_assigned;           /* NTR assigned flag */
} ServerState;

/* Initialize server state */
void server_init(ServerState *state) {
    memset(state, 0, sizeof(ServerState));
    state->current_slot = 0;
    state->ntr_assigned = 0;
}

/* Add JU to server */
int add_ju(ServerState *state, int sock_fd) {
    if (state->ju_count >= MAX_JUS) return -1;
    JUState *ju = &state->jus[state->ju_count];
    ju->sock_fd = sock_fd;
    ju->ju_address = JU_ADDRESS_BASE + state->ju_count;
    ju->role = JU_ROLE_NON_C2;
    ju->slot_count = 1;
    ju->time_slots[0] = state->ju_count * 100; /* Simple slot assignment */
    state->ju_count++;
    return 0;
}

/* Subscribe JU to NPG */
void subscribe_npg(JUState *ju, uint8_t npg) {
    for (int i = 0; i < 32; i++) {
        if (ju->subscribed_npgs[i] == 0 || ju->subscribed_npgs[i] == npg) {
            ju->subscribed_npgs[i] = npg;
            break;
        }
    }
}

/* Broadcast message to subscribed JUs */
void broadcast_message(ServerState *state, const JMessage *msg) {
    uint8_t buffer[MAX_BUFFER];
    int len = jmessage_serialize(msg, buffer, MAX_BUFFER);
    if (len < 0) return;

    for (uint32_t i = 0; i < state->ju_count; i++) {
        JUState *ju = &state->jus[i];
        for (int j = 0; j < 32 && ju->subscribed_npgs[j]; j++) {
            if (ju->subscribed_npgs[j] == msg->npg && ju->sock_fd > 0) {
                send(ju->sock_fd, buffer, len, 0);
            }
        }
    }
}

/* Process control message */
void process_control(ServerState *state, JUState *ju, JMessage *msg) {
    if (msg->type == J_MSG_INITIAL_ENTRY) {
        /* Assign role and NPGs */
        subscribe_npg(ju, 1); /* Initial entry */
        subscribe_npg(ju, 7); /* Surveillance */
        if (!state->ntr_assigned) {
            ju->role = JU_ROLE_NTR;
            state->ntr_assigned = 1;
            subscribe_npg(ju, 4); /* Network management */
        }
        printf("JU %05o joined, role: %d\n", ju->ju_address, ju->role);
    } else if (msg->type == J_MSG_NETWORK_MANAGEMENT && ju->role == JU_ROLE_NTR) {
        /* Handle time sync or slot reassignment */
        printf("Network management from NTR %05o\n", ju->ju_address);
    }
}

/* Process client message */
void handle_message(ServerState *state, JUState *ju, JMessage *msg) {
    if (msg->time_slot != state->current_slot) return; /* TDMA check */

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

int main() {
    ServerState state;
    server_init(&state);

    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    fd_set read_fds;
    int max_fd;

    /* Create socket */
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    /* Configure server address */
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    /* Bind socket */
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(1);
    }

    /* Listen for connections */
    if (listen(server_sock, 5) < 0) {
        perror("Listen failed");
        exit(1);
    }
    printf("Link 16 server listening on port %d...\n", PORT);

    /* Simulate TDMA */
    struct timespec slot_time = {0, (long)(TIME_SLOT_INTERVAL_MS * 1000000)};
    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(server_sock, &read_fds);
        max_fd = server_sock;

        for (uint32_t i = 0; i < state.ju_count; i++) {
            if (state.jus[i].sock_fd > 0) {
                FD_SET(state.jus[i].sock_fd, &read_fds);
                if (state.jus[i].sock_fd > max_fd) max_fd = state.jus[i].sock_fd;
            }
        }

        /* Wait for activity or slot interval */
        struct timeval timeout = {0, (long)(TIME_SLOT_INTERVAL_MS * 1000)};
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);

        if (activity < 0) {
            perror("Select failed");
            continue;
        }

        /* New connection */
        if (FD_ISSET(server_sock, &read_fds)) {
            client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
            if (client_sock >= 0) {
                if (add_ju(&state, client_sock) < 0) {
                    close(client_sock);
                }
            }
        }

        /* Handle client messages */
        uint8_t buffer[MAX_BUFFER];
        for (uint32_t i = 0; i < state.ju_count; i++) {
            JUState *ju = &state.jus[i];
            if (ju->sock_fd > 0 && FD_ISSET(ju->sock_fd, &read_fds)) {
                int len = recv(ju->sock_fd, buffer, MAX_BUFFER, 0);
                if (len <= 0) {
                    close(ju->sock_fd);
                    ju->sock_fd = 0;
                    continue;
                }
                JMessage msg;
                if (jmessage_deserialize(&msg, buffer, len) >= 0) {
                    handle_message(&state, ju, &msg);
                }
            }
        }

        /* Advance time slot */
        state.current_slot = (state.current_slot + 1) % TADIL_J_FRAME_SLOTS;
        nanosleep(&slot_time, NULL);
    }

    close(server_sock);
    return 0;
}
