// gcc -o skynet skynet.c skynet_proto.c -pthread -lcrypto
// skynet server

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <net/if.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "skynet.h"

#define PORT 6566
#define MAX_NODES 2000
#define TIME_SLOT_INTERVAL_US 1000
#define THREAD_COUNT 4
#define QUEUE_SIZE 1024
#define MAX_SEQUENCES 64
#define MAX_EVENTS 32
#define NEIGHBOR_TIMEOUT_US 5000000

typedef struct {
    struct sockaddr_in addr;
    uint32_t node_id;
    NodeRole role;
    uint8_t subscribed_npgs[32];
    uint64_t last_seen;
    float position[3];
    float velocity[3];
    char node_name[MAX_NODE_NAME];
} NodeState;

typedef struct {
    atomic_uint claimed;
    uint32_t node_id;
    uint32_t seq_no;
    uint64_t timestamp;
} MessageSeq;

typedef struct {
    SkyNetMessage messages[QUEUE_SIZE];
    struct sockaddr_in addrs[QUEUE_SIZE];
    uint64_t recv_times[QUEUE_SIZE];
    atomic_uint head;
    atomic_uint tail;
    int event_fds[THREAD_COUNT];
} MessageQueue;

typedef struct {
    NodeState nodes[MAX_NODES];
    atomic_uint node_count;
    uint32_t current_slot;
    int socket_fd;
    int epoll_fd;
    int timer_fd;
    MessageQueue mq;
    pthread_t workers[THREAD_COUNT];
    atomic_int running;
    MessageSeq seqs[MAX_SEQUENCES];
    atomic_uint seq_idx;
    struct sockaddr_in server_addr;
    atomic_int timer_active;
    uint8_t aes_key[32];
    EVP_PKEY *ec_key;
    char server_name[MAX_NODE_NAME];
    EVP_PKEY *topic_priv_keys[8];
    uint32_t node_id;
} ServerState;

typedef struct {
    ServerState *state;
    int worker_id;
    int epoll_fd;
} WorkerState;

void queue_init(MessageQueue *q) {
    atomic_store(&q->head, 0);
    atomic_store(&q->tail, 0);
    for (int i = 0; i < THREAD_COUNT; i++) {
        q->event_fds[i] = eventfd(0, EFD_NONBLOCK);
        if (q->event_fds[i] < 0) {
            perror("eventfd creation failed");
            exit(1);
        }
    }
}

int queue_enqueue(ServerState *state, const SkyNetMessage *msg, const struct sockaddr_in *addr, uint64_t recv_time) {
    MessageQueue *q = &state->mq;
    uint32_t head, next_head;
    do {
        head = atomic_load_explicit(&q->head, memory_order_acquire);
        next_head = (head + 1) % QUEUE_SIZE;
        if (next_head == atomic_load_explicit(&q->tail, memory_order_acquire)) {
            fprintf(stderr, "Queue full, dropping message\n");
            return -1;
        }
    } while (!atomic_compare_exchange_strong(&q->head, &head, next_head));
    q->messages[head] = *msg;
    q->addrs[head] = *addr;
    q->recv_times[head] = recv_time;
    uint64_t signal = 1;
    for (int i = 0; i < THREAD_COUNT; i++) {
        if (write(q->event_fds[i], &signal, sizeof(signal)) < 0) {
            perror("eventfd write failed");
        }
    }
    return 0;
}

int queue_dequeue(ServerState *state, SkyNetMessage *msg, struct sockaddr_in *addr, uint64_t *recv_time) {
    MessageQueue *q = &state->mq;
    uint32_t tail, next_tail;
    do {
        tail = atomic_load_explicit(&q->tail, memory_order_acquire);
        if (tail == atomic_load_explicit(&q->head, memory_order_acquire)) {
            return -1;
        }
        next_tail = (tail + 1) % QUEUE_SIZE;
    } while (!atomic_compare_exchange_strong(&q->tail, &tail, next_tail));
    *msg = q->messages[tail];
    *addr = q->addrs[tail];
    *recv_time = q->recv_times[tail];
    return 0;
}

void pin_thread(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) < 0) {
        perror("pthread_setaffinity_np failed");
    }
}

void server_init(ServerState *state, const char *node_name) {
    memset(state, 0, sizeof(ServerState));
    strncpy(state->server_name, node_name, MAX_NODE_NAME - 1);
    state->server_name[MAX_NODE_NAME - 1] = '\0';

    if (load_private(1, node_name, &state->ec_key)) {
        fprintf(stderr, "Failed to load server private key\n");
        exit(1);
    }

    const char *topics[] = { "npg_control", "npg_pli", "npg_surveillance",
                             "npg_chat", "npg_c2", "npg_alerts", "npg_logistics", "npg_coord"};

    for (int i = 0; i < 8; i++) {
        uint32_t topic_hash = fnv1a_32(topics[i], strlen(topics[i]));
        char topic_name[16];
        snprintf(topic_name, sizeof(topic_name), "%08x", topic_hash);
        state->topic_priv_keys[i] = load_ec_key(1, topic_name, 1);

        if (!state->topic_priv_keys[i]) {
            fprintf(stderr, "Failed to load topic private key %s (%s)\n", topics[i], topic_name);
            for (int j = 0; j < i; j++) EVP_PKEY_free(state->topic_priv_keys[j]);
            EVP_PKEY_free(state->ec_key);
            exit(1);
        }
    }
    state->current_slot = 0;
    atomic_store(&state->running, 1);
    atomic_store(&state->timer_active, 0);
    queue_init(&state->mq);
    atomic_store(&state->node_count, 0);
    atomic_store(&state->seq_idx, 0);
    for (int i = 0; i < MAX_SEQUENCES; i++) {
        atomic_store(&state->seqs[i].claimed, 0);
    }
    state->server_addr.sin_family = AF_INET;
    state->server_addr.sin_addr.s_addr = INADDR_ANY;
    state->server_addr.sin_port = htons(PORT);
}

int is_duplicate(ServerState *state, uint32_t node_id, uint32_t seq_no, uint8_t type, struct sockaddr_in *addr) {
    uint64_t current_time = time(NULL);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime((time_t *)&current_time));
    uint32_t hash = (node_id ^ seq_no) % MAX_SEQUENCES;
    for (int i = 0; i < MAX_SEQUENCES; i++) {
        uint32_t idx = (hash + i) % MAX_SEQUENCES;
        if (atomic_load(&state->seqs[idx].claimed)) {
            if (state->seqs[idx].node_id == node_id && state->seqs[idx].seq_no == seq_no) {
                if (current_time - state->seqs[idx].timestamp < 2) {
//                    printf("[%s] Dropped duplicate message from node %u, type=%d, seq=%u, src=%s:%d\n", time_str, node_id, type, seq_no, inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
                    return 1;
                }
            }
        }
    }
    return 0;
}

void record_sequence(ServerState *state, uint32_t node_id, uint32_t seq_no) {
    uint32_t hash = (node_id ^ seq_no) % MAX_SEQUENCES;
    uint32_t idx = atomic_fetch_add(&state->seq_idx, 1) % MAX_SEQUENCES;
    for (int i = 0; i < MAX_SEQUENCES; i++) {
        uint32_t probe = (hash + i) % MAX_SEQUENCES;
        uint32_t expected = 0;
        uint32_t desired = 1;
        if (atomic_load(&state->seqs[probe].claimed) == 0 ||
            time(NULL) - state->seqs[probe].timestamp >= 2) {
            if (atomic_compare_exchange_strong(&state->seqs[probe].claimed, &expected, desired)) {
                state->seqs[probe].node_id = node_id;
                state->seqs[probe].seq_no = seq_no;
                state->seqs[probe].timestamp = time(NULL);
                break;
            }
        }
    }
}

NodeState *find_or_add_node(ServerState *state, struct sockaddr_in *addr, uint32_t node_id, NodeRole role, const char *node_name) {
    uint32_t count = atomic_load(&state->node_count);
    for (size_t i = 0; i < count; i++) {
        if (memcmp(&state->nodes[i].addr, addr, sizeof(*addr)) == 0) {
            return &state->nodes[i];
        }
    }
    if (count >= MAX_NODES) {
        fprintf(stderr, "Error: Max nodes reached\n");
        return NULL;
    }
    uint32_t new_count = count + 1;
    if (atomic_compare_exchange_strong(&state->node_count, &count, new_count)) {
        NodeState *node = &state->nodes[count];
        node->addr = *addr;
        node->node_id = node_id;
        node->role = role;
        node->last_seen = get_time_us();
        strncpy(node->node_name, node_name, MAX_NODE_NAME - 1);
        node->node_name[MAX_NODE_NAME - 1] = '\0';
        printf("%sNode %x added from %s:%d.%s\n", CYAN, node_id, inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), RESET);
        if (new_count == 1 && !atomic_load(&state->timer_active)) {
            struct itimerspec timer_spec = {
                .it_interval = { .tv_sec = 0, .tv_nsec = TIME_SLOT_INTERVAL_US * 1000 },
                .it_value = { .tv_sec = 0, .tv_nsec = TIME_SLOT_INTERVAL_US * 1000 }
            };
            if (timerfd_settime(state->timer_fd, 0, &timer_spec, NULL) < 0) {
                perror("timerfd_settime failed");
                exit(1);
            }
            atomic_store(&state->timer_active, 1);
        }
        return node;
    }
    return find_or_add_node(state, addr, node_id, role, node_name);
}

void subscribe_npg(NodeState *node, uint8_t npg_id) {
    for (int i = 0; i < 32; i++) {
        if (node->subscribed_npgs[i] == 0 || node->subscribed_npgs[i] == npg_id) {
            node->subscribed_npgs[i] = npg_id;
            printf("%sNode %x subscribed to NPG %d.%s\n", CYAN, node->node_id, npg_id, RESET);
            break;
        }
    }
}

void send_to_npg(ServerState *state, const SkyNetMessage *msg, uint64_t recv_time) {
    uint64_t send_time = get_time_us();
    uint8_t buffer[MAX_BUFFER];
    const char *topic = NULL;
    switch (msg->npg_id) {
        case SKYNET_NPG_CONTROL: topic = "npg_control"; break;
        case SKYNET_NPG_PLI: topic = "npg_pli"; break;
        case SKYNET_NPG_SURVEILLANCE: topic = "npg_surveillance"; break;
        case SKYNET_NPG_CHAT: topic = "npg_chat"; break;
        case SKYNET_NPG_C2: topic = "npg_c2"; break;
        case SKYNET_NPG_ALERTS: topic = "npg_alerts"; break;
        case SKYNET_NPG_LOGISTICS: topic = "npg_logistics"; break;
        case SKYNET_NPG_COORD: topic = "npg_coord"; break;
        default: return;
    }

    SkyNetMessage enc_msg = *msg;
    uint32_t topic_hash = fnv1a_32(topic, strlen(topic));
    char topic_name[16];
    snprintf(topic_name, sizeof(topic_name), "%08x", topic_hash);

    if (skynet_encrypt(1, &enc_msg, 0x40ac3dd2, topic_hash, msg->payload, msg->payload_len) < 0) {
        fprintf(stderr, "Failed to encrypt message for NPG %d\n", msg->npg_id);
        return;
    }

    int len = skynet_serialize(&enc_msg, buffer, MAX_BUFFER);
    if (len < 0) return;

    struct sockaddr_in mcast_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
    };
    char mcast_ip[16];
    snprintf(mcast_ip, sizeof(mcast_ip), "239.255.0.%d", msg->npg_id & 0xFF);
    inet_pton(AF_INET, mcast_ip, &mcast_addr.sin_addr);
    if (sendto(state->socket_fd, buffer, len, 0, (struct sockaddr *)&mcast_addr, sizeof(mcast_addr)) < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("sendto failed");
        }
    } else {
        printf("%sMesssage sent from=%x, to=%x, seq=%u, multicast=%s, latency=%lu.%s\n", YELLOW,
               msg->node_id, msg->npg_id, msg->seq_no, mcast_ip, send_time - recv_time, RESET);
        record_sequence(state, msg->node_id, msg->seq_no);
    }
}

void process_control(ServerState *state, NodeState *node, SkyNetMessage *msg, uint64_t recv_time, struct sockaddr_in *addr) {
    if (msg->type == SKYNET_MSG_SLOT_REQUEST) {
        subscribe_npg(node, msg->npg_id);
        if (node->role == NODE_ROLE_DRONE && msg->npg_id == SKYNET_NPG_CONTROL) {
            node->role = NODE_ROLE_CONTROLLER;
            printf("Node %u promoted to swarm controller\n", node->node_id);
        }
    } else if (msg->type == SKYNET_MSG_STATUS) {
        if (msg->payload_len >= 6 * sizeof(float)) {
            memcpy(node->position, msg->payload, sizeof(float) * 3);
            memcpy(node->velocity, msg->payload + 3 * sizeof(float), sizeof(float) * 3);
            node->last_seen = get_time_us();
            printf("%sUpdated PLI for node %u: pos=[%.1f, %.1f, %.1f], vel=[%.1f, %.1f, %.1f].%s\n", CYAN,
                   node->node_id, node->position[0], node->position[1], node->position[2],
                   node->velocity[0], node->velocity[1], node->velocity[2], RESET);
        }
    } else if (msg->type == SKYNET_MSG_KEY_EXCHANGE) {
        if (msg->payload_len < 2 || msg->payload_len > MAX_BUFFER - 1) {
            fprintf(stderr, "Invalid payload length %u for key exchange\n", msg->payload_len);
            return;
        }

        char client_name[16];
        snprintf(client_name, sizeof(client_name), "%08x", msg->node_id);

        if (strlen(client_name) >= MAX_NODE_NAME) {
            fprintf(stderr, "Invalid or too long node name in key exchange\n");
            return;
        }
        if (save_public_key(1, client_name, msg->payload, msg->payload_len) == 0) {
            printf("%sSaved public key for client %s.%s\n", CYAN, client_name, RESET);
            SkyNetMessage response;
            skynet_init(&response, 0x40ac3dd2, msg->node_id, SKYNET_NPG_CONTROL, SKYNET_QOS_C2);
            response.seq_no = state->current_slot;
            BIO *bio = BIO_new(BIO_s_mem());
            if (!bio || !PEM_write_bio_PUBKEY(bio, state->ec_key)) {
                fprintf(stderr, "Failed to write public key to BIO\n");
                BIO_free(bio);
                return;
            }
            char pub_key_data[512];
            long pub_key_len = BIO_read(bio, pub_key_data, sizeof(pub_key_data));
            BIO_free(bio);
            if (pub_key_len <= 0) {
                fprintf(stderr, "Failed to read public key from BIO\n");
                return;
            }
            char to[16];
            char from[16];
            snprintf(from, 16, "%08x", 0x40ac3dd2);
            snprintf(to, 16, "%08x", msg->node_id);
            if (skynet_encrypt(1, &response, 0x40ac3dd2, msg->node_id, "OK", 2) < 0) {
                fprintf(stderr, "Failed to encrypt key exchange response\n");
                return;
            }
            uint8_t buffer[MAX_BUFFER];
            int len = skynet_serialize(&response, buffer, MAX_BUFFER);
            if (len > 0) {
                send_to_npg(state, &response, recv_time);
            }
        }
    }
}

void process_self_healing(ServerState *state) {
    uint64_t now = get_time_us();
    for (size_t i = 0; i < atomic_load(&state->node_count); i++) {
        if (now - state->nodes[i].last_seen > NEIGHBOR_TIMEOUT_US) {
            printf("%sNode %x timed out, removing.%s\n", CYAN, state->nodes[i].node_id, RESET);
            for (size_t j = i; j < atomic_load(&state->node_count) - 1; j++) {
                state->nodes[j] = state->nodes[j + 1];
            }
            atomic_fetch_sub(&state->node_count, 1);
            SkyNetMessage msg;
            skynet_init(&msg, SKYNET_MSG_WAYPOINT, state->node_id, SKYNET_NPG_CONTROL, SKYNET_QOS_C2);
            msg.seq_no = state->current_slot;
            const char *topic = "npg_control";
            uint32_t topic_hash = fnv1a_32(topic, strlen(topic));
            char topic_name[16];
            snprintf(topic_name, sizeof(topic_name), "%08x", topic_hash);
            if (skynet_encrypt(1, &msg, 0x40ac3dd2, topic_hash, NULL, 0) < 0) {
                fprintf(stderr, "Failed to encrypt waypoint message\n");
                return;
            }
            send_to_npg(state, &msg, now);
        }
    }
}

void handle_message(ServerState *state, NodeState *node, SkyNetMessage *msg, uint64_t recv_time, struct sockaddr_in *addr) {

    uint8_t aes_key[32], hmac_key[32];
    node->last_seen = get_time_us();


    fprintf(stderr, "%sMessage received, from=%x, to=%x, size=%u.%s\n", YELLOW, msg->node_id, msg->npg_id, msg->payload_len, RESET);

    const char *topic = NULL;
    switch (msg->npg_id) {
        case SKYNET_NPG_CONTROL: topic = "npg_control"; break;
        case SKYNET_NPG_PLI: topic = "npg_pli"; break;
        case SKYNET_NPG_SURVEILLANCE: topic = "npg_surveillance"; break;
        case SKYNET_NPG_CHAT: topic = "npg_chat"; break;
        case SKYNET_NPG_C2: topic = "npg_c2"; break;
        case SKYNET_NPG_ALERTS: topic = "npg_alerts"; break;
        case SKYNET_NPG_LOGISTICS: topic = "npg_logistics"; break;
        case SKYNET_NPG_COORD: topic = "npg_coord"; break;
        default:
            fprintf(stderr, "Invalid NPG ID %u\n", msg->npg_id);
            return;
    }

    uint32_t server_hash = fnv1a_32("server", strlen("server"));
    uint32_t topic_hash = fnv1a_32(topic, strlen(topic));
    uint32_t to = msg->npg_id;
    uint32_t from = msg->node_id;

    char from_name[16];
    char to_name[16];
    char topic_str[16];

    snprintf(from_name, sizeof(from_name), "%08x", msg->node_id);
    snprintf(to_name, sizeof(to_name), "%08x", msg->npg_id);
    snprintf(topic_str, 16, "%08x", topic_hash);

    if (is_duplicate(state, msg->node_id, msg->seq_no, msg->type, addr)) { return; }

    to = (msg->npg_id == SKYNET_NPG_CONTROL) ? server_hash : topic_hash;

    if (skynet_decrypt(1, msg, to, msg->node_id) < 0) {
        fprintf(stderr, "%s", MAGENTA);
        fprintf(stderr, "Decryption failed (from=%u, to=%u, seq=%u)\n", msg->node_id, to, msg->seq_no);
        hex_dump("SKY HEX DUMP", (const uint8_t *)msg, msg->payload_len);
        fprintf(stderr, "%s", RESET);
        return;
    }

    switch (msg->type) {
        case SKYNET_MSG_PUBLIC:
        case SKYNET_MSG_CHAT:
        case SKYNET_MSG_ACK:
        case SKYNET_MSG_WAYPOINT:
        case SKYNET_MSG_FORMATION:
        case SKYNET_MSG_STATUS:
             msg->node_id = server_hash;
             send_to_npg(state, msg, recv_time);
             break;
        case SKYNET_MSG_KEY_EXCHANGE:
        case SKYNET_MSG_SLOT_REQUEST:
             process_control(state, node, msg, recv_time, addr);
             break;
        default:
             printf("Unsupported message type: %d\n", msg->type);
    }
}

void *worker_thread(void *arg) {
    WorkerState *ws = (WorkerState *)arg;
    ServerState *state = ws->state;
    int worker_id = ws->worker_id;
    int epoll_fd = ws->epoll_fd;
    pin_thread(worker_id);
    struct epoll_event events[MAX_EVENTS];
    while (atomic_load(&state->running)) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno != EINTR) perror("epoll_wait failed");
            continue;
        }
        for (int i = 0; i < nfds; i++) {
            uint64_t count;
            if (read(state->mq.event_fds[worker_id], &count, sizeof(count)) < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    perror("eventfd read failed");
                }
                continue;
            }
            SkyNetMessage msg;
            struct sockaddr_in addr;
            uint64_t recv_time;
            while (queue_dequeue(state, &msg, &addr, &recv_time) == 0) {

                NodeState *node = NULL;
                if (msg.type == SKYNET_MSG_KEY_EXCHANGE || msg.type == SKYNET_MSG_STATUS) {
                    char node_name[16];
                    snprintf(node_name, sizeof(node_name), "%08x", msg.node_id);
                    if (strlen(node_name) >= MAX_NODE_NAME) {
                        fprintf(stderr, "Invalid node name in key exchange message (%zu): %s\n", strlen(node_name), node_name);
                        continue;
                    }
                    node = find_or_add_node(state, &addr, msg.node_id,
                                            msg.type == SKYNET_MSG_STATUS ? NODE_ROLE_DRONE : NODE_ROLE_INFANTRY,
                                            node_name);
                } else {
                    for (uint32_t j = 0; j < atomic_load(&state->node_count); j++) {
                        if (state->nodes[j].node_id == msg.node_id) {
                            node = &state->nodes[j];
                            break;
                        }
                    }
                }

                if (node) { handle_message(state, node, &msg, recv_time, &addr); }
                     else { fprintf(stderr, "%sNo node found for id=%u.%s\n", CYAN, msg.node_id, RESET); }
            }
        }
    }
    close(epoll_fd);
    close(state->mq.event_fds[worker_id]);
    free(ws);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <nodeName>\n", argv[0]);
        return 1;
    }
    const char *node_name2 = argv[1];
    uint32_t hash = fnv1a_32(node_name2, strlen(node_name2));
    char node_name[16];
    snprintf(node_name, sizeof(node_name), "%08x", hash);

    if (strlen(node_name) >= MAX_NODE_NAME) {
        fprintf(stderr, "Node name too long (max %d)\n", MAX_NODE_NAME - 1);
        return 1;
    }

    ServerState state;
    server_init(&state, node_name);
    pin_thread(0);

    state.socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (state.socket_fd < 0) {
        perror("socket creation failed");
        EVP_PKEY_free(state.ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(state.topic_priv_keys[i]);
        return 1;
    }
    if (set_non_blocking(state.socket_fd) < 0) {
        perror("set_non_blocking failed");
        close(state.socket_fd);
        EVP_PKEY_free(state.ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(state.topic_priv_keys[i]);
        return 1;
    }
    int opt = 1;
    if (setsockopt(state.socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR failed");
        close(state.socket_fd);
        EVP_PKEY_free(state.ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(state.topic_priv_keys[i]);
        return 1;
    }
    int buf_size = 1 * 1024 * 1024;
    if (setsockopt(state.socket_fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0 ||
        setsockopt(state.socket_fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) < 0) {
        perror("setsockopt buffer failed");
        close(state.socket_fd);
        EVP_PKEY_free(state.ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(state.topic_priv_keys[i]);
        return 1;
    }
    if (bind(state.socket_fd, (struct sockaddr *)&state.server_addr, sizeof(state.server_addr)) < 0) {
        perror("bind failed");
        close(state.socket_fd);
        EVP_PKEY_free(state.ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(state.topic_priv_keys[i]);
        return 1;
    }
    printf("%sNode %s bound to %s:%d.%s\n", CYAN, node_name, inet_ntoa(state.server_addr.sin_addr), ntohs(state.server_addr.sin_port), RESET);

    uint8_t npgs[] = { SKYNET_NPG_CONTROL, SKYNET_NPG_PLI, SKYNET_NPG_SURVEILLANCE, SKYNET_NPG_CHAT,
                       SKYNET_NPG_C2, SKYNET_NPG_ALERTS, SKYNET_NPG_LOGISTICS, SKYNET_NPG_COORD };
    struct ip_mreq mreq;
    for (size_t i = 0; i < sizeof(npgs) / sizeof(npgs[0]); i++) {
        char mcast_ip[16];
        snprintf(mcast_ip, sizeof(mcast_ip), "239.255.0.%d", npgs[i]);
        inet_pton(AF_INET, mcast_ip, &mreq.imr_multiaddr);
        mreq.imr_interface.s_addr = INADDR_ANY;
        if (setsockopt(state.socket_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            fprintf(stderr, "Failed to join multicast group %s: %s\n", mcast_ip, strerror(errno));
        } else {
            printf("%sJoined multicast group %s.%s\n", CYAN, mcast_ip, RESET);
        }
    }

    state.epoll_fd = epoll_create1(0);
    if (state.epoll_fd < 0) {
        perror("epoll_create1 failed");
        close(state.socket_fd);
        EVP_PKEY_free(state.ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(state.topic_priv_keys[i]);
        return 1;
    }
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = state.socket_fd };
    if (epoll_ctl(state.epoll_fd, EPOLL_CTL_ADD, state.socket_fd, &ev) < 0) {
        perror("epoll_ctl socket failed");
        close(state.epoll_fd);
        close(state.socket_fd);
        EVP_PKEY_free(state.ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(state.topic_priv_keys[i]);
        return 1;
    }

    state.timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (state.timer_fd < 0) {
        perror("timerfd_create failed");
        close(state.epoll_fd);
        close(state.socket_fd);
        EVP_PKEY_free(state.ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(state.topic_priv_keys[i]);
        return 1;
    }
    ev.events = EPOLLIN;
    ev.data.fd = state.timer_fd;
    if (epoll_ctl(state.epoll_fd, EPOLL_CTL_ADD, state.timer_fd, &ev) < 0) {
        perror("epoll_ctl timer failed");
        close(state.timer_fd);
        close(state.epoll_fd);
        close(state.socket_fd);
        EVP_PKEY_free(state.ec_key);
        for (int i = 0; i < 8; i++) EVP_PKEY_free(state.topic_priv_keys[i]);
        return 1;
    }

    for (int i = 0; i < THREAD_COUNT; i++) {
        WorkerState *ws = malloc(sizeof(WorkerState));
        ws->state = &state;
        ws->worker_id = i;
        ws->epoll_fd = epoll_create1(0);
        if (ws->epoll_fd < 0) {
            perror("epoll_create1 worker failed");
            free(ws);
            continue;
        }
        ev.events = EPOLLIN;
        ev.data.fd = state.mq.event_fds[i];
        if (epoll_ctl(ws->epoll_fd, EPOLL_CTL_ADD, state.mq.event_fds[i], &ev) < 0) {
            perror("epoll_ctl eventfd failed");
            close(ws->epoll_fd);
            free(ws);
            continue;
        }
        if (pthread_create(&state.workers[i], NULL, worker_thread, ws) != 0) {
            perror("pthread_create failed");
            close(ws->epoll_fd);
            free(ws);
            continue;
        }
    }

    struct epoll_event events[MAX_EVENTS];
    while (atomic_load(&state.running)) {
        int nfds = epoll_wait(state.epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno != EINTR) perror("epoll_wait main failed");
            continue;
        }
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == state.socket_fd) {
                uint8_t buffer[MAX_BUFFER];
                struct sockaddr_in addr;
                socklen_t addr_len = sizeof(addr);
                ssize_t len = recvfrom(state.socket_fd, buffer, MAX_BUFFER, 0, (struct sockaddr *)&addr, &addr_len);

                if (len < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("recvfrom failed");
                    }
                    continue;
                }

                SkyNetMessage msg;

                if (skynet_deserialize(&msg, buffer, len) < 0) {
                    fprintf(stderr, "Failed to deserialize message from %s:%d\n",
                            inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
                    continue;
                }

                uint64_t recv_time = get_time_us();
                if (queue_enqueue(&state, &msg, &addr, recv_time) < 0) {
                    fprintf(stderr, "Failed to enqueue message from %s:%d\n",
                            inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
                }
            } else if (events[i].data.fd == state.timer_fd) {
                uint64_t expirations;
                if (read(state.timer_fd, &expirations, sizeof(expirations)) < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("timerfd read failed");
                    }
                    continue;
                }
                state.current_slot = (state.current_slot + 1) % SKYNET_MAX_NODES;
                process_self_healing(&state);
            }
        }
    }

    atomic_store(&state.running, 0);
    for (int i = 0; i < THREAD_COUNT; i++) { pthread_join(state.workers[i], NULL); }
    close(state.timer_fd);
    close(state.epoll_fd);
    close(state.socket_fd);
    EVP_PKEY_free(state.ec_key);
    for (int i = 0; i < 8; i++) EVP_PKEY_free(state.topic_priv_keys[i]);
    return 0;
}
