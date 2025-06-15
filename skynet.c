// gcc -o skynet skynet.c skynet_proto.c -lcrypto
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

typedef struct {
    uint32_t current_slot;
    int socket_fd;
    int epoll_fd;
    int timer_fd;
    MessageQueue mq; // Global network queue
    MessageQueue topic_queues[MAX_TOPICS]; // Per-topic queues
    pthread_t workers[THREAD_COUNT];
    atomic_int running;
    struct sockaddr_in server_addr;
    EVP_PKEY *ec_key;
    EVP_PKEY *topic_priv_keys[MAX_TOPICS];
    char server_name[MAX_NODE_NAME];
    uint32_t node_id;
    uint32_t slots[SLOT_COUNT]; // Slot assignments (node_id or 0)
    uint32_t slot_count; // Number of assigned slots
    struct { // Deduplication cache
        uint32_t node_id;
        uint32_t seq_no;
        uint64_t timestamp;
    } seq_cache[SEQ_CACHE_SIZE];
} ServerState;

typedef struct {
    ServerState *state;
    int worker_id;
    int epoll_fd;
} WorkerState;

static uint8_t npg_ids[MAX_TOPICS] = {
    SKYNET_NPG_CONTROL, SKYNET_NPG_PLI, SKYNET_NPG_SURVEILLANCE, SKYNET_NPG_CHAT,
    SKYNET_NPG_C2, SKYNET_NPG_ALERTS, SKYNET_NPG_LOGISTICS, SKYNET_NPG_COORD
};

static char *topic_names[MAX_TOPICS] = {
    "npg_control", "npg_pli", "npg_surveillance", "npg_chat",
    "npg_c2", "npg_alerts", "npg_logistics", "npg_coord"
};

// Queue initialization
void queue_init(MessageQueue *q) {
    atomic_store(&q->head, 0);
    atomic_store(&q->tail, 0);
    for (int i = 0; i < THREAD_COUNT; i++) {
        q->event_fds[i] = -1; // Initialize to invalid
        q->event_fds[i] = eventfd(0, EFD_NONBLOCK);
        if (q->event_fds[i] < 0) {
            perror("eventfd creation failed");
            for (int j = 0; j < i; j++) {
                if (q->event_fds[j] >= 0) close(q->event_fds[j]);
            }
            exit(1);
        }
    }
}

// Enqueue
int queue_enqueue(MessageQueue *q, const SkyNetMessage *msg, const struct sockaddr_in *addr, uint64_t recv_time) {
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
        if (q->event_fds[i] >= 0) {
            if (write(q->event_fds[i], &signal, sizeof(signal)) < 0) {
                perror("eventfd write failed");
            }
        }
    }
    return 0;
}

// Dequeue
int queue_dequeue(MessageQueue *q, SkyNetMessage *msg, struct sockaddr_in *addr, uint64_t *recv_time) {
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

// Pin thread to core
void pin_thread(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) < 0) {
        perror("pthread_setaffinity_np failed");
    }
}

// Server initialization
void server_init(ServerState *state, char *node_name) {
    memset(state, 0, sizeof(ServerState));
    strncpy(state->server_name, node_name, MAX_NODE_NAME - 1);
    state->server_name[MAX_NODE_NAME - 1] = '\0';
    state->node_id = fnv1a_32(node_name, strlen(node_name));

    uint32_t hash = fnv1a_32(node_name, strlen(node_name));
    char node_hash[16];
    snprintf(node_hash, 16, "%08x", hash);

    state->ec_key = load_ec_key(1, node_hash, 1);
    if (!state->ec_key) {
        fprintf(stderr, "Failed to load server private key for %s\n", node_hash);
        exit(1);
    }

    for (int i = 0; i < MAX_TOPICS; i++) {

        uint32_t topic_hash = fnv1a_32(topic_names[i], strlen(topic_names[i]));
        char topic_name[16];
        snprintf(topic_name, sizeof(topic_name), "%08x", topic_hash);
        state->topic_priv_keys[i] = load_ec_key(1, topic_name, 1);

        if (!state->topic_priv_keys[i]) {
            fprintf(stderr, "Failed to load topic private key %s\n", topic_names[i]);
            EVP_PKEY_free(state->ec_key);
            for (int j = 0; j < i; j++) EVP_PKEY_free(state->topic_priv_keys[j]);
            exit(1);
        }

        printf("%sInitializing topic queue %d=%s (%x).%s\n", CYAN, i, topic_names[i], topic_hash, RESET);

        queue_init(&state->topic_queues[i]);
    }

    state->current_slot = 0;
    state->slot_count = 0;
    memset(state->slots, 0, sizeof(state->slots));
    memset(state->seq_cache, 0, sizeof(state->seq_cache));
    atomic_store(&state->running, 1);
    printf("%sInitializing local queue 0=%s (%x).%s\n", CYAN, state->server_name, state->node_id, RESET);
    queue_init(&state->mq);
    state->server_addr.sin_family = AF_INET;
    state->server_addr.sin_addr.s_addr = INADDR_ANY;
    state->server_addr.sin_port = htons(PORT);
}

// Check for duplicate message
int is_duplicate(ServerState *state, uint32_t node_id, uint32_t seq_no) {
    uint64_t now = get_time_us();
    uint32_t hash = fnv1a_32(&node_id, sizeof(node_id)) ^ fnv1a_32(&seq_no, sizeof(seq_no));
    uint32_t idx = hash % SEQ_CACHE_SIZE;
    if (state->seq_cache[idx].node_id == node_id && state->seq_cache[idx].seq_no == seq_no &&
        now - state->seq_cache[idx].timestamp < 1000000) {
        return 1;
    }
    state->seq_cache[idx].node_id = node_id;
    state->seq_cache[idx].seq_no = seq_no;
    state->seq_cache[idx].timestamp = now;
    return 0;
}

// Assign slot to node
int assign_slot(ServerState *state, uint32_t node_id) {
    if (state->slot_count >= SLOT_COUNT) {
        fprintf(stderr, "No free slots available\n");
        return -1;
    }
    for (uint32_t i = 0; i < SLOT_COUNT; i++) {
        if (state->slots[i] == 0) {
            state->slots[i] = node_id;
            state->slot_count++;
            printf("%sAssigned slot %d to node %08x.%s\n", CYAN, i, node_id, RESET);
            return i;
        }
    }
    return -1;
}

// Send message to multicast group (supports dynamic topics)
void send_to_npg(ServerState *state, const SkyNetMessage *msg, uint64_t recv_time, int slot_id) {
    uint64_t send_time = get_time_us();
    uint8_t buffer[MAX_BUFFER];
    int topic_idx = -1;
    if (slot_id >= 0) {
        topic_idx = -1;
    } else {
        for (int i = 0; i < MAX_TOPICS; i++) {
            if (npg_ids[i] == msg->npg_id) {
                topic_idx = i;
                break;
            }
        }
        if (topic_idx < 0) {
            fprintf(stderr, "Invalid NPG ID %u\n", msg->npg_id);
            return;
        }
    }

    SkyNetMessage enc_msg = *msg;
    uint32_t topic_hash = (topic_idx >= 0) ? fnv1a_32(topic_names[topic_idx], strlen(topic_names[topic_idx])) : msg->node_id;
    if (skynet_encrypt(1, &enc_msg, state->node_id, topic_hash, msg->payload, msg->payload_len) < 0) {
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
    if (slot_id >= 0) {
        snprintf(mcast_ip, sizeof(mcast_ip), "239.255.1.%d", slot_id % 256);
    } else {
        snprintf(mcast_ip, sizeof(mcast_ip), "239.255.0.%d", msg->npg_id & 0xFF);
    }
    inet_pton(AF_INET, mcast_ip, &mcast_addr.sin_addr);
    if (sendto(state->socket_fd, buffer, len, 0, (struct sockaddr *)&mcast_addr, sizeof(mcast_addr)) < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("sendto failed");
        }
    } else {
        printf("%sMessage sent from=%x, to=%x, seq=%u, multicast=%s, latency=%lu.%s\n", YELLOW,
               msg->node_id, msg->npg_id, msg->seq_no, mcast_ip, send_time - recv_time, RESET);
    }
}

// Process message
void process_message(ServerState *state, SkyNetMessage *msg, struct sockaddr_in *addr, uint64_t recv_time) {
    if (msg->node_id == state->node_id) {
        printf("Skipping self-sent message from=%x, to=%x, seq=%u\n", msg->node_id, msg->npg_id, msg->seq_no);
        return;
    }

    if (is_duplicate(state, msg->node_id, msg->seq_no)) {
        fprintf(stderr, "Duplicate message from %x, seq=%u\n", msg->node_id, msg->seq_no);
        return;
    }

    fprintf(stderr, "%sMessage received, from=%x, to=%x, size=%u.%s\n", YELLOW, msg->node_id, msg->npg_id, msg->payload_len, RESET);

    int topic_idx = 0; // Default to SKYNET_NPG_CONTROL
    if (msg->npg_id != SKYNET_NPG_CONTROL) {
        for (int i = 0; i < MAX_TOPICS; i++) {
            if (npg_ids[i] == msg->npg_id) {
                topic_idx = i;
                break;
            }
        }
        if (topic_idx == 0 && msg->npg_id != SKYNET_NPG_CONTROL) {
            fprintf(stderr, "Invalid NPG ID %u\n", msg->npg_id);
            return;
        }
    }

    uint32_t topic_hash = (topic_idx >= 0) ? fnv1a_32(topic_names[topic_idx], strlen(topic_names[topic_idx])) : state->node_id;
    uint32_t to = (msg->npg_id == SKYNET_NPG_CONTROL) ? state->node_id : topic_hash;

    if (skynet_decrypt(1, msg, to, msg->node_id) < 0) {
        fprintf(stderr, "Decryption failed (from=%u, to=%u, seq=%u)\n", msg->node_id, to, msg->seq_no);
        return;
    }

    if (msg->type == SKYNET_MSG_KEY_EXCHANGE) {
        if (msg->payload_len < 2 || msg->payload_len > MAX_BUFFER - 1) {
            fprintf(stderr, "Invalid payload length %u for key exchange\n", msg->payload_len);
            return;
        }
        char client_name[16];
        snprintf(client_name, sizeof(client_name), "%08x", msg->node_id);
        if (save_public_key(1, client_name, msg->payload, msg->payload_len) == 0) {
            printf("%sSaved public key for client %s.%s\n", CYAN, client_name, RESET);
            SkyNetMessage response;
            skynet_init(&response, SKYNET_MSG_KEY_EXCHANGE, state->node_id, SKYNET_NPG_CONTROL, SKYNET_QOS_C2);
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
            if (skynet_encrypt(1, &response, state->node_id, msg->node_id, (uint8_t *)pub_key_data, pub_key_len) < 0) {
                fprintf(stderr, "Failed to encrypt key exchange response\n");
                return;
            }
            queue_enqueue(&state->topic_queues[topic_idx], &response, addr, recv_time);
        }
    } else if (msg->type == SKYNET_MSG_SLOT_REQUEST) {
        int slot_id = assign_slot(state, msg->node_id);
        if (slot_id >= 0) {
            SkyNetMessage response;
            skynet_init(&response, SKYNET_MSG_ACK, state->node_id, SKYNET_NPG_CONTROL, SKYNET_QOS_C2);
            response.seq_no = state->current_slot;
            uint8_t slot_data[4];
            memcpy(slot_data, &slot_id, 4);
            if (skynet_encrypt(1, &response, state->node_id, msg->node_id, slot_data, 4) < 0) {
                fprintf(stderr, "Failed to encrypt slot response\n");
                return;
            }
            queue_enqueue(&state->topic_queues[topic_idx], &response, addr, recv_time);
            printf("%sAssigned slot %d to node %x.%s\n", CYAN, slot_id, msg->node_id, RESET);
        } else {
            fprintf(stderr, "No slots available for node %x\n", msg->node_id);
        }
    } else {
        int slot_id = -1;
        for (uint32_t i = 0; i < SLOT_COUNT; i++) {
            if (state->slots[i] == msg->node_id) {
                slot_id = i;
                break;
            }
        }
        if (msg->npg_id != SKYNET_NPG_CONTROL) {
            queue_enqueue(&state->topic_queues[topic_idx], msg, addr, recv_time);
        }
        send_to_npg(state, msg, recv_time, slot_id);
    }
}

// Worker thread
void *worker_thread(void *arg) {
    WorkerState *ws = (WorkerState *)arg;
    ServerState *state = ws->state;
    int worker_id = ws->worker_id;
    int epoll_fd = ws->epoll_fd;
    pin_thread(worker_id);
    struct epoll_event events[32];
    while (atomic_load(&state->running)) {
        int nfds = epoll_wait(epoll_fd, events, 32, -1);
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
            while (queue_dequeue(&state->mq, &msg, &addr, &recv_time) == 0) {
                process_message(state, &msg, &addr, recv_time);
            }
        }
        for (int i = 0; i < MAX_TOPICS; i++) {
            SkyNetMessage msg;
            struct sockaddr_in addr;
            uint64_t recv_time;
            while (queue_dequeue(&state->topic_queues[i], &msg, &addr, &recv_time) == 0) {
                int slot_id = -1;
                for (uint32_t j = 0; j < SLOT_COUNT; j++) {
                    if (state->slots[j] == msg.node_id) {
                        slot_id = j;
                        break;
                    }
                }
                send_to_npg(state, &msg, recv_time, slot_id);
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
    char *node_name = argv[1];
    if (strlen(node_name) >= MAX_NODE_NAME) {
        fprintf(stderr, "Node name too long (max %d)\n", MAX_NODE_NAME - 1);
        return 1;
    }

    ServerState *state = malloc(sizeof(ServerState));
    if (!state) {
        perror("Failed to allocate ServerState");
        return 1;
    }

    server_init(state, node_name);
    pin_thread(0);

    state->socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (state->socket_fd < 0) {
        perror("socket creation failed");
        goto cleanup;
    }
    if (set_non_blocking(state->socket_fd) < 0) {
        perror("set_non_blocking failed");
        goto cleanup;
    }
    int opt = 1;
    if (setsockopt(state->socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR failed");
        goto cleanup;
    }
    if (bind(state->socket_fd, (struct sockaddr *)&state->server_addr, sizeof(state->server_addr)) < 0) {
        perror("bind failed");
        goto cleanup;
    }

    struct ip_mreq mreq;
    for (int i = 0; i < MAX_TOPICS; i++) {
        char mcast_ip[16];
        snprintf(mcast_ip, sizeof(mcast_ip), "239.255.0.%d", npg_ids[i]);
        inet_pton(AF_INET, mcast_ip, &mreq.imr_multiaddr);
        mreq.imr_interface.s_addr = INADDR_ANY;
        if (setsockopt(state->socket_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            fprintf(stderr, "Failed to join multicast group %s: %s\n", mcast_ip, strerror(errno));
        } else {
            printf("%sJoined multicast group %s.%s\n", CYAN, mcast_ip, RESET);
        }
    }

    state->epoll_fd = epoll_create1(0);
    if (state->epoll_fd < 0) {
        perror("epoll_create1 failed");
        goto cleanup;
    }
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = state->socket_fd };
    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, state->socket_fd, &ev) < 0) {
        perror("epoll_ctl socket failed");
        goto cleanup;
    }

    state->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (state->timer_fd < 0) {
        perror("timerfd_create failed");
        goto cleanup;
    }
    struct itimerspec timer_spec = {
        .it_interval = { .tv_sec = 0, .tv_nsec = TIME_SLOT_INTERVAL_US * 1000 },
        .it_value = { .tv_sec = 0, .tv_nsec = TIME_SLOT_INTERVAL_US * 1000 }
    };
    if (timerfd_settime(state->timer_fd, 0, &timer_spec, NULL) < 0) {
        perror("timerfd_settime failed");
        goto cleanup;
    }
    ev.events = EPOLLIN;
    ev.data.fd = state->timer_fd;
    if (epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, state->timer_fd, &ev) < 0) {
        perror("epoll_ctl timer failed");
        goto cleanup;
    }


    printf("%sNode %s bound to %s:%d.%s\n", CYAN, node_name, inet_ntoa(state->server_addr.sin_addr), ntohs(state->server_addr.sin_port), RESET);

    for (int i = 0; i < THREAD_COUNT; i++) {
        WorkerState *ws = malloc(sizeof(WorkerState));
        if (!ws) {
            perror("Failed to allocate WorkerState");
            continue;
        }
        ws->state = state;
        ws->worker_id = i;
        ws->epoll_fd = epoll_create1(0);
        if (ws->epoll_fd < 0) {
            perror("epoll_create1 worker failed");
            free(ws);
            continue;
        }
        ev.events = EPOLLIN;
        ev.data.fd = state->mq.event_fds[i];
        if (epoll_ctl(ws->epoll_fd, EPOLL_CTL_ADD, state->mq.event_fds[i], &ev) < 0) {
            perror("epoll_ctl eventfd failed");
            close(ws->epoll_fd);
            free(ws);
            continue;
        }
        if (pthread_create(&state->workers[i], NULL, worker_thread, ws) != 0) {
            perror("pthread_create failed");
            close(ws->epoll_fd);
            free(ws);
            continue;
        }
    }

    struct epoll_event events[32];
    while (atomic_load(&state->running)) {
        int nfds = epoll_wait(state->epoll_fd, events, 32, -1);
        if (nfds < 0) {
            if (errno != EINTR) perror("epoll_wait main failed");
            continue;
        }
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == state->socket_fd) {
                uint8_t buffer[MAX_BUFFER];
                struct sockaddr_in addr;
                socklen_t addr_len = sizeof(addr);
                ssize_t len = recvfrom(state->socket_fd, buffer, MAX_BUFFER, 0, (struct sockaddr *)&addr, &addr_len);
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
                if (queue_enqueue(&state->mq, &msg, &addr, recv_time) < 0) {
                    fprintf(stderr, "Failed to enqueue message from %s:%d\n",
                            inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
                }
            } else if (events[i].data.fd == state->timer_fd) {
                uint64_t expirations;
                if (read(state->timer_fd, &expirations, sizeof(expirations)) < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("timerfd read failed");
                    }
                    continue;
                }
                state->current_slot = (state->current_slot + 1) % SKYNET_MAX_NODES;
            }
        }
    }

cleanup:
    atomic_store(&state->running, 0);
    for (int i = 0; i < THREAD_COUNT; i++) {
        if (state->workers[i]) pthread_join(state->workers[i], NULL);
    }
    if (state->timer_fd >= 0) close(state->timer_fd);
    if (state->epoll_fd >= 0) close(state->epoll_fd);
    if (state->socket_fd >= 0) close(state->socket_fd);
    if (state->ec_key) EVP_PKEY_free(state->ec_key);
    for (int i = 0; i < MAX_TOPICS; i++) {
        if (state->topic_priv_keys[i]) EVP_PKEY_free(state->topic_priv_keys[i]);
    }
    for (int i = 0; i < THREAD_COUNT; i++) {
        if (state->mq.event_fds[i] >= 0) close(state->mq.event_fds[i]);
    }
    for (int i = 0; i < MAX_TOPICS; i++) {
        for (int j = 0; j < THREAD_COUNT; j++) {
            if (state->topic_queues[i].event_fds[j] >= 0) close(state->topic_queues[i].event_fds[j]);
        }
    }
    free(state);
    return 0;
}
