// gcc -o skynet skynet.c skynet_proto.c skynet_conv.c -pthread -lcrypto
// skynet server

#define _POSIX_C_SOURCE 200809L

#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _GNU_SOURCE
#include <sched.h> // For CPU_ZERO, CPU_SET, etc. on Linux
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <net/if.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#ifdef __APPLE__
#include <sys/event.h>
#include <sys/time.h>
#else
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>
#endif
#include "skynet.h"
#include "skynet_conv.h"

typedef struct {
    uint32_t current_slot;
    int socket_fd;
#ifdef __APPLE__
    int kqueue_fd;
    int timer_id; // For kqueue timer
#else
    int epoll_fd;
    int timer_fd; // For timerfd
#endif
    MessageQueue mq;
    MessageQueue topic_queues[MAX_TOPICS];
    pthread_t workers[THREAD_COUNT];
    atomic_int running;
    struct sockaddr_in server_addr;
    EVP_PKEY *ec_key;
    EVP_PKEY *topic_priv_keys[MAX_TOPICS];
    char server_name[MAX_NODE_NAME];
    uint32_t node_id;
    uint32_t slots[SLOT_COUNT];
    uint32_t slot_count;
    struct {
        uint32_t node_id;
        uint32_t seq_no;
        uint64_t timestamp;
    } seq_cache[SEQ_CACHE_SIZE];
    QoSSlotAssignment qos_slots[MAX_TOPICS];
    uint32_t qos_slot_count;
    NodeRole role;
    bool slots_assigned;
} ServerState;

typedef struct {
    ServerState *state;
    int worker_id;
#ifdef __APPLE__
    int kqueue_fd;
#else
    int epoll_fd;
#endif
} WorkerState;

static uint8_t npg_ids[MAX_TOPICS] = {
    SKYNET_NPG_CONTROL, SKYNET_NPG_PLI, SKYNET_NPG_SURVEILLANCE, SKYNET_NPG_CHAT,
    SKYNET_NPG_C2, SKYNET_NPG_ALERTS, SKYNET_NPG_LOGISTICS, SKYNET_NPG_COORD
};

static char *topic_names[MAX_TOPICS] = {
    "npg_control", "npg_pli", "npg_surveillance", "npg_chat",
    "npg_c2", "npg_alerts", "npg_logistics", "npg_coord"
};

void queue_init(MessageQueue *q) {
    atomic_store(&q->head, 0);
    atomic_store(&q->tail, 0);
    for (int i = 0; i < THREAD_COUNT; i++) {
#ifdef __APPLE__
        int pipefd[2];
        if (pipe(pipefd) < 0) {
            perror("pipe creation failed");
            exit(1);
        }
        q->event_fds[i] = pipefd[0];
        q->event_fds_write[i] = pipefd[1];
        if (fcntl(q->event_fds[i], F_SETFL, O_NONBLOCK) < 0 ||
            fcntl(q->event_fds_write[i], F_SETFL, O_NONBLOCK) < 0) {
            perror("fcntl non-blocking failed");
            exit(1);
        }
#else
        q->event_fds[i] = eventfd(0, EFD_NONBLOCK);
        if (q->event_fds[i] < 0) {
            perror("eventfd creation failed");
            exit(1);
        }
#endif
    }
}

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
#ifdef __APPLE__
        if (q->event_fds_write[i] >= 0) {
            if (write(q->event_fds_write[i], &signal, sizeof(signal)) < 0) {
                perror("pipe write failed");
            }
        }
#else
        if (q->event_fds[i] >= 0) {
            if (write(q->event_fds[i], &signal, sizeof(signal)) < 0) {
                perror("eventfd write failed");
            }
        }
#endif
    }
    return 0;
}

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

void pin_thread(int core_id) {
#ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) < 0) {
        perror("pthread_setaffinity_np failed");
    }
#else
    (void)core_id;
#endif
}

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

    state->qos_slot_count = 0;
    for (int i = 0; i < MAX_TOPICS; i++) {
        uint8_t qos = (npg_ids[i] == SKYNET_NPG_C2) ? SKYNET_QOS_C2 :
                      (npg_ids[i] == SKYNET_NPG_PLI) ? SKYNET_QOS_PLI :
                      (npg_ids[i] == SKYNET_NPG_CONTROL) ? SKYNET_QOS_C2 :
                      SKYNET_QOS_CHAT;
        state->qos_slots[i].npg_id = npg_ids[i];
        state->qos_slots[i].qos = qos;
        state->qos_slots[i].priority = (qos == SKYNET_QOS_C2) ? 1 :
                                      (qos == SKYNET_QOS_VOICE) ? 5 :
                                      (qos == SKYNET_QOS_PLI) ? 10 : 15;
        state->qos_slots[i].slot_count = (qos == SKYNET_QOS_C2) ? 3 :
                                        (qos == SKYNET_QOS_PLI) ? 2 : 1;
        state->qos_slot_count++;
    }
    state->role = NODE_ROLE_CONTROLLER;
    state->slots_assigned = false;

    if (state->role == NODE_ROLE_CONTROLLER) {
        for (uint32_t i = 0; i < SLOT_COUNT; i++) {
            state->slots[i] = i + 1;
        }
        skynet_convergence_schedule_slots_qos(state->qos_slots, state->slots, state->qos_slot_count, SLOT_COUNT);
        state->slots_assigned = true;
        for (uint32_t i = 0; i < state->qos_slot_count; i++) {
            printf("%sAssigned %u slots to NPG %u (QoS %u).%s\n", CYAN,
                   state->qos_slots[i].slot_count, state->qos_slots[i].npg_id, state->qos_slots[i].qos, RESET);
        }
    }
}

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

void send_to_npg(ServerState *state, const SkyNetMessage *msg, uint64_t recv_time) {
    uint64_t send_time = get_time_us();
    uint8_t buffer[MAX_BUFFER];
    int topic_idx = -1;
    uint32_t slot_id = -1;

    for (uint32_t i = 0; i < state->qos_slot_count; i++) {
        if (state->qos_slots[i].npg_id == msg->npg_id) {
            if (state->qos_slots[i].slot_count > 0) {
                slot_id = state->qos_slots[i].slot_ids[state->current_slot % state->qos_slots[i].slot_count];
            }
            topic_idx = i;
            break;
        }
    }
    if (topic_idx < 0) {
        fprintf(stderr, "Invalid NPG ID %u\n", msg->npg_id);
        return;
    }

    SkyNetMessage enc_msg = *msg;
    uint32_t topic_hash = fnv1a_32(topic_names[topic_idx], strlen(topic_names[topic_idx]));
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
    if (slot_id != -1) {
        snprintf(mcast_ip, sizeof(mcast_ip), "239.255.1.%d", slot_id % 256);
    } else {
        snprintf(mcast_ip, sizeof(mcast_ip), "239.255.0.%d", msg->npg_id & 0xFF);
    }
    if (inet_pton(AF_INET, mcast_ip, &mcast_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid multicast address %s\n", mcast_ip);
        return;
    }
    if (sendto(state->socket_fd, buffer, len, 0, (struct sockaddr *)&mcast_addr, sizeof(mcast_addr)) < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("sendto failed");
        }
    } else {
        printf("%sMessage sent from=%x, to=%x, seq=%u, multicast=%s, latency=%llu.%s\n", YELLOW,
               msg->node_id, msg->npg_id, msg->seq_no, mcast_ip, (unsigned long long)(send_time - recv_time), RESET);
    }
}

void process_message(ServerState *state, SkyNetMessage *msg, struct sockaddr_in *addr, uint64_t recv_time) {
    if (msg->node_id == state->node_id) {
        printf("%sSkipping self-sent message from=%x, to=%x, seq=%u.%s\n", CYAN,
               msg->node_id, msg->npg_id, msg->seq_no, RESET);
        return;
    }

    if (is_duplicate(state, msg->node_id, msg->seq_no)) {
        fprintf(stderr, "Duplicate message: node_id=%x, seq_no=%u\n", msg->node_id, msg->seq_no);
        return;
    }

    int topic_idx = 0;
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

    uint32_t topic_hash = fnv1a_32(topic_names[topic_idx], strlen(topic_names[topic_idx]));
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
            uint8_t pub_key_data[512];
            long pub_key_len = BIO_read(bio, pub_key_data, sizeof(pub_key_data));
            BIO_free(bio);
            if (pub_key_len <= 0) {
                fprintf(stderr, "Failed to read public key from BIO\n");
                return;
            }
            if (skynet_encrypt(1, &response, state->node_id, msg->node_id, pub_key_data, pub_key_len) < 0) {
                fprintf(stderr, "Failed to encrypt key exchange response\n");
                return;
            }
            queue_enqueue(&state->topic_queues[topic_idx], &response, addr, recv_time);
        }
    } else if (msg->type == SKYNET_MSG_SLOT_REQUEST) {
        uint32_t npg_id = msg->npg_id;
        uint8_t qos = msg->qos;
        bool slot_found = false;
        for (uint32_t i = 0; i < state->qos_slot_count; i++) {
            if (state->qos_slots[i].npg_id == npg_id && state->qos_slots[i].qos == qos) {
                SkyNetMessage response;
                skynet_init(&response, SKYNET_MSG_ACK, state->node_id, SKYNET_NPG_CONTROL, SKYNET_QOS_C2);
                response.seq_no = state->current_slot;
                uint8_t slot_data[4];
                memcpy(slot_data, &state->qos_slots[i].slot_ids[0], 4);
                if (skynet_encrypt(1, &response, state->node_id, msg->node_id, slot_data, 4) < 0) {
                    fprintf(stderr, "Failed to encrypt slot response\n");
                    return;
                }
                queue_enqueue(&state->topic_queues[0], &response, addr, recv_time);
                printf("%sAssigned slot %u to NPG %u (QoS %u) for node %u.%s\n", CYAN,
                       state->qos_slots[i].slot_ids[0], npg_id, qos, msg->node_id, RESET);
                slot_found = true;
                break;
            }
        }
        if (!slot_found && state->role == NODE_ROLE_CONTROLLER) {
            for (uint32_t i = 0; i < state->qos_slot_count; i++) {
                state->qos_slots[i].slot_count = (state->qos_slots[i].qos == SKYNET_QOS_C2) ? 3 :
                                                (state->qos_slots[i].qos == SKYNET_QOS_PLI) ? 2 : 1;
            }
            skynet_convergence_schedule_slots_qos(state->qos_slots, state->slots, state->qos_slot_count, SLOT_COUNT);
            for (uint32_t i = 0; i < state->qos_slot_count; i++) {
                printf("%sRe-assigned %u slots to NPG %u (QoS %u) for node %u.%s\n", CYAN,
                       state->qos_slots[i].slot_count, state->qos_slots[i].npg_id, state->qos_slots[i].qos, msg->node_id, RESET);
            }
            for (uint32_t i = 0; i < state->qos_slot_count; i++) {
                if (state->qos_slots[i].npg_id == npg_id && state->qos_slots[i].qos == qos) {
                    SkyNetMessage response;
                    skynet_init(&response, SKYNET_MSG_ACK, state->node_id, SKYNET_NPG_CONTROL, SKYNET_QOS_C2);
                    response.seq_no = state->current_slot;
                    uint8_t slot_data[4];
                    memcpy(slot_data, &state->qos_slots[i].slot_ids[0], 4);
                    if (skynet_encrypt(1, &response, state->node_id, msg->node_id, slot_data, 4) < 0) {
                        fprintf(stderr, "Failed to encrypt slot response\n");
                        return;
                    }
                    queue_enqueue(&state->topic_queues[0], &response, addr, recv_time);
                    printf("%sAssigned slot %u to NPG %u (QoS %u) for node %u.%s\n", CYAN,
                           state->qos_slots[i].slot_ids[0], npg_id, qos, msg->node_id, RESET);
                    break;
                }
            }
        }
        if (!slot_found) {
            fprintf(stderr, "No slot for NPG %u (QoS %u)\n", npg_id, qos);
        }
    } else {
        queue_enqueue(&state->topic_queues[topic_idx], msg, addr, recv_time);
        send_to_npg(state, msg, recv_time);
    }
}

void *worker_thread(void *arg) {
    WorkerState *ws = (WorkerState *)arg;
    ServerState *state = ws->state;
    int worker_id = ws->worker_id;
    printf("%sWorker thread %d started.%s\n", CYAN, ws->worker_id, RESET);

#ifdef __APPLE__
    int kq = kqueue();
    if (kq < 0) {
        perror("kqueue failed");
        free(ws);
        return NULL;
    }
    ws->kqueue_fd = kq;

    struct kevent ev;
    EV_SET(&ev, state->mq.event_fds[worker_id], EVFILT_READ, EV_ADD, 0, 0, NULL);
    if (kevent(kq, &ev, 1, NULL, 0, NULL) < 0) {
        perror("kevent add failed");
        close(kq);
        free(ws);
        return NULL;
    }

    struct kevent events[32];
    while (atomic_load(&state->running)) {
        int nfds = kevent(kq, NULL, 0, events, 32, NULL);
        if (nfds < 0) {
            if (errno != EINTR) perror("kevent wait failed");
            continue;
        }
        for (int i = 0; i < nfds; i++) {
            if (events[i].filter == EVFILT_READ && events[i].ident == (uintptr_t)state->mq.event_fds[worker_id]) {
                uint64_t count;
                if (read(state->mq.event_fds[worker_id], &count, sizeof(count)) < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("pipe read failed");
                    }
                    continue;
                }
                SkyNetMessage msg;
                struct sockaddr_in addr;
                uint64_t recv_time;
                while (queue_dequeue(&state->mq, &msg, &addr, &recv_time) == 0) {
                    process_message(state, &msg, &addr, recv_time);
                }
                for (int j = 0; j < MAX_TOPICS; j++) {
                    while (queue_dequeue(&state->topic_queues[j], &msg, &addr, &recv_time) == 0) {
                        send_to_npg(state, &msg, recv_time);
                    }
                }
            }
        }
    }
    close(kq);
#else
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1 failed");
        free(ws);
        return NULL;
    }
    ws->epoll_fd = epoll_fd;

    struct epoll_event ev = { .events = EPOLLIN, .data.fd = state->mq.event_fds[worker_id] };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, state->mq.event_fds[worker_id], &ev) < 0) {
        perror("epoll_ctl eventfd failed");
        close(epoll_fd);
        free(ws);
        return NULL;
    }

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
            for (int j = 0; j < MAX_TOPICS; j++) {
                while (queue_dequeue(&state->topic_queues[j], &msg, &addr, &recv_time) == 0) {
                    send_to_npg(state, &msg, recv_time);
                }
            }
        }
    }
    close(epoll_fd);
#endif
    close(state->mq.event_fds[worker_id]);
#ifdef __APPLE__
    close(state->mq.event_fds_write[worker_id]);
#endif
    free(ws);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <node_name>\n", argv[0]);
        return 1;
    }
    char *node_name = argv[1];
    if (strlen(node_name) >= MAX_NODE_NAME) {
        fprintf(stderr, "Node name too long (max %d)\n", MAX_NODE_NAME - 1);
        return 1;
    }

    ServerState *state = malloc(sizeof(ServerState));
    if (!state) {
        perror("malloc failed");
        return 1;
    }

    server_init(state, node_name);
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
    memset(&mreq, 0, sizeof(mreq)); // Initialize to avoid undefined behavior
    for (int i = 0; i < MAX_TOPICS; i++) {
        char mcast_ip[16];
        snprintf(mcast_ip, sizeof(mcast_ip), "239.255.0.%d", npg_ids[i]);
        if (inet_pton(AF_INET, mcast_ip, &mreq.imr_multiaddr) <= 0) {
            fprintf(stderr, "Invalid multicast address %s\n", mcast_ip);
            continue;
        }
        mreq.imr_interface.s_addr = INADDR_ANY;
        int loop=0;
        if (setsockopt(state->socket_fd, IPPROTO_IP, IP_MULTICAST_IF, &loop, sizeof(loop)) < 0) {
            fprintf(stderr, "Failed disabling multicast.\n");
        }
        if (setsockopt(state->socket_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            fprintf(stderr, "Failed to join multicast group %s: %s\n", mcast_ip, strerror(errno));
        } else {
            printf("%sJoined multicast group %s.%s\n", CYAN, mcast_ip, RESET);
        }
    }

#ifdef __APPLE__
    state->kqueue_fd = kqueue();
    if (state->kqueue_fd < 0) {
        perror("kqueue failed");
        goto cleanup;
    }

    struct kevent ev[2];
    EV_SET(&ev[0], state->socket_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    state->timer_id = 1; // Unique identifier for timer
    EV_SET(&ev[1], state->timer_id, EVFILT_TIMER, EV_ADD, 0, TIME_SLOT_INTERVAL_US / 1000, NULL); // Timer in milliseconds
    if (kevent(state->kqueue_fd, ev, 2, NULL, 0, NULL) < 0) {
        perror("kevent add failed");
        goto cleanup;
    }
#else
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
        perror("epoll_ctl timerfd failed");
        goto cleanup;
    }
#endif

    char addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &state->server_addr.sin_addr, addr_str, INET_ADDRSTRLEN);
    printf("%sNode %s bound to %s:%d.%s\n", CYAN, node_name, addr_str, ntohs(state->server_addr.sin_port), RESET);

    for (int i = 0; i < THREAD_COUNT; i++) {
        WorkerState *ws = malloc(sizeof(WorkerState));
        if (!ws) {
            perror("malloc WorkerState failed");
            continue;
        }
        ws->state = state;
        ws->worker_id = i;
#ifdef __APPLE__
        ws->kqueue_fd = kqueue();
#else
        ws->epoll_fd = epoll_create1(0);
#endif
        if (
#ifdef __APPLE__
            ws->kqueue_fd < 0
#else
            ws->epoll_fd < 0
#endif
        ) {
            perror("kqueue/epoll_create1 worker failed");
            free(ws);
            continue;
        }
        if (pthread_create(&state->workers[i], NULL, worker_thread, ws) != 0) {
            perror("pthread_create failed");
#ifdef __APPLE__
            close(ws->kqueue_fd);
#else
            close(ws->epoll_fd);
#endif
            free(ws);
            continue;
        }
    }

#ifdef __APPLE__
    struct kevent events[32];
#else
    struct epoll_event events[32];
#endif
    while (atomic_load(&state->running)) {
#ifdef __APPLE__
        int nfds = kevent(state->kqueue_fd, NULL, 0, events, 32, NULL);
        if (nfds < 0) {
            if (errno != EINTR) perror("kevent wait failed");
            continue;
        }
        for (int i = 0; i < nfds; i++) {
            if (events[i].filter == EVFILT_READ && events[i].ident == (uintptr_t)state->socket_fd) {
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
                if (skynet_deserialize(&msg, buffer, len) != 0) {
                    char addr_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr.sin_addr, addr_str, INET_ADDRSTRLEN);
                    fprintf(stderr, "Failed to deserialize message from %s:%d\n", addr_str, ntohs(addr.sin_port));
                    continue;
                }
                uint64_t recv_time = get_time_us();
                if (queue_enqueue(&state->mq, &msg, &addr, recv_time) != 0) {
                    char addr_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr.sin_addr, addr_str, INET_ADDRSTRLEN);
                    fprintf(stderr, "Failed to enqueue message from %s:%d\n", addr_str, ntohs(addr.sin_port));
                }
            } else if (events[i].filter == EVFILT_TIMER && events[i].ident == state->timer_id) {
                state->current_slot = (state->current_slot + 1) % SLOT_COUNT;
            }
        }
#else
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
                if (skynet_deserialize(&msg, buffer, len) != 0) {
                    char addr_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr.sin_addr, addr_str, INET_ADDRSTRLEN);
                    fprintf(stderr, "Failed to deserialize message from %s:%d\n", addr_str, ntohs(addr.sin_port));
                    continue;
                }
                uint64_t recv_time = get_time_us();
                if (queue_enqueue(&state->mq, &msg, &addr, recv_time) != 0) {
                    char addr_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr.sin_addr, addr_str, INET_ADDRSTRLEN);
                    fprintf(stderr, "Failed to enqueue message from %s:%d\n", addr_str, ntohs(addr.sin_port));
                }
            } else if (events[i].data.fd == state->timer_fd) {
                uint64_t expirations;
                if (read(state->timer_fd, &expirations, sizeof(expirations)) != sizeof(expirations)) {
                    if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("timerfd read failed");
                    }
                    continue;
                }
                state->current_slot = (state->current_slot + 1) % SLOT_COUNT;
            }
        }
#endif
    }

cleanup:
    atomic_store(&state->running, 0);
    for (int i = 0; i < THREAD_COUNT; i++) {
        if (state->workers[i]) {
            pthread_join(state->workers[i], NULL);
        }
    }
#ifdef __APPLE__
    if (state->kqueue_fd >= 0) close(state->kqueue_fd);
#else
    if (state->timer_fd >= 0) close(state->timer_fd);
    if (state->epoll_fd >= 0) close(state->epoll_fd);
#endif
    if (state->socket_fd >= 0) close(state->socket_fd);
    if (state->ec_key) EVP_PKEY_free(state->ec_key);
    for (int i = 0; i < MAX_TOPICS; i++) {
        if (state->topic_priv_keys[i]) EVP_PKEY_free(state->topic_priv_keys[i]);
    }
    for (size_t i = 0; i < THREAD_COUNT; i++) {
        if (state->mq.event_fds[i] >= 0) close(state->mq.event_fds[i]);
#ifdef __APPLE__
        if (state->mq.event_fds_write[i] >= 0) close(state->mq.event_fds_write[i]);
#endif
    }
    for (size_t i = 0; i < MAX_TOPICS; i++) {
        for (size_t j = 0; j < THREAD_COUNT; j++) {
            if (state->topic_queues[i].event_fds[j] >= 0) close(state->topic_queues[i].event_fds[j]);
#ifdef __APPLE__
            if (state->topic_queues[i].event_fds_write[j] >= 0) close(state->topic_queues[i].event_fds_write[j]);
#endif
        }
    }
    free(state);
    return 0;
}