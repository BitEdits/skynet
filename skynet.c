// gcc -o skynet skynet.c skynet_proto.c -pthread -lcrypto

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
#include <openssl/kdf.h>
#include <openssl/params.h>
#include "skynet.h"

#define PORT 6566
#define MAX_NODES 2000
#define MAX_BUFFER 1490
#define TIME_SLOT_INTERVAL_US 1000
#define THREAD_COUNT 4
#define QUEUE_SIZE 1024
#define MAX_SEQUENCES 64
#define MAX_EVENTS 32
#define NEIGHBOR_TIMEOUT_US 5000000 // 5 seconds to prevent premature timeouts
#define MAX_NODE_NAME 64
#define BASE_PATH "~/.skynet/ecc/secp384r1/"

static void print_openssl_error(void) {
    unsigned long err = ERR_get_error();
    char err_str[256];
    ERR_error_string_n(err, err_str, sizeof(err_str));
    fprintf(stderr, "OpenSSL error: %s\n", err_str);
}

static char *expand_home(const char *path) {
    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "HOME environment variable not set\n");
        return NULL;
    }
    size_t len = strlen(home) + strlen(path) + 1;
    char *expanded = malloc(len);
    if (!expanded) {
        fprintf(stderr, "Failed to allocate memory for path\n");
        return NULL;
    }
    snprintf(expanded, len, "%s%s", home, path + 1);
    return expanded;
}

static EVP_PKEY *load_ec_key(const char *node_name, int is_private) {
    char *dir_path = expand_home(BASE_PATH);
    if (!dir_path) return NULL;
    char key_path[256];
    snprintf(key_path, sizeof(key_path), "%s/%s.ec_%s", dir_path, node_name, is_private ? "priv" : "pub");
    FILE *key_file = fopen(key_path, "rb");
    free(dir_path);
    if (!key_file) {
        fprintf(stderr, "Failed to open %s: %s\n", key_path, strerror(errno));
        return NULL;
    }
    EVP_PKEY *key = is_private ? PEM_read_PrivateKey(key_file, NULL, NULL, NULL) :
                                 PEM_read_PUBKEY(key_file, NULL, NULL, NULL);
    fclose(key_file);
    if (!key) print_openssl_error();
    return key;
}

static int load_keys(const char *node_name, uint8_t *aes_key, uint8_t *hmac_key, uint32_t *node_id, EVP_PKEY **ec_key) {
    char *dir_path = expand_home(BASE_PATH);
    if (!dir_path) return -1;
    char aes_path[256], hmac_path[256], id_path[256];
    snprintf(aes_path, sizeof(aes_path), "%s/%s.aes", dir_path, node_name);
    snprintf(hmac_path, sizeof(hmac_path), "%s/%s.hmac", dir_path, node_name);
    snprintf(id_path, sizeof(id_path), "%s/%s.id", dir_path, node_name);
    free(dir_path);

    FILE *file = fopen(aes_path, "rb");
    if (!file || fread(aes_key, 1, 32, file) != 32) {
        fprintf(stderr, "Failed to read AES key from %s: %s\n", aes_path, strerror(errno));
        if (file) fclose(file);
        return -1;
    }
    fclose(file);

    file = fopen(hmac_path, "rb");
    if (!file || fread(hmac_key, 1, 32, file) != 32) {
        fprintf(stderr, "Failed to read HMAC key from %s: %s\n", hmac_path, strerror(errno));
        if (file) fclose(file);
        return -1;
    }
    fclose(file);

    file = fopen(id_path, "rb");
    if (!file || fread(node_id, 1, sizeof(uint32_t), file) != sizeof(uint32_t)) {
        fprintf(stderr, "Failed to read node ID from %s: %s\n", id_path, strerror(errno));
        if (file) fclose(file);
        return -1;
    }
    fclose(file);

    *ec_key = load_ec_key(node_name, 1);
    if (!*ec_key) return -1;
    return 0;
}

static int save_public_key(const char *node_name, const uint8_t *pub_key_data, size_t pub_key_len) {
    char *dir_path = expand_home(BASE_PATH);
    if (!dir_path) return -1;
    char pub_path[256];
    snprintf(pub_path, sizeof(pub_path), "%s/%s.ec_pub", dir_path, node_name);
    FILE *pub_file = fopen(pub_path, "wb");
    free(dir_path);
    if (!pub_file || fwrite(pub_key_data, 1, pub_key_len, pub_file) != pub_key_len) {
        fprintf(stderr, "Failed to write public key to %s: %s\n", pub_path, strerror(errno));
        if (pub_file) fclose(pub_file);
        return -1;
    }
    fclose(pub_file);
    return 0;
}

static int derive_shared_key(EVP_PKEY *priv_key, EVP_PKEY *peer_pub_key, uint8_t *aes_key, uint8_t *hmac_key) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0) {
        print_openssl_error();
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    if (EVP_PKEY_derive_set_peer(ctx, peer_pub_key) <= 0) {
        print_openssl_error();
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    size_t secret_len;
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0) {
        print_openssl_error();
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    uint8_t *shared_secret = malloc(secret_len);
    if (!shared_secret || EVP_PKEY_derive(ctx, shared_secret, &secret_len) <= 0) {
        print_openssl_error();
        free(shared_secret);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kdf_ctx = EVP_KDF_CTX_new(kdf);
    if (!kdf_ctx) {
        print_openssl_error();
        free(shared_secret);
        EVP_KDF_free(kdf);
        return -1;
    }
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
        OSSL_PARAM_construct_octet_string("key", shared_secret, secret_len),
        OSSL_PARAM_construct_end()
    };
    if (EVP_KDF_derive(kdf_ctx, aes_key, 32, params) <= 0) {
        print_openssl_error();
        EVP_KDF_CTX_free(kdf_ctx);
        EVP_KDF_free(kdf);
        free(shared_secret);
        return -1;
    }
    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string("key", shared_secret, secret_len);
    params[2] = OSSL_PARAM_construct_octet_string("info", (unsigned char *)"HMAC", 4);
    params[3] = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(kdf_ctx, hmac_key, 32, params) <= 0) {
        print_openssl_error();
        EVP_KDF_CTX_free(kdf_ctx);
        EVP_KDF_free(kdf);
        free(shared_secret);
        return -1;
    }
    EVP_KDF_CTX_free(kdf_ctx);
    EVP_KDF_free(kdf);
    free(shared_secret);
    return 0;
}

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
    uint8_t hmac_key[32];
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

static uint64_t get_time_us(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        perror("clock_gettime failed");
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
}

static uint32_t crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return ~crc;
}

static void queue_init(MessageQueue *q) {
    atomic_store(&q->head, 0);
    atomic_store(&q->tail, 0);
    for (int i = 0; i < THREAD_COUNT; i++) {
        q->event_fds[i] = eventfd(0, EFD_NONBLOCK);
        if (q->event_fds[i] < 0) {
            perror("Eventfd creation failed");
            exit(1);
        }
    }
}

static int queue_enqueue(ServerState *state, const SkyNetMessage *msg, const struct sockaddr_in *addr, uint64_t recv_time) {
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
            perror("Eventfd write failed");
        }
    }
    return 0;
}

static int queue_dequeue(ServerState *state, SkyNetMessage *msg, struct sockaddr_in *addr, uint64_t *recv_time) {
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

static int set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void pin_thread(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) < 0) {
        perror("Pin thread error");
    }
}

static void server_init(ServerState *state, const char *node_name) {
    memset(state, 0, sizeof(ServerState));
    strncpy(state->server_name, node_name, MAX_NODE_NAME - 1);
    state->server_name[MAX_NODE_NAME - 1] = '\0';
    if (load_keys(node_name, state->aes_key, state->hmac_key, &state->node_id, &state->ec_key)) {
        fprintf(stderr, "Failed to load keys\n");
        exit(1);
    }
    const char *topics[] = {"npg_control", "npg_pli", "npg_surveillance", "npg_chat",
                            "npg_c2", "npg_alerts", "npg_logistics", "npg_coord"};
    for (int i = 0; i < 8; i++) {

        uint32_t topic_hash = fnv1a_32(topics[i], strlen(topics[i]));
        char node_name[16];
        snprintf(node_name, sizeof(node_name), "%08x", topic_hash);

        state->topic_priv_keys[i] = load_ec_key(node_name, 1);
        if (!state->topic_priv_keys[i]) {
            fprintf(stderr, "Failed to load topic private key %s (%s)\n", topics[i], node_name);
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

static int is_duplicate(ServerState *state, uint32_t node_id, uint32_t seq_no, uint8_t type, struct sockaddr_in *addr) {
    uint64_t current_time = time(NULL);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime((time_t *)&current_time));
    uint32_t hash = (node_id ^ seq_no) % MAX_SEQUENCES;
    for (int i = 0; i < MAX_SEQUENCES; i++) {
        uint32_t idx = (hash + i) % MAX_SEQUENCES;
        if (atomic_load_explicit(&state->seqs[idx].claimed, memory_order_acquire)) {
            if (state->seqs[idx].node_id == node_id && state->seqs[idx].seq_no == seq_no) {
                if (current_time - state->seqs[idx].timestamp < 2) {
                    printf("[[%s]] Dropped duplicate message from node %u, type=%d, seq=%u, src=%s:%d\n",
                           time_str, node_id, type, seq_no, inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
                    return 1;
                }
            }
        }
    }
    return 0;
}

static void record_sequence(ServerState *state, uint32_t node_id, uint32_t seq_no) {
    uint32_t hash = (node_id ^ seq_no) % MAX_SEQUENCES;
    uint32_t idx = atomic_fetch_add_explicit(&state->seq_idx, 1, memory_order_seq_cst) % MAX_SEQUENCES;
    for (int i = 0; i < MAX_SEQUENCES; i++) {
        uint32_t probe = (hash + i) % MAX_SEQUENCES;
        uint32_t expected = 0;
        uint32_t desired = 1;
        if (atomic_load_explicit(&state->seqs[probe].claimed, memory_order_acquire) == 0 ||
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

static NodeState *find_or_add_node(ServerState *state, struct sockaddr_in *addr, uint32_t node_id, NodeRole role, const char *node_name2) {

    uint32_t topic_hash = node_id;
    char node_name[16];
    snprintf(node_name, sizeof(node_name), "%08x", topic_hash);

    uint32_t count = atomic_load_explicit(&state->node_count, memory_order_acquire);
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
        strncpy(node->node_name, node_name2, MAX_NODE_NAME - 1);
        node->node_name[MAX_NODE_NAME - 1] = '\0';
        printf("Node %u (%s) added from %s:%d\n", node_id, node->node_name, inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
        if (new_count == 1 && !atomic_load(&state->timer_active)) {
            struct itimerspec timer_spec = {
                .it_interval = { .tv_sec = 0, .tv_nsec = TIME_SLOT_INTERVAL_US * 1000 },
                .it_value = { .tv_sec = 0, .tv_nsec = TIME_SLOT_INTERVAL_US * 1000 }
            };
            if (timerfd_settime(state->timer_fd, 0, &timer_spec, NULL) < 0) {
                perror("Timerfd settime failed");
                exit(1);
            } else {
                atomic_store(&state->timer_active, 1);
            }
        }
        return node;
    }
    return find_or_add_node(state, addr, node_id, role, node_name);
}

static void subscribe_npg(NodeState *node, uint8_t npg_id) {
    for (int i = 0; i < 32; i++) {
        if (node->subscribed_npgs[i] == 0 || node->subscribed_npgs[i] == npg_id) {
            node->subscribed_npgs[i] = npg_id;
            printf("Node %u subscribed to NPG %d\n", node->node_id, npg_id);
            break;
        }
    }
}

static void send_to_npg(ServerState *state, const SkyNetMessage *msg, uint64_t recv_time) {
    uint64_t send_time = get_time_us();
    uint8_t buffer[MAX_BUFFER];
    const char *topic = NULL;
    int topic_idx = -1;
    switch (msg->npg_id) {
        case SKYNET_NPG_CONTROL: topic = "npg_control"; topic_idx = 0; break;
        case SKYNET_NPG_PLI: topic = "npg_pli"; topic_idx = 1; break;
        case SKYNET_NPG_SURVEILLANCE: topic = "npg_surveillance"; topic_idx = 2; break;
        case SKYNET_NPG_CHAT: topic = "npg_chat"; topic_idx = 3; break;
        case SKYNET_NPG_C2: topic = "npg_c2"; topic_idx = 4; break;
        case SKYNET_NPG_ALERTS: topic = "npg_alerts"; topic_idx = 5; break;
        case SKYNET_NPG_LOGISTICS: topic = "npg_logistics"; topic_idx = 6; break;
        case SKYNET_NPG_COORD: topic = "npg_coord"; topic_idx = 7; break;
        default: return;
    }

    uint32_t topic_hash = fnv1a_32(topic, strlen(topic));
    char node_name[16];
    snprintf(node_name, sizeof(node_name), "%08x", topic_hash);

    EVP_PKEY *topic_pub_key = load_ec_key(node_name, 0);
    if (!topic_pub_key) return;
    uint8_t topic_aes_key[32], topic_hmac_key[32];
    if (derive_shared_key(state->topic_priv_keys[topic_idx], topic_pub_key, topic_aes_key, topic_hmac_key) < 0) {
        EVP_PKEY_free(topic_pub_key);
        return;
    }
    SkyNetMessage enc_msg = *msg;
    skynet_set_data(&enc_msg, msg->payload, msg->payload_len, topic_aes_key, topic_hmac_key);
    int len = skynet_serialize(&enc_msg, buffer, MAX_BUFFER);
    EVP_PKEY_free(topic_pub_key);
    if (len < 0) return;

    struct sockaddr_in mcast_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr.s_addr = 0
    };
    char mcast_ip[16];
    snprintf(mcast_ip, sizeof(mcast_ip), "239.255.0.%d", msg->npg_id & 0xFF);
    inet_pton(AF_INET, mcast_ip, &mcast_addr.sin_addr);
    if (sendto(state->socket_fd, buffer, len, 0, (struct sockaddr *)&mcast_addr, sizeof(mcast_addr)) < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("Sendto failed");
        }
    } else {
        printf("SENT [NPG:%d][seq:%u][multicast:%s] latency [us:%lu]\n",
               msg->npg_id, msg->seq_no, mcast_ip, send_time - recv_time);
        record_sequence(state, msg->node_id, msg->seq_no);
    }
}

static void process_control(ServerState *state, NodeState *node, SkyNetMessage *msg, uint64_t recv_time, struct sockaddr_in *addr) {
    if (msg->type == SKYNET_MSG_SLOT_REQUEST) {
        subscribe_npg(node, msg->npg_id);
        if (node->role == NODE_ROLE_DRONE && msg->npg_id == SKYNET_NPG_CONTROL) {
            node->role = NODE_ROLE_CONTROLLER;
            printf("Node %u promoted to swarm controller\n", node->node_id);
        }
    } else if (msg->type == SKYNET_MSG_STATUS) {
        if (msg->payload_len >= 6 * sizeof(float)) {
            memcpy(node->position, msg->payload, sizeof(float) * 3);
            memcpy(node->velocity, (float *)msg->payload + 3, sizeof(float) * 3);
            node->last_seen = get_time_us();
            printf("Updated PLI for node %u: pos=[%.1f, %.1f, %.1f], vel=[%.1f, %.1f, %.1f]\n",
                   node->node_id, node->position[0], node->position[1], node->position[2],
                   node->velocity[0], node->velocity[1], node->velocity[2]);
        }
    } else if (msg->type == SKYNET_MSG_KEY_EXCHANGE) {
        if (msg->payload_len < 2 || msg->payload_len > MAX_BUFFER - 1) {
            fprintf(stderr, "Invalid payload length %u for key exchange\n", msg->payload_len);
            return;
        }

        char client_name[16];
        snprintf(client_name, sizeof(client_name), "%08x", msg->node_id);
        size_t name_len = strlen(client_name);

        if (name_len >= MAX_NODE_NAME) {
            fprintf(stderr, "Invalid or too long node name in key exchange\n");
            return;
        }
//        client_name[name_len] = '\0';
        size_t pub_key_offset = name_len + 1;
        if (pub_key_offset >= msg->payload_len) {
            fprintf(stderr, "No public key data in key exchange\n");
            return;
        }
        size_t pub_key_len = msg->payload_len - pub_key_offset;
        if (save_public_key(client_name, msg->payload + pub_key_offset, pub_key_len) == 0) {
            printf("Saved public key for client %s\n", client_name);
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
            long pub_key_len_written = BIO_read(bio, pub_key_data, sizeof(pub_key_data));
            BIO_free(bio);
            if (pub_key_len_written <= 0) {
                fprintf(stderr, "Failed to read public key from BIO\n");
                return;
            }
            char response_data[1024];
            size_t server_name_len = strlen(state->server_name) + 1;
            if (server_name_len + pub_key_len_written > sizeof(response_data)) {
                fprintf(stderr, "Response data too large for buffer\n");
                return;
            }
            memcpy(response_data, state->server_name, server_name_len);
            memcpy(response_data + server_name_len, pub_key_data, pub_key_len_written);
            EVP_PKEY *client_pub_key = load_ec_key(client_name, 0);
            if (!client_pub_key) {
                fprintf(stderr, "Failed to load client public key\n");
                return;
            }
            uint8_t aes_key[32], hmac_key[32];
            if (derive_shared_key(state->ec_key, client_pub_key, aes_key, hmac_key) < 0) {
                fprintf(stderr, "Failed to derive shared key\n");
                EVP_PKEY_free(client_pub_key);
                return;
            }
            skynet_set_data(&response, (uint8_t *)response_data, server_name_len + pub_key_len_written, aes_key, hmac_key);
            EVP_PKEY_free(client_pub_key);
            uint8_t buffer[MAX_BUFFER];
            int len = skynet_serialize(&response, buffer, MAX_BUFFER);
            if (len > 0) {
                send_to_npg(state, &response, recv_time);
            }
        }
    }
}

static void process_self_healing(ServerState *state) {
    uint64_t now = get_time_us();
    for (size_t i = 0; i < atomic_load(&state->node_count); i++) {
        if (now - state->nodes[i].last_seen > NEIGHBOR_TIMEOUT_US) {
            printf("Node %u (%s) timed out, removing\n", state->nodes[i].node_id, state->nodes[i].node_name);
            for (size_t j = i; j < atomic_load(&state->node_count) - 1; j++) {
                state->nodes[j] = state->nodes[j + 1];
            }
            atomic_fetch_sub(&state->node_count, 1);
            SkyNetMessage msg;
            skynet_init(&msg, SKYNET_MSG_WAYPOINT, state->node_id, SKYNET_NPG_CONTROL, SKYNET_QOS_C2);
            msg.seq_no = state->current_slot;

            const char *npg_control = "npg_control";
            uint32_t topic_hash = fnv1a_32(npg_control, strlen(npg_control));
            char self_name[16];
            snprintf(self_name, sizeof(self_name), "%08x", topic_hash);

            EVP_PKEY *topic_pub_key = load_ec_key(self_name, 0);
            if (!topic_pub_key) return;
            uint8_t topic_aes_key[32], topic_hmac_key[32];
            if (derive_shared_key(state->topic_priv_keys[0], topic_pub_key, topic_aes_key, topic_hmac_key) < 0) {
                EVP_PKEY_free(topic_pub_key);
                return;
            }
            skynet_set_data(&msg, NULL, 0, topic_aes_key, topic_hmac_key);
            EVP_PKEY_free(topic_pub_key);
            send_to_npg(state, &msg, now);
        }
    }
}

static void handle_message(ServerState *state, NodeState *node, SkyNetMessage *msg, uint64_t recv_time, struct sockaddr_in *addr) {
    node->last_seen = get_time_us();
    if (msg->version != SKYNET_VERSION) {
        fprintf(stderr, "Invalid version %d from node %u\n", msg->version, msg->node_id);
        return;
    }
/*
    uint32_t computed_crc = crc32((uint8_t *)msg, offsetof(SkyNetMessage, crc));
    if (computed_crc != msg->crc) {
        fprintf(stderr, "CRC32 mismatch for node %u, seq=%u, computed=0x%08x, expected=0x%08x\n",
                msg->node_id, msg->seq_no, computed_crc, msg->crc);
        return;
    }
*/
    EVP_PKEY *dec_key = NULL;
    uint8_t dec_aes_key[32], dec_hmac_key[32];
    if (msg->npg_id == SKYNET_NPG_CONTROL) {

        const char node_name[16];
        snprintf(node_name, sizeof(node_name), "%08x", msg->node_id);
        //dec_key = load_ec_key("40ac3dd2", 0);
        dec_key = load_ec_key(node_name, 0);
        if (!dec_key) {
            fprintf(stderr, "Failed to load public key for node %s\n", node->node_name);
            return;
        }
        if (derive_shared_key(state->ec_key, dec_key, dec_aes_key, dec_hmac_key) < 0) {
            fprintf(stderr, "Failed to derive shared key for node %s\n", node->node_name);
            EVP_PKEY_free(dec_key);
            return;
        }

    } else {
        const char *topic = NULL;
        int topic_idx = -1;
        switch (msg->npg_id) {
            case SKYNET_NPG_PLI: topic = "npg_pli"; topic_idx = 1; break;
            case SKYNET_NPG_SURVEILLANCE: topic = "npg_surveillance"; topic_idx = 2; break;
            case SKYNET_NPG_CHAT: topic = "npg_chat"; topic_idx = 3; break;
            case SKYNET_NPG_C2: topic = "npg_c2"; topic_idx = 4; break;
            case SKYNET_NPG_ALERTS: topic = "npg_alerts"; topic_idx = 5; break;
            case SKYNET_NPG_LOGISTICS: topic = "npg_logistics"; topic_idx = 6; break;
            case SKYNET_NPG_COORD: topic = "npg_coord"; topic_idx = 7; break;
            default:
                fprintf(stderr, "Invalid NPG ID %u\n", msg->npg_id);
                return;
        }
        dec_key = load_ec_key(topic, 0);
        if (!dec_key) {
            fprintf(stderr, "Failed to load public key for topic %s\n", topic);
            return;
        }
        if (derive_shared_key(state->topic_priv_keys[topic_idx], dec_key, dec_aes_key, dec_hmac_key) < 0) {
            fprintf(stderr, "Failed to derive shared key for topic %s\n", topic);
            EVP_PKEY_free(dec_key);
            return;
        }
    }
/*
    if (skynet_verify_hmac(msg, dec_hmac_key) != 0) {
        fprintf(stderr, "HMAC verification failed for node %u, seq=%u\n", msg->node_id, msg->seq_no);
        EVP_PKEY_free(dec_key);
        return;
    }
*/

    if (skynet_decrypt_payload(msg, dec_aes_key) != 0) {
        fprintf(stderr, "Decryption failed for node %u, seq=%u\n", msg->node_id, msg->seq_no);
        EVP_PKEY_free(dec_key);
        return;
    }
    EVP_PKEY_free(dec_key);
    if (is_duplicate(state, msg->node_id, msg->seq_no, msg->type, addr)) {
        return;
    }
    printf("RCVD [NPG:%d][seq:%u][node:%u][type:%d][src:%s:%d]\n",
           msg->npg_id, msg->seq_no, msg->node_id, msg->type,
           inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));

    switch (msg->type) {
        case SKYNET_MSG_PUBLIC:
        case SKYNET_MSG_CHAT:
        case SKYNET_MSG_ACK:
        case SKYNET_MSG_WAYPOINT:
        case SKYNET_MSG_STATUS:
        case SKYNET_MSG_FORMATION:
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

static void *worker_thread(void *arg) {
    WorkerState *ws = (WorkerState *)arg;
    ServerState *state = ws->state;
    int worker_id = ws->worker_id;
    int epoll_fd = ws->epoll_fd;
    pin_thread(worker_id);
    struct epoll_event events[MAX_EVENTS];
    while (atomic_load(&state->running)) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno != EINTR) perror("Worker epoll_wait failed");
            continue;
        }
        for (int i = 0; i < nfds; i++) {
            uint64_t count;
            if (read(state->mq.event_fds[worker_id], &count, sizeof(count)) < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    perror("Eventfd read failed");
                }
                continue;
            }
            SkyNetMessage msg;
            struct sockaddr_in addr;
            uint64_t recv_time;
            while (queue_dequeue(state, &msg, &addr, &recv_time) == 0) {
                NodeState *node = NULL;
                if (msg.type == SKYNET_MSG_KEY_EXCHANGE) {

                    uint32_t node_id = msg.node_id;
                    char node_name[16];
                    snprintf(node_name, sizeof(node_name), "%08x", node_id);

                    if (strlen(node_name) >= MAX_NODE_NAME) {
                        fprintf(stderr, "Invalid node name in key exchange message (%d): %s\n", strlen(node_name), node_name);
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
                if (node) {
                    handle_message(state, node, &msg, recv_time, &addr);
                } else {
                    fprintf(stderr, "No node found for ID %u\n", msg.node_id);
                }
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

    fprintf(stderr, "Node name: %s\n", node_name);

    ServerState state;
    server_init(&state, node_name);
    pin_thread(0);

    state.socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (state.socket_fd == -1) {
        perror("Socket creation failed");
        EVP_PKEY_free(state.ec_key);
        for (int i = 0; i < 8; i++) {
            EVP_PKEY_free(state.topic_priv_keys[i]);
        }
        return 1;
    }
    if (set_non_blocking(state.socket_fd) < 0) {
        perror("Set non-blocking failed");
        close(state.socket_fd);
        EVP_PKEY_free(state.ec_key);
        for (int i = 0; i < 8; i++) {
            EVP_PKEY_free(state.topic_priv_keys[i]);
        }
        return 1;
    }
    int opt = 1;
    if (setsockopt(state.socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Set SO_REUSEADDR failed");
        close(state.socket_fd);
        EVP_PKEY_free(state.ec_key);
        for (int i = 0; i < 8; i++) {
            EVP_PKEY_free(state.topic_priv_keys[i]);
        }
        return 1;
    }
    int buf_size = 1 * 1024 * 1024;
    if (setsockopt(state.socket_fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0 ||
        setsockopt(state.socket_fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) < 0) {
        perror("Set buffer failed");
        close(state.socket_fd);
        EVP_PKEY_free(state.ec_key);
        for (int i = 0; i < 8; i++) {
            EVP_PKEY_free(state.topic_priv_keys[i]);
        }
        return 1;
    }
    if (bind(state.socket_fd, (struct sockaddr *)&state.server_addr, sizeof(state.server_addr)) < 0) {
        perror("Bind failed");
        close(state.socket_fd);
        EVP_PKEY_free(state.ec_key);
        for (int i = 0; i < 8; i++) {
            EVP_PKEY_free(state.topic_priv_keys[i]);
        }
        return 1;
    }
    printf("SkyNet server bound to %s:%d\n",
           inet_ntoa(state.server_addr.sin_addr), ntohs(state.server_addr.sin_port));
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
            printf("Joined multicast group %s\n", mcast_ip);
        }
    }
    state.epoll_fd = epoll_create1(0);
    if (state.epoll_fd == -1) {
        perror("Epoll creation failed");
        close(state.socket_fd);
        EVP_PKEY_free(state.ec_key);
        for (int i = 0; i < 8; i++) {
            EVP_PKEY_free(state.topic_priv_keys[i]);
        }
        return 1;
    }
    struct epoll_event ev = { .events = EPOLLIN, .data = { .fd = state.socket_fd } };
    if (epoll_ctl(state.epoll_fd, EPOLL_CTL_ADD, state.socket_fd, &ev) < 0) {
        perror("Epoll add socket failed");
        close(state.epoll_fd);
        close(state.socket_fd);
        EVP_PKEY_free(state.ec_key);
        for (int i = 0; i < 8; i++) {
            EVP_PKEY_free(state.topic_priv_keys[i]);
        }
        return 1;
    }
    state.timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (state.timer_fd == -1) {
        perror("Timerfd creation failed");
        close(state.epoll_fd);
        close(state.socket_fd);
        EVP_PKEY_free(state.ec_key);
        for (int i = 0; i < 8; i++) {
            EVP_PKEY_free(state.topic_priv_keys[i]);
        }
        return 1;
    }
    ev.events = EPOLLIN;
    ev.data.fd = state.timer_fd;
    if (epoll_ctl(state.epoll_fd, EPOLL_CTL_ADD, state.timer_fd, &ev) < 0) {
        perror("Epoll add timer failed");
        close(state.timer_fd);
        close(state.epoll_fd);
        close(state.socket_fd);
        EVP_PKEY_free(state.ec_key);
        for (int i = 0; i < 8; i++) {
            EVP_PKEY_free(state.topic_priv_keys[i]);
        }
        return 1;
    }
    for (int i = 0; i < THREAD_COUNT; i++) {
        WorkerState *ws = malloc(sizeof(WorkerState));
        if (!ws) {
            perror("Worker state allocation failed");
            close(state.timer_fd);
            close(state.epoll_fd);
            close(state.socket_fd);
            EVP_PKEY_free(state.ec_key);
            for (int j = 0; j < 8; j++) {
                EVP_PKEY_free(state.topic_priv_keys[j]);
            }
            return 1;
        }
        ws->state = &state;
        ws->worker_id = i;
        ws->epoll_fd = epoll_create1(0);
        if (ws->epoll_fd < 0) {
            perror("Worker epoll creation");
            free(ws);
            close(state.timer_fd);
            close(state.epoll_fd);
            close(state.socket_fd);
            EVP_PKEY_free(state.ec_key);
            for (int j = 0; j < 8; j++) {
                EVP_PKEY_free(state.topic_priv_keys[j]);
            }
            return 1;
        }
        ev.events = EPOLLIN;
        ev.data.fd = state.mq.event_fds[i];
        if (epoll_ctl(ws->epoll_fd, EPOLL_CTL_ADD, state.mq.event_fds[i], &ev) < 0) {
            perror("Worker epoll add eventfd failed");
            close(ws->epoll_fd);
            free(ws);
            close(state.timer_fd);
            close(state.epoll_fd);
            close(state.socket_fd);
            EVP_PKEY_free(state.ec_key);
            for (int j = 0; j < 8; j++) {
                EVP_PKEY_free(state.topic_priv_keys[j]);
            }
            return 1;
        }
        if (pthread_create(&state.workers[i], NULL, worker_thread, ws)) {
            perror("Failed to create worker thread");
            close(ws->epoll_fd);
            free(ws);
            close(state.timer_fd);
            close(state.epoll_fd);
            close(state.socket_fd);
            EVP_PKEY_free(state.ec_key);
            for (int j = 0; j < 8; j++) {
                EVP_PKEY_free(state.topic_priv_keys[j]);
            }
            return 1;
        }
        printf("Started worker thread %d\n", i);
    }
    printf("SkyNet server listening on port %d with %d worker threads\n", PORT, THREAD_COUNT);
    struct epoll_event events[MAX_EVENTS];
    uint8_t eventsbuffer[MAX_BUFFER];
    struct iovec iov = { .iov_base = eventsbuffer, .iov_len = MAX_BUFFER };
    struct msghdr mhdr = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = NULL,
        .msg_controllen = 0
    };
    while (atomic_load(&state.running)) {
        int nfds = epoll_wait(state.epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno != EINTR) {
                perror("Epoll wait failed");
            }
            continue;
        }
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == state.socket_fd) {
                uint64_t recv_time = get_time_us();
                struct sockaddr_in client_addr;
                mhdr.msg_name = &client_addr;
                mhdr.msg_namelen = sizeof(client_addr);
                ssize_t len = recvmsg(state.socket_fd, &mhdr, 0);
                if (len < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("Recvmsg failed");
                    }
                    continue;
                }
                SkyNetMessage msg;
                if (skynet_deserialize(&msg, eventsbuffer, len) < 0) {
                    fprintf(stderr, "Failed to deserialize message from %s:%d\n",
                            inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                    continue;
                }
                if (msg.node_id == 0 || msg.payload_len > MAX_BUFFER) {
                    fprintf(stderr, "Invalid message: node_id=%u, payload_len=%u\n",
                            msg.node_id, msg.payload_len);
                    continue;
                }
                if (queue_enqueue(&state, &msg, &client_addr, recv_time) < 0) {
                    fprintf(stderr, "Failed to enqueue message from %s:%d\n",
                            inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                }
            } else if (events[i].data.fd == state.timer_fd) {
                uint64_t expirations;
                if (read(state.timer_fd, &expirations, sizeof(uint64_t)) < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("Timerfd read failed");
                    }
                    continue;
                }
                state.current_slot = (state.current_slot + 1) % 1000;
                process_self_healing(&state);
                if (atomic_load(&state.node_count) == 0 && atomic_load(&state.timer_active)) {
                    struct itimerspec timer_spec = { .it_interval = {0}, .it_value = {0} };
                    if (timerfd_settime(state.timer_fd, 0, &timer_spec, NULL) < 0) {
                        perror("Timerfd disable failed");
                    }
                    atomic_store(&state.timer_active, 0);
                }
            }
        }
    }
    atomic_store(&state.running, 0);
    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(state.workers[i], NULL);
    }
    for (int i = 0; i < THREAD_COUNT; i++) {
        close(state.mq.event_fds[i]);
    }
    close(state.timer_fd);
    close(state.epoll_fd);
    close(state.socket_fd);
    EVP_PKEY_free(state.ec_key);
    for (int i = 0; i < 8; i++) {
        EVP_PKEY_free(state.topic_priv_keys[i]);
    }
    return 0;
}
