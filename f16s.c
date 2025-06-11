// sudo apt-get install libnuma-dev
// gcc -o f16s f16s.c j-msg.c -pthread -lnuma

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <numa.h>
#include <stdatomic.h>
#include <net/if.h>
#include "j-msg.h"

#define PORT 8080
#define MAX_JUS 32
#define MAX_BUFFER 1024
#define JU_ADDRESS_BASE 00001
#define TIME_SLOT_INTERVAL_US 7812 /* 7.8125 ms in microseconds */
#define THREAD_COUNT 4
#define QUEUE_SIZE 1024
#define MAX_SEQUENCES 1024

/* Message sequence tracking */
typedef struct {
    uint32_t ju_address;
    uint32_t sequence; /* Using time_slot as sequence */
    uint64_t timestamp;
} MessageSeq;

/* Lock-free ring buffer with timing */
typedef struct {
    JMessage messages[QUEUE_SIZE];
    struct sockaddr_in addrs[QUEUE_SIZE];
    uint64_t recv_times[QUEUE_SIZE]; /* Receive timestamp */
    atomic_uint head;
    atomic_uint tail;
} MessageQueue;

/* JU State */
typedef struct {
    struct sockaddr_in addr;
    uint32_t ju_address;
    JURole role;
    uint8_t subscribed_npgs[32];
    uint32_t time_slots[16];
    uint32_t slot_count;
} JUState;

/* Server State */
typedef struct {
    JUState jus[MAX_JUS];
    atomic_uint ju_count;
    uint32_t current_slot;
    int ntr_assigned;
    int socket_fd;
    int epoll_fd;
    int timer_fd;
    MessageQueue mq;
    pthread_t workers[THREAD_COUNT];
    pthread_cond_t queue_cond;
    pthread_mutex_t queue_mutex;
    int running;
    MessageSeq seqs[MAX_SEQUENCES];
    atomic_uint seq_idx;
    struct sockaddr_in server_addr;
} ServerState;

/* Get current time in microseconds */
static uint64_t get_time_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

/* Initialize message queue */
void queue_init(MessageQueue *q) {
    q->head = 0;
    q->tail = 0;
}

/* Enqueue message */
int queue_enqueue(ServerState *state, const JMessage *msg, const struct sockaddr_in *addr, uint64_t recv_time) {
    MessageQueue *q = &state->mq;
    uint32_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
    uint32_t next_head = (head + 1) % QUEUE_SIZE;
    if (next_head == atomic_load_explicit(&q->tail, memory_order_acquire)) {
        fprintf(stderr, "Queue full, dropping message\n");
        return -1;
    }
    q->messages[head] = *msg;
    q->addrs[head] = *addr;
    q->recv_times[head] = recv_time;
    atomic_store_explicit(&q->head, next_head, memory_order_release);
    pthread_mutex_lock(&state->queue_mutex);
    pthread_cond_signal(&state->queue_cond);
    pthread_mutex_unlock(&state->queue_mutex);
    return 0;
}

/* Dequeue message */
int queue_dequeue(ServerState *state, JMessage *msg, struct sockaddr_in *addr, uint64_t *recv_time) {
    MessageQueue *q = &state->mq;
    uint32_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    if (tail == atomic_load_explicit(&q->head, memory_order_acquire)) {
        return -1;
    }
    *msg = q->messages[tail];
    *addr = q->addrs[tail];
    *recv_time = q->recv_times[tail];
    atomic_store_explicit(&q->tail, (tail + 1) % QUEUE_SIZE, memory_order_release);
    return 0;
}

/* Set socket to non-blocking mode */
int set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Set real-time scheduling */
void set_realtime_priority() {
    struct sched_param param = { .sched_priority = 99 };
    if (sched_setscheduler(0, SCHED_FIFO, &param) < 0) {
        perror("Set real-time scheduling failed");
    }
}

/* Pin thread to CPU core */
void pin_thread(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) < 0) {
        perror("Pin thread failed");
    }
}

/* Initialize server state */
void server_init(ServerState *state) {
    memset(state, 0, sizeof(ServerState));
    state->current_slot = 0;
    state->ntr_assigned = 0;
    state->running = 1;
    queue_init(&state->mq);
    atomic_store(&state->ju_count, 0);
    atomic_store(&state->seq_idx, 0);
    state->server_addr.sin_family = AF_INET;
    state->server_addr.sin_addr.s_addr = INADDR_ANY;
    state->server_addr.sin_port = htons(PORT);
    pthread_mutex_init(&state->queue_mutex, NULL);
    pthread_cond_init(&state->queue_cond, NULL);
}

/* Hash-based duplicate detection */
int is_duplicate(ServerState *state, uint32_t ju_addr, uint32_t seq) {
    uint64_t current_time = time(NULL);
    uint32_t hash = (ju_addr ^ seq) % MAX_SEQUENCES;
    for (int i = 0; i < MAX_SEQUENCES; i++) {
        uint32_t idx = (hash + i) % MAX_SEQUENCES;
        if (state->seqs[idx].ju_address == ju_addr && state->seqs[idx].sequence == seq) {
            if (current_time - state->seqs[idx].timestamp < 10) {
                return 1;
            }
        }
        if (state->seqs[idx].ju_address == 0) break; /* Empty slot */
    }
    return 0;
}

/* Record message sequence */
void record_sequence(ServerState *state, uint32_t ju_addr, uint32_t seq) {
    uint32_t hash = (ju_addr ^ seq) % MAX_SEQUENCES;
    uint32_t idx = atomic_fetch_add(&state->seq_idx, 1) % MAX_SEQUENCES;
    for (int i = 0; i < MAX_SEQUENCES; i++) {
        uint32_t probe = (hash + i) % MAX_SEQUENCES;
        if (state->seqs[probe].ju_address == 0 || 
            time(NULL) - state->seqs[probe].timestamp >= 10) {
            state->seqs[probe].ju_address = ju_addr;
            state->seqs[probe].sequence = seq;
            state->seqs[probe].timestamp = time(NULL);
            break;
        }
    }
}

/* Find or add JU */
JUState *find_or_add_ju(ServerState *state, struct sockaddr_in *addr) {
    for (uint32_t i = 0; i < atomic_load(&state->ju_count); i++) {
        if (memcmp(&state->jus[i].addr, addr, sizeof(*addr)) == 0) {
            return &state->jus[i];
        }
    }
    uint32_t count = atomic_load(&state->ju_count);
    if (count >= MAX_JUS) {
        fprintf(stderr, "Error: Max JUs reached\n");
        return NULL;
    }
    uint32_t new_count = count + 1;
    if (atomic_compare_exchange_strong(&state->ju_count, &count, new_count)) {
        JUState *ju = &state->jus[count];
        ju->addr = *addr;
        ju->ju_address = JU_ADDRESS_BASE + count;
        ju->role = JU_ROLE_NON_C2;
        ju->slot_count = 1;
        ju->time_slots[0] = count * 100;
        printf("Added JU %05o from %s:%d\n", ju->ju_address,
               inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
        return ju;
    }
    return find_or_add_ju(state, addr);
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

/* Send message to NPG multicast group */
void send_to_npg(ServerState *state, const JMessage *msg, uint64_t recv_time) {
    uint64_t send_time = get_time_us();
    uint8_t buffer[MAX_BUFFER];
    int len = jmessage_serialize(msg, buffer, sizeof(buffer));
    if (len < 0) {
        fprintf(stderr, "Error: Serialization failed\n");
        return;
    }

    struct iovec iov = { .iov_base = buffer, .iov_len = len };
    struct msghdr mhdr = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0
    };

    struct sockaddr_in mcast_addr;
    memset(&mcast_addr, 0, sizeof(mcast_addr));
    mcast_addr.sin_family = AF_INET;
    mcast_addr.sin_port = htons(PORT);
    char mcast_ip[16];
    snprintf(mcast_ip, sizeof(mcast_ip), "239.255.0.%d", msg->npg);
    inet_pton(AF_INET, mcast_ip, &mcast_addr.sin_addr);
    mhdr.msg_name = &mcast_addr;
    mhdr.msg_namelen = sizeof(mcast_addr);

    if (sendmsg(state->socket_fd, &mhdr, 0) < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("Sendmsg failed");
        }
    } else {
        printf("Sent to NPG %d multicast %s, seq %u, latency %llu us\n",
               msg->npg, mcast_ip, msg->time_slot, send_time - recv_time);
        record_sequence(state, msg->ju_address, msg->time_slot);
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

/* Handle message */
void handle_message(ServerState *state, JUState *ju, JMessage *msg, uint64_t recv_time) {
    uint64_t process_time = get_time_us();
    if (is_duplicate(state, msg->ju_address, msg->time_slot)) {
        printf("Dropped duplicate message from JU %05o, seq %u, latency %llu us\n",
               ju->ju_address, msg->time_slot, process_time - recv_time);
        return;
    }

    printf("Received message from JU %05o, type: %d, NPG: %d, seq: %u, src: %s:%d, latency %llu us\n",
           ju->ju_address, msg->type, msg->npg, msg->time_slot,
           inet_ntoa(ju->addr.sin_addr), ntohs(ju->addr.sin_port), process_time - recv_time);
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
            send_to_npg(state, msg, recv_time);
            jmessage_print(msg);
            break;
        default:
            printf("Unsupported message type: %d\n", msg->type);
    }
}

/* Worker thread function */
void *worker_thread(void *arg) {
    ServerState *state = (ServerState *)arg;
    int core_id = syscall(SYS_gettid) % THREAD_COUNT;
    pin_thread(core_id);
    set_realtime_priority();

    if (numa_available() >= 0) {
        numa_set_preferred(numa_node_of_cpu(core_id));
    } else {
        fprintf(stderr, "NUMA not available\n");
    }

    while (state->running) {
        JMessage msg;
        struct sockaddr_in addr;
        uint64_t recv_time;
        pthread_mutex_lock(&state->queue_mutex);
        while (queue_dequeue(state, &msg, &addr, &recv_time) < 0 && state->running) {
            pthread_cond_wait(&state->queue_cond, &state->queue_mutex);
        }
        pthread_mutex_unlock(&state->queue_mutex);
        if (!state->running) break;
        JUState *ju = find_or_add_ju(state, &addr);
        if (ju) {
            handle_message(state, ju, &msg, recv_time);
        }
    }
    return NULL;
}

/* Main server loop */
int main() {
    ServerState state;
    server_init(&state);

    set_realtime_priority();
    pin_thread(0);

    if (numa_available() >= 0) {
        numa_set_preferred(0);
    } else {
        fprintf(stderr, "NUMA not available\n");
    }

    state.socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (state.socket_fd == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    if (set_non_blocking(state.socket_fd) < 0) {
        perror("Set non-blocking failed");
        exit(1);
    }

    int opt = 1;
    if (setsockopt(state.socket_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        perror("Set SO_REUSEPORT failed");
    }
    if (setsockopt(state.socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Set SO_REUSEADDR failed");
    }

    /* Disable multicast loopback */
    opt = 0;
    if (setsockopt(state.socket_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &opt, sizeof(opt)) < 0) {
        perror("Disable IP_MULTICAST_LOOP failed");
    }

    /* Set smaller socket buffers */
    int buf_size = 1 * 1024 * 1024; /* 1 MB */
    if (setsockopt(state.socket_fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0) {
        perror("Set SO_RCVBUF failed");
    }
    if (setsockopt(state.socket_fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) < 0) {
        perror("Set SO_SNDBUF failed");
    }

    if (bind(state.socket_fd, (struct sockaddr *)&state.server_addr, sizeof(state.server_addr)) < 0) {
        perror("Bind failed");
        exit(1);
    }

    /* Get actual bound address */
    socklen_t addr_len = sizeof(state.server_addr);
    if (getsockname(state.socket_fd, (struct sockaddr *)&state.server_addr, &addr_len) < 0) {
        perror("Getsockname failed");
        exit(1);
    }
    printf("Server bound to %s:%d\n", inet_ntoa(state.server_addr.sin_addr), ntohs(state.server_addr.sin_port));

    /* Join multicast groups for compatibility */
    struct ip_mreq mreq;
    for (uint8_t npg = 1; npg <= 31; npg++) {
        char mcast_ip[16];
        snprintf(mcast_ip, sizeof(mcast_ip), "239.255.0.%d", npg);
        inet_pton(AF_INET, mcast_ip, &mreq.imr_multiaddr);
        mreq.imr_interface.s_addr = INADDR_ANY;
        if (setsockopt(state.socket_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            perror("Join multicast failed");
        } else {
            printf("Joined multicast group %s\n", mcast_ip);
        }
    }

    state.epoll_fd = epoll_create1(0);
    if (state.epoll_fd == -1) {
        perror("Epoll creation failed");
        exit(1);
    }

    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.fd = state.socket_fd
    };
    if (epoll_ctl(state.epoll_fd, EPOLL_CTL_ADD, state.socket_fd, &ev) < 0) {
        perror("Epoll add socket failed");
        exit(1);
    }

    state.timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (state.timer_fd == -1) {
        perror("Timerfd creation failed");
        exit(1);
    }

    struct itimerspec timer_spec = {
        .it_interval = { .tv_sec = 0, .tv_nsec = TIME_SLOT_INTERVAL_US * 1000 },
        .it_value = { .tv_sec = 0, .tv_nsec = TIME_SLOT_INTERVAL_US * 1000 }
    };
    if (timerfd_settime(state.timer_fd, 0, &timer_spec, NULL) < 0) {
        perror("Timerfd settime failed");
        exit(1);
    }

    ev.events = EPOLLIN;
    ev.data.fd = state.timer_fd;
    if (epoll_ctl(state.epoll_fd, EPOLL_CTL_ADD, state.timer_fd, &ev) < 0) {
        perror("Epoll add timer failed");
        exit(1);
    }

    for (int i = 0; i < THREAD_COUNT; i++) {
        if (pthread_create(&state.workers[i], NULL, worker_thread, &state) != 0) {
            perror("Worker thread creation failed");
            exit(1);
        }
        printf("Started worker thread %d\n", i);
    }

    printf("Link 16 UDP server listening on port %d with %d worker threads...\n", PORT, THREAD_COUNT);

    struct epoll_event events[32]; /* Increased capacity */
    uint8_t buffer[MAX_BUFFER];
    struct iovec iov = { .iov_base = buffer, .iov_len = MAX_BUFFER };
    struct msghdr mhdr = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0
    };

    while (state.running) {
        int nfds = epoll_wait(state.epoll_fd, events, 32, -1);
        if (nfds < 0) {
            perror("Epoll wait failed");
            continue;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == state.socket_fd) {
                uint64_t recv_time = get_time_us();
                struct sockaddr_in client_addr;
                mhdr.msg_name = &client_addr;
                mhdr.msg_namelen = sizeof(client_addr);
                int len = recvmsg(state.socket_fd, &mhdr, 0);
                if (len < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("Recvmsg failed");
                    }
                    continue;
                }
                JMessage msg;
                if (jmessage_deserialize(&msg, buffer, len) >= 0) {
                    if (queue_enqueue(&state, &msg, &client_addr, recv_time) < 0) {
                        fprintf(stderr, "Queue full, dropping message\n");
                    }
                } else {
                    fprintf(stderr, "Deserialization failed, len: %d\n", len);
                }
            } else if (events[i].data.fd == state.timer_fd) {
                uint64_t expirations;
                read(state.timer_fd, &expirations, sizeof(expirations));
                state.current_slot = (state.current_slot + 1) % TADIL_J_FRAME_SLOTS;
            }
        }
    }

    state.running = 0;
    pthread_mutex_lock(&state.queue_mutex);
    pthread_cond_broadcast(&state.queue_cond);
    pthread_mutex_unlock(&state.queue_mutex);
    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(state.workers[i], NULL);
    }
    pthread_cond_destroy(&state.queue_cond);
    pthread_mutex_destroy(&state.queue_mutex);
    close(state.timer_fd);
    close(state.epoll_fd);
    close(state.socket_fd);
    return 0;
}
