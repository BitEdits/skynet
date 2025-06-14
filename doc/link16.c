// gcc -o link16 link16.c j-msg.c -pthread

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
#include <sys/syscall.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <net/if.h>
#include "j-msg.h"

#define PORT 8080
#define MAX_JUS 32
#define MAX_BUFFER 1024
#define JU_ADDRESS_BASE 00001
#define TIME_SLOT_INTERVAL_US 7812 /* 7.8125 ms */
#define THREAD_COUNT 12
#define QUEUE_SIZE 1024
#define MAX_SEQUENCES 64
#define MAX_EVENTS 32

typedef struct {
    atomic_uint claimed; /* 0=free, 1=claimed */
    uint32_t ju_address;
    uint32_t sequence;
    uint64_t timestamp;
} MessageSeq;

typedef struct {
    JMessage messages[QUEUE_SIZE];
    struct sockaddr_in addrs[QUEUE_SIZE];
    uint64_t recv_times[QUEUE_SIZE];
    atomic_uint head;
    atomic_uint tail;
    int event_fds[THREAD_COUNT]; /* One eventfd per worker */
} MessageQueue;

typedef struct {
    struct sockaddr_in addr;
    uint32_t ju_address;
    JURole role;
    uint8_t subscribed_npgs[32];
    uint32_t time_slots[16];
    uint32_t slot_count;
} JUState;

typedef struct {
    JUState jus[MAX_JUS];
    atomic_uint ju_count;
    uint32_t current_slot;
    atomic_int ntr_assigned;
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
} ServerState;

typedef struct {
    ServerState *server;
    int worker_id;
    int epoll_fd;
} WorkerState;

uint64_t get_time_us(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0) {
        return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
    }
    /* Fallback to CLOCK_MONOTONIC */
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        perror("clock_gettime failed");
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
}

void queue_init(MessageQueue *q) {
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

int queue_enqueue(ServerState *state, const JMessage *msg, const struct sockaddr_in *addr, uint64_t recv_time) {
    MessageQueue *q = &state->mq;
    uint32_t head, next_head;
    do {
        head = atomic_load_explicit(&q->head, memory_order_acquire);
        next_head = (head + 1) % QUEUE_SIZE;
        if (next_head == atomic_load_explicit(&q->tail, memory_order_acquire)) {
            fprintf(stderr, "Queue full, dropping message\n");
            return -1;
        }
    } while (!__atomic_compare_exchange_n(&q->head, &head, next_head, false,
                                          memory_order_release, memory_order_acquire));
    q->messages[head] = *msg;
    q->addrs[head] = *addr;
    q->recv_times[head] = recv_time;
    /* Signal all workers */
    uint64_t signal = 1;
    for (int i = 0; i < THREAD_COUNT; i++) {
        if (write(q->event_fds[i], &signal, sizeof(signal)) < 0) {
            perror("Eventfd write failed");
        }
    }
    return 0;
}

int queue_dequeue(ServerState *state, JMessage *msg, struct sockaddr_in *addr, uint64_t *recv_time) {
    MessageQueue *q = &state->mq;
    uint32_t tail, next_tail;
    do {
        tail = atomic_load_explicit(&q->tail, memory_order_acquire);
        if (tail == atomic_load_explicit(&q->head, memory_order_acquire)) {
            return -1;
        }
        next_tail = (tail + 1) % QUEUE_SIZE;
    } while (!__atomic_compare_exchange_n(&q->tail, &tail, next_tail, false,
                                          memory_order_release, memory_order_acquire));
    *msg = q->messages[tail];
    *addr = q->addrs[tail];
    *recv_time = q->recv_times[tail];
    return 0;
}

int set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void pin_thread(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) < 0) {
        perror("Pin thread error");
    }
}

void server_init(ServerState *state) {
    memset(state, 0, sizeof(ServerState));
    state->current_slot = 0;
    atomic_store(&state->ntr_assigned, 0);
    atomic_store(&state->running, 1);
    atomic_store(&state->timer_active, 0);
    queue_init(&state->mq);
    atomic_store(&state->ju_count, 0);
    atomic_store(&state->seq_idx, 0);
    for (int i = 0; i < MAX_SEQUENCES; i++) {
        atomic_store(&state->seqs[i].claimed, 0);
    }
    state->server_addr.sin_family = AF_INET;
    state->server_addr.sin_addr.s_addr = INADDR_ANY;
    state->server_addr.sin_port = htons(PORT);
}

int is_duplicate(ServerState *state, uint32_t ju_addr, uint32_t seq, JMessageType type, struct sockaddr_in *addr) {
    uint64_t current_time = time(NULL);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&current_time));
    uint32_t hash = (ju_addr ^ seq) % MAX_SEQUENCES;
    for (int i = 0; i < MAX_SEQUENCES; i++) {
        uint32_t idx = (hash + i) % MAX_SEQUENCES;
        if (atomic_load_explicit(&state->seqs[idx].claimed, memory_order_acquire) == 0) {
            break;
        }
        if (state->seqs[idx].ju_address == ju_addr && state->seqs[idx].sequence == seq) {
            if (current_time - state->seqs[idx].timestamp < 2) {
                printf("[%s] Dropped duplicate message from JU %05o, type=%d, seq=%u, src=%s:%d\n",
                       time_str, ju_addr, type, seq, inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
                return 1;
            }
        }
    }
    return 0;
}

void record_sequence(ServerState *state, uint32_t ju_addr, uint32_t seq) {
    uint32_t hash = (ju_addr ^ seq) % MAX_SEQUENCES;
    uint32_t idx = atomic_fetch_add_explicit(&state->seq_idx, 1, memory_order_relaxed) % MAX_SEQUENCES;
    for (int i = 0; i < MAX_SEQUENCES; i++) {
        uint32_t probe = (hash + i) % MAX_SEQUENCES;
        uint32_t expected = 0;
        uint32_t desired = 1;
        if (atomic_load_explicit(&state->seqs[probe].claimed, memory_order_acquire) == 0 ||
            time(NULL) - state->seqs[probe].timestamp >= 2) {
            if (__atomic_compare_exchange_n(&state->seqs[probe].claimed, &expected, desired, false,
                                            memory_order_release, memory_order_acquire)) {
                state->seqs[probe].ju_address = ju_addr;
                state->seqs[probe].sequence = seq;
                state->seqs[probe].timestamp = time(NULL);
                break;
            }
        }
    }
}

JUState *find_or_add_ju(ServerState *state, struct sockaddr_in *addr) {
    uint32_t count = atomic_load_explicit(&state->ju_count, memory_order_acquire);
    for (size_t i = 0; i < count; i++) {
        if (memcmp(&state->jus[i].addr, addr, sizeof(*addr)) == 0) {
            return &state->jus[i];
        }
    }
    if (count >= MAX_JUS) {
        fprintf(stderr, "Error: Max JUs reached\n");
        return NULL;
    }
    uint32_t new_count = count + 1;
    if (__atomic_compare_exchange_n(&state->ju_count, &count, new_count, false,
                                    memory_order_release, memory_order_acquire)) {
        JUState *ju = &state->jus[count];
        ju->addr = *addr;
        ju->ju_address = JU_ADDRESS_BASE + count;
        ju->role = JU_ROLE_NON_C2;
        ju->slot_count = 1;
        ju->time_slots[0] = count * 100;
        printf("Added JU %05o from %s:%d\n", ju->ju_address,
               inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
        /* Activate timer if first JU */
        if (new_count == 1 && !atomic_load(&state->timer_active)) {
            struct itimerspec timer_spec = {
                .it_interval = { .tv_sec = 0, .tv_nsec = TIME_SLOT_INTERVAL_US * 1000 },
                .it_value = { .tv_sec = 0, .tv_nsec = TIME_SLOT_INTERVAL_US * 1000 }
            };
            if (timerfd_settime(state->timer_fd, 0, &timer_spec, NULL) < 0) {
                perror("Timerfd settime failed");
            } else {
                atomic_store(&state->timer_active, 1);
            }
        }
        return ju;
    }
    return find_or_add_ju(state, addr);
}

void subscribe_npg(JUState *ju, uint8_t npg) {
    for (int i = 0; i < 32; i++) {
        if (ju->subscribed_npgs[i] == 0 || ju->subscribed_npgs[i] == npg) {
            ju->subscribed_npgs[i] = npg;
            printf("JU %05o subscribed to NPG %d\n", ju->ju_address, npg);
            break;
        }
    }
}

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
        printf("SENT [NPG:%d][seq:%u][multicast:%s] latency [us:%llu]\n",
               msg->npg, msg->time_slot, mcast_ip, send_time - recv_time);
        record_sequence(state, msg->ju_address, msg->time_slot);
    }
}

void process_control(ServerState *state, JUState *ju, JMessage *msg) {
    if (msg->type == J_MSG_INITIAL_ENTRY) {
        subscribe_npg(ju, 1);
        subscribe_npg(ju, 7);
        int expected = 0;
        int desired = 1;
        if (__atomic_compare_exchange_n(&state->ntr_assigned, &expected, desired, false,
                                        memory_order_release, memory_order_acquire)) {
            ju->role = JU_ROLE_NTR;
            subscribe_npg(ju, 4);
        }
        printf("JU %05o joined, role: %d\n", ju->ju_address, ju->role);
    } else if (msg->type == J_MSG_NETWORK_MANAGEMENT && ju->role == JU_ROLE_NTR) {
        printf("Network management from NTR %05o\n", ju->ju_address);
    }
}

void handle_message(ServerState *state, JUState *ju, JMessage *msg, uint64_t recv_time) {
    uint64_t process_time = get_time_us();
    if (msg->time_slot == 0) {
        fprintf(stderr, "Warning: Invalid time_slot=0 from JU %05o, type=%d, src=%s:%d\n",
                ju->ju_address, msg->type, inet_ntoa(ju->addr.sin_addr), ntohs(ju->addr.sin_port));
    }
    if (msg->npg > 0 && memcmp(&ju->addr, &state->server_addr, sizeof(struct sockaddr_in)) == 0) {
        printf("Dropped self-sent message from JU %05o, type=%d, seq=%u, latency %llu us\n",
               ju->ju_address, msg->type, msg->time_slot, process_time - recv_time);
        return;
    }
    if (is_duplicate(state, msg->ju_address, msg->time_slot, msg->type, &ju->addr)) {
        return;
    }
    printf("RCVD [NPG:%d][seq:%u][ju:%05o][type:%d][src:%s:%d] latency [us:%llu]\n",
           msg->npg, msg->time_slot, ju->ju_address, msg->type,
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

void *worker_thread(void *arg) {
    WorkerState *ws = (WorkerState *)arg;
    ServerState *state = ws->server;
    int worker_id = ws->worker_id;
    int epoll_fd = ws->epoll_fd;
    pin_thread(worker_id);

    struct epoll_event events[1];
    while (atomic_load_explicit(&state->running, memory_order_acquire)) {
        int nfds = epoll_wait(epoll_fd, events, 1, -1);
        if (nfds < 0) {
            if (errno != EINTR) perror("Worker epoll_wait failed");
            continue;
        }
        if (nfds > 0) {
            uint64_t count;
            read(state->mq.event_fds[worker_id], &count, sizeof(count));
            JMessage msg;
            struct sockaddr_in addr;
            uint64_t recv_time;
            while (queue_dequeue(state, &msg, &addr, &recv_time) == 0) {
                JUState *ju = find_or_add_ju(state, &addr);
                if (ju) {
                    handle_message(state, ju, &msg, recv_time);
                }
            }
        }
    }
    close(epoll_fd);
    close(state->mq.event_fds[worker_id]);
    free(ws);
    return NULL;
}

int main() {
    ServerState state;
    server_init(&state);
    pin_thread(0);

    state.socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (state.socket_fd == -1) {
        perror("Socket creation failed");
        exit(1);
    }
    if (set_non_blocking(state.socket_fd) < 0) {
        perror("Set non-blocking failed");
        close(state.socket_fd);
        exit(1);
    }
    int opt = 1;
    if (setsockopt(state.socket_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        perror("Set SO_REUSEPORT failed");
        close(state.socket_fd);
        exit(1);
    }
    if (setsockopt(state.socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Set SO_REUSEADDR failed");
        close(state.socket_fd);
        exit(1);
    }
    opt = 0;
    if (setsockopt(state.socket_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &opt, sizeof(opt)) < 0) {
        perror("Disable IP_MULTICAST_LOOP failed");
        close(state.socket_fd);
        exit(1);
    }
    int buf_size = 1 * 1024 * 1024;
    if (setsockopt(state.socket_fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0) {
        perror("Set SO_RCVBUF failed");
        close(state.socket_fd);
        exit(1);
    }
    if (setsockopt(state.socket_fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) < 0) {
        perror("Set SO_SNDBUF failed");
        close(state.socket_fd);
        exit(1);
    }
    if (bind(state.socket_fd, (struct sockaddr *)&state.server_addr, sizeof(state.server_addr)) < 0) {
        perror("Bind failed");
        close(state.socket_fd);
        exit(1);
    }
    socklen_t addr_len = sizeof(state.server_addr);
    if (getsockname(state.socket_fd, (struct sockaddr *)&state.server_addr, &addr_len) < 0) {
        perror("Getsockname failed");
        close(state.socket_fd);
        exit(1);
    }
    printf("Server bound to %s:%d\n", inet_ntoa(state.server_addr.sin_addr), ntohs(state.server_addr.sin_port));
    uint8_t npgs[] = {1, 4, 7};
    struct ip_mreq mreq;
    for (size_t i = 0; i < sizeof(npgs) / sizeof(npgs[0]); i++) {
        uint8_t npg = npgs[i];
        char mcast_ip[16];
        snprintf(mcast_ip, sizeof(mcast_ip), "239.255.0.%d", npg);
        inet_pton(AF_INET, mcast_ip, &mreq.imr_multiaddr);
        mreq.imr_interface.s_addr = INADDR_ANY;
        if (setsockopt(state.socket_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            fprintf(stderr, "Warning: Failed to join multicast group %s: %s\n", mcast_ip, strerror(errno));
        } else {
            printf("Joined multicast group %s\n", mcast_ip);
        }
    }
    state.epoll_fd = epoll_create1(0);
    if (state.epoll_fd == -1) {
        perror("Epoll creation failed");
        close(state.socket_fd);
        exit(1);
    }
    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.fd = state.socket_fd
    };
    if (epoll_ctl(state.epoll_fd, EPOLL_CTL_ADD, state.socket_fd, &ev) < 0) {
        perror("Epoll add socket failed");
        close(state.epoll_fd);
        close(state.socket_fd);
        exit(1);
    }
    state.timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (state.timer_fd == -1) {
        perror("Timerfd creation failed");
        close(state.epoll_fd);
        close(state.socket_fd);
        exit(1);
    }
    ev.events = EPOLLIN;
    ev.data.fd = state.timer_fd;
    if (epoll_ctl(state.epoll_fd, EPOLL_CTL_ADD, state.timer_fd, &ev) < 0) {
        perror("Epoll add timer failed");
        close(state.timer_fd);
        close(state.epoll_fd);
        close(state.socket_fd);
        exit(1);
    }
    for (int i = 0; i < THREAD_COUNT; i++) {
        WorkerState *ws = malloc(sizeof(WorkerState));
        ws->server = &state;
        ws->worker_id = i;
        ws->epoll_fd = epoll_create1(0);
        if (ws->epoll_fd < 0) {
            perror("Worker epoll creation failed");
            exit(1);
        }
        ev.events = EPOLLIN;
        ev.data.fd = state.mq.event_fds[i];
        if (epoll_ctl(ws->epoll_fd, EPOLL_CTL_ADD, state.mq.event_fds[i], &ev) < 0) {
            perror("Worker epoll add eventfd failed");
            exit(1);
        }
        if (pthread_create(&state.workers[i], NULL, worker_thread, ws) != 0) {
            perror("Worker thread creation failed");
            exit(1);
        }
        printf("Started worker thread %d\n", i);
    }
    printf("Link 16 Multicast UDP server listening on port %d with %d worker threads...\n", PORT, THREAD_COUNT);
    struct epoll_event events[MAX_EVENTS];
    uint8_t buffer[MAX_BUFFER];
    struct iovec iov = { .iov_base = buffer, .iov_len = MAX_BUFFER };
    struct msghdr mhdr = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0
    };
    while (atomic_load_explicit(&state.running, memory_order_acquire)) {
        int nfds = epoll_wait(state.epoll_fd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            if (errno != EINTR) perror("Epoll wait failed");
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
                /* Disable timer if no JUs */
                if (atomic_load(&state.ju_count) == 0 && atomic_load(&state.timer_active)) {
                    struct itimerspec timer_spec = { .it_interval = {0}, .it_value = {0} };
                    if (timerfd_settime(state.timer_fd, 0, &timer_spec, NULL) < 0) {
                        perror("Timerfd disable failed");
                    }
                    atomic_store(&state.timer_active, 0);
                }
            }
        }
    }
    atomic_store_explicit(&state.running, 0, memory_order_release);
    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(state.workers[i], NULL);
    }
    for (int i = 0; i < THREAD_COUNT; i++) {
        close(state.mq.event_fds[i]);
    }
    close(state.timer_fd);
    close(state.epoll_fd);
    close(state.socket_fd);
    return 0;
}
