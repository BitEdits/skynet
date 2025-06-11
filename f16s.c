// sudo apt-get install libnuma-dev
// gcc -o f16s f16s.c j-msg.c -pthread -lnuma

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
#include "j-msg.h"

#define PORT 8080
#define MAX_JUS 32
#define MAX_BUFFER 1024
#define JU_ADDRESS_BASE 00001
#define TIME_SLOT_INTERVAL_US 7812 /* 7.8125 ms in microseconds */
#define FRAME_SLOTS TADIL_J_FRAME_SLOTS
#define MULTICAST_BASE "239.255.0.0"
#define THREAD_COUNT sysconf(_SC_NPROCESSORS_ONLN) /* Default to CPU core count */
#define QUEUE_SIZE 1024 /* Lock-free queue capacity */

/* Lock-free ring buffer */
typedef struct {
    JMessage messages[QUEUE_SIZE];
    struct sockaddr_in addrs[QUEUE_SIZE];
    atomic_uint head;
    atomic_uint tail;
} MessageQueue;

/* JU State */
typedef struct {
    struct sockaddr_in addr;    /* Client address */
    uint32_t ju_address;        /* JU address */
    JURole role;                /* JU role */
    uint8_t subscribed_npgs[32]; /* Subscribed NPGs */
    uint32_t time_slots[16];    /* Assigned time slots */
    uint32_t slot_count;        /* Number of assigned slots */
} JUState;

/* Server State */
typedef struct {
    JUState jus[MAX_JUS];       /* Known JUs */
    atomic_uint ju_count;       /* Number of JUs */
    uint32_t current_slot;      /* Current time slot */
    int ntr_assigned;           /* NTR assigned flag */
    int sock_fd;                /* UDP socket */
    int epoll_fd;               /* Epoll instance */
    int timer_fd;               /* Timer for TDMA slots */
    MessageQueue queue;         /* Lock-free queue */
    pthread_t workers[THREAD_COUNT]; /* Worker threads */
    int running;                /* Server running flag */
} ServerState;

/* Initialize message queue */
void queue_init(MessageQueue *q) {
    q->head = 0;
    q->tail = 0;
}

/* Enqueue message */
int queue_enqueue(MessageQueue *q, const JMessage *msg, const struct sockaddr_in *addr) {
    uint32_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
    uint32_t next_head = (head + 1) % QUEUE_SIZE;
    if (next_head == atomic_load_explicit(&q->tail, memory_order_acquire)) {
        return -1; /* Queue full */
    }
    q->messages[head] = *msg;
    q->addrs[head] = *addr;
    atomic_store_explicit(&q->head, next_head, memory_order_release);
    return 0;
}

/* Dequeue message */
int queue_dequeue(MessageQueue *q, JMessage *msg, struct sockaddr_in *addr) {
    uint32_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    if (tail == atomic_load_explicit(&q->head, memory_order_acquire)) {
        return -1; /* Queue empty */
    }
    *msg = q->messages[tail];
    *addr = q->addrs[tail];
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
    struct sched_param param;
    param.sched_priority = 99; /* Highest FIFO priority */
    if (sched_setscheduler(0, SCHED_FIFO, &param) < 0) {
        perror("Set real-time scheduling failed");
    }
}

/* Pin thread to CPU core */
void pin_thread(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
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
    queue_init(&state->queue);
    atomic_store(&state->ju_count, 0);
}

/* Find or add JU by address */
JUState *find_or_add_ju(ServerState *state, struct sockaddr_in *addr) {
    for (uint32_t i = 0; i < atomic_load(&state->ju_count); i++) {
        if (memcmp(&state->jus[i].addr, addr, sizeof(*addr)) == 0) {
            return &state->jus[i];
        }
    }
    uint32_t count = atomic_load(&state->ju_count);
    if (count >= MAX_JUS) {
        printf("Max JUs reached\n");
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
        printf("Added JU %05o\n", ju->ju_address);
        return ju;
    }
    return find_or_add_ju(state, addr); /* Retry if CAS failed */
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
void send_to_npg(ServerState *state, const JMessage *msg) {
    uint8_t buffer[MAX_BUFFER];
    int len = jmessage_serialize(msg, buffer, MAX_BUFFER);
    if (len < 0) {
        printf("Serialization failed\n");
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

    if (sendmsg(state->sock_fd, &mhdr, 0) < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("Sendmsg failed");
        }
    } else {
        printf("Sent to NPG %d multicast %s\n", msg->npg, mcast_ip);
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

/* Process message */
void handle_message(ServerState *state, JUState *ju, JMessage *msg) {
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
            send_to_npg(state, msg);
            jmessage_print(msg);
            break;
        default:
            printf("Unsupported message type: %d\n", msg->type);
    }
}

/* Worker thread function */
void *worker_thread(void *arg) {
    ServerState *state = (ServerState *)arg;
    int core_id = syscall(SYS_gettid) % THREAD_COUNT; /* Simple core assignment */
    pin_thread(core_id);
    set_realtime_priority();

    /* NUMA-aware memory allocation */
    if (numa_available() >= 0) {
        numa_set_preferred(numa_node_of_cpu(core_id));
    }

    while (state->running) {
        JMessage msg;
        struct sockaddr_in addr;
        if (queue_dequeue(&state->queue, &msg, &addr) == 0) {
            JUState *ju = find_or_add_ju(state, &addr);
            if (ju) {
                handle_message(state, ju, &msg);
            }
        } else {
            usleep(1); /* Avoid busy looping */
        }
    }
    return NULL;
}

/* Main server loop */
int main() {
    ServerState state;
    server_init(&state);

    /* Set real-time scheduling for main thread */
    set_realtime_priority();
    pin_thread(0);

    /* NUMA-aware memory allocation */
    if (numa_available() >= 0) {
        numa_set_preferred(0);
    }

    /* Create UDP socket */
    state.sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (state.sock_fd == -1) {
        perror("Socket creation failed");
        exit(1);
    }

    if (set_non_blocking(state.sock_fd) < 0) {
        perror("Set non-blocking failed");
        exit(1);
    }

    /* Enable SO_REUSEPORT and checksum offloading */
    int opt = 1;
    if (setsockopt(state.sock_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        perror("Set SO_REUSEPORT failed");
    }
    if (setsockopt(state.sock_fd, SOL_SOCKET, SO_NO_CHECK, &opt, sizeof(opt)) < 0) {
        perror("Set SO_NO_CHECK failed");
    }

    /* Set large socket buffers */
    int buf_size = 8 * 1024 * 1024; /* 8MB */
    if (setsockopt(state.sock_fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size)) < 0) {
        perror("Set SO_RCVBUF failed");
    }
    if (setsockopt(state.sock_fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size)) < 0) {
        perror("Set SO_SNDBUF failed");
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(state.sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(1);
    }

    /* Join multicast groups for NPGs */
    struct ip_mreq mreq;
    for (uint8_t npg = 1; npg <= 31; npg++) {
        char mcast_ip[16];
        snprintf(mcast_ip, sizeof(mcast_ip), "239.255.0.%d", npg);
        inet_pton(AF_INET, mcast_ip, &mreq.imr_multiaddr);
        mreq.imr_interface.s_addr = INADDR_ANY;
        if (setsockopt(state.sock_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            perror("Join multicast failed");
        }
    }

    /* Create epoll instance */
    state.epoll_fd = epoll_create1(0);
    if (state.epoll_fd == -1) {
        perror("Epoll creation failed");
        exit(1);
    }

    /* Add UDP socket to epoll */
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = state.sock_fd;
    if (epoll_ctl(state.epoll_fd, EPOLL_CTL_ADD, state.sock_fd, &ev) < 0) {
        perror("Epoll add socket failed");
        exit(1);
    }

    /* Create timerfd for TDMA slots */
    state.timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (state.timer_fd == -1) {
        perror("Timerfd creation failed");
        exit(1);
    }

    struct itimerspec timer_spec;
    timer_spec.it_interval.tv_sec = 0;
    timer_spec.it_interval.tv_nsec = TIME_SLOT_INTERVAL_US * 1000;
    timer_spec.it_value.tv_sec = 0;
    timer_spec.it_value.tv_nsec = TIME_SLOT_INTERVAL_US * 1000;
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

    /* Spawn worker threads */
    for (int i = 0; i < THREAD_COUNT; i++) {
        if (pthread_create(&state.workers[i], NULL, worker_thread, &state) != 0) {
            perror("Worker thread creation failed");
            exit(1);
        }
        printf("Started worker thread %d\n", i);
    }

    printf("Link 16 UDP server listening on port %d with %d worker threads...\n", PORT, THREAD_COUNT);

    struct epoll_event events[10];
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
        int nfds = epoll_wait(state.epoll_fd, events, 10, -1);
        if (nfds < 0) {
            perror("Epoll wait failed");
            continue;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == state.sock_fd) {
                /* Receive message */
                struct sockaddr_in client_addr;
                mhdr.msg_name = &client_addr;
                mhdr.msg_namelen = sizeof(client_addr);
                int len = recvmsg(state.sock_fd, &mhdr, 0);
                if (len < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        perror("Recvmsg failed");
                    }
                    continue;
                }
                JMessage msg;
                if (jmessage_deserialize(&msg, buffer, len) >= 0) {
                    if (queue_enqueue(&state.queue, &msg, &client_addr) < 0) {
                        printf("Queue full, dropping message\n");
                    }
                } else {
                    printf("Deserialization failed\n");
                }
            } else if (events[i].data.fd == state.timer_fd) {
                /* Advance TDMA slot */
                uint64_t expirations;
                read(state.timer_fd, &expirations, sizeof(expirations));
                state.current_slot = (state.current_slot + 1) % FRAME_SLOTS;
                printf("Advanced to slot %u\n", state.current_slot);
            }
        }
    }

    state.running = 0;
    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(state.workers[i], NULL);
    }
    close(state.timer_fd);
    close(state.epoll_fd);
    close(state.sock_fd);
    return 0;
}
