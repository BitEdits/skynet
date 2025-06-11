// gcc -o f16c f16c.c j-msg.c

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
#define TIME_SLOT_INTERVAL_US 7812
#define THREAD_COUNT 4
#define QUEUE_SIZE 1024
#define MAX_SEQUENCES 64

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
} ServerState;

static uint64_t get_time_us(void) {
 struct timespec ts;
 clock_gettime(CLOCK_MONOTONIC, &ts);
 return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
}

void queue_init(MessageQueue *q) {
 atomic_store(&q->head, 0);
 atomic_store(&q->tail, 0);
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

void set_realtime_priority() {
 struct sched_param param = { .sched_priority = 99 };
 if (sched_setscheduler(0, SCHED_FIFO, &param) < 0) {
 perror("Set real-time scheduling failed");
 }
}

void pin_thread(int core_id) {
 cpu_set_t cpuset;
 CPU_ZERO(&cpuset);
 CPU_SET(core_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
 if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) < 0) {
 perror("Pin thread failed");
 }
}

void server_init(ServerState *state) {
 memset(state, 0, sizeof(ServerState));
 state->current_slot = 0;
 atomic_store(&state->ntr_assigned, 0);
 atomic_store(&state->running, 1);
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
 uint32_t hash = (ju_addr ^ seq) % MAX_SEQUENCES;
 for (int i = 0; i < MAX_SEQUENCES; i++) {
 uint32_t idx = (hash + i) % MAX_SEQUENCES;
 if (atomic_load_explicit(&state->seqs[idx].claimed, memory_order_acquire) == 0) {
 break;
 }
 if (state->seqs[idx].ju_address == ju_addr && state->seqs[idx].sequence == seq) {
 if (current_time - state->seqs[idx].timestamp < 10) {
 printf("Dropped duplicate message from JU %05o, type=%d, seq=%u, src=%s:%d\n",
 ju_addr, type, seq, inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
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
 if (atomic_load_explicit(&state->seqs[probe].claimed , memory_order_acquire) == 0 ||
 time(NULL) - state->seqs[probe].timestamp >= 10) {
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
 for (uint32_t i = 0; i < count; i++) {
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
 return ju;
 }
 return 

