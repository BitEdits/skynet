// gcc -o skynet skynet.c -pthread -lcrypto

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
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define PORT 6566                    // SkyNet Port
#define MAX_NODES 2000               // Support 1000 infantry nodes + 1000 drones (Phase II)
#define MAX_BUFFER 1490              // Max SkyNetMessage size
#define TIME_SLOT_INTERVAL_US 1000   // 1 ms TDMA slots (1,000 slots/s)
#define THREAD_COUNT 4               // Fewer threads for Raspberry Pi
#define QUEUE_SIZE 1024              // Message queue size
#define MAX_SEQUENCES 64             // Deduplication table size
#define MAX_EVENTS 32                // Epoll events
#define PERCEPTION_RADIUS 5.0        // For drone neighbor discovery (meters)
#define NEIGHBOR_TIMEOUT_US 500000   // 0.5 s timeout for neighbor removal

#define SKYNET_VERSION 1             /* Protocol version */
#define SKYNET_MAX_NODES 100         /* Max nodes (Phase II, roadmap to 1,000) */
#define SKYNET_MAX_PAYLOAD 400       /* Max payload size (bytes) */
#define SKYNET_TIME_SLOT_US 1000     /* TDMA slot duration (1 ms, 1,000 slots/s) */
#define SKYNET_NPG_MAX 255           /* Highest NPG ID */
#define SKYNET_MAX_HOPS 5            /* Max hop count for OLSR mesh */
#define SKYNET_FREQ_MIN_MHZ 400      /* UHF minimum frequency (MHz) */
#define SKYNET_FREQ_MAX_MHZ 470      /* UHF maximum frequency (MHz) */
#define SKYNET_HOPS_PER_SEC 100      /* FHSS hops per second */
#define SKYNET_QOS_CHAT 0            /* QoS for chat (CSMA) */
#define SKYNET_QOS_PLI 1             /* QoS for PLI (TDMA) */
#define SKYNET_QOS_VOICE 2           /* QoS for voice (reserved) */
#define SKYNET_QOS_C2 3              /* QoS for C2 (TDMA) */

/* Network Participation Groups (NPGs) */
#define SKYNET_NPG_CONTROL 1         /* Control: slot requests, key exchange */
#define SKYNET_NPG_PLI 6             /* PLI: position, velocity, status */
#define SKYNET_NPG_SURVEILLANCE 7    /* Surveillance: sensor data */
#define SKYNET_NPG_CHAT 29           /* TacChat: group chat */
#define SKYNET_NPG_C2 100            /* C2: waypoints, formations */
#define SKYNET_NPG_ALERTS 101        /* Alerts: failures, self-healing */
#define SKYNET_NPG_LOGISTICS 102     /* Logistics: supply chain */
#define SKYNET_NPG_COORD 103         /* Inter-agent coordination */

typedef enum {

    // Ground Vehicles (Army, Marine Corps):

    // Armored Fighting Vehicles
    VEHICLE_M1_ABRAMS = 0,           // M1A1/A2 Main Battle Tank
    VEHICLE_M2_BRADLEY,              // M2/M3 Infantry/Cavalry Fighting Vehicle
    VEHICLE_M1126_STRYKER,           // Stryker Infantry Carrier Vehicle
    VEHICLE_M113_APC,                // M113 Armored Personnel Carrier
    VEHICLE_AMPV,                    // Armored Multi-Purpose Vehicle
    VEHICLE_M10_BOOKER,              // M10 Booker Mobile Protected Firepower
    VEHICLE_TERREX_ICV,              // Terrex Infantry Carrier (testing)

    // Reconnaissance and Light Vehicles
    VEHICLE_HMMWV,                   // Humvee (M998, M1151, etc.)
    VEHICLE_JLTV,                    // Joint Light Tactical Vehicle
    VEHICLE_MRAP,                    // Mine-Resistant Ambush Protected (MaxxPro, Cougar)
    VEHICLE_LAV_25,                  // Light Armored Vehicle (Marine Corps)
    VEHICLE_ISV,                     // Infantry Squad Vehicle (GM Defense)

    // Artillery and Support
    VEHICLE_M109_PALADIN,            // M109A7 Self-Propelled Howitzer
    VEHICLE_M142_HIMARS,             // High Mobility Artillery Rocket System
    VEHICLE_M270_MLRS,               // Multiple Launch Rocket System
    VEHICLE_M88_HERCULES,            // M88A2 Recovery Vehicle
    VEHICLE_M9_ACE,                  // M9 Armored Combat Earthmover

    // Logistics and Transport
    VEHICLE_HEMTT,                   // Heavy Expanded Mobility Tactical Truck
    VEHICLE_LMTV,                    // Light Medium Tactical Vehicle
    VEHICLE_FMTV,                    // Family of Medium Tactical Vehicles
    VEHICLE_M1070_HET,               // Heavy Equipment Transporter
    VEHICLE_PLS,                     // Palletized Load System

    // Unmanned Ground Vehicles
    VEHICLE_RCV_L,                   // Robotic Combat Vehicle (Light)
    VEHICLE_RCV_M,                   // Robotic Combat Vehicle (Medium)
    VEHICLE_S_MMET,                  // Small Multipurpose Equipment Transport

    // Air Vehicles (Army, Air Force, Navy, Marine Corps):

    // Fixed-Wing Aircraft
    VEHICLE_F_15_EAGLE,              // F-15C/D/E Strike Eagle
    VEHICLE_F_16_FALCON,             // F-16C/D Fighting Falcon
    VEHICLE_F_22_RAPTOR,             // F-22A Stealth Fighter
    VEHICLE_F_35_LIGHTNING,          // F-35A/B/C Joint Strike Fighter
    VEHICLE_A_10_THUNDERBOLT,        // A-10C Warthog
    VEHICLE_B_1_LANCER,              // B-1B Supersonic Bomber
    VEHICLE_B_2_SPIRIT,              // B-2A Stealth Bomber
    VEHICLE_B_21_RAIDER,             // B-21 Raider (in development)
    VEHICLE_C_130_HERCULES,          // C-130H/J Transport
    VEHICLE_C_17_GLOBEMASTER,        // C-17A Transport
    VEHICLE_C_5_GALAXY,              // C-5M Super Galaxy
    VEHICLE_KC_135_STRATOTANKER,     // KC-135R/T Refueler
    VEHICLE_KC_46_PEGASUS,           // KC-46A Refueler
    VEHICLE_E_3_SENTRY,              // E-3G AWACS
    VEHICLE_E_8_JSTARS,              // E-8C Joint STARS
    VEHICLE_U_2_DRAGON_LADY,         // U-2S Reconnaissance
    VEHICLE_P_8_POSEIDON,            // P-8A Maritime Patrol
    VEHICLE_C_12_HURON,              // C-12J Utility
    VEHICLE_C_40_CLIPPER,            // C-40A/B Transport

    // Rotary-Wing Aircraft
    VEHICLE_AH_64_APACHE,            // AH-64D/E Attack Helicopter
    VEHICLE_UH_60_BLACK_HAWK,        // UH-60L/M Utility Helicopter
    VEHICLE_CH_47_CHINOOK,           // CH-47F Heavy-Lift Helicopter
    VEHICLE_AH_1Z_VIPER,             // Marine Corps Attack Helicopter
    VEHICLE_UH_1Y_VENOM,             // Marine Corps Utility Helicopter
    VEHICLE_CH_53K_KING_STALLION,    // Marine Corps Heavy-Lift Helicopter
    VEHICLE_MH_60_SEAHAWK,           // Navy Multi-Mission Helicopter
    VEHICLE_V_22_OSPREY,             // Tiltrotor Transport

    // Unmanned Aerial Vehicles
    VEHICLE_MQ_9_REAPER,             // MQ-9A Armed Drone
    VEHICLE_RQ_4_GLOBAL_HAWK,        // RQ-4B High-Altitude UAV
    VEHICLE_MQ_1C_GRAY_EAGLE,        // Army Reconnaissance UAV
    VEHICLE_RQ_7_SHADOW,             // Army Tactical UAV
    VEHICLE_RQ_11_RAVEN,             // Small Hand-Launched UAV
    VEHICLE_CQ_10_SNOWGOOSE,         // Cargo UAV
    VEHICLE_MQ_25_STINGRAY,          // Navy Carrier-Based Refueling UAV
    VEHICLE_X_47B,                   // Experimental Stealth UAV

    // Air Defense and Support
    VEHICLE_PATRIOT_PAC_3,           // Patriot Missile System (mobile launcher)
    VEHICLE_THAAD,                   // Terminal High Altitude Area Defense
    VEHICLE_AVENGER,                 // AN/TWQ-1 Air Defense System

    // Sea Vehicles (Navy, Marine Corps, Coast Guard):

    // Aircraft Carriers
    VEHICLE_CVN_NIMITZ,              // Nimitz-class Nuclear Carrier
    VEHICLE_CVN_FORD,                // Gerald R. Ford-class Nuclear Carrier

    // Surface Combatants
    VEHICLE_DDG_ARLEIGH_BURKE,       // Arleigh Burke-class Destroyer
    VEHICLE_CG_TICONDEROGA,          // Ticonderoga-class Cruiser
    VEHICLE_FFG_CONSTELLATION,       // Constellation-class Frigate
    VEHICLE_LCS_FREEDOM,             // Freedom-class Littoral Combat Ship
    VEHICLE_LCS_INDEPENDENCE,        // Independence-class Littoral Combat Ship

    // Amphibious Ships
    VEHICLE_LHA_AMERICA,             // America-class Amphibious Assault Ship
    VEHICLE_LHD_WASP,                // Wasp-class Amphibious Assault Ship
    VEHICLE_LPD_SAN_ANTONIO,         // San Antonio-class Amphibious Transport Dock
    VEHICLE_LSD_HARPER_FERRY,        // Harpers Ferry-class Dock Landing Ship

    // Submarines
    VEHICLE_SSN_VIRGINIA,            // Virginia-class Attack Submarine
    VEHICLE_SSN_LOS_ANGELES,         // Los Angeles-class Attack Submarine
    VEHICLE_SSBN_OHIO,               // Ohio-class Ballistic Missile Submarine
    VEHICLE_SSGN_OHIO,               // Ohio-class Guided Missile Submarine

    // Support and Logistics Ships
    VEHICLE_T_AKE_LEWIS_CLARK,       // Lewis and Clark-class Dry Cargo Ship
    VEHICLE_T_AO_JOHN_LEWIS,         // John Lewis-class Fleet Replenishment Oiler
    VEHICLE_T_ATF_POWHATAN,          // Powhatan-class Fleet Ocean Tug
    VEHICLE_T_AH_MERCY,              // Mercy-class Hospital Ship

    // Coast Guard Cutters
    VEHICLE_WMSL_LEGEND,             // Legend-class National Security Cutter
    VEHICLE_WPC_SENTINEL,            // Sentinel-class Fast Response Cutter
    VEHICLE_WMEC_BEAR,               // Bear-class Medium Endurance Cutter
    VEHICLE_WPB_ISLAND,              // Island-class Patrol Boat

    // Unmanned Surface/Subsurface Vehicles
    VEHICLE_ORCA_XLUUV,              // Orca Extra Large Unmanned Undersea Vehicle
    VEHICLE_MUSV,                    // Medium Unmanned Surface Vehicle
    VEHICLE_LUSV,                    // Large Unmanned Surface Vehicle

    // Landing Craft
    VEHICLE_LCAC,                    // Landing Craft Air Cushion
    VEHICLE_LCU_1700,                // Landing Craft Utility
    VEHICLE_SSC_SHIP_TO_SHORE,       // Ship-to-Shore Connector

    // Space Vehicles (Space Force, Air Force):

    // Satellites
    VEHICLE_GPS_III,                 // GPS III Navigation Satellite
    VEHICLE_AEHF,                    // Advanced Extremely High Frequency Satellite
    VEHICLE_SBIRS,                   // Space-Based Infrared System Satellite
    VEHICLE_WGS,                     // Wideband Global SATCOM Satellite

    // Spacecraft
    VEHICLE_X_37B,                   // Boeing X-37B Orbital Test Vehicle
    VEHICLE_CST_100_STARLINER,       // Crew/Cargo Spacecraft (used by USAF)

    // Launch Vehicles
    VEHICLE_FALCON_9,                // SpaceX Falcon 9 (DoD launches)
    VEHICLE_FALCON_HEAVY,            // SpaceX Falcon Heavy
    VEHICLE_ATLAS_V,                 // ULA Atlas V
    VEHICLE_DELTA_IV,                // ULA Delta IV Heavy
    VEHICLE_VULCAN_CENTAUR,          // ULA Vulcan Centaur (emerging)

    // End of Enum
    VEHICLE_COUNT                    // Total number of vehicle types
} USMilitaryVehicleType;

/* Message Types */
typedef enum {
    SKYNET_MSG_PUBLIC = 0,       /* Group chat (TacChat) */
    SKYNET_MSG_CHAT,             /* Private chat (TacChat) */
    SKYNET_MSG_ACK,              /* Acknowledgment */
    SKYNET_MSG_KEY_EXCHANGE,     /* ECDH key exchange */
    SKYNET_MSG_SLOT_REQUEST,     /* TDMA slot request */
    SKYNET_MSG_WAYPOINT,         /* C2 waypoint command */
    SKYNET_MSG_STATUS,           /* PLI or surveillance data */
    SKYNET_MSG_FORMATION         /* C2 formation command */
} MessageType;

/* Node Roles */
typedef enum {
    NODE_ROLE_INFANTRY = 0,         /* Infantry node (TacChat) */
    NODE_ROLE_DRONE,                /* Drone (Swarm C2) */
    NODE_ROLE_RELAY,                /* Drone acting as relay */
    NODE_ROLE_CONTROLLER,           /* Swarm controller */
    NODE_ROLE_GROUND_VEHICLE,       /* Armored Fighting, Reconnaissance and Light, Artillery and Support, Logistics and Transport, Unmanned Ground Vehicles */
    NODE_ROLE_AIR_VEHICLE,          /* Fixed-Wing Aircraft, Rotary-Wing Aircraft, Unmanned Aerial Vehicles, Air Defense and Support */
    NODE_ROLE_SEA_VEHICLE,          /* Aircraft Carriers, Surface Combatants, Amphibious Ships, Submarines,  Support and Logistics Ships, Coast Guard Cutters, Unmanned Surface/Subsurface Vehicles, Landing Crafts, */
    NODE_ROLE_SPACE_VEHICLE,        /* Satellites, Spacecraft, Launch Vehicles  */
} NodeRole;

// SkyNetMessage structure (from project scope)
typedef struct {
    uint8_t version;      // 1
    uint8_t type;         // 0=chat, 1=ack, 2=key_exchange, 3=slot_request, 4=waypoint, 5=status, 6=formation
    uint32_t npg_id;      // NPG/swarm_id (1–1000)
    uint32_t node_id;     // Unique node ID
    uint32_t seq_no;      // Deduplication
    uint64_t timestamp;   // Relative time (us)
    uint8_t qos;          // 0=chat, 1=PLI, 2=voice, 3=swarm_cmd
    uint8_t hop_count;    // 0–3
    uint8_t iv[16];       // AES-256-GCM IV
    uint16_t payload_len; // 0–400 bytes
    uint8_t payload[400]; // Encrypted: chat, PLI, waypoint, status, formation
    uint8_t hmac[32];     // HMAC-SHA256
    uint32_t crc;         // CRC-32
} SkyNetMessage;

// Node state
typedef struct {
    struct sockaddr_in addr;    // Network address
    uint32_t node_id;          // Unique ID
    NodeRole role;             // Role
    uint8_t subscribed_npgs[32]; // Subscribed NPGs
    uint64_t last_seen;        // Timestamp (us) for self-healing
    float position[3];         // [x, y, z] for PLI
    float velocity[3];         // [x, y, z] for flocking
} NodeState;

// Message sequence for deduplication
typedef struct {
    atomic_uint claimed; // 0=free, 1=claimed
    uint32_t node_id;
    uint32_t seq_no;
    uint64_t timestamp;
} MessageSeq;

// Message queue
typedef struct {
    SkyNetMessage messages[QUEUE_SIZE];
    struct sockaddr_in addrs[QUEUE_SIZE];
    uint64_t recv_times[QUEUE_SIZE];
    atomic_uint head;
    atomic_uint tail;
    int event_fds[THREAD_COUNT]; // One eventfd per worker
} MessageQueue;

// Server state
typedef struct {
    NodeState nodes[MAX_NODES];
    atomic_uint node_count;
    uint32_t current_slot; // TDMA slot
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
    uint8_t aes_key[32]; // AES-256-GCM key
    uint8_t hmac_key[32]; // HMAC-SHA256 key
} ServerState;

// Worker state
typedef struct {
    ServerState *server;
    int worker_id;
    int epoll_fd;
} WorkerState;

// Utility functions
static uint64_t get_time_us(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0) {
        return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
    }
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

static int verify_hmac(const SkyNetMessage *msg, const uint8_t *hmac_key) {
    unsigned char computed_hmac[32];
    uint32_t data_len = 1 + 1 + 4 + 4 + 4 + 8 + 1 + 1 + 16 + 2 + msg->payload_len;
    uint8_t *data = malloc(data_len);
    if (!data) return -1;
    size_t offset = 0;
    data[offset++] = msg->version;
    data[offset++] = msg->type;
    *(uint32_t *)(data + offset) = htonl(msg->npg_id); offset += 4;
    *(uint32_t *)(data + offset) = htonl(msg->node_id); offset += 4;
    *(uint32_t *)(data + offset) = htonl(msg->seq_no); offset += 4;
    *(uint64_t *)(data + offset) = htobe64(msg->timestamp); offset += 8;
    data[offset++] = msg->qos;
    data[offset++] = msg->hop_count;
    memcpy(data + offset, msg->iv, 16); offset += 16;
    *(uint16_t *)(data + offset) = htons(msg->payload_len); offset += 2;
    memcpy(data + offset, msg->payload, msg->payload_len);
    HMAC(EVP_sha256(), hmac_key, 32, data, data_len, computed_hmac, NULL);
    free(data);
    return memcmp(msg->hmac, computed_hmac, 32) == 0 ? 0 : -1;
}

static int decrypt_payload(SkyNetMessage *msg, const uint8_t *aes_key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key, msg->iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int outlen, finallen;
    uint8_t outbuf[400];
    if (EVP_DecryptUpdate(ctx, outbuf, &outlen, msg->payload, msg->payload_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_DecryptFinal_ex(ctx, outbuf + outlen, &finallen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    memcpy(msg->payload, outbuf, outlen + finallen);
    msg->payload_len = outlen + finallen;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// Queue functions
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
    } while (!__atomic_compare_exchange_n(&q->head, &head, next_head, false,
                                          memory_order_release, memory_order_acquire));
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

int queue_dequeue(ServerState *state, SkyNetMessage *msg, struct sockaddr_in *addr, uint64_t *recv_time) {
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

// Server functions
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
    // Initialize keys (placeholder; in practice, use ECDH)
    RAND_bytes(state->aes_key, 32);
    RAND_bytes(state->hmac_key, 32);
}

int is_duplicate(ServerState *state, uint32_t node_id, uint32_t seq_no, uint8_t type, struct sockaddr_in *addr) {
    uint64_t current_time = time(NULL);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&current_time));
    uint32_t hash = (node_id ^ seq_no) % MAX_SEQUENCES;
    for (int i = 0; i < MAX_SEQUENCES; i++) {
        uint32_t idx = (hash + i) % MAX_SEQUENCES;
        if (atomic_load_explicit(&state->seqs[idx].claimed, memory_order_acquire) == 0) {
            break;
        }
        if (state->seqs[idx].node_id == node_id && state->seqs[idx].seq_no == seq_no) {
            if (current_time - state->seqs[idx].timestamp < 2) {
                printf("[%s] Dropped duplicate message from node %u, type=%d, seq=%u, src=%s:%d\n",
                       time_str, node_id, type, seq_no, inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
                return 1;
            }
        }
    }
    return 0;
}

void record_sequence(ServerState *state, uint32_t node_id, uint32_t seq_no) {
    uint32_t hash = (node_id ^ seq_no) % MAX_SEQUENCES;
    uint32_t idx = atomic_fetch_add_explicit(&state->seq_idx, 1, memory_order_relaxed) % MAX_SEQUENCES;
    for (int i = 0; i < MAX_SEQUENCES; i++) {
        uint32_t probe = (hash + i) % MAX_SEQUENCES;
        uint32_t expected = 0;
        uint32_t desired = 1;
        if (atomic_load_explicit(&state->seqs[probe].claimed, memory_order_acquire) == 0 ||
            time(NULL) - state->seqs[probe].timestamp >= 2) {
            if (__atomic_compare_exchange_n(&state->seqs[probe].claimed, &expected, desired, false,
                                            memory_order_release, memory_order_acquire)) {
                state->seqs[probe].node_id = node_id;
                state->seqs[probe].seq_no = seq_no;
                state->seqs[probe].timestamp = time(NULL);
                break;
            }
        }
    }
}

NodeState *find_or_add_node(ServerState *state, struct sockaddr_in *addr, uint32_t node_id, NodeRole role) {
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
    if (__atomic_compare_exchange_n(&state->node_count, &count, new_count, false,
                                    memory_order_release, memory_order_acquire)) {
        NodeState *node = &state->nodes[count];
        node->addr = *addr;
        node->node_id = node_id;
        node->role = role;
        node->last_seen = get_time_us();
        printf("Added node %u (%s) from %s:%d\n", node_id,
               role == NODE_ROLE_INFANTRY ? "infantry" : role == NODE_ROLE_DRONE ? "drone" : "relay",
               inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
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
        return node;
    }
    return find_or_add_node(state, addr, node_id, role);
}

void subscribe_npg(NodeState *node, uint8_t npg_id) {
    for (int i = 0; i < 32; i++) {
        if (node->subscribed_npgs[i] == 0 || node->subscribed_npgs[i] == npg_id) {
            node->subscribed_npgs[i] = npg_id;
            printf("Node %u subscribed to NPG %d\n", node->node_id, npg_id);
            break;
        }
    }
}

void send_to_npg(ServerState *state, const SkyNetMessage *msg, uint64_t recv_time) {
    uint64_t send_time = get_time_us();
    uint8_t buffer[MAX_BUFFER];
    size_t offset = 0;
    buffer[offset++] = msg->version;
    buffer[offset++] = msg->type;
    *(uint32_t *)(buffer + offset) = htonl(msg->npg_id); offset += 4;
    *(uint32_t *)(buffer + offset) = htonl(msg->node_id); offset += 4;
    *(uint32_t *)(buffer + offset) = htonl(msg->seq_no); offset += 4;
    *(uint64_t *)(buffer + offset) = htobe64(msg->timestamp); offset += 8;
    buffer[offset++] = msg->qos;
    buffer[offset++] = msg->hop_count;
    memcpy(buffer + offset, msg->iv, 16); offset += 16;
    *(uint16_t *)(buffer + offset) = htons(msg->payload_len); offset += 2;
    memcpy(buffer + offset, msg->payload, msg->payload_len); offset += msg->payload_len;
    *(uint32_t *)(buffer + offset) = htonl(msg->crc); offset += 4;
    memcpy(buffer + offset, msg->hmac, 32); offset += 32;

    struct iovec iov = { .iov_base = buffer, .iov_len = offset };
    struct msghdr mhdr = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1
    };
    struct sockaddr_in mcast_addr;
    memset(&mcast_addr, 0, sizeof(mcast_addr));
    mcast_addr.sin_family = AF_INET;
    mcast_addr.sin_port = htons(PORT);
    char mcast_ip[16];
    snprintf(mcast_ip, sizeof(mcast_ip), "239.255.0.%d", msg->npg_id & 0xFF);
    inet_pton(AF_INET, mcast_ip, &mcast_addr.sin_addr);
    mhdr.msg_name = &mcast_addr;
    mhdr.msg_namelen = sizeof(mcast_addr);
    if (sendmsg(state->socket_fd, &mhdr, 0) < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("Sendmsg failed");
        }
    } else {
        printf("SENT [NPG:%d][seq:%u][multicast:%s] latency [us:%llu]\n",
               msg->npg_id, msg->seq_no, mcast_ip, send_time - recv_time);
        record_sequence(state, msg->node_id, msg->seq_no);
    }
}

void process_control(ServerState *state, NodeState *node, SkyNetMessage *msg) {
    if (msg->type == 3) { // slot_request
        subscribe_npg(node, msg->npg_id);
        if (node->role == NODE_ROLE_DRONE && msg->npg_id == 1) { // Assume NPG 1 for swarm control
            node->role = NODE_ROLE_CONTROLLER;
            printf("Node %u promoted to swarm controller\n", node->node_id);
        }
    } else if (msg->type == 5) { // status (PLI)
        float *pli = (float *)msg->payload;
        memcpy(node->position, pli, sizeof(float) * 3);
        memcpy(node->velocity, pli + 3, sizeof(float) * 3);
        node->last_seen = get_time_us();
        printf("Updated PLI for node %u: pos=[%.1f, %.1f, %.1f], vel=[%.1f, %.1f, %.1f]\n",
               node->node_id, node->position[0], node->position[1], node->position[2],
               node->velocity[0], node->velocity[1], node->velocity[2]);
    }
}

void process_self_healing(ServerState *state) {
    uint64_t now = get_time_us();
    for (size_t i = 0; i < atomic_load(&state->node_count); i++) {
        if (now - state->nodes[i].last_seen > NEIGHBOR_TIMEOUT_US) {
            printf("Node %u timed out, removing\n", state->nodes[i].node_id);
            // Shift nodes to remove
            for (size_t j = i; j < atomic_load(&state->node_count) - 1; j++) {
                state->nodes[j] = state->nodes[j + 1];
            }
            atomic_fetch_sub(&state->node_count, 1);
            // Reallocate tasks (simplified; in practice, use optimization)
            SkyNetMessage cmd = { .version = 1, .type = 4, .npg_id = 1, .node_id = 0, .seq_no = state->current_slot,
                                     .timestamp = now, .qos = 3, .hop_count = 0, .payload_len = 0 };
            send_to_npg(state, &cmd, now); // Broadcast task reallocation
        }
    }
}

void handle_message(ServerState *state, NodeState *node, SkyNetMessage *msg, uint64_t recv_time) {
    uint64_t process_time = get_time_us();
    if (msg->version != 1) {
        fprintf(stderr, "Invalid version %d from node %u\n", msg->version, msg->node_id);
        return;
    }
    uint32_t computed_crc = crc32((uint8_t *)msg, offsetof(SkyNetMessage, crc));
    if (computed_crc != msg->crc) {
        fprintf(stderr, "CRC mismatch for node %u, seq=%u\n", msg->node_id, msg->seq_no);
        return;
    }
    if (verify_hmac(msg, state->hmac_key) != 0) {
        fprintf(stderr, "HMAC verification failed for node %u, seq=%u\n", msg->node_id, msg->seq_no);
        return;
    }
    if (decrypt_payload(msg, state->aes_key) != 0) {
        fprintf(stderr, "Decryption failed for node %u, seq=%u\n", msg->node_id, msg->seq_no);
        return;
    }
    if (is_duplicate(state, msg->node_id, msg->seq_no, msg->type, &node->addr)) {
        return;
    }
    printf("RCVD [NPG:%d][seq:%u][node:%u][type:%d][src:%s:%d] latency [us:%llu]\n",
           msg->npg_id, msg->seq_no, msg->node_id, msg->type,
           inet_ntoa(node->addr.sin_addr), ntohs(node->addr.sin_port), process_time - recv_time);
    switch (msg->type) {
        case 0: // chat
        case 1: // ack
        case 4: // waypoint
        case 5: // status
        case 6: // formation
            send_to_npg(state, msg, recv_time);
            break;
        case 2: // key_exchange (placeholder; implement ECDH)
        case 3: // slot_request
            process_control(state, node, msg);
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
            SkyNetMessage msg;
            struct sockaddr_in addr;
            uint64_t recv_time;
            while (queue_dequeue(state, &msg, &addr, &recv_time) == 0) {
                NodeState *node = find_or_add_node(state, &addr, msg.node_id,
                                                   msg.type == 5 ? NODE_ROLE_DRONE : NODE_ROLE_INFANTRY);
                if (node) {
                    handle_message(state, node, &msg, recv_time);
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
    printf("SkyNet server bound to %s:%d\n", inet_ntoa(state.server_addr.sin_addr), ntohs(state.server_addr.sin_port));
    uint8_t npgs[] = {1, 6, 7, 29, 100, 101, 102, 103};
    struct ip_mreq mreq;
    for (size_t i = 0; i < sizeof(npgs) / sizeof(npgs[0]); i++) {
        char mcast_ip[16];
        snprintf(mcast_ip, sizeof(mcast_ip), "239.255.0.%d", npgs[i]);
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
    printf("SkyNet UDP server listening on port %d with %d worker threads...\n", PORT, THREAD_COUNT);
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
                SkyNetMessage msg;
                size_t offset = 0;
                if (len < offsetof(SkyNetMessage, crc) + 4) continue;
                msg.version = buffer[offset++];
                msg.type = buffer[offset++];
                msg.npg_id = ntohl(*(uint32_t *)(buffer + offset)); offset += 4;
                msg.node_id = ntohl(*(uint32_t *)(buffer + offset)); offset += 4;
                msg.seq_no = ntohl(*(uint32_t *)(buffer + offset)); offset += 4;
                msg.timestamp = be64toh(*(uint64_t *)(buffer + offset)); offset += 8;
                msg.qos = buffer[offset++];
                msg.hop_count = buffer[offset++];
                memcpy(msg.iv, buffer + offset, 16); offset += 16;
                msg.payload_len = ntohs(*(uint16_t *)(buffer + offset)); offset += 2;
                if (msg.payload_len > 400 || offset + msg.payload_len + 36 > len) continue;
                memcpy(msg.payload, buffer + offset, msg.payload_len); offset += msg.payload_len;
                msg.crc = ntohl(*(uint32_t *)(buffer + offset)); offset += 4;
                memcpy(msg.hmac, buffer + offset, 32);
                if (queue_enqueue(&state, &msg, &client_addr, recv_time) < 0) {
                    fprintf(stderr, "Queue full, dropping message\n");
                }
            } else if (events[i].data.fd == state.timer_fd) {
                uint64_t expirations;
                read(state.timer_fd, &expirations, sizeof(expirations));
                state.current_slot = (state.current_slot + 1) % 1000; // 1,000 slots/s
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