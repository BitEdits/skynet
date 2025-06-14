#ifndef SKYNET_H
#define SKYNET_H

#include <arpa/inet.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>

#define SERVER_BASE_PATH "~/.skynet/ecc/secp384r1/"
#define CLIENT_BASE_PATH "~/.skynet_client/ecc/secp384r1/"

#define AES_KEY_LEN 32
#define MAX_NODE_NAME 64
#define MAX_BUFFER 1590
#define SKYNET_VERSION 1
#define SKYNET_MAX_NODES 11000
#define TIME_SLOT_INTERVAL_US 1000
#define QUEUE_SIZE 1024
#define MAX_TOPICS 8
#define THREAD_COUNT 4
#define PORT 6566
#define SLOT_COUNT 1000 // Number of slots for TDMA
#define SEQ_CACHE_SIZE 1024 // Size of deduplication cache

#define SKYNET_VERSION 1
#define SKYNET_MAX_NODES 11000
#define SKYNET_TIME_SLOT_US 1000
#define SKYNET_NPG_MAX 255
#define SKYNET_FREQ_MIN_MHZ 400
#define SKYNET_FREQ_MAX_MHZ 470
#define SKYNET_HOPS_PER_SEC 100
#define SKYNET_QOS_PUBLIC 0
#define SKYNET_QOS_CHAT 0
#define SKYNET_QOS_PLI 1
#define SKYNET_QOS_VOICE 2
#define SKYNET_QOS_C2 3
#define SKYNET_MAX_HOPS 5
#define SKYNET_NPG_CONTROL 1
#define SKYNET_NPG_PLI 6
#define SKYNET_NPG_SURVEILLANCE 7
#define SKYNET_NPG_CHAT 29
#define SKYNET_NPG_C2 100
#define SKYNET_NPG_ALERTS 101
#define SKYNET_NPG_LOGISTICS 102
#define SKYNET_NPG_COORD 103

#define GRAY          "\x1b[0;90m"
#define YELLOW        "\x1b[0;93m"
#define BLUE          "\x1b[0;34m"
#define MAGENTA       "\x1b[0;35m"
#define CYAN          "\x1b[0;36m"
#define SILVER        "\x1b[0;37m"
#define BRIGHT_YELLOW "\x1b[0;93m"
#define BRIGHT_BLUE   "\x1b[0;94m"
#define RESET         "\x1b[0m"

typedef enum {
    VEHICLE_M1_ABRAMS = 0, VEHICLE_M2_BRADLEY, VEHICLE_M1126_STRYKER, VEHICLE_M113_APC,
    VEHICLE_AMPV, VEHICLE_M10_BOOKER, VEHICLE_TERREX_ICV, VEHICLE_HMMWV, VEHICLE_JLTV,
    VEHICLE_MRAP, VEHICLE_LAV_25, VEHICLE_ISV, VEHICLE_M109_PALADIN, VEHICLE_M142_HIMARS,
    VEHICLE_M270_MLRS, VEHICLE_M88_HERCULES, VEHICLE_M9_ACE, VEHICLE_HEMTT, VEHICLE_LMTV,
    VEHICLE_FMTV, VEHICLE_M1070_HET, VEHICLE_PLS, VEHICLE_RCV_L, VEHICLE_RCV_M, VEHICLE_S_MMET,
    VEHICLE_F_15_EAGLE, VEHICLE_F_16_FALCON, VEHICLE_F_22_RAPTOR, VEHICLE_F_35_LIGHTNING,
    VEHICLE_A_10_THUNDERBOLT, VEHICLE_B_1_LANCER, VEHICLE_B_2_SPIRIT, VEHICLE_B_21_RAIDER,
    VEHICLE_C_130_HERCULES, VEHICLE_C_17_GLOBEMASTER, VEHICLE_C_5_GALAXY, VEHICLE_KC_135_STRATOTANKER,
    VEHICLE_KC_46_PEGASUS, VEHICLE_E_3_SENTRY, VEHICLE_E_8_JSTARS, VEHICLE_U_2_DRAGON_LADY,
    VEHICLE_P_8_POSEIDON, VEHICLE_C_12_HURON, VEHICLE_C_40_CLIPPER, VEHICLE_AH_64_APACHE,
    VEHICLE_UH_60_BLACK_HAWK, VEHICLE_CH_47_CHINOOK, VEHICLE_AH_1Z_VIPER, VEHICLE_UH_1Y_VENOM,
    VEHICLE_CH_53K_KING_STALLION, VEHICLE_MH_60_SEAHAWK, VEHICLE_V_22_OSPREY, VEHICLE_MQ_9_REAPER,
    VEHICLE_RQ_4_GLOBAL_HAWK, VEHICLE_MQ_1C_GRAY_EAGLE, VEHICLE_RQ_7_SHADOW, VEHICLE_RQ_11_RAVEN,
    VEHICLE_CQ_10_SNOWGOOSE, VEHICLE_MQ_25_STINGRAY, VEHICLE_X_47B, VEHICLE_PATRIOT_PAC_3,
    VEHICLE_THAAD, VEHICLE_AVENGER,
    VEHICLE_CVN_NIMITZ, VEHICLE_CVN_FORD, VEHICLE_DDG_ARLEIGH_BURKE, VEHICLE_CG_TICONDEROGA,
    VEHICLE_FFG_CONSTELLATION, VEHICLE_LCS_FREEDOM, VEHICLE_LCS_INDEPENDENCE, VEHICLE_LHA_AMERICA,
    VEHICLE_LHD_WASP, VEHICLE_LPD_SAN_ANTONIO, VEHICLE_LSD_HARPER_FERRY, VEHICLE_SSN_VIRGINIA,
    VEHICLE_SSN_LOS_ANGELES, VEHICLE_SSBN_OHIO, VEHICLE_SSGN_OHIO, VEHICLE_T_AKE_LEWIS_CLARK,
    VEHICLE_T_AO_JOHN_LEWIS, VEHICLE_T_ATF_POWHATAN, VEHICLE_T_AH_MERCY, VEHICLE_WMSL_LEGEND,
    VEHICLE_WPC_SENTINEL, VEHICLE_WMEC_BEAR, VEHICLE_WPB_ISLAND, VEHICLE_ORCA_XLUUV, VEHICLE_MUSV,
    VEHICLE_LUSV, VEHICLE_LCAC, VEHICLE_LCU_1700, VEHICLE_SSC_SHIP_TO_SHORE,
    VEHICLE_GPS_III, VEHICLE_AEHF, VEHICLE_SBIRS, VEHICLE_WGS, VEHICLE_X_37B, VEHICLE_CST_100_STARLINER,
    VEHICLE_FALCON_9, VEHICLE_FALCON_HEAVY, VEHICLE_ATLAS_V, VEHICLE_DELTA_IV, VEHICLE_VULCAN_CENTAUR, VEHICLE_COUNT
} USMilitaryVehicleType;

typedef enum {
    SKYNET_MSG_KEY_EXCHANGE = 0,
    SKYNET_MSG_SLOT_REQUEST,
    SKYNET_MSG_PUBLIC,
    SKYNET_MSG_CHAT,
    SKYNET_MSG_ACK,
    SKYNET_MSG_WAYPOINT,
    SKYNET_MSG_STATUS,
    SKYNET_MSG_FORMATION
} SkyNetMessageType;

typedef enum {
    NODE_ROLE_INFANTRY = 0,
    NODE_ROLE_DRONE,
    NODE_ROLE_RELAY,
    NODE_ROLE_CONTROLLER,
    NODE_ROLE_GROUND_VEHICLE,
    NODE_ROLE_AIR_VEHICLE,
    NODE_ROLE_SEA_VEHICLE,
    NODE_ROLE_SPACE_VEHICLE
} NodeRole;

typedef struct {
    uint8_t version : 4;         // 1/2 byte
    uint8_t type : 4;            // 1/2 byte
    uint8_t qos : 4;             // 1/2 byte
    uint8_t hop_count : 4;       // 1/2 byte
    uint32_t npg_id;             // 4   bytes
    uint32_t node_id;            // 4   bytes
    uint32_t seq_no;             // 4   bytes
    uint8_t iv[16];              // 16  bytes
    uint16_t payload_len;        // 2   bytes
    uint8_t payload[MAX_BUFFER]; // Variable
} SkyNetMessage;

#define FNV_OFFSET_BASIS_32 2166136261U
#define FNV_PRIME_32 16777619U

typedef struct {
    SkyNetMessage messages[QUEUE_SIZE];
    struct sockaddr_in addrs[QUEUE_SIZE];
    uint64_t recv_times[QUEUE_SIZE];
    atomic_uint head;
    atomic_uint tail;
    int event_fds[THREAD_COUNT];
} MessageQueue;

struct ServerState; // Forward declaration

uint32_t fnv1a_32(void *data, size_t len);
void skynet_init(SkyNetMessage *msg, SkyNetMessageType type, uint32_t node_id, uint32_t npg_id, uint8_t qos);
void skynet_encrypt_payload(SkyNetMessage *msg, const uint8_t *data, uint16_t data_length, const uint8_t *aes_key);
int skynet_serialize(const SkyNetMessage *msg, uint8_t *buffer, size_t buffer_size);
int skynet_deserialize(SkyNetMessage *msg, const uint8_t *buffer, size_t buffer_size);
void skynet_print(const SkyNetMessage *msg);
int skynet_decrypt_payload(SkyNetMessage *msg, const uint8_t *aes_key);
int skynet_encrypt(int srv, SkyNetMessage *msg, uint32_t from_node, uint32_t to_node, const uint8_t *data, uint16_t data_len);
int skynet_decrypt(int srv, SkyNetMessage *msg, uint32_t to_node, uint32_t from_node);
int derive_shared_key(EVP_PKEY *priv_key, EVP_PKEY *peer_pub_key, uint8_t *aes_key);
EVP_PKEY *load_ec_key(int srv, const char *node_name, int is_private);
char *base_path(int srv);
int save_public_key(int srv, char *node_name, const uint8_t *pub_key_data, size_t pub_key_len);
void print_openssl_error(void);
char *expand_home(const char *path);
int set_non_blocking(int fd);
uint64_t get_time_us(void);
void hex_dump(const char *label, const uint8_t *data, size_t len);

#endif /* SKYNET_H */
