#ifndef SKYNET_H
#define SKYNET_H

#include <stdint.h>
#include <stddef.h>

/* SkyNet Constants */
#define SKYNET_VERSION 1             /* Protocol version */
#define SKYNET_MAX_NODES 2000        /* Max nodes (Phase II, roadmap to 4,000) */
#define SKYNET_MAX_PAYLOAD 400       /* Max payload size (bytes) */
#define SKYNET_TIME_SLOT_US 1000     /* TDMA slot duration (1 ms, 1,000 slots/s) */
#define SKYNET_NPG_MAX 255           /* Highest NPG ID */
#define SKYNET_FREQ_MIN_MHZ 400      /* UHF minimum frequency (MHz) */
#define SKYNET_FREQ_MAX_MHZ 470      /* UHF maximum frequency (MHz) */
#define SKYNET_HOPS_PER_SEC 100      /* FHSS hops per second */
#define SKYNET_QOS_PUBLIC 0          /* QoS for public chat (CSMA) */
#define SKYNET_QOS_CHAT 0            /* QoS for private chat (CSMA) */
#define SKYNET_QOS_PLI 1             /* QoS for PLI (TDMA) */
#define SKYNET_QOS_VOICE 2           /* QoS for voice (reserved) */
#define SKYNET_QOS_C2 3              /* QoS for C2 (TDMA) */
#define SKYNET_MAX_HOPS 5            /* Max hop count for OLSR mesh */

/* Network Participation Groups (NPGs) */
#define SKYNET_NPG_CONTROL 1         /* Control: slot requests, key exchange */
#define SKYNET_NPG_PLI 6             /* PLI: position, velocity, status */
#define SKYNET_NPG_SURVEILLANCE 7    /* Surveillance: sensor data */
#define SKYNET_NPG_CHAT 29           /* TacChat: group and private chat */
#define SKYNET_NPG_C2 100            /* C2: waypoints, formations */
#define SKYNET_NPG_ALERTS 101        /* Alerts: failures, self-healing */
#define SKYNET_NPG_LOGISTICS 102     /* Logistics: supply chain */
#define SKYNET_NPG_COORD 103         /* Inter-agent coordination */

/* US Military Vehicle Types */
typedef enum {
    // Ground Vehicles
    VEHICLE_M1_ABRAMS = 0, VEHICLE_M2_BRADLEY, VEHICLE_M1126_STRYKER, VEHICLE_M113_APC,
    VEHICLE_AMPV, VEHICLE_M10_BOOKER, VEHICLE_TERREX_ICV, VEHICLE_HMMWV, VEHICLE_JLTV,
    VEHICLE_MRAP, VEHICLE_LAV_25, VEHICLE_ISV, VEHICLE_M109_PALADIN, VEHICLE_M142_HIMARS,
    VEHICLE_M270_MLRS, VEHICLE_M88_HERCULES, VEHICLE_M9_ACE, VEHICLE_HEMTT, VEHICLE_LMTV,
    VEHICLE_FMTV, VEHICLE_M1070_HET, VEHICLE_PLS, VEHICLE_RCV_L, VEHICLE_RCV_M, VEHICLE_S_MMET,
    // Air Vehicles
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
    // Sea Vehicles
    VEHICLE_CVN_NIMITZ, VEHICLE_CVN_FORD, VEHICLE_DDG_ARLEIGH_BURKE, VEHICLE_CG_TICONDEROGA,
    VEHICLE_FFG_CONSTELLATION, VEHICLE_LCS_FREEDOM, VEHICLE_LCS_INDEPENDENCE, VEHICLE_LHA_AMERICA,
    VEHICLE_LHD_WASP, VEHICLE_LPD_SAN_ANTONIO, VEHICLE_LSD_HARPER_FERRY, VEHICLE_SSN_VIRGINIA,
    VEHICLE_SSN_LOS_ANGELES, VEHICLE_SSBN_OHIO, VEHICLE_SSGN_OHIO, VEHICLE_T_AKE_LEWIS_CLARK,
    VEHICLE_T_AO_JOHN_LEWIS, VEHICLE_T_ATF_POWHATAN, VEHICLE_T_AH_MERCY, VEHICLE_WMSL_LEGEND,
    VEHICLE_WPC_SENTINEL, VEHICLE_WMEC_BEAR, VEHICLE_WPB_ISLAND, VEHICLE_ORCA_XLUUV, VEHICLE_MUSV,
    VEHICLE_LUSV, VEHICLE_LCAC, VEHICLE_LCU_1700, VEHICLE_SSC_SHIP_TO_SHORE,
    // Space Vehicles
    VEHICLE_GPS_III, VEHICLE_AEHF, VEHICLE_SBIRS, VEHICLE_WGS, VEHICLE_X_37B, VEHICLE_CST_100_STARLINER,
    VEHICLE_FALCON_9, VEHICLE_FALCON_HEAVY, VEHICLE_ATLAS_V, VEHICLE_DELTA_IV, VEHICLE_VULCAN_CENTAUR,
    VEHICLE_COUNT
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
} SkyNetMessageType;

/* Node Roles */
typedef enum {
    NODE_ROLE_INFANTRY = 0,      /* Infantry node (TacChat) */
    NODE_ROLE_DRONE,             /* Drone (Swarm C2) */
    NODE_ROLE_RELAY,             /* Drone acting as relay */
    NODE_ROLE_CONTROLLER,        /* Swarm controller */
    NODE_ROLE_GROUND_VEHICLE,    /* Armored, recon, artillery, logistics, unmanned */
    NODE_ROLE_AIR_VEHICLE,       /* Fixed-wing, rotary-wing, UAVs, air defense */
    NODE_ROLE_SEA_VEHICLE,       /* Carriers, combatants, amphibious, subs, support */
    NODE_ROLE_SPACE_VEHICLE      /* Satellites, spacecraft, launch vehicles */
} NodeRole;

/* SkyNet Message Structure */
typedef struct {
    uint8_t version;             /* Protocol version (1) */
    uint8_t type;                /* Message type (SkyNetMessageType) */
    uint32_t npg_id;             /* NPG ID (1–255) */
    uint32_t node_id;            /* Unique node ID */
    uint32_t seq_no;             /* Sequence number for deduplication */
    uint64_t timestamp;          /* Relative time (us) */
    uint8_t qos;                 /* QoS: 0=chat, 1=PLI, 2=voice, 3=C2 */
    uint8_t hop_count;           /* Hop count (0–5) */
    uint8_t iv[16];              /* AES-256-GCM IV */
    uint16_t payload_len;        /* Payload length (0–400 bytes) */
    uint8_t payload[400];        /* Encrypted payload */
    uint8_t hmac[32];            /* HMAC-SHA256 */
    uint32_t crc;                /* CRC-32 */
} SkyNetMessage;

/* Function Prototypes */
void skynet_init(SkyNetMessage *msg, SkyNetMessageType type, uint32_t node_id, uint32_t npg_id, uint8_t qos);
void skynet_set_data(SkyNetMessage *msg, const uint8_t *data, uint16_t data_length);
int skynet_serialize(const SkyNetMessage *msg, uint8_t *buffer, size_t buffer_size);
int skynet_deserialize(SkyNetMessage *msg, const uint8_t *buffer, size_t buffer_size);
void skynet_print(const SkyNetMessage *msg);
int skynet_verify_hmac(const SkyNetMessage *msg, const uint8_t *hmac_key);
int skynet_decrypt_payload(SkyNetMessage *msg, const uint8_t *aes_key);

#endif /* SKYNET_H */
