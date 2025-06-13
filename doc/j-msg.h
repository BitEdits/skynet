#ifndef TADIL_J_MESSAGES_H
#define TADIL_J_MESSAGES_H

#include <stdint.h>
#include <stddef.h>

/* TADIL J Constants (from ADA404334.pdf) */
#define TADIL_J_FREQ_MIN_MHZ 960    /* Minimum frequency (MHz) */
#define TADIL_J_FREQ_MAX_MHZ 1215   /* Maximum frequency (MHz) */
#define TADIL_J_TIME_SLOT_MS 7.8125 /* Time slot duration (milliseconds) */
#define TADIL_J_HOPS_PER_SEC 77000  /* Frequency hops per second */
#define TADIL_J_NETS 128            /* Maximum number of nets (0-127) */
#define TADIL_J_FRAME_SLOTS 1536    /* Slots per 12-second frame */
#define TADIL_J_EPOCH_SLOTS 98304   /* Slots per 12.8-minute epoch */
#define TADIL_J_VOICE_RATE_LOW_KBPS 2.4  /* Low voice data rate (kbps) */
#define TADIL_J_VOICE_RATE_HIGH_KBPS 16.0 /* High voice data rate (kbps) */
#define TADIL_J_JU_ADDRESS_MIN 00001 /* Minimum JU address (octal) */
#define TADIL_J_JU_ADDRESS_MAX 77776 /* Maximum JU address (octal) */

/* J-series Message Types (based on NPGs from Figure I-1, ADA404334) */
typedef enum {
    J_MSG_INITIAL_ENTRY = 1,      /* NPG 1: Initial entry */
    J_MSG_RTT_ADDRESSED,          /* NPG 2: Round-trip timing (addressed) */
    J_MSG_RTT_BROADCAST,          /* NPG 3: Round-trip timing (broadcast) */
    J_MSG_NETWORK_MANAGEMENT,     /* NPG 4: Network management */
    J_MSG_PPLI_C2,                /* NPG 5: PPLI (C2 units) */
    J_MSG_PPLI_NON_C2,            /* NPG 6: PPLI (non-C2 units) */
    J_MSG_SURVEILLANCE,           /* NPG 7: Surveillance (tracks, points) */
    J_MSG_MISSION_MGMT,           /* NPG 8: Mission management */
    J_MSG_AIR_CONTROL,            /* NPG 9: Air control */
    J_MSG_EW,                     /* NPG 10: Electronic warfare */
    J_MSG_VOICE_A,                /* NPG 12: Voice channel A */
    J_MSG_VOICE_B,                /* NPG 13: Voice channel B */
    J_MSG_INDIRECT_PPLI,          /* NPG 14: Indirect PPLIs (USN) */
    J_MSG_WEAPONS_COORD,          /* NPG 18: Weapons coordination */
    J_MSG_FIGHTER_TO_FIGHTER,     /* NPG 19: Fighter-to-fighter net */
    J_MSG_ENGAGEMENT_COORD,       /* NPG 21: Engagement coordination */
    J_MSG_JOINT_PPLI,             /* NPG 27: Joint PPLI */
    J_MSG_FREE_TEXT,              /* NPG 29: Free text messages */
    J_MSG_IJMS_POSITION,          /* NPG 30: IJMS position */
    J_MSG_IJMS_TRACK,             /* NPG 31: IJMS track report */
    J_MSG_USA_NEEDLINES           /* NPG 400-511: USA-specific needlines */
} JMessageType;

/* JU Roles */
typedef enum {
    JU_ROLE_NONE = 0,
    JU_ROLE_NTR,                  /* Net Time Reference */
    JU_ROLE_C2,                   /* Command and Control */
    JU_ROLE_NON_C2,               /* Non-Command and Control */
    JU_ROLE_NAV_CONTROLLER        /* Navigation Controller */
} JURole;

/* Generic J-series Message Structure */
typedef struct {
    JMessageType type;          /* Message type */
    uint32_t ju_address;        /* JU address (octal, 00001-77776) */
    uint8_t npg;                /* Network Participation Group */
    uint8_t net_number;         /* Net number (0-127) */
    uint32_t time_slot;         /* Time slot number (0-98303) */
    uint8_t tsec_key;           /* TSEC key ID (placeholder) */
    uint8_t msec_key;           /* MSEC key ID (placeholder) */
    uint8_t data[256];          /* Message data (placeholder) */
    uint32_t data_length;       /* Length of data field */
} JMessage;

/* Serialization Functions */
int jmessage_serialize(const JMessage *msg, uint8_t *buffer, size_t buffer_size);
int jmessage_deserialize(JMessage *msg, const uint8_t *buffer, size_t buffer_size);

/* Message Handling Functions */
void jmessage_init(JMessage *msg, JMessageType type, uint32_t ju_address, uint8_t npg, uint8_t net_number);
void jmessage_set_data(JMessage *msg, const uint8_t *data, uint32_t data_length);
void jmessage_print(const JMessage *msg);

#endif /* TADIL_J_MESSAGES_H */
