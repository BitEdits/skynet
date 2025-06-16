#ifndef SKYNET_CONVERGENCE_H
#define SKYNET_CONVERGENCE_H

#include "skynet.h"
#include <stdint.h>
#include <stdatomic.h>

#define SKYNET_MAX_BEARERS 8    // Max bearers per node
#define SKYNET_REORDER_SIZE 256 // Size of reorder queue
#define SKYNET_REORDER_MS 50    // Reorder timeout (ms)
#define SKYNET_DISCARD_MS 500   // Discard old packets (ms)
#define SKYNET_MIN_SLOTS 1      // Minimum slots per bearer
#define SKYNET_MAX_SLOTS 10     // Maximum slots per bearer
#define MAX_QOS_SLOTS 10

// Bearer QoS parameters (inspired by LTE QCI)
typedef struct {
    uint8_t priority;        // 1-15 (1 = highest)
    uint32_t delay_budget_ms;// Delay tolerance (ms)
    uint8_t reliability;     // 0 (best-effort), 1 (reliable)
    uint32_t min_slots;      // Minimum TDMA slots
} SkyNetBearerQoS;

// Bearer state
typedef struct {
    uint32_t bearer_id;      // Unique bearer ID (0 to SKYNET_MAX_BEARERS-1)
    SkyNetBearerQoS qos;     // QoS parameters
    uint32_t node_id;        // Owning node
    uint32_t npg_id;         // Associated NPG
    uint32_t assigned_slots[SKYNET_MAX_SLOTS]; // Assigned slot IDs
    uint32_t slot_count;     // Number of assigned slots
    SkyNetMessage reorder_queue[SKYNET_REORDER_SIZE]; // Reorder queue
    uint32_t expected_seq_no;// Next expected sequence number
    uint32_t last_delivered; // Last delivered sequence number
    uint64_t last_reorder_time_us; // Last reorder check
} SkyNetBearer;

// Convergence entity (per node)
typedef struct {
    SkyNetBearer bearers[SKYNET_MAX_BEARERS]; // Active bearers
    uint32_t bearer_count;   // Number of active bearers
    atomic_uint slot_requests_pending; // Pending slot requests
} SkyNetConvergenceEntity;

// QoS-only reduced Bearer/Entity
typedef struct {
    uint32_t npg_id;
    uint8_t qos;
    uint32_t slot_count;
    uint32_t slot_ids[MAX_QOS_SLOTS];
    uint8_t priority;
} QoSSlotAssignment;

void skynet_convergence_init(SkyNetConvergenceEntity *entity, uint32_t node_id); // Initialize convergence entity
int skynet_convergence_process(SkyNetConvergenceEntity *entity, SkyNetMessage *msg, struct sockaddr_in *addr, uint64_t recv_time); // Process incoming message (reordering, deduplication)
int skynet_convergence_deliver(SkyNetConvergenceEntity *entity, SkyNetBearer *bearer, SkyNetMessage *delivered_msg); // Deliver reordered messages to upper layer
int skynet_convergence_request_slots(SkyNetConvergenceEntity *entity, uint32_t bearer_id, uint32_t npg_id, uint8_t qos); // Request slots for a bearer
void skynet_convergence_schedule_slots_qos(QoSSlotAssignment *qos_slots, uint32_t *slots, uint32_t qos_slot_count, uint32_t slot_count);
void skynet_convergence_schedule_slots(SkyNetConvergenceEntity *entity, uint32_t *slots, uint32_t slot_count); // Schedule slots across bearers
int skynet_convergence_preempt_slots(SkyNetConvergenceEntity *entity, uint32_t high_priority_bearer_id); // Preempt low-priority slots
int skynet_convergence_add_bearer(SkyNetConvergenceEntity *entity, uint32_t npg_id, uint8_t qos); // Add a new bearer
void skynet_convergence_remove_bearer(SkyNetConvergenceEntity *entity, uint32_t bearer_id); // Remove a bearer

#endif /* SKYNET_CONVERGENCE_H */
