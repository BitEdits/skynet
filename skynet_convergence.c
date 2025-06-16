/*
 * SkyNet Convergence Layer Overview
 * Copoyright (c) 2025 Namdak Tonpa
 *
 * This module implements a PDCP-like Convergence Layer for SkyNet,
 * enhancing QoS, slot management, and traffic isolation. Below is a
 * summary of key functionalities, designed to align with LTE 4G
 * standards while maintaining simplicity (KISS principle).
 *
 * QoS with Bearers:
 *     SkyNetBearerQoS defines LTE-like parameters (priority, delay budget, reliability).
 *     skynet_convergence_add_bearer maps SKYNET_QOS_* to QoS
 *     parameters (e.g., SKYNET_QOS_C2 -> priority 1, 50ms delay).
 *     Each bearer has its own slot allocation and reorder queue.
 *
 * Reordering:
 *     skynet_convergence_process implements PDCP-like reordering
 *     using a fixed-size queue (SKYNET_REORDER_SIZE).
 *     Messages are delivered in sequence or queued if out of order,
 *     with timeouts (SKYNET_REORDER_MS, SKYNET_DISCARD_MS).
 *     Deduplication prevents duplicates using last_delivered.
 *
 * Slot Allocations:
 *     skynet_convergence_request_slots handles slot requests per
 *     bearer, tracked via slot_requests_pending.
 *     Slots are assigned based on min_slots and priority.
 *
 * Dynamic Scheduling:
 *     skynet_convergence_schedule_slots uses Weighted Fair Queuing
 *     to allocate slots proportionally to 16 - priority.
 *     Scheduling occurs every TDMA frame (1ms, via timer_fd).
 *
 * Traffic Isolation:
 *     Bearers are tied to NPGs (e.g., SKYNET_NPG_C2), ensuring traffic separation.
 *     Slots map to multicast groups (239.255.1.<slot_id>),
 *     isolating bearer traffic.
 *
 * Controller Logic:
 *     Nodes with NODE_ROLE_CONTROLLER run
 *     skynet_convergence_schedule_slots and
 *     skynet_convergence_preempt_slots.
 *     Centralized slot allocation ensures fairness and QoS
 *     enforcement.
 *
 * Preemption:
 *     skynet_convergence_preempt_slots reassigns slots from
 *     low-priority bearers to high-priority ones during congestion.
 *
 */

#include "skynet_convergence.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>


void skynet_convergence_init(SkyNetConvergenceEntity *entity, uint32_t node_id) {
    memset(entity, 0, sizeof(SkyNetConvergenceEntity));
    entity->bearer_count = 0;
    atomic_store(&entity->slot_requests_pending, 0);
    for (uint32_t i = 0; i < SKYNET_MAX_BEARERS; i++) {
        entity->bearers[i].bearer_id = i;
        entity->bearers[i].node_id = node_id;
        entity->bearers[i].expected_seq_no = 0;
        entity->bearers[i].last_delivered = UINT32_MAX;
    }
}

int skynet_convergence_add_bearer(SkyNetConvergenceEntity *entity, uint32_t npg_id, uint8_t qos) {
    if (entity->bearer_count >= SKYNET_MAX_BEARERS) {
        fprintf(stderr, "Max bearers reached\n");
        return -1;
    }
    uint32_t bearer_id = entity->bearer_count++;
    SkyNetBearer *bearer = &entity->bearers[bearer_id];
    bearer->npg_id = npg_id;
    bearer->qos.priority = (qos == SKYNET_QOS_C2) ? 1 : (qos == SKYNET_QOS_VOICE) ? 5 : (qos == SKYNET_QOS_PLI) ? 10 : 15;
    bearer->qos.delay_budget_ms = (qos == SKYNET_QOS_C2) ? 50 : (qos == SKYNET_QOS_VOICE) ? 150 : 300;
    bearer->qos.reliability = (qos == SKYNET_QOS_C2 || qos == SKYNET_QOS_PLI) ? 1 : 0;
    bearer->qos.min_slots = SKYNET_MIN_SLOTS;
    bearer->slot_count = 0;
    bearer->last_reorder_time_us = get_time_us();
    printf("Added bearer %u: npg_id=%u, priority=%u, delay_budget=%ums\n",
           bearer_id, npg_id, bearer->qos.priority, bearer->qos.delay_budget_ms);
    return bearer_id;
}

void skynet_convergence_remove_bearer(SkyNetConvergenceEntity *entity, uint32_t bearer_id) {
    if (bearer_id >= entity->bearer_count) return;
    SkyNetBearer *bearer = &entity->bearers[bearer_id];
    memset(bearer, 0, sizeof(SkyNetBearer));
    bearer->bearer_id = bearer_id;
    bearer->node_id = entity->bearers[0].node_id;
    bearer->expected_seq_no = 0;
    bearer->last_delivered = UINT32_MAX;
}

int skynet_convergence_process(SkyNetConvergenceEntity *entity, SkyNetMessage *msg, struct sockaddr_in *addr, uint64_t recv_time) {
    // Find bearer by npg_id
    SkyNetBearer *bearer = NULL;
    for (uint32_t i = 0; i < entity->bearer_count; i++) {
        if (entity->bearers[i].npg_id == msg->npg_id) {
            bearer = &entity->bearers[i];
            break;
        }
    }
    if (!bearer) {
        fprintf(stderr, "No bearer for npg_id=%u\n", msg->npg_id);
        return -1;
    }

    // Deduplication
    if (msg->seq_no <= bearer->last_delivered) {
        fprintf(stderr, "Duplicate or old message: seq_no=%u, last_delivered=%u\n", msg->seq_no, bearer->last_delivered);
        return -1;
    }

    // Reordering
    uint32_t queue_idx = msg->seq_no % SKYNET_REORDER_SIZE;
    if (msg->seq_no == bearer->expected_seq_no) {
        bearer->expected_seq_no++;
        bearer->last_delivered = msg->seq_no;
        return 0; // Deliver immediately
    } else if (msg->seq_no > bearer->expected_seq_no) {
        bearer->reorder_queue[queue_idx] = *msg;
        return 1; // Queued for reordering
    }
    return -1; // Out of window
}

int skynet_convergence_deliver(SkyNetConvergenceEntity *entity, SkyNetBearer *bearer, SkyNetMessage *delivered_msg) {
    uint64_t now = get_time_us();
    if (now - bearer->last_reorder_time_us < SKYNET_REORDER_MS * 1000) {
        return 0; // Not yet time to check
    }
    bearer->last_reorder_time_us = now;

    for (uint32_t i = 0; i < SKYNET_REORDER_SIZE; i++) {
        uint32_t seq_no = bearer->expected_seq_no;
        uint32_t queue_idx = seq_no % SKYNET_REORDER_SIZE;
        SkyNetMessage *queued_msg = &bearer->reorder_queue[queue_idx];
        if (queued_msg->seq_no == seq_no) {
            *delivered_msg = *queued_msg;
            memset(queued_msg, 0, sizeof(SkyNetMessage));
            bearer->expected_seq_no++;
            bearer->last_delivered = seq_no;
            return 1; // Delivered
        }
        // Discard old packets
        if (queued_msg->seq_no != 0 && now - queued_msg->seq_no * 1000 > SKYNET_DISCARD_MS * 1000) {
            memset(queued_msg, 0, sizeof(SkyNetMessage));
        }
    }
    return 0; // Nothing delivered
}

int skynet_convergence_request_slots(SkyNetConvergenceEntity *entity, uint32_t bearer_id, uint32_t npg_id, uint8_t qos) {
    if (bearer_id >= entity->bearer_count) return -1;
    SkyNetBearer *bearer = &entity->bearers[bearer_id];
    if (bearer->slot_count >= bearer->qos.min_slots) return 0; // Already satisfied
    atomic_fetch_add(&entity->slot_requests_pending, 1);
    printf("Requested slots for bearer %u: npg_id=%u, qos=%u\n", bearer_id, npg_id, qos);
    return 1; // Request pending
}

void skynet_convergence_schedule_slots(SkyNetConvergenceEntity *entity, uint32_t *slots, uint32_t slot_count) {
    // Weighted Fair Queuing: Allocate slots based on priority
    uint32_t total_weight = 0;
    for (uint32_t i = 0; i < entity->bearer_count; i++) {
        total_weight += (16 - entity->bearers[i].qos.priority); // Lower priority = higher weight
    }
    if (total_weight == 0) return;

    uint32_t slot_idx = 0;
    for (uint32_t i = 0; i < entity->bearer_count && slot_idx < slot_count; i++) {
        SkyNetBearer *bearer = &entity->bearers[i];
        uint32_t weight = (16 - bearer->qos.priority);
        uint32_t slots_needed = bearer->qos.min_slots - bearer->slot_count;
        uint32_t slots_to_assign = (weight * slot_count) / total_weight;
        slots_to_assign = slots_to_assign > slots_needed ? slots_needed : slots_to_assign;

        for (uint32_t j = 0; j < slots_to_assign && slot_idx < slot_count; j++) {
            if (bearer->slot_count < SKYNET_MAX_SLOTS) {
                bearer->assigned_slots[bearer->slot_count++] = slots[slot_idx++];
                printf("Assigned slot %u to bearer %u (priority=%u)\n",
                       bearer->assigned_slots[bearer->slot_count-1], bearer->bearer_id, bearer->qos.priority);
            }
        }
    }
}

int skynet_convergence_preempt_slots(SkyNetConvergenceEntity *entity, uint32_t high_priority_bearer_id) {
    if (high_priority_bearer_id >= entity->bearer_count) return -1;
    SkyNetBearer *high_bearer = &entity->bearers[high_priority_bearer_id];
    if (high_bearer->slot_count >= high_bearer->qos.min_slots) return 0;

    // Find lowest-priority bearer with excess slots
    SkyNetBearer *low_bearer = NULL;
    uint32_t lowest_priority = 0;
    for (uint32_t i = 0; i < entity->bearer_count; i++) {
        if (i == high_priority_bearer_id) continue;
        SkyNetBearer *b = &entity->bearers[i];
        if (b->slot_count > b->qos.min_slots && b->qos.priority > lowest_priority) {
            lowest_priority = b->qos.priority;
            low_bearer = b;
        }
    }

    if (low_bearer) {
        uint32_t slot = low_bearer->assigned_slots[--low_bearer->slot_count];
        high_bearer->assigned_slots[high_bearer->slot_count++] = slot;
        printf("Preempted slot %u from bearer %u to bearer %u\n",
               slot, low_bearer->bearer_id, high_bearer->bearer_id);
        return 1;
    }
    return -1;
}
