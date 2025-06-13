#include "j-msg.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

void jmessage_init(JMessage *msg, JMessageType type, uint32_t ju_address, uint8_t npg, uint8_t net_number) {
    memset(msg, 0, sizeof(JMessage));
    msg->type = type;
    msg->ju_address = ju_address;
    msg->npg = npg;
    msg->net_number = net_number;
    msg->time_slot = 0; /* Set by server */
    msg->tsec_key = 0;
    msg->msec_key = 0;
}

void jmessage_set_data(JMessage *msg, const uint8_t *data, uint32_t data_length) {
    if (data_length <= sizeof(msg->data)) {
        memcpy(msg->data, data, data_length);
        msg->data_length = data_length;
    }
}

int jmessage_serialize(const JMessage *msg, uint8_t *buffer, size_t buffer_size) {
    size_t required = sizeof(JMessageType) + sizeof(uint32_t) * 4 + sizeof(uint8_t) * 3 + msg->data_length;
    if (buffer_size < required) return -1;

    size_t offset = 0;
    uint32_t type = htonl(msg->type);
    memcpy(buffer + offset, &type, sizeof(type));
    offset += sizeof(type);

    uint32_t ju_addr = htonl(msg->ju_address);
    memcpy(buffer + offset, &ju_addr, sizeof(ju_addr));
    offset += sizeof(ju_addr);

    buffer[offset++] = msg->npg;
    buffer[offset++] = msg->net_number;

    uint32_t time_slot = htonl(msg->time_slot);
    memcpy(buffer + offset, &time_slot, sizeof(time_slot));
    offset += sizeof(time_slot);

    buffer[offset++] = msg->tsec_key;
    buffer[offset++] = msg->msec_key;

    uint32_t data_len = htonl(msg->data_length);
    memcpy(buffer + offset, &data_len, sizeof(data_len));
    offset += sizeof(data_len);

    memcpy(buffer + offset, msg->data, msg->data_length);
    offset += msg->data_length;

    return offset;
}

int jmessage_deserialize(JMessage *msg, const uint8_t *buffer, size_t buffer_size) {
    size_t offset = 0;
    if (buffer_size < sizeof(JMessageType) + sizeof(uint32_t) * 3 + sizeof(uint8_t) * 3) return -1;

    uint32_t type;
    memcpy(&type, buffer + offset, sizeof(type));
    msg->type = ntohl(type);
    offset += sizeof(type);

    uint32_t ju_addr;
    memcpy(&ju_addr, buffer + offset, sizeof(ju_addr));
    msg->ju_address = ntohl(ju_addr);
    offset += sizeof(ju_addr);

    msg->npg = buffer[offset++];
    msg->net_number = buffer[offset++];

    uint32_t time_slot;
    memcpy(&time_slot, buffer + offset, sizeof(time_slot));
    msg->time_slot = ntohl(time_slot);
    offset += sizeof(time_slot);

    msg->tsec_key = buffer[offset++];
    msg->msec_key = buffer[offset++];

    uint32_t data_len;
    memcpy(&data_len, buffer + offset, sizeof(data_len));
    msg->data_length = ntohl(data_len);
    offset += sizeof(data_len);

    if (buffer_size < offset + msg->data_length || msg->data_length > sizeof(msg->data)) return -1;
    memcpy(msg->data, buffer + offset, msg->data_length);

    return offset;
}

void jmessage_print(const JMessage *msg) {
    printf("JMSG [NPG:%d][seq:%d][JU:%05o][Type:%d][Net:%u][Slot:%u][len:%u][Data:%.*s]\n",
           msg->npg, msg->time_slot,  msg->type, msg->ju_address, msg->net_number, msg->time_slot,
           msg->data_length, msg->data_length, msg->data);
}
