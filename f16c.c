#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "j-msg.h"

#define PORT 8080
#define MAX_BUFFER 4096
#define JU_ADDRESS 00001
#define DEFAULT_NPG 7
#define DEFAULT_NET 0

int main() {
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket creation failed");
        return 1;
    }

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
    };
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    if (connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) + 1 == 0) {
       perror("connection failed");
       return -1;
    }

    /* Send initial entry message */
    JMessage msg;
    jmessage_init(&msg, J_MSG_INITIAL_ENTRY, JU_ADDRESS, 1, 0);
    uint8_t buffer[MAX_BUFFER];
    int len = jmessage_serialize(&msg, buffer, MAX_BUFFER);
    if (len > 0) send(sock_fd, buffer, len, 0);

    /* Send sample surveillance message */
    jmessage_init(&msg, J_MSG_SURVEILLANCE, JU_ADDRESS, 7, 0);
    char *data = "Track: F-18, Lat:50.0, Lon:10.0";
    jmessage_set_data(&msg, (uint8_t *)data, strlen(data) + 1);
    len = jmessage_serialize(&msg, buffer, MAX_BUFFER);
    if (len > 0) send(sock_fd, buffer, len, 0);

    {
        len = recv(sock_fd, buffer, MAX_BUFFER, 0);
        JMessage rx_msg;
        if (jmessage_deserialize(&rx_msg, buffer, len) >= 0) {
            jmessage_print(&rx_msg);
        }
    }

    close(sock_fd);
    return 0;
}
