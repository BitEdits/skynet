#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define MAX_BUFFER 1024

int main() {
    int sock;
    struct sockaddr_in server_addr;
    char buffer[MAX_BUFFER];

    // Create UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    // Send mock PPLI message
    char *message = "J0.0 F16_001 40.0 -75.0";
    sendto(sock, message, strlen(message), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    printf("Sent: %s\n", message);

    // Receive response
    socklen_t addr_len = sizeof(server_addr);
    int len = recvfrom(sock, buffer, MAX_BUFFER - 1, 0, (struct sockaddr *)&server_addr, &addr_len);
    if (len > 0) {
        buffer[len] = '\0';
        printf("Received: %s\n", buffer);
    } else {
        printf("No response received\n");
    }

    close(sock);
    return 0;
}
