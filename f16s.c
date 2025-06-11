#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define PORT 8080
#define MAX_BUFFER 1024
#define SLOT_DURATION_MS 100 // Scaled for simplicity (real Link 16: 7.8125 ms)
#define SLOTS_PER_CYCLE 10 // Simplified (real Link 16: 128 slots/second)
#define MAX_CLIENTS 10

// Mock J-series message (e.g., J0.0 for PPLI)
typedef struct {
    char type[10]; // e.g., "J0.0"
    char source_id[20]; // e.g., "F16_001"
    double lat, lon; // Mock position data
} Message;

// Client info
typedef struct {
    struct sockaddr_in addr;
    int slot; // Assigned time slot (0 to SLOTS_PER_CYCLE-1)
} Client;

Client clients[MAX_CLIENTS];
int client_count = 0;

// Broadcast message to all clients
void broadcast(int sock, char *buffer, int len) {
    for (int i = 0; i < client_count; i++) {
        sendto(sock, buffer, len, 0, (struct sockaddr *)&clients[i].addr, sizeof(clients[i].addr));
    }
}

int main() {
    int sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[MAX_BUFFER];
    struct timespec slot_time = {0, SLOT_DURATION_MS * 1000000}; // 100 ms
    // For real 7.8125 ms slots: {0, 7812500}

    // Create UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind socket
    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(1);
    }
    printf("Link 16 simulation server (MIDS-LVT-like) running on port %d...\n", PORT);

    // Main loop: Simulate TDMA slots
    int slot = 0;
    while (1) {
        printf("Slot %d\n", slot);

        // Receive messages in current slot (non-blocking)
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        struct timeval timeout = {0, 100000}; // 100 us timeout
        if (select(sock + 1, &read_fds, NULL, NULL, &timeout) > 0) {
            int len = recvfrom(sock, buffer, MAX_BUFFER - 1, 0, (struct sockaddr *)&client_addr, &addr_len);
            if (len > 0) {
                buffer[len] = '\0';

                // Register new client
                int client_exists = 0;
                for (int i = 0; i < client_count; i++) {
                    if (clients[i].addr.sin_addr.s_addr == client_addr.sin_addr.s_addr &&
                        clients[i].addr.sin_port == client_addr.sin_port) {
                        client_exists = 1;
                        break;
                    }
                }
                if (!client_exists && client_count < MAX_CLIENTS) {
                    clients[client_count].addr = client_addr;
                    clients[client_count].slot = client_count % SLOTS_PER_CYCLE;
                    client_count++;
                    printf("New client (%s:%d) assigned slot %d\n",
                           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port),
                           clients[client_count - 1].slot);
                }

                // Process message (e.g., "J0.0 F16_001 40.0 -75.0")
                Message msg;
                if (sscanf(buffer, "%s %s %lf %lf", msg.type, msg.source_id, &msg.lat, &msg.lon) == 4) {
                    printf("Received in slot %d: %s from %s (lat: %.2f, lon: %.2f)\n",
                           slot, msg.type, msg.source_id, msg.lat, msg.lon);
                    // Broadcast to all clients in next slot
                    broadcast(sock, buffer, len);
                } else {
                    printf("Invalid message format in slot %d\n", slot);
                }
            }
        }

        // Move to next slot
        slot = (slot + 1) % SLOTS_PER_CYCLE;
        nanosleep(&slot_time, NULL); // Wait for slot duration
    }

    close(sock);
    return 0;
}
