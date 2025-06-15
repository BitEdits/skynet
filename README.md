# Skynet/Link32

Link32 is a tactical communication protocol inspired by VMF, LINK16, TSM, SRW, and MQTT,
designed for military applications requiring low-latency, secure, and scalable data
exchange in contested environments. It supports swarm coordination, real-time position
location information (PLI), command and control (C2), and tactical chat over UDP-based
multicast networks.

Skynet is the reference server implementing Link32 tactical battlefield protocol implemented
in pure C99 with zero dependencies (awaiting OpenSSL replacement).

## Properties

* Implementation: Written in C99 for portability and performance on resource-constrained devices.
* Message Size: Minimum 32-byte header (48 bytes with AES-256-GCM authentication tag) to optimize bandwidth.
* Security: ECDH key exchange over secp384r1, with AES-256-GCM encryption for all messages.
* Latency: Microsecond-precision timing using monotonic clocks and non-blocking I/O.
* Concurrency: Lock-free atomic operations (CMPXCHG) for multicore thread-safe queue management.
* Networking: UDP multicast with topic-based subscriptions, using IP multicast groups (e.g., 239.255.0.<npg_id>).
* Footprint: ~64KB L1 cache usage, ~2000 lines of code (LOC) for minimal resource consumption.
* Dependencies: Single dependency on OpenSSL for cryptographic operations.
* Threat Model: Prioritizes confidentiality and integrity without non-repudiation (no HMAC required).

## Principles

* Key Provisioning: public keys require controleable (manual) distribution.
* Mandatory Encryption: All messages are encrypted with AES-256-GCM.
* Node Identification: Node names are hashed to 32-bit using FNV-1a for compact addressing.
* Lock-Free Design: No mutexes or semaphores; uses atomic compare-and-swap (CMPXCHG) for concurrency.
* Topic Architecture: Topics map to IP multicast groups, enabling scalable publish-subscribe communication.
* Queue Management: Global network queue for incoming messages with per-topic subscriber queues.
* Key Storage: Separate key stores per executable.

## Link32 Protocol

### S-Message Format

The Skynet Message structure is compact, designed for swarms of thousands of nodes:

```
typedef struct {
    uint8_t version : 4;         // Protocol version (current: 1)
    uint8_t type : 4;            // Message type (0-6)
    uint8_t qos : 4;             // Quality of Service (0-3)
    uint8_t hop_count : 4;       // Hop count for routing (0-15)
    uint32_t npg_id;             // Topic identifier (1-103)
    uint32_t node_id;            // Sender node ID (FNV-1a hash)
    uint32_t seq_no;             // Sequence number for deduplication
    uint8_t iv[16];              // AES-256-GCM initialization vector
    uint16_t payload_len;        // Payload length (0-32767)
    uint8_t payload[MAX_BUFFER]; // Encrypted payload + 16-byte GCM tag
} SkyNetMessage;
```

* Header Size: 32 bytes (version, type, QoS, hop_count, npg_id, node_id, seq_no, iv, payload_len).
* Total Size: 48 bytes minimum (32-byte header + 16-byte GCM tag for empty payload).
* Payload: Up to 32720 bytes.

### Message Types

|Id | Type         | Description                                              |
|---|--------------|----------------------------------------------------------|
| 0 | Key Exchange | Exchanges ECC public keys for ECDH session setup.        |
| 1 | Slot Request | Requests a TDMA slot from the server.                    |
| 2 | Chat         | Sends tactical chat messages.                            |
| 3 | Ack          | Acknowledges slot assignments or other control messages. |
| 4 | Waypoint     | Specifies navigation waypoints for C2.                   |
| 5 | Status       | Reports position, velocity, or sensor data (e.g., PLI).  |
| 6 | Formation    | Coordinates swarm formations.                            |

### Multicast Topics

| NPG | Name             | Multicast     | Purpose                                                            |
|-----|------------------|---------------|--------------------------------------------------------------------|
| 1   | npg_control      | 239.255.0.1   | Handles key exchange and slot requests for network control.        |
| 6   | npg_pli          | 239.255.0.6   | Processes status messages for position information .               |
| 7   | npg_surveillance | 239.255.0.7   | Forwards status messages with sensor data to subscribers.          |
| 29  | npg_chat         | 239.255.0.29  | Relays chat and ack messages for tactical communication.           |
| 100 | npg_c2           | 239.255.0.100 | Processes waypoint and formation messages for C2.                  |
| 101 | npg_alerts       | 239.255.0.101 | Broadcasts status messages for network alerts and self-healing.    |
| 102 | npg_logistics    | 239.255.0.102 | Handles status and chat for logistical coordination.               |
| 103 | npg_coord        | 239.255.0.103 | Relays chat, waypoint, and formation for inter-agent coordination. |

### Slot Management

Link32 uses a minimalistic Time Division Multiple Access (TDMA)-like slot manager to reduce message collisions and emulate dynamic topics:

* Slot Array: The server maintains a fixed-size array (`slots[SLOT_COUNT=256]`) in `ServerState`, where each slot is either free (0) or assigned to a `node_id`.
* Dynamic Topics: Each assigned slot creates a temporary multicast group for node-specific communication, extending the static topic set (`MAX_TOPICS=8`).
* Allocation Policy: First-come, first-serve with no timeouts or reallocation to minimize complexity.
* Timing: Slots cycle every `TIME_SLOT_INTERVAL_US=1000µs`, synchronized via a timerfd in the server.

Implementation details:

* Clients send a `SKYNET_MSG_SLOT_REQUEST` (type 1) with their `node_id` to `239.255.0.1` (NPG 1).
* The server assigns the first free slot using `assign_slot` and responds with a `SKYNET_MSG_ACK` (type 3) containing the slot ID (4-byte payload).
* The client joins the slot’s multicast group (`239.255.1.<slot_id % 256>`) and sends messages to it.

### Deduplication

To prevent message loops and duplicates, the server uses a fixed-size circular buffer `seq_cache` for deduplication:

* Structure: Each entry stores `{node_id, seq_no, timestamp}`.
* Memory: ~16KB (1024 × 16 bytes per entry: 4 for node_id, 4 for seq_no, 8 for timestamp).
* Complexity: O(1) lookup and update using FNV-1a hashing.
* Timestamp Threshold: Discards duplicates received within 1 second.

Implementation details:

* Incoming messages are hashed (`node_id ^ seq_no` via FNV-1a) to an index in `seq_cache`.
* If the entry matches and the timestamp is recent (<1s), the message is discarded as a duplicate.
* Otherwise, the entry is updated with the new message’s details.

### Security

* Key Exchange: ECDH over secp384r1 generates 256-bit AES keys for each session.
* Encryption: All payloads are encrypted with AES-256-GCM, using a 16-byte random IV and appending a 16-byte authentication tag.
* Server Key Storage: `~/.skynet/ecc/secp384r1/<node_hash>.{ec_priv,ec_pub}`.
* Client Key Storage: `~/.skynet_client/ecc/secp384r1/<node_hash>.{ec_priv,ec_pub}`
* Key Derivation: Uses HKDF-SHA256 to derive AES keys from ECDH shared secrets.
* Self-Sent Message Handling: The server skips processing messages where `msg->node_id == state->node_id` to prevent decryption errors and loops.

### Subscriptions

Nodes subscribe to topics based on their role, joining the corresponding multicast groups:

| Role       | NPGs Subscribed        | Purpose |
|------------|------------------------|-----------------------------------------------------------|
| Infantry   | 1, 29                  | Network control and tactical chat.                        |
| Drone      | 1, 6, 7, 100, 101      | Control, PLI, surveillance, C2, and alerts.               |
| Air        | 1, 6, 7, 100, 101, 103 | Control, PLI, surveillance, C2, alerts, and coordination. |
| Sea        | 1, 7, 29, 102, 103     | Control, surveillance, chat, logistics, and coordination. |
| Ground     | 1, 7, 29, 102          | Control, surveillance, chat, and logistics.               |
| Relay      | 1, 6, 101              | Control, PLI, and alerts for message relaying.            |
| Controller | 1, 6, 100, 101         | Control, PLI, C2, and alerts for command posts.           |

## Skynet

### Dependencies

* OpenSSL: Required for ECC key generation, ECDH, and AES-256-GCM encryption/decryption.
* C99 Compiler: GCC or equivalent for building the server and client binaries.
* POSIX Environment: For threading, epoll, and timerfd support.

### Build

```
$ git clone git@github.com:BitEdits/skynet
$ cd skynet
$ gcc -o skynet_client skynet_client.c skynet_proto.c -lcrypto
$ gcc -o skynet skynet.c skynet_proto.c -pthread -lcrypto
```

### Installation

Link32 deploys via a provisioning script (skynet.sh), which generates ECC key pairs for all network nodes and topics. Public keys must be manually copied to client key stores for mutual authentication.

```
$ ./skynet.sh
Generated keys for node npg_control (hash: 06c5bc52) in /home/user/.skynet/ecc/secp384r1/
Generated keys for node npg_pli (hash: c9aef284) in /home/user/.skynet/ecc/secp384r1/
Generated keys for node npg_surveillance (hash: 4d128cdc) in /home/user/.skynet/ecc/secp384r1/
Generated keys for node npg_chat (hash: 9c69a767) in /home/user/.skynet/ecc/secp384r1/
Generated keys for node npg_c2 (hash: 89f28794) in /home/user/.skynet/ecc/secp384r1/
Generated keys for node npg_alerts (hash: 9f456bca) in /home/user/.skynet/ecc/secp384r1/
Generated keys for node npg_logistics (hash: 542105cc) in /home/user/.skynet/ecc/secp384r1/
Generated keys for node npg_coord (hash: e46c0c22) in /home/user/.skynet/ecc/secp384r1/
Generated keys for node server (hash: 40ac3dd2) in /home/user/.skynet/ecc/secp384r1/
Generated keys for node client (hash: 8f929c1e) in /home/user/.skynet_client/ecc/secp384r1/
$ cp ~/.skynet/ecc/secp384r1/*.ec_pub ~/.skynet_client/ecc/secp384r1/
```

### Server Operation

The server `skynet` binds to UDP port 6566, joins multicast groups for all topics `239.255.0.<npg_id>`,
and processes incoming messages using a global network queue (MessageQueue mq). It spawns worker
threads pinned to CPU cores for concurrent message handling.

Each topic has a dedicated subscriber queue `topic_queues`,
and messages are forwarded to slot-specific multicast groups `239.255.1.<slot_id>` for dynamic topics.

Example server output:

```
$ ./skynet server
Node 40ac3dd2 bound to 0.0.0.0:6566.
Joined multicast group 239.255.0.1 (NPG 1: control).
Joined multicast group 239.255.0.6 (NPG 6: PLI).
...
Message received, from=8f929c1e, to=1, size=231.
Decryption successful, from=8f929c1e, to=1, size=215.
Saved public key for client 8f929c1e.
Assigned slot 0 to node 8f929c1e.
Message received, from=8f929c1e, to=6, size=40.
Decryption successful, from=8f929c1e, to=6, size=24.
Message sent from=8f929c1e, to=6, seq=3, multicast=239.255.1.0, latency=36643.
```

### Client Operation

The client `skynet_client` connects to port 6566, joins topic-specific multicast groups, and sends:

* A key exchange message (SKYNET_MSG_KEY_EXCHANGE) to 239.255.0.1.
* A slot request (SKYNET_MSG_SLOT_REQUEST) to 239.255.0.1.
* Periodic status messages (SKYNET_MSG_STATUS) to the assigned slot’s multicast group (239.255.1.<slot_id>) or topic group (239.255.0.6 for PLI), limited to 10 messages by default (MESSAGE_LIMIT=10).

Example client output:

```
$ ./skynet_client client
Node 8f929c1e connecting to port 6566.
Joined multicast group 239.255.0.1 (NPG 1).
Joined multicast group 239.255.0.6 (NPG 6).
...
Sent key exchange message to server.
Sent slot request message to server.
Received slot assignment: slot=0.
Joined slot multicast group 239.255.1.0.
Sent status message: pos=[0.1, 0.1, 0.1], vel=[0.0, 0.0, 0.0], seq=2, multicast=239.255.1.0.
```

### Usage

Skynet distribution contains 5 binary files.

#### `skynet_keygen <node> [--server|--client]`

Generates ECC secp384r1 key pairs for the specified node,
storing them in `~/.skynet/ecc/secp384r1/` (server) or `~/.skynet_client/ecc/secp384r1/` (client).

#### `skynet_encrypt <sender> <recipient> <file>`

Encrypts a test message from `<sender>` to `<recipient>` for the specified NPG, producing `<npg_id>.sky`.

#### `skynet_decrypt <sender> <recipient> <file.sky>`

Decrypts `<file>` (e.g., `<npg_id>.sky`) using keys for `<sender>` and `<recipient>`.

#### `skynet <node>`

Runs the server named as `<node>`, FNV1A 32-bit hash is used.
The server assigns a slot, forwards status messages to `239.255.1.<slot_id>`, and logs all activity.

#### `skynet_client <node>`

Runs the client named as `<node>`, FNV1A 32-bit hash is used.
The client sends key exchange, slot request, and status messages.

### Limitations

* Slot Scalability: Fixed `SLOT_COUNT=256` limits dynamic topics to 256 nodes.
* No Retransmission: Messages dropped due to network errors are not retransmitted (aligned with QoS settings).
* Key Management: Manual public key copying required; no automated key distribution.
* Deduplication: `SEQ_CACHE_SIZE=1024` may lead to cache collisions in high-traffic scenarios.

## Author

* Namdak Tonpa
