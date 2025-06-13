Skynet
======

Skynet is LINK16/TSM/SRW/MQTT inspired tactical protocol for military appliances.

Properties
----------

* C99 implementation
* ECC key exchange
* Microseconds-precise latency
* Non-Blocking atomic primitives
* AES-256-GCM encryption
* Multicast Topics
* UDP interface
* OpenSSL based

Message
-------

Skynet message format is designed for swarms of thousands.

```
typedef struct {
    uint8_t version;       // 1
    uint8_t type;          // 0=key, 1=slot, 2=chat, 3=ack, 4=waypoint, 5=status, 6=formation
    uint32_t npg_id;       // NPG/swarm_id (1–1000)
    uint32_t node_id;      // Unique node ID
    uint32_t seq_no;       // Deduplication
    uint64_t timestamp;    // Relative time (us)
    uint8_t qos;           // 0=chat, 1=PLI, 2=voice, 3=swarm_cmd
    uint8_t hop_count;     // 0–3
    uint8_t iv[16];        // AES-256-GCM IV
    uint16_t payload_len;  // 0–400 bytes
    uint8_t payload[1590]; // Encrypted: chat, PLI, waypoint, status, formation
    uint8_t hmac[32];      // HMAC-SHA256
} SkyNetMessage;
```

Types
-----

* 0: Key Exchange
* 1: Slot Request
* 2: Chat
* 3: Ack
* 4: Waypoint
* 5: Status
* 6: Formation

Multicast Topics
----------------

* NPG 1: Process slot_request (type 3) to assign TDMA slots; key_exchange (type 2) for security.
* NPG 6: Handle status (type 5) for PLI, updating position and velocity for neighbor discovery.
* NPG 7: Forward status (type 5) sensor data to subscribers (e.g., command posts).
* NPG 29: Relay chat (type 0) and ack (type 1) for TacChat.
* NPG 100: Process waypoint (type 4) and formation (type 6) for C2.
* NPG 101: Broadcast status (type 5) alerts for self-healing.
* NPG 102: Handle status (type 5) and chat (type 0) for logistics.
* NPG 103: Relay chat (type 0), waypoint (type 4), and formation (type 6) for coordination.

Subscriptions
-------------

* Infantry: NPGs 1, 29 (control, chat).
* Drone: NPGs 1, 6, 7, 100, 101 (control, PLI, surveillance, C2, alerts).
* Aircraft: NPGs 1, 6, 7, 100, 101, 103 (control, PLI, surveillance, C2, alerts, inter-agent).
* Warship: NPGs 1, 7, 29, 102, 103 (control, surveillance, chat, logistics, inter-agent).
* Platform: NPGs 1, 7, 29, 102 (control, surveillance, chat, logistics).
* Train: NPGs 1, 6, 100, 102, 103 (control, PLI, C2, logistics, inter-agent).
* Wheels: NPGs 1, 6, 29, 100, 102, 103 (control, PLI, chat, C2, logistics, inter-agent).
* Relay: NPGs 1, 6, 101 (control, PLI, alerts).
* Controller: NPGs 1, 6, 100, 101 (control, PLI, C2, alerts).

Author
------

* Namdak Tonpa
* Moneta Rocco
