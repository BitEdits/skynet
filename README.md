Link32
======

Link32 is a VMF/LINK16/TSM/SRW/MQTT inspired tactical protocol for military appliances.

Properties
----------

* C99 Implementation
* 32 bytes Minimal Message (including IV)
* ECC DH Key Exchange
* Microseconds-precise Latency
* Non-Blocking Atomic Primitives
* Multicore Processing
* AES-256-GCM Encryption
* Multicast Topics
* UDP Interface
* Single dependency (OpenSSL, replaceable)
* Threat model doesn't require non-repudiation (HMAC)
* 64KB L1 footprint, 2000 LOC

Install
-------

The system should be able to deploy with one script `skynet.sh` having mounted key stores of all network allowed devices.

```
$ git clone git@github.com:BitEdits/skynet
$ cd skynet
$ ./skynet.sh
Generated keys for node npg_control (hash: 06c5bc52) in /home/tonpa/.skynet/ecc/secp384r1/
Generated keys for node npg_pli (hash: c9aef284) in /home/tonpa/.skynet/ecc/secp384r1/
Generated keys for node npg_surveillance (hash: 4d128cdc) in /home/tonpa/.skynet/ecc/secp384r1/
Generated keys for node npg_chat (hash: 9c69a767) in /home/tonpa/.skynet/ecc/secp384r1/
Generated keys for node npg_c2 (hash: 89f28794) in /home/tonpa/.skynet/ecc/secp384r1/
Generated keys for node npg_alerts (hash: 9f456bca) in /home/tonpa/.skynet/ecc/secp384r1/
Generated keys for node npg_logistics (hash: 542105cc) in /home/tonpa/.skynet/ecc/secp384r1/
Generated keys for node npg_coord (hash: e46c0c22) in /home/tonpa/.skynet/ecc/secp384r1/
Generated keys for node server (hash: 40ac3dd2) in /home/tonpa/.skynet/ecc/secp384r1/
Generated keys for node client (hash: 8f929c1e) in /home/tonpa/.skynet_client/ecc/secp384r1/
$ cp /home/tonpa/.skynet/ecc/secp384r1/*.ec_pub /home/tonpa/.skynet_client/ecc/secp384r1/
$ ./skynet server &
$ ./skynet_client client
```

Skynet
------

Server:

```
$ ./skynet server
Node 40ac3dd2 bound to 0.0.0.0:6566.
Joined multicast group 239.255.0.1.
Joined multicast group 239.255.0.6.
Joined multicast group 239.255.0.7.
Joined multicast group 239.255.0.29.
Joined multicast group 239.255.0.100.
Joined multicast group 239.255.0.101.
Joined multicast group 239.255.0.102.
Joined multicast group 239.255.0.103.
Node 8f929c1e added from 172.23.86.121:45520.
Message received, from=8f929c1e, to=1, size=231.
Message received, from=8f929c1e, to=1, size=16.
Decryption successful, from=8f929c1e, to=1, size=215.
Saved public key for client 8f929c1e.
Message received, from=8f929c1e, to=6, size=40.
Decryption successful, from=8f929c1e, to=1, size=0.
Node 8f929c1e subscribed to NPG 1.
Message received, from=8f929c1e, to=6, size=40.
Decryption successful, from=8f929c1e, to=6, size=24.
Encryption successful, from=8f929c1e, to=1, size=18.
Decryption successful, from=8f929c1e, to=6, size=24.
Message received, from=8f929c1e, to=6, size=40.
Encryption successful, from=40ac3dd2, to=6, size=40.
Messsage sent from=40ac3dd2, to=6, seq=2, multicast=239.255.0.6, latency=5511.
Node 40ac3dd2 added from 172.23.86.121:6566.
Message received, from=40ac3dd2, to=6, size=40.
Encryption successful, from=8f929c1e, to=1, size=34.
Message received, from=8f929c1e, to=6, size=40.
Messsage sent from=8f929c1e, to=1, seq=3, multicast=239.255.0.1, latency=10248.
```

Client:

```
$ ./skynet_client client
Node 8f929c1e connecting to port 6566.
Joined multicast group 239.255.0.1 (NPG 1).
Joined multicast group 239.255.0.6 (NPG 6).
Joined multicast group 239.255.0.7 (NPG 7).
Joined multicast group 239.255.0.29 (NPG 29).
Joined multicast group 239.255.0.100 (NPG 100).
Joined multicast group 239.255.0.101 (NPG 101).
Joined multicast group 239.255.0.102 (NPG 102).
Joined multicast group 239.255.0.103 (NPG 103).
Encryption successful, from=8f929c1e, to=1, size=231.
Sent key exchange message to server.
Encryption successful, from=8f929c1e, to=1, size=16.
Sent slot request message to server.
Encryption successful, from=8f929c1e, to=6, size=40.
Sent status message: pos=[0.0, 0.0, 0.0], vel=[0.0, 0.0, 0.0], seq=2.
```

S-Message
---------

Skynet message format is designed for swarms of thousands.

```
typedef struct  __attribute__((packed)) {
    uint8_t version : 4;         // 1/2 byte
    uint8_t type : 4;            // 1/2 byte
    uint8_t qos : 4;             // 1/2 byte
    uint8_t hop_count : 4;       // 1/2 byte
    uint32_t npg_id;             // 4   bytes
    uint32_t node_id;            // 4   bytes
    uint32_t seq_no;             // 4   bytes
    uint8_t iv[16];              // 16  bytes
    uint16_t payload_len;        // 2   bytes
    uint8_t payload[MAX_BUFFER]; // Variable
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
* Air: NPGs 1, 6, 7, 100, 101, 103 (control, PLI, surveillance, C2, alerts, inter-agent).
* Sea: NPGs 1, 7, 29, 102, 103 (control, surveillance, chat, logistics, inter-agent).
* Ground: NPGs 1, 7, 29, 102 (control, surveillance, chat, logistics).
* Relay: NPGs 1, 6, 101 (control, PLI, alerts).
* Controller: NPGs 1, 6, 100, 101 (control, PLI, C2, alerts).

Author
------

* Namdak Tonpa
