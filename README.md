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
* Only POSIX/OpenSSL dependencies
& 64KB L1 footprint

Install
-------

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
$ ./slynet server &
$ ./skynet_client client
```

Skynet Server Log
-----------------

```
Node name: 40ac3dd2
Debug: Accessing keystore: /home/tonpa/.skynet/ecc/secp384r1/40ac3dd2.ec_priv
Debug: Accessing keystore: /home/tonpa/.skynet/ecc/secp384r1/06c5bc52.ec_priv
Debug: Accessing keystore: /home/tonpa/.skynet/ecc/secp384r1/c9aef284.ec_priv
Debug: Accessing keystore: /home/tonpa/.skynet/ecc/secp384r1/4d128cdc.ec_priv
Debug: Accessing keystore: /home/tonpa/.skynet/ecc/secp384r1/9c69a767.ec_priv
Debug: Accessing keystore: /home/tonpa/.skynet/ecc/secp384r1/89f28794.ec_priv
Debug: Accessing keystore: /home/tonpa/.skynet/ecc/secp384r1/9f456bca.ec_priv
Debug: Accessing keystore: /home/tonpa/.skynet/ecc/secp384r1/542105cc.ec_priv
Debug: Accessing keystore: /home/tonpa/.skynet/ecc/secp384r1/e46c0c22.ec_priv
SkyNet server bound to 0.0.0.0:6566
Joined multicast group 239.255.0.1
Joined multicast group 239.255.0.6
Joined multicast group 239.255.0.7
Joined multicast group 239.255.0.29
Joined multicast group 239.255.0.100
Joined multicast group 239.255.0.101
Joined multicast group 239.255.0.102
Joined multicast group 239.255.0.103
SERIALIZED LEN: 305
Node 2408750110 (8f929c1e) added from 172.23.86.121:32796
Debug: Starting decryption on server: from=8f929c1e, to=40ac3dd2, size=e7
Debug: Accessing keystore: /home/tonpa/.skynet/ecc/secp384r1/40ac3dd2.ec_priv
Debug: Accessing keystore: /home/tonpa/.skynet_client/ecc/secp384r1/8f929c1e.ec_pub
Debug: Decryption done OK
SKY HEX DUMP:
01 00 00 00 01 00 00 00 1e 9c 92 8f 00 00 00 00
74 1f a8 a7 69 37 06 00 03 00 a8 56 22 47 6b b6
11 cd a1 6f be a6 66 74 ee 3c d7 00 2d 2d 2d 2d
2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45
59 2d 2d 2d 2d 2d 0a 4d 48 59 77 45 41 59 48 4b
6f 5a 49 7a 6a 30 43 41 51 59 46 4b 34 45 45 41
43 49 44 59 67 41 45 46 44 52 46 6d 46 64 77 6a
62 43 42 48 44 67 75 6d 52 65 35 64 70 76 75 45
43 62 32 45 45 4b 6d 0a 6f 78 45 30 41 2f 4e 46
35 33 4d 5a 49 44 49 4c 70 51 70 54 5a 66 41 34
6b 62 4f 58 7a 56 59 72 32 65 55 5a 31 66 2f 6b
53 36 2b 55 77 63 55 44 71 49 4c 70 34 44 49 37
31 36 52 62 53 4a 38 73 0a 6e 41 57 6e 6b 31 57
77 6c 38 6d 51 7a 62 79 49 61 72 66 74 7a 41 33
37 53 39 69 65 66 55 45 70 0a 2d 2d 2d 2d 2d 45
4e 44 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d
2d 2d 0a 16 91 44 fe 46 9e 4b 9d 27 60 e9 9f b1
0f 58 9f 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00
Saved public key for client 8f929c1e
Debug: Starting encryption on server: from=40ac3dd2, to=8f929c1e, size=2
Debug: Accessing keystore: /home/tonpa/.skynet/ecc/secp384r1/40ac3dd2.ec_priv
Debug: Accessing keystore: /home/tonpa/.skynet_client/ecc/secp384r1/8f929c1e.ec_pub
Debug: Enryption done OK
Debug: Starting encryption on server: from=40ac3dd2, to=6c5bc52, size=12
Debug: Accessing keystore: /home/tonpa/.skynet/ecc/secp384r1/40ac3dd2.ec_priv
Debug: Accessing keystore: /home/tonpa/.skynet_client/ecc/secp384r1/06c5bc52.ec_pub
Debug: Enryption done OK
SENT [NPG:1][seq:2][multicast:239.255.0.1] latency [us:5066]
SERIALIZED LEN: 108
Debug: Starting encryption on server: from=40ac3dd2, to=6c5bc52, size=0
Debug: Accessing keystore: /home/tonpa/.skynet/ecc/secp384r1/40ac3dd2.ec_priv
Debug: Accessing keystore: /home/tonpa/.skynet_client/ecc/secp384r1/06c5bc52.ec_pub
Debug: Enryption done OK
Debug: Starting encryption on server: from=40ac3dd2, to=6c5bc52, size=10
Debug: Accessing keystore: /home/tonpa/.skynet/ecc/secp384r1/40ac3dd2.ec_priv
Debug: Accessing keystore: /home/tonpa/.skynet_client/ecc/secp384r1/06c5bc52.ec_pub
Debug: Enryption done OK
```

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
* Air: NPGs 1, 6, 7, 100, 101, 103 (control, PLI, surveillance, C2, alerts, inter-agent).
* Sea: NPGs 1, 7, 29, 102, 103 (control, surveillance, chat, logistics, inter-agent).
* Ground: NPGs 1, 7, 29, 102 (control, surveillance, chat, logistics).
* Relay: NPGs 1, 6, 101 (control, PLI, alerts).
* Controller: NPGs 1, 6, 100, 101 (control, PLI, C2, alerts).

Author
------

* Namdak Tonpa
* Moneta Rocco
