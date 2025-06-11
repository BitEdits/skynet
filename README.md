Skynet
======

Message
-------

```
// SkyNetMessage structure (from project scope)
typedef struct {
    uint8_t version;      // 1
    uint8_t type;         // 0=chat, 1=ack, 2=key_exchange, 3=slot_request, 4=waypoint, 5=status, 6=formation
    uint32_t npg_id;      // NPG/swarm_id (1–1000)
    uint32_t node_id;     // Unique node ID
    uint32_t seq_no;      // Deduplication
    uint64_t timestamp;   // Relative time (us)
    uint8_t qos;          // 0=chat, 1=PLI, 2=voice, 3=swarm_cmd
    uint8_t hop_count;    // 0–3
    uint8_t iv[16];       // AES-256-GCM IV
    uint16_t payload_len; // 0–400 bytes
    uint8_t payload[400]; // Encrypted: chat, PLI, waypoint, status, formation
    uint8_t hmac[32];     // HMAC-SHA256
    uint32_t crc;         // CRC-32
} SkyNetMessage;
```

Types
-----

* 0: Chat
* 1: Ack
* 2: Key Exchange
* 3: Slot Request
* 4: Waypoint
* 5: Status
* 6: Formation

Handling
--------

* NPG 1: Process slot_request (type 3) to assign TDMA slots; key_exchange (type 2) for security.
* NPG 6: Handle status (type 5) for PLI, updating NodeState.position and NodeState.velocity for neighbor discovery.
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

J-Messages
----------

Network Management:
* J0.0   Initial Entry
* J0.1   Test
* J0.2   Network Time Update
* J0.3   Time Slot Assignment
* J0.4   Radio Relay Control
* J0.5   Repromulgation Relay
* J0.6   Communication Control
* J0.7   Time Slot Reallocation
* J1.0   Connectivity Interrogation
* J1.1   Connectivity Status
* J1.2   Route Establishment
* J1.3   Acknowledgment
* J1.4   Communication Status
* J1.5   Net Control Initialization
* J1.6   Needline Participation
* ()     Group Assignment

Precise Participant Location and Identification
* J2.0   Indirect Interface Unit PPLI
* J2.2   Air PPLI
* J2.3   Surface PPLI
* J2.4   Subsurface PPLI
* J2.5   Land Point PPLI
* J2.6   Land Track PPLI

Surveillance
* J3.0   Reference Point
* J3.1   Emergency Point
* J3.2   Air Track
* J3.3   Surface Track
* J3.4   Subsurface Track
* J3.5   Land Point or Track
* J3.6   Space Track
* J3.7   Electronic Warfare Product Information

Antisubmarine Warfare
* J5.4   Acoustic Bearing and Range

Intelligence
* J6.0   Intelligence Information

Information Management
* J7.0    Track Management
* J7.1    Data Update Request
* J7.2    Correlation
* J7.3    Pointer
* J7.4    Track Identifier
* J7.5    IFF/SIF Management
* J7.6    Filter Management
* J7.7    Association
* J8.0   Unit Designator
* J8.1   Mission Correlator Change

Weapons Coordination and Management
* J9.0     Command
* J10.2   Engagement Status
* J10.3   Hand Over
* J10.5   Controlling Unit Report
* J10.6   Pairing

Control
* J12.0   Mission Assignment
* J12.1   Vector
* J12.2   Precision Aircraft Direction
* J12.3   Flight Path
* J12.4   Controlling Unit Change
* J12.5   Target/Track Correlation
* J12.6   Target Sorting
* J12.7   Target Bearing

Platform and System Status:

* J13.0   Airfield Status Message
* J13.2   Air Platform and System

Status:

* J13.3   Surface Platform and System Status
* J13.4   Subsurface Platform and System Status
* J13.5   Land Platform and System Status

Electronic:

* J14.0   Parametric Information
* J14.2   Electronic Warfare Control/Coordination

Threat Warning:

* J15.0   Threat Warning

National Use:

* J28.0   U.S. National 1 (Army)
* J28.1   U.S. National 2 (Navy)
* J28.2   U.S. National 3 (Air Force)
* J28.2 (0)  Text Message
* J28.3   U.S. National 4 (Marine Corps)
* J28.4   French National 1
* J28.5   French National 2
* J28.6   U.S. National 5 (NSA)
* J28.7   UK National
* J29     National Use (reserved)
* J30     National Use (reserved)

Miscellaneous:

* J31.0   Over-the-Air Rekeying Management
* J31.1   Over-the-Air Rekeying
* J31.7   No Statement

Aircrafts
---------

* AH-1Z Viper
* AH-64E Apache
* ATR 72MP
* B-1B Lancer
* B-2 Spirit
* C-130J
* C-295 MPA/Persuader
* E-2C Hawkeye
* E-3 Sentry
* E-7A Wedgetail
* E-8 Joint STARS
* EA-6B Prowler
* EA-18G Growler
* EP-3E
* Embraer C-390 Millennium
* Eurocopter Tiger
* Eurofighter Typhoon
* F-15 Eagle
* F-16 Fighting Falcon
* F/A-18 Hornet
* F/A-18 Super Hornet
* F-22 Raptor
* F-35 Lightning II
* HH-60W
* JAS 39 Gripen
* Kaman SH-2G Super Seasprite
* KC-135
* KC-30A MRTT
* KC-46
* MH-60S/R Seahawk
* Mirage 2000D
* Mirage 2000
* P-3C Orion
* P-8A Poseidon
* Rafale
* R-99
* RC-135 Rivet Joint
* S 100B Argus (Saab 340 AEW&C) (ASC 890)
* Sea King Mk 7 ASaC
* Tornado

Missile Defence Systems
-----------------------

* Arrow
* SAMP/T
* Patriot ICC and Battery Command Post (BCP)
* THAAD
* JTAGS
* NASAMS

Bibliography
------------

* <a href="https://apps.dtic.mil/sti/pdfs/ADA404334.pdf">TADIL J:  INTRODUCTION TO TACTICAL DIGITAL INFORMATION LINK J ANDQUICK REFERENCE GUIDE</a>
