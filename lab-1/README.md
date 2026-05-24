# Lab 1 — ARP Cache Poisoning

**Course:** SEED Labs — Network Security  
**Team:** Bar Sberro · Shalev Cohen · Noam Hadad  
**Date:** March 23, 2026  
**Report:** [Download Full Report (Word)](./Lab-1-Report.docx)

---

## Overview

ARP (Address Resolution Protocol) maps IP addresses to MAC addresses at Layer 2.  
It is stateless and has **no authentication**: any host can broadcast a fabricated IP-to-MAC mapping and other hosts will accept it unconditionally.

This lab exploits that fundamental flaw to:
1. Poison ARP caches using three different methods
2. Position the attacker as a transparent Man-in-the-Middle (MITM)
3. Intercept and modify live Telnet and Netcat sessions in real time

**Network topology (all on 10.0.2.0/24):**

| Role | IP | MAC |
|---|---|---|
| Client A (victim) | 10.0.2.7 | 08:00:27:xx:xx:xx |
| Server B (victim) | 10.0.2.8 | 08:00:27:29:a5:7d |
| Attacker M | 10.0.2.6 | **08:00:27:36:98:8e** |

---

## Task 1 — ARP Cache Poisoning (3 Methods)

**Goal:** Make Client A's ARP table map Server B's IP (10.0.2.8) to Attacker's MAC (08:00:27:36:98:8e).

### Task 1A — Spoofed ARP Request (op=1)

Sent an unsolicited ARP Request claiming that 10.0.2.8 is at Attacker's MAC.  
Even without a prior ARP entry, Client A accepted and cached the mapping.

**Result:** `10.0.2.8 → 08:00:27:36:98:8e` ✅

**Key insight:** ARP has no authentication — a host accepts any IP-to-MAC claim without verifying it.

![](assets/screenshot-05.png)

### Task 1B — Spoofed ARP Reply (op=2)

Sent a targeted ARP Reply directly to Client A.  
**Important discovery:** Linux rejects spoofed ARP Replies when the ARP cache is completely empty.  
The attack only works after the victim initiates communication (creating an `(incomplete)` cache entry).  
Once the system is actively waiting for a reply, it blindly trusts our spoofed response.

**Result:** `10.0.2.8 → 08:00:27:36:98:8e` ✅

![](assets/screenshot-10.png)

### Task 1C — Gratuitous ARP (Broadcast)

A Gratuitous ARP is a special Request where `src IP == dst IP` and Ethernet destination is `ff:ff:ff:ff:ff:ff` (broadcast).  
Normally used to announce IP changes — here used maliciously.

**One packet simultaneously poisons ALL hosts on the subnet.**

**Result:** `10.0.2.8 → 08:00:27:36:98:8e` ✅

![](assets/screenshot-15.png)

---

## Task 2 — MITM Attack on Telnet

**Goal:** Intercept Telnet traffic between A and B, replace every alphabetic character with `Z`.

### Step 1: Two-Way ARP Poisoning
Script (`midm.py`) runs continuously every 2 seconds, sending:
- ARP Reply to A: "B's IP is at Attacker's MAC"
- ARP Reply to B: "A's IP is at Attacker's MAC"

Both victims' ARP tables now point to the Attacker for each other's IP.

### Step 2: Ping Test — IP Forwarding OFF (forward=0)
With `net.ipv4.ip_forward=0`, packets arrive at Attacker but are dropped.  
Client A: `127 packets transmitted, 0 received, 100% packet loss`.  
Wireshark on Attacker confirms packets arrive but shows `[No response seen]`.

![](assets/screenshot-22.png)

### Step 3: Ping Test — IP Forwarding ON (forward=1)
With `net.ipv4.ip_forward=1`, Attacker forwards packets to their real destination.  
Traffic flows: A → M → B → M → A (fully transparent MITM).  
Wireshark shows ICMP request/reply pairs passing through Attacker.

### Step 4: Live Telnet Payload Modification
Script (`mitm_telnet.py`) intercepts TCP port 23 packets from A to B.  
For each packet: iterates over payload bytes, replaces every alphabetic character (`ord('A')` to `ord('Z')`) with `ord('Z')`.  
Packets from B to A are forwarded unchanged.

**Results:**
- `"hello"` typed by Client → arrives at Server as `"ZZZZZ"`
- `"bar shalev"` → `"ZZZ ZZZZZ"`
- `"1213"` (numbers) → `"1213"` (unchanged)
- `"!@#@!"` (special chars) → `"!@#@!"` (unchanged)

Wireshark confirmed Telnet traffic (TCP port 23) passing through Attacker with TCP Spurious Retransmissions visible due to payload modification.

![](assets/screenshot-32.png)

---

## Task 3 — MITM Attack on Netcat

**Goal:** Replace every occurrence of the name `"Adrian"` with `"AAAAAA"` in Netcat messages (TCP port 9090).

**Critical constraint:** Payload length must be preserved exactly (6 chars → 6 chars) to avoid corrupting TCP sequence numbers.

### ARP Poisoning Update
Switched from ARP Reply (op=2) to ARP Request (op=1) — proved more reliable for maintaining continuous poisoning.

### NetMitm Script
`netmitm.py` listens on TCP port 9090 and replaces all variants:
- `Adrian` → `AAAAAA`
- `adrian` → `AAAAAA`
- `Adrain` → `AAAAAA` (typo variant)
- `adrain` → `AAAAAA`

**Demo (Server sends → Client receives):**

| Server typed | Client received |
|---|---|
| `hello adrian,` | `hello AAAAAA,` |
| `how are you?` | `how are you?` |
| `bar shalev adrian noam` | `bar shalev AAAAAA noam` |
| `my name is adrian` | `my name is AAAAAA` |

![](assets/screenshot-42.png)

![](assets/screenshot-47.png)

---

## Lab Summary & Defenses

**Key takeaways:**
- ARP is fundamentally insecure: all 3 poisoning methods succeeded with no authentication at Layer 2
- MITM is fully transparent with IP forwarding enabled — victims communicate normally
- Unencrypted protocols (Telnet, Netcat) expose all payload content to any MITM attacker
- Continuous re-poisoning is required — ARP cache entries typically expire within minutes
- Layer 2 attacks are LAN-scoped: ARP poisoning cannot cross routers

**Defenses:**
- Dynamic ARP Inspection (DAI) on managed switches
- Static ARP entries for critical hosts
- Use encrypted protocols: SSH instead of Telnet, HTTPS instead of HTTP, TLS everywhere
- Network IDS tools: `arpwatch`, XArp to detect anomalous ARP activity
- VPNs on untrusted networks

---

## Beyond Requirements

Real-world tooling research: discovered and tested **arpspoof** (part of the `dsniff` suite):
```bash
sudo arpspoof -i eth0 -t 10.0.2.7 10.0.2.8   # Poison A
sudo arpspoof -i eth0 -t 10.0.2.8 10.0.2.7   # Poison B
```
Combined with `ettercap` or Wireshark, a complete passive MITM is achievable in seconds — highlighting how low the barrier is in practice and reinforcing the importance of DAI and encrypted protocols.

---

## Screenshots

<details>
<summary>View all screenshots (47 images)</summary>

| | | |
|---|---|---|
| ![](assets/screenshot-01.png) | ![](assets/screenshot-02.png) | ![](assets/screenshot-03.png) |
| ![](assets/screenshot-04.png) | ![](assets/screenshot-05.png) | ![](assets/screenshot-06.png) |
| ![](assets/screenshot-07.png) | ![](assets/screenshot-08.png) | ![](assets/screenshot-09.png) |
| ![](assets/screenshot-10.png) | ![](assets/screenshot-11.png) | ![](assets/screenshot-12.png) |
| ![](assets/screenshot-13.png) | ![](assets/screenshot-14.png) | ![](assets/screenshot-15.png) |
| ![](assets/screenshot-16.png) | ![](assets/screenshot-17.png) | ![](assets/screenshot-18.png) |
| ![](assets/screenshot-19.png) | ![](assets/screenshot-20.png) | ![](assets/screenshot-21.png) |
| ![](assets/screenshot-22.png) | ![](assets/screenshot-23.png) | ![](assets/screenshot-24.png) |
| ![](assets/screenshot-25.png) | ![](assets/screenshot-26.png) | ![](assets/screenshot-27.png) |
| ![](assets/screenshot-28.jpg) | ![](assets/screenshot-29.jpg) | ![](assets/screenshot-30.jpg) |
| ![](assets/screenshot-31.jpg) | ![](assets/screenshot-32.png) | ![](assets/screenshot-33.png) |
| ![](assets/screenshot-34.png) | ![](assets/screenshot-35.png) | ![](assets/screenshot-36.png) |
| ![](assets/screenshot-37.png) | ![](assets/screenshot-38.png) | ![](assets/screenshot-39.png) |
| ![](assets/screenshot-40.png) | ![](assets/screenshot-41.png) | ![](assets/screenshot-42.png) |
| ![](assets/screenshot-43.png) | ![](assets/screenshot-44.png) | ![](assets/screenshot-45.png) |
| ![](assets/screenshot-46.png) | ![](assets/screenshot-47.png) | |

</details>

---

[Back to all labs](../README.md)
