# Lab 3 — Local DNS Attacks

**Course:** SEED Labs — Network Security  
**Team:** Bar Sberro · Shalev Cohen · Noam Hadad  
**Report:** [Download Full Report (Word)](./Lab-3-Report.docx)

---

## Overview

DNS (Domain Name System) translates human-readable domain names to IP addresses.  
Because DNS responses are unauthenticated by default, an attacker on the same LAN can:
- Poison a victim's local resolver cache
- Intercept and replace DNS responses in transit
- Redirect entire domains by poisoning authoritative NS records

This lab covers the full DNS attack surface from the simplest (hosts file) to the most impactful (cache poisoning with Authority section injection).

**Network topology:**

| Role | IP |
|---|---|
| Client | 10.0.2.10 |
| Local DNS Server (BIND9 "Apollo") | 10.0.2.20 |
| Attacker | 10.0.2.6 |
| Fake attacker IP (target of spoofing) | 10.0.2.100 |

---

## Tasks 1-3 — Environment Setup & Local DNS Configuration

### Task 1 — Configure Client DNS
Set `/etc/resolv.conf` on Client to point to Local DNS Server: `nameserver 10.0.2.20`.

### Task 2 — Verify Recursive Resolution
Ran `dig www.google.com` from Client, capturing the exchange in Wireshark.  
DNS query flows: Client → Apollo (10.0.2.20) → Root → TLD → Authoritative → back.  
Apollo's BIND9 configured as a **Forwarder** — 8 IP addresses returned in the Answer section.

### Task 3 — Authoritative Zone Setup
Configured BIND9 as **Authoritative** for `example.com` by creating a Zone File.  
`dig example.com`:
- `aa` flag set in response header (Authoritative Answer) ✅
- Answer: `10.0.2.20`
- Query time: 2ms (served locally, no external lookup)

![](assets/screenshot-08.png)

---

## Task 4 — Hosts File Poisoning

**Concept:** `/etc/hosts` is checked **before** DNS — it takes absolute precedence.  
An attacker with local access can silently redirect any domain.

**Attack:** Added to `/etc/hosts` on Client:
```
10.0.2.100   www.bank32.com
```

**Results:**
- `ping www.bank32.com` → sends to 10.0.2.100 (attacker's IP) ✅
- `dig www.bank32.com` → queries DNS server normally (10.0.2.20), returns the real answer — dig bypasses hosts file
- **Key insight:** `ping`, `curl`, browsers use `getaddrinfo()` (which checks hosts first). `dig` queries DNS directly.

**Implication:** With root access on a compromised machine, an attacker can silently redirect any domain for all normal applications without touching DNS at all.

![](assets/screenshot-14.png)

---

## Task 5 — Direct DNS Response Spoofing

**Concept:** DNS runs over UDP — responses are not authenticated. An attacker on the same LAN can sniff DNS queries and inject a spoofed reply faster than the real server responds.

**The spoofed reply must match:**
- Transaction ID (16-bit, copied from the query)
- Source and destination IP/port (swapped from the query)
- Question section (matching the queried name)

**Implementation (`dns_spoof.py`):**
```python
# Sniffs UDP port 53
# On DNS query for www.example.net:
#   - Copies Transaction ID from query
#   - Sets aa=1 (Authoritative Answer)
#   - Answer: www.example.net → 10.0.2.100
#   - Sends spoofed response before real server replies
```

**Results:**
- `dig www.example.net` on Client → returned 10.0.2.100 (attacker's IP) ✅
- Real DNS server (10.0.2.20) also responded, but our spoofed response arrived first
- Wireshark on Client confirmed: two responses received, Client accepted the first one

![](assets/screenshot-22.png)

---

## Task 6 — DNS Cache Poisoning

**Concept:** Instead of spoofing the client directly, poison the **resolver's cache**.  
Once poisoned, every client using that resolver gets the fake answer until the TTL expires.

**Goal:** Poison Apollo (10.0.2.20)'s cache so that `www.example.net` resolves to 10.0.2.100.

**Implementation (`Task6.py`):**
Continuously sends spoofed DNS responses to Apollo (not the client), targeting queries Apollo makes upstream.  
The spoofed reply includes:
- Answer: `www.example.net → 10.0.2.100`
- TTL: 259,000 seconds (≈3 days)

**Verification:**
1. `rndc flush` — clear Apollo's cache
2. Run Task6.py
3. `rndc dumpdb -cache` then inspect `dump.db`

**Result in dump.db:**
```
www.example.net.   259000  A   10.0.2.100
```
Cache poisoned ✅ — all clients using Apollo will now receive the fake IP for 3 days without further attack.

![](assets/screenshot-30.png)

---

## Task 7 — Authority Section Poisoning

**Concept:** The **Authority Section** of a DNS response specifies which nameserver is authoritative for a domain.  
By poisoning the Authority Section, an attacker can redirect **all future queries** for an entire domain — not just one hostname.

**Goal:** Inject a fake NS record so that Apollo believes `attacker32.com` is the nameserver for `example.net`.

**Implementation:**
Spoofed DNS reply contains two sections:
- **Answer:** `www.example.net → 10.0.2.100` (the specific hostname)
- **Authority:** `example.net NS attacker32.com` (the entire domain's nameserver)

**Result in dump.db:**
```
example.net.   NS   attacker32.com.
```
Authority poisoned ✅ — Apollo now routes ALL queries for `*.example.net` through the attacker's nameserver.

**Bailiwick Check:** BIND9 enforces the Bailiwick Rule — it only accepts Authority records for domains within the same namespace as the query.  
Since the query was for `example.net`, an Authority record for `example.net` is within scope (in-Bailiwick) and accepted.

![](assets/screenshot-36.png)

---

## Task 8 — Bailiwick Rule Bypass

**Concept:** The Bailiwick Rule prevents an NS record for `google.com` from being accepted in a response about `example.net`.  
Two bypass strategies were tested.

### Method A — Piggybacking
Send two Authority records in the same response:
- `example.net NS ns.example.net` (in-Bailiwick, accepted)
- `google.com NS attacker32.com` (out-of-Bailiwick, rejected)

**Result:** BIND9 accepted the `example.net` NS record but silently discarded the `google.com` NS record. ✅ Bailiwick holds.

### Method B — Decoupled Poisoning
Strategy: first poison `example.net` so that our nameserver handles its queries.  
Then, for any query that comes to our nameserver, respond with a poisoned answer for a completely different domain.

**Implementation:**
Two separate spoofed responses:
1. Response for `example.net` query → Authority: `example.net NS attacker32.com` (accepted)
2. Later response from attacker32.com for `google.com` query → contains fake A records for `google.com`

**Result in dump.db:**
```
google.com.   NS   attacker32.com.    (in-Bailiwick from google.com's perspective)
```
Successfully bypassed Bailiwick by making BIND9 ask our server for `google.com`. ✅

**Root cause:** Once our NS is accepted for `example.net`, any response from `attacker32.com` is treated as authoritative for its own namespace — including `google.com` if we structure the queries correctly.

![](assets/screenshot-43.png)

---

## Task 9 — Additional Section Attack

**Concept:** The **Additional Section** provides "glue records" — IP addresses for nameservers mentioned in the Authority section.  
BIND9 applies Bailiwick checks to the Additional Section as well — only In-Bailiwick glue is cached.

**Implementation:**
Spoofed reply for `www.example.net` with 3 Additional records:
- `ns.example.net → <IP>` (In-Bailiwick: accepted ✅)
- `attacker32.com → 1.2.3.4` (Out-of-Bailiwick: rejected ✅)
- `www.facebook.com → 3.4.5.6` (Out-of-Bailiwick: rejected ✅)

**Confirmed in dump.db:** Only `ns.example.net` (the glue record for the in-Bailiwick nameserver) was cached.

**AAAA/IPv6 Race Condition bypass:** BIND9 makes simultaneous IPv4 (A) and IPv6 (AAAA) queries. Filtering only on `qtype == 1` (IPv4 A record) in the script prevented the AAAA query from triggering a separate race and interfering with our poisoning timing.

![](assets/screenshot-48.png)

---

## Lab Summary

**DNS is fundamentally unauthenticated in its base form** — every attack in this lab succeeded because DNS responses carry no cryptographic proof of authenticity.

The attack hierarchy:
1. Hosts file → affects only the local machine
2. Direct response spoofing → affects the querying client only, requires LAN presence
3. Cache poisoning → affects ALL clients of the poisoned resolver, persists for TTL
4. Authority/NS poisoning → affects ALL queries for an entire domain, cascading effect

**Defenses:**
- **DNSSEC:** Cryptographic signatures on DNS records — defeats all spoofing attacks at the protocol level
- **DNS-over-HTTPS (DoH) / DNS-over-TLS (DoT):** Encrypts DNS transport
- **Source port randomization:** BIND9 default — adds 16 bits of entropy to Transaction ID attacks
- **Bailiwick enforcement:** Already implemented in modern resolvers (BIND9, Unbound)

---

## Beyond Requirements

- **AAAA/IPv6 Race Condition exploit:** Identified and filtered IPv6 AAAA queries to prevent timing interference — a subtle but critical detail for reliable cache poisoning
- **Decoupled Bailiwick bypass:** Successfully redirected `google.com` NS through chained poisoning without directly targeting it — a real-world relevant technique
- **DNSSEC configuration:** Researched and documented how DNSSEC signing and validation would defeat each attack in this lab
- **Kaminsky Attack preview:** Documented the theory of the Kaminsky Attack (remote cache poisoning) as a natural extension of this lab's techniques

---

## Screenshots

<details>
<summary>View all screenshots (48 images)</summary>

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
| ![](assets/screenshot-46.png) | ![](assets/screenshot-47.png) | ![](assets/screenshot-48.png) |

</details>

---

[Back to all labs](../README.md)
