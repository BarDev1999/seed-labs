# Lab 2: IP / ICMP Attacks

**SEED Labs — Network Security Laboratory**
**Team:** Bar Sberro (314683665) · Shalev Cohen (314745456) · Noam Hadad (3147014118)

---

## Network Topology

Tasks 1 and 2 use a two-machine layout (Attacker + Server) on the same subnet. Task 3 extends this to include a Router VM bridging two separate subnets.

![Network topology diagram for Lab 2 tasks](assets/screenshot-01.png)

---

## Task 1.a: IP Fragmentation

### Background

IP fragmentation allows large packets to be split into smaller fragments for transmission across networks with smaller MTUs. Each fragment carries:
- **Identification field:** a shared ID tying all fragments of the same original packet together
- **Flags field:** the More Fragments (MF) bit signals whether more fragments follow
- **Fragment Offset field:** the byte position of this fragment's payload within the original packet (units: 8-byte blocks)

### Objective

Manually craft a UDP datagram split into exactly 3 fragments, each carrying 32 bytes of payload (96 bytes total), and deliver the reassembled datagram to a `netcat` UDP server on port 9090.

### Execution

A `netcat` UDP server was started on the Server VM:

![Server terminal: nc -lu 9090 — waiting for UDP data](assets/screenshot-02.png)

The fragmentation script was written in Python using Scapy. The UDP checksum was set to 0 to prevent Scapy from recalculating it (which would be invalid once the header is split). Fragment offsets are expressed in units of 8 bytes: Fragment 2 at offset 5 (40 bytes), Fragment 3 at offset 10 (80 bytes).

![Fragmentation script: three IP fragments with shared ID, correct MF flags, and offsets 0/5/10](assets/screenshot-03.png)

Wireshark was used to verify fragment transmission. The fragments appeared as separate packets, each with the same Identification value, the correct More Fragments flag, and the expected offset values:

![Wireshark capture: Fragment 1 (offset=0, MF=1), Fragment 2 (offset=5, MF=1), Fragment 3 (offset=10, MF=0)](assets/screenshot-04.png)

![Wireshark: fragment details expanded — shared ID, correct flags and offsets](assets/screenshot-05.png)

The netcat server on the Server VM received the reassembled 96-byte payload:

The kernel correctly identified all three fragments as belonging to the same datagram (matching ID), reassembled them in offset order, and delivered the complete 96-byte payload to the netcat listener.

### Summary

**What was learned?** Fragment offset arithmetic is critical. Scapy's `frag` parameter takes the offset in units of 8 bytes, not raw bytes. The first fragment must have offset 0 and `flags=1` (MF set); intermediate fragments have non-zero offsets and `flags=1`; the final fragment has `flags=0`. The UDP header lives entirely in the first fragment and the kernel reconstructs the full UDP datagram before delivering to the application.

> **Problem encountered:** Scapy auto-recalculates UDP checksums, which invalidates the checksum once the UDP header is split from part of its payload. Setting `pkt[UDP].checksum = 0` before sending instructs the OS to skip checksum validation on receipt, allowing the experiment to proceed correctly.

---

## Task 1.b: IP Fragments with Overlapping Contents

### Background

When two fragments cover the same byte range (overlapping offsets), the kernel must decide which fragment's bytes take precedence. Historically, ambiguous overlap handling caused the **Teardrop attack** — specially crafted overlapping fragments caused kernel buffer overflows and system crashes. Modern Linux kernels enforce a **Favor Lower Offset** policy: data from the fragment with the lower offset always wins, regardless of arrival order.

### Objective

Test two overlap scenarios against Ubuntu's kernel:
1. **Partial Overlap:** Fragment B partially overlaps Fragment A
2. **Enclosed Overlap:** Fragment B is entirely contained within Fragment A's byte range

### Scenario 1: Partial Overlap

Fragment A carries 32 bytes of `'A'` at offset 0. Fragment B carries 32 bytes of `'B'` starting at offset 4 (byte 32), overlapping the last 8 bytes of Fragment A's range.

![send_overlap() function: Fragment A (32×'A', offset=0, MF=1), Fragment B (32×'B', offset=4, MF=0) — B's first 8 bytes overlap A's last 8 bytes](assets/screenshot-06.png)

![Same script view with function structure visible](assets/screenshot-06.png)

The Server received the reassembled payload:

![Server netcat output: 32 bytes of 'A' followed by 24 bytes of 'B' — Linux preserved all of 'A' and trimmed 8 bytes from the beginning of 'B'](assets/screenshot-07.png)

![Continued server output confirming the pattern](assets/screenshot-08.png)

**Result:** Linux preserved Fragment A's data in the overlapping region and truncated Fragment B by 8 bytes. The final output was `32×'A' + 24×'B'` — identical regardless of which fragment arrived first.

### Scenario 2: Enclosed Overlap

Fragment A carries 64 bytes of `'A'` at offset 0. Fragment B carries 16 bytes of `'B'` at offset 2 (byte 16) — entirely inside Fragment A's range. Fragment C carries 32 bytes of `'C'` at offset 8 (byte 64), immediately after Fragment A.

![send_enclosed() function: Fragment A (64×'A', offset=0, MF=1), Fragment B (16×'B', offset=2 — enclosed), Fragment C (32×'C', offset=8, MF=0)](assets/screenshot-09.png)

The Server received the reassembled payload:

![Server netcat output: 64 bytes of 'A' followed by 32 bytes of 'C' — Fragment B (enclosed) was discarded entirely](assets/screenshot-10.png)

![Continued server output showing 'A' and 'C' with no trace of 'B'](assets/screenshot-11.png)

**Result:** Fragment B was completely discarded. The kernel applied Favor Lower Offset strictly: since Fragment A (offset=0) already covered the entire byte range that Fragment B occupied, Fragment B's data was silently dropped regardless of arrival order.

### Summary

**What was learned?** Linux's reassembly policy is deterministic and arrival-order-independent:
- **Partial overlap:** The lower-offset fragment's bytes always prevail. The higher-offset fragment is trimmed.
- **Enclosed overlap:** The enclosing fragment's data completely replaces the enclosed fragment's data.

This makes the Teardrop attack (which relied on kernel panics from overlapping fragments) ineffective on modern systems. The kernel simply applies its conflict resolution policy and drops conflicting data safely.

> **Problem solved:** Scapy's automatic UDP header recalculation corrupted checksums when fragments were crafted manually. This was resolved by using Python's `struct` module to build a raw UDP header with checksum=0 and embedding it directly into the first fragment's payload, preventing Scapy from modifying the header bytes.

---

## Task 1.c: Ping of Death

### Background

The maximum legal IPv4 packet size is 65,535 bytes (the IP Total Length field is 16 bits). The **Ping of Death** attack exploits IP fragmentation by sending fragments that, when reassembled, would produce a packet exceeding this maximum. On historical systems, the kernel's reassembly buffer overflowed, causing crashes. Modern kernels detect and discard the oversized reconstruction attempt.

### Objective

Send two fragments: Fragment 1 at offset 0 with MF=1, Fragment 2 at offset 65,528 (byte position 65,528×8 = incorrect — offset 65,528 in units that produce a reconstructed size of 65,628 bytes) with 100 bytes of payload, producing a total reconstructed size of 65,628 bytes — exceeding the 65,535 byte maximum.

### Execution

![Task1C.py: Fragment 1 (flags=1 MF set), Fragment 2 (frag=8191 to produce offset 65,528, flags=0, 100-byte payload)](assets/screenshot-12.png)

A netcat UDP server was running on the Server VM (`nc -luv 9090`). The attack script was executed from the Attacker:

![Attacker terminal: Task1C.py executed, fragments sent](assets/screenshot-13.png)

![Server terminal: service continued running without crashing — no error output or process termination](assets/screenshot-14.png)

Wireshark captured the oversized fragment on the Server:

![Wireshark: Fragment 2 shows Fragment Offset=65528, Flags=0x00 (last fragment), 100-byte payload — kernel must attempt to reassemble a packet exceeding 65,535 bytes](assets/screenshot-15.png)

The Server responded with ICMP Type 11 (Time-to-Live Exceeded) rather than crashing:

![Server (10.0.2.8) sending ICMP Type 11 Time-to-live exceeded back to Attacker — indicates fragment timeout, not crash](assets/screenshot-16.png)

After approximately 30 seconds, the kernel's reassembly timer expired. The kernel reported the dropped fragments via `netstat`:

![netstat output on Server: fragment reassembly timeout count incremented — kernel cleaned up memory safely](assets/screenshot-17.png)

**Analysis:** Modern Ubuntu kernels handle this gracefully. When the huge gap between Fragment 1 (offset=0) and Fragment 2 (offset=65,528) is detected, the kernel holds the fragments in its reassembly queue until the timeout fires, then discards them and increments the failure counter. No buffer overflow occurs because the kernel validates the total reassembled size before allocating a full buffer.

### Summary

**What was learned?** The Ping of Death is a historical attack that exploited unvalidated buffer allocation in early IP stacks. Modern kernels enforce the 65,535-byte limit as a sanity check during reassembly queue management. The attack still generates observable side effects (ICMP Time Exceeded, reassembly failure counters) that confirm the fragments were received — the protection is in the kernel's refusal to allocate an oversize buffer, not in network-level blocking.

---

## Task 1.d: Fragment Flood DoS

### Background

When a router or host receives IP fragments with MF=1, it must hold them in a **Reassembly Queue** in kernel memory while waiting for the remaining fragments. If the final fragment never arrives, the kernel eventually times out and discards the entry. A **Fragment Flood** attack exploits this by sending millions of first fragments (MF=1) with different IDs, each one forcing the kernel to open a new reassembly queue entry. When these entries accumulate faster than they time out, the kernel's reassembly buffer is exhausted and legitimate fragmented traffic is dropped.

### Comparison: Python vs C Attack Speed

**Experiment A — Python/Scapy flood:**

A Scapy-based Python script sent fragmented UDP packets with MF=1 and random IDs in an infinite loop.

![Python flood script: Scapy loop sending UDP fragments with MF=1 and random IDs](assets/screenshot-18.png)

The Server's reassembly statistics were monitored with `watch -n 1 'netstat -s | grep -i reasm'`:

![Server netstat: reassembly required count — only ~497 entries after Python flood, indicating low packet rate](assets/screenshot-19.png)

![Attacker terminal with Python flood running](assets/screenshot-20.png)

![Server after Python flood: counter barely moved — kernel cleared entries via timeout before saturation](assets/screenshot-21.png)

**Conclusion:** Python/Scapy is too slow. The kernel's reassembly timeout clears entries faster than Python can fill them. The DoS failed.

---

**Experiment B — C/Raw Sockets flood (5 parallel terminals):**

A C program using Raw Sockets was written. It builds IP headers directly in memory, sets random fragment IDs, and sends packets at maximum kernel throughput. Five instances were run simultaneously from separate terminals.

![attack.c Part 1: Raw Socket creation, IP header struct, 1400-byte payload filled with 'A'](assets/screenshot-22.png)

![attack.c Part 2: in_cksum() checksum helper function for IP header](assets/screenshot-23.png)

![attack.c Part 3: infinite loop — randomize ID, set MF=1, fire packet](assets/screenshot-24.png)

A large ping (8000-byte payload, forcing fragmentation) from the Client VM to the Server VM was tested before the attack:

![Client: ping -s 8000 10.0.2.8 — 4 packets sent, 4 received, 0% packet loss (baseline, no attack)](assets/screenshot-25.png)

All five attack terminals were launched simultaneously:

![5 terminals on Attacker all running ./attack in parallel — millions of fragments per second sent to 10.0.2.8](assets/screenshot-26.png)

The Server's reassembly counters were monitored during the attack:

![Server netstat: reassembly failure counter jumped from ~5 million to ~178 million in seconds — kernel memory saturated](assets/screenshot-27.png)

The large ping was retried from the Client VM during the attack:

![Client: ping -s 8000 during attack — 50% packet loss in first attempt, 75% packet loss in second attempt](assets/screenshot-28.png)

**Result:** The C-based flood successfully exhausted the kernel's reassembly buffer. Legitimate fragmented traffic from the Client was dropped because the kernel had no space to hold its fragments during reconstruction — a successful DoS.

**Why 5 terminals?** Sending from 5 parallel processes multiplied the packet rate, ensuring the fill rate exceeded the timeout-based eviction rate.

---

## Task 2: ICMP Redirect Attack

### Background

ICMP Redirect (Type 5, Code 1) is sent by routers to inform a host of a shorter path to a destination. The receiving host updates its routing cache accordingly. An attacker on the LAN can forge these messages — impersonating the legitimate gateway — to redirect a victim's outbound traffic through the attacker machine, enabling a MITM or DoS.

### Objective

Force the Server VM (`10.0.2.8`) to redirect all traffic destined for `8.8.8.8` through the Attacker VM (`10.0.2.6`) by sending spoofed ICMP Redirect packets that appear to come from the real gateway (`10.0.2.1`).

### Implementation

The Python script listens for outbound traffic from the Server and responds with a spoofed ICMP Redirect. The spoof logic:
- `IP.src = 10.0.2.1` (impersonates the real gateway)
- `ICMP type=5, code=1` (Redirect for Host)
- `ICMP.gw = 10.0.2.6` (the attacker's IP as the new next-hop)
- The original IP header is appended to the ICMP payload as required by the protocol

![ICMP Redirect script: sniff for traffic from 10.0.2.8, craft spoofed Redirect with src=10.0.2.1, gw=10.0.2.6](assets/screenshot-29.png)

IP forwarding was enabled on the Attacker so the Server does not lose connectivity:

![Attacker: sysctl net.ipv4.ip_forward=1 — Attacker will transparently forward traffic to the real destination](assets/screenshot-30.png)

The Server was already sending legitimate traffic. The attack script was started, with the Server simultaneously pinging `8.8.8.8`:

![Attacker script running: detecting Server's ICMP Echo Requests and injecting spoofed Redirect packets](assets/screenshot-31.png)

![Server terminal: real-time receipt of "Redirect Host (New nexthop: 10.0.2.6)" messages appearing alongside each ping response](assets/screenshot-32.png)

![Server terminal: each ping line shows ICMP Redirect Host message with the attacker's IP as the announced new next-hop](assets/screenshot-33.png)

Final verification using `ip route get` on the Server confirms the routing cache was poisoned:

![Server: ip route get 8.8.8.8 — output shows "via 10.0.2.6 dev enp0s3 src 10.0.2.8 <redirected>" — routing to the attacker is confirmed](assets/screenshot-34.png)

Attacker terminal confirming Redirect packets were sent:

![Attacker terminal: confirmation of spoofed Redirect packets being sent](assets/screenshot-35.png)

**Result:** The `<redirected>` flag in the routing output confirms the Server's kernel updated its routing cache based on the forged ICMP Redirect. All subsequent traffic to `8.8.8.8` was routed through the Attacker.

### Redirect Research Questions

**Q1: Can an ICMP Redirect point to a remote machine (e.g., 8.8.8.8)?**

![Experiment: sending Redirect with gw=8.8.8.8 — ip route get shows no change, attack failed](assets/screenshot-36.png)

![Server routing table unchanged](assets/screenshot-37.png)

![Wireshark confirms redirect was sent but routing table was not updated](assets/screenshot-38.png)

**No.** Ubuntu performs a sanity check on the new gateway address: if `icmp.gw` is not in the same subnet as the interface the redirect arrived on, the kernel discards the redirect as illogical (you cannot communicate at Layer 2 with a gateway that is not on the same LAN segment).

---

**Q2: Can an ICMP Redirect point to a non-existent LAN machine (e.g., 10.0.2.99)?**

![Experiment: sending Redirect with gw=10.0.2.99 — ip route get shows route updated to via 10.0.2.99](assets/screenshot-40.png)

![Server: ping 8.8.8.8 now fails — ARP for 10.0.2.99 broadcasts but receives no response; packets are dropped](assets/screenshot-41.png)

**Yes — and it causes a targeted DoS.** The routing table is updated because `10.0.2.99` passes the subnet sanity check. However, when the Server tries to send packets to that gateway, it broadcasts ARP requests for `10.0.2.99`. Since no machine exists at that address, ARP gets no response, the Ethernet frame is never built, and all outbound traffic to `8.8.8.8` is silently dropped.

![Wireshark: after Redirect accepted, Server broadcasts "Who has 10.0.2.99?" ARP requests (lines 47, 50, 53) — no reply — followed by Destination Unreachable](assets/screenshot-42.png)

This demonstrates that ICMP Redirect can be weaponized for a targeted DoS even when the attacker does not have a valid listening machine.

---

## Task 3.a and 3.b: Multi-Subnet Routing Setup

### Background

Two machines on different subnets cannot communicate without a router. A standard Linux machine can be configured as a router by enabling **IP Forwarding** in the kernel and adding static routes on the endpoint machines.

### Network Setup

| Machine | Role | Interface 1 | Interface 2 |
|---|---|---|---|
| Client VM | Router | enp0s3: 10.0.2.7 (NAT) | enp0s8: 192.168.60.1 (Internal) |
| Server VM | Target | enp0s3: 192.168.60.5 (Internal) | — |
| Attacker VM | Source | enp0s3: 10.0.2.6 (NAT) | — |

![ifconfig on Router (Client VM): enp0s3=10.0.2.7, enp0s8=192.168.60.1 — both interfaces active](assets/screenshot-44.png)

![ifconfig on Server VM: enp0s3=192.168.60.5 (internal subnet only)](assets/screenshot-45.png)

IP Forwarding was enabled on the Router:

![Router VM: sysctl net.ipv4.ip_forward=1](assets/screenshot-46.png)

Static routes were added in both directions:

![Attacker: ip route add 192.168.60.0/24 via 10.0.2.7 — enables reaching the internal subnet](assets/screenshot-47.png)

![Server: ip route add 10.0.2.0/24 via 192.168.60.1 — enables return path back to the NAT subnet](assets/screenshot-48.png)

Connectivity verification from Attacker to Server:

![Attacker: ping 192.168.60.5 — 4 packets sent, 4 received, 0% packet loss — cross-subnet routing confirmed](assets/screenshot-49.png)

**Key point:** Routing is bidirectional. Without the return route on the Server, pings would appear to succeed on the Attacker but the Server would silently drop reply packets because it had no route back to `10.0.2.0/24`.

---

## Task 3.c: Reverse Path Filtering (RPF) Bypass Research

### Background

**Reverse Path Filtering (rp\_filter)** is a Linux kernel mechanism that defends against IP Spoofing by validating the source address of incoming packets. When enabled, the kernel checks whether a packet destined back to the source IP would exit via the same interface the packet arrived on. If not, the packet is dropped.

Two modes:
- **Strict RPF (`rp_filter=1`):** The return path must use exactly the same interface as the incoming packet.
- **Loose RPF (`rp_filter=2`):** The return path just needs to exist somewhere in the routing table, regardless of interface.

---

### Phase A: Strict RPF — Bypass Attempt

Three spoofed ICMP packets were sent toward the internal network (`192.168.60.5`):
1. Source `10.0.2.99` (same subnet as the router's external interface)
2. Source `192.168.60.1` wrapped inside an outer IP packet (IP-in-IP encapsulation attempt)
3. Source `1.2.3.4` (a random internet address)

![Scapy script: three ICMP packets with different forged source IPs sent to 192.168.60.5](assets/screenshot-50.png)

![Attacker terminal: packets sent, awaiting Wireshark analysis on the router](assets/screenshot-51.png)

Wireshark on the Router captured both interfaces simultaneously:

![Wireshark on Router: packets 5, 8, 12 (the three spoofed packets) each appear ONCE — they arrived on the external interface but were never forwarded to the internal interface](assets/screenshot-52.png)

**All three attempts failed.** Strict RPF dropped every packet before it reached the forwarding logic. The IP-in-IP encapsulation bypass also failed — the Linux kernel does not auto-decapsulate inner IP headers without an explicit tunnel interface (e.g., `ipip` or `tun`) configured.

---

### Phase B: Loose RPF — Successful Bypass

In enterprise environments with asymmetric routing, `rp_filter=2` (Loose) is commonly used. The Router was switched to Loose RPF:

![Router: sysctl net.ipv4.conf.all.rp_filter=2](assets/screenshot-53.png)

The Attacker's routing table was updated to include the internal subnet:

![Attacker: ip route add 192.168.60.0/24 via 10.0.2.7](assets/screenshot-54.png)

A forged packet with source `192.168.60.99` (impersonating an internal machine) was sent to `192.168.60.5`:

Wireshark captured the result on the Router:

![Wireshark: packets 18 and 19 — the spoofed packet with src=192.168.60.99 appears TWICE (once on external interface, once on internal) — the router forwarded it](assets/screenshot-55.png)

**The attack succeeded.** Packet 18/19 appears on both interfaces, confirming the Router forwarded the spoofed packet from the external NAT interface to the internal segment. Under Loose RPF, the check passes because `192.168.60.0/24` exists in the routing table — even though it should only be reachable from the internal interface.

The Server sent ARP requests looking for `192.168.60.99` (Host Unreachable error in Wireshark), confirming the packet reached the internal subnet.

**Security implication:** Loose RPF allows an external attacker to impersonate internal hosts. This bypasses firewalls and ACLs that trust traffic based on source IP address, potentially granting access to internal services that should not be reachable from outside.

---

## Lab Summary

### Attack Results

| Task | Attack | Result | Defense |
|---|---|---|---|
| 1.a | IP Fragmentation | Reassembly successful | Manual offset calculation required |
| 1.b | Overlapping Fragments | Linux enforces Favor Lower Offset | No crash — data conflict resolved silently |
| 1.c | Ping of Death | No crash on modern kernel | Kernel validates reassembled size before allocating buffer |
| 1.d | Fragment Flood DoS | 50–75% packet loss achieved with C/5 threads | Python too slow; C at full speed required |
| 2 | ICMP Redirect | Routing cache poisoned | IP forwarding on attacker kept communication transparent |
| 3.a/b | Cross-subnet routing | Successful with ifconfig + ip route | Both directions required |
| 3.c | RPF bypass | Strict: blocked; Loose: successful | Strict RPF defeats spoofing; Loose RPF creates a bypass path |

### Core Lessons

1. **Fragmentation is a rich attack surface.** Offset arithmetic, overlap handling, and assembly buffer exhaustion are all exploitable attack vectors.
2. **Tool choice determines success.** Python/Scapy is ideal for precise packet construction but too slow for flood attacks. C/Raw Sockets achieves near-line-rate speeds.
3. **ICMP Redirect is LAN-scoped.** The target gateway must be on the same subnet. This limits the attack but makes it highly effective within a compromised LAN segment.
4. **RPF mode matters.** Strict RPF effectively blocks spoofed packets; Loose RPF creates an exploitable path for source address impersonation in enterprise topologies.
