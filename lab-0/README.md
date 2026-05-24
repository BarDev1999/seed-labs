# Lab 0: Packet Sniffing and Spoofing

**SEED Labs — Network Security Laboratory**
**Team:** Bar Sberro (314683665) · Shalev Cohen (314745456) · Noam Hadad (3147014118)

---

## Network Topology

The following topology is used throughout all tasks in this lab. Three virtual machines share the same subnet.

![Network topology diagram for all tasks in Lab 0](assets/screenshot-01.png)

---

## Task 1.1A: Packet Sniffing with Scapy (Python)

### Objective

Learn to use Python's Scapy library to capture live network traffic (Packet Sniffing). A sniffer script prints details of incoming ICMP packets, and the task is run both with and without root privileges to understand the OS permission model.

### Implementation

The sniffer script uses Scapy's `sniff()` function with an `icmp` filter and a callback function that parses and displays each captured packet.

![Sniffer script code — Python/Scapy implementation with ICMP filter](assets/screenshot-02.png)

![Sniffer code continued](assets/screenshot-03.jpeg)

![Sniffer code continued](assets/screenshot-04.png)

![Sniffer code continued — callback function printing packet details](assets/screenshot-09.png)

### Execution

**Run 1 — With Root privileges:**

The sniffer was started under `sudo`, then `ping 8.8.8.8` was run in a second terminal to generate ICMP traffic. Scapy's `sniff()` function correctly captured and displayed the packet details.

![Sniffer running with root: ICMP packets captured and printed in real time](assets/screenshot-12.png)

**Run 2 — Without Root privileges:**

Running `./sniffer.py` without `sudo` causes the program to crash immediately with:

```
PermissionError: [Errno 1] Operation not permitted
```

This failure occurs precisely when Scapy attempts to open a Raw Socket (`socket.SOCK_RAW`). Linux protects network interfaces from unprivileged access — both Packet Sniffing and Spoofing require root.

### Summary

**Success?** Yes — packets were captured and parsed correctly when run as root.

**What was learned?** Scapy integrates sniffing and packet parsing into a simple Python API. The OS enforces a strict permission boundary: raw socket access is gated behind root/CAP\_NET\_RAW, because allowing unprivileged sniffing would expose all LAN traffic to any user on the machine.

---

## Task 1.1B: BPF Packet Filtering

### Objective

Demonstrate Berkeley Packet Filter (BPF) expressions to selectively capture only relevant traffic, avoiding the information overload of capturing everything. Three filters are tested: TCP from a specific host to port 23, and a full subnet range (CIDR).

### Filter 1: TCP Source Host + Destination Port 23 (Telnet)

The sniffer was updated with filter string: `tcp and src host 10.0.2.6 and dst port 23`

![Sniffer code with TCP/port-23 BPF filter applied](assets/screenshot-13.png)

Two terminals were opened: the top one ran the sniffer, the bottom one ran `telnet 8.8.8.8 23` to generate matching traffic.

![Terminal showing sniffer ready and telnet command being issued](assets/screenshot-14.png)

![Sniffer output: the TCP packet from 10.0.2.6 to port 23 was captured and printed; no other packets were displayed](assets/screenshot-15.png)

The sniffer correctly isolated a single packet matching all three conditions (TCP protocol + source IP 10.0.2.6 + destination port 23). Scapy's layer parsing correctly identified the transport layer as TCP and showed `dport=telnet`.

![Wireshark confirmation of the captured telnet packet](assets/screenshot-16.png)

### Filter 2: Subnet (CIDR) Filter

Filter string: `net 128.230.0.0/16`

![Sniffer code updated with subnet CIDR filter](assets/screenshot-17.png)

![Running sniffer with ping to 128.230.1.1 (an address within the filtered subnet)](assets/screenshot-18.png)

![Sniffer output: IP and ICMP layers printed for the packet destined to 128.230.1.1](assets/screenshot-19.png)

Although the ping returned `Destination Host Unreachable` (the address is not reachable in the virtual environment), the packet itself was transmitted and captured. The BPF engine correctly matched the CIDR range and printed the packet details, proving subnet-level filtering works regardless of reachability.

### Summary

**What was learned?** BPF filter expressions can chain multiple conditions using `and`. This enables precise, surgical filtering — capturing only the traffic relevant to the analysis task without processing irrelevant background noise. The same BPF syntax used in Scapy is identical to that used by Wireshark and `tcpdump`.

---

## Task 1.2: ICMP Packet Spoofing

### Objective

Demonstrate IP Spoofing: craft and send a valid ICMP Echo Request with a fabricated source IP address (`1.2.3.4`) to a real destination (`8.8.8.8`). Capture the outgoing packet in Wireshark to prove the forged source address is transmitted on the wire.

### Implementation

A Python script (`spoofer.py`) was written using Scapy. The script creates an IP layer with the forged source address, stacks an ICMP layer on top, and calls `send()`.

![spoofer.py code: IP layer with src=1.2.3.4, ICMP layer, send() call](assets/screenshot-20.png)

### Execution

Wireshark was configured to listen on `enp0s3` with filter `icmp` before the script was run.

![Wireshark started and listening on enp0s3 with icmp filter](assets/screenshot-21.png)

![Wireshark capture showing outgoing ICMP packet](assets/screenshot-22.png)

![Packet details expanded in Wireshark](assets/screenshot-23.png)

The script was executed with `sudo`:

![Sniffer terminal: "Sent 1 packets." confirmation from Scapy](assets/screenshot-24.png)

Wireshark captured the packet and confirmed all fields:

![Wireshark: Source = 1.2.3.4 (forged), Destination = 8.8.8.8, Protocol = ICMP Echo Request](assets/screenshot-25.png)

The source column shows `1.2.3.4` and the destination shows `8.8.8.8`. The Internet Protocol layer confirms the forged address was transmitted exactly as constructed. Because the source is not our real address, any Echo Reply from Google goes to `1.2.3.4` and never returns to our machine.

### Summary

**What was learned?** The IP protocol was designed without source address authentication. With root privileges and Scapy, any source IP can be set freely — the OS does not validate that the source address belongs to the sending network interface. This forms the technical foundation for many attack classes including DoS amplification and identity spoofing.

---

## Task 1.3: Traceroute Implementation

### Objective

Implement a custom Traceroute tool using Scapy by exploiting the TTL (Time-To-Live) field. Each router decrements TTL by 1; when TTL reaches 0, the router drops the packet and sends back an ICMP Time Exceeded (Type 11) message, revealing its IP address. This maps the network path to a destination.

### Implementation

A Python script (`trace.py`) sends ICMP Echo Requests to `8.8.8.8` with TTL starting at 1 and incrementing each iteration. Each ICMP Time Exceeded response reveals one hop.

![trace.py code: loop incrementing TTL, sr1() with timeout, printing each hop's IP](assets/screenshot-26.png)

![trace.py continued — handling no-response (timeout) and detecting Echo Reply as final hop](assets/screenshot-27.png)

### Execution

![Traceroute output: Hop 1 = 10.0.2.1 (VirtualBox router), Hop 2 = 192.168.1.1 (home router), Hops 3–11 = timeouts (ISP routers blocking ICMP), Hop 15 = 8.8.8.8 Echo Reply received](assets/screenshot-28.png)

**Hop analysis:**
- **Hop 1:** `10.0.2.1` — the VirtualBox virtual gateway
- **Hop 2:** `192.168.1.1` — the physical home router
- **Hops 3–14:** Request timed out — ISP routers blocking ICMP Time Exceeded responses
- **Hop 15:** `8.8.8.8` responded with ICMP Echo Reply (Type 0), marking the final destination

### Summary

**What was learned?** The TTL mechanism was designed to prevent routing loops, but it can be exploited as a network topology mapping tool. Timeouts in the output represent routers that drop packets without sending ICMP Time Exceeded, which is standard ISP practice. The `timeout` parameter in Scapy's `sr1()` call prevents the script from blocking indefinitely on non-responsive hops.

---

## Task 1.4: Sniff-and-Spoof

### Objective

Combine sniffing and spoofing into a single real-time program: intercept ICMP Echo Requests on the LAN and immediately inject forged Echo Replies before the legitimate destination can respond. A client pinging a non-existent IP (`1.2.3.4`) should receive replies, believing the host is alive.

### Implementation

Script `sniff_spoof.py` listens for ICMP type 8 (Echo Request). On each capture, it swaps source and destination IPs, sets ICMP type to 0 (Echo Reply), and copies the original ID and Sequence Number so the `ping` utility recognizes the reply as valid.

![sniff_spoof.py callback: detects ICMP Echo Request, swaps src/dst, sets type=0, copies ID and Sequence](assets/screenshot-29.png)

![sniff_spoof.py continued](assets/screenshot-30.png)

![sniff_spoof.py continued — listening loop](assets/screenshot-31.png)

### Execution

The Sniff-and-Spoof script was launched on the Attacker VM. From the Client VM (10.0.2.7), `ping 1.2.3.4` was run:

![Client terminal: ping 1.2.3.4 receives full replies — "64 bytes from 1.2.3.4" with valid RTT times — despite the address not existing](assets/screenshot-32.png)

The Client believed `1.2.3.4` was alive and responding, entirely due to the forged replies from the Attacker machine.

![Attacker terminal: script detecting each Echo Request from 10.0.2.7 to 1.2.3.4 and sending spoofed Echo Replies](assets/screenshot-33.png)

> **Problem solved:** In the first attempt, both the ping and the sniffer ran on the same VM. Linux's internal routing detected the anomaly (receiving a packet with a spoofed source destined to itself) and dropped it. The solution was to separate the attacker and client onto two different VMs so the packet crosses the LAN segment and is received naturally.

### Summary

**What was learned?** The `ping` utility trusts any packet with matching ID and Sequence Number — it has no mechanism to verify whether the reply actually originated from the declared source. Any attacker with LAN access can fabricate valid ping responses. This demonstrates the fundamental trust weakness in IPv4 in local network environments.

---

## Task 2.1A: C-Level Sniffer using libpcap

### Objective

Implement a packet sniffer in C using the `libpcap` library to understand how sniffing works at the system level, below Python abstractions. The program captures ICMP packets on `enp0s3` and prints source and destination IPs.

### Implementation

The `main()` function calls `pcap_open_live()` to open the interface, `pcap_compile()` and `pcap_setfilter()` to apply a BPF filter, then `pcap_loop()` to enter an infinite capture loop.

![C sniffer code Part 1: includes, struct definitions, main() opening interface](assets/screenshot-34.png)

![C sniffer code Part 2: pcap_compile and pcap_setfilter applying ICMP filter](assets/screenshot-35.png)

![C sniffer code Part 3: pcap_loop and got_packet callback — casts raw bytes to Ethernet/IP structs, prints src/dst IPs](assets/screenshot-36.png)

The sniffer was compiled with `-lpcap` and run as root:

![Terminal: gcc compilation with -lpcap, then sudo ./sniffer — program waiting for packets](assets/screenshot-37.png)

A `ping 8.8.8.8` was run in a parallel terminal. The sniffer captured and decoded each ICMP packet in real time:

![Sniffer output and ping running in parallel: "Got a packet from 10.0.2.6 to 8.8.8.8 (ICMP)" printed for each captured packet](assets/screenshot-38.png)

![Continued output showing multiple ICMP packets captured](assets/screenshot-39.png)

### Key Concepts Demonstrated

**Required `libpcap` sequence:**
1. `pcap_open_live()` — opens the NIC for raw capture
2. `pcap_compile()` — translates BPF text to kernel filter bytecode
3. `pcap_setfilter()` — installs the compiled filter
4. `pcap_loop()` — enters infinite receive loop, dispatching to callback
5. `pcap_close()` — releases the handle

**Why root is required:** `pcap_open_live()` requires `CAP_NET_RAW`. Without it, the call returns `NULL` with `"Operation not permitted"`.

**Promiscuous mode** is controlled by the third parameter of `pcap_open_live()` (`1` = on, `0` = off). With it off, the NIC only receives packets addressed to its own MAC. With it on, it receives all LAN traffic regardless of destination MAC — capturing traffic between other hosts.

---

## Task 2.1B: BPF Filters in C

### Objective

Apply two distinct BPF filters inside the C sniffer code to demonstrate the same filter engine used by Python/Scapy works identically at the C level.

### Filter 1: ICMP between two specific hosts

Filter: `icmp and host 10.0.2.6 and host 8.8.8.8`

![C sniffer with ICMP host-pair filter applied](assets/screenshot-40.png)

Running `ping 8.8.8.8` — both source and destination match the filter, so the sniffer captures and prints the packets:

![Sniffer output: ICMP packets between the two specified hosts captured and decoded](assets/screenshot-41.png)

![Continued output showing multiple packets](assets/screenshot-42.png)

### Filter 2: TCP to port range 10–100

Filter: `tcp and dst portrange 10-100`

![C sniffer with TCP port-range filter applied](assets/screenshot-43.png)

`telnet 8.8.8.8 23` was used to generate TCP traffic to port 23 (within the 10–100 range):

![Two terminals: top running telnet to port 23, bottom showing sniffer capturing the TCP packets](assets/screenshot-44.png)

![Sniffer output: TCP SYN packets to port 23 captured](assets/screenshot-45.png)

![Continued: packets decoded with correct port and IP information](assets/screenshot-46.png)

---

## Task 2.1C: Sniffing Telnet Passwords in C

### Objective

Extend the C sniffer to extract and print the payload of TCP packets, demonstrating that Telnet transmits credentials in plaintext.

### Implementation

The callback function navigates through the packet using pointer arithmetic:
1. Skip the Ethernet header (`sizeof(struct ethhdr)`)
2. Skip the IP header (`ip->ihl * 4` bytes)
3. Skip the TCP header (`tcp->doff * 4` bytes)
4. Print the remaining bytes as ASCII characters

![C sniffer password extraction code Part 1: struct definitions for IP and TCP headers](assets/screenshot-47.png)

![C sniffer password extraction code Part 2: pointer arithmetic to reach TCP payload](assets/screenshot-48.png)

![C sniffer password extraction code Part 3: loop printing printable ASCII characters from payload](assets/screenshot-49.png)

A connection to `telnet telehack.com` was initiated while the sniffer (with `tcp port 23` filter) ran in the background:

![Telnet terminal: connected to telehack.com, password ".password1233" typed](assets/screenshot-50.png)

![Telnet session continued](assets/screenshot-51.png)

![Telnet session showing the login prompt](assets/screenshot-52.png)

The sniffer captured the keystrokes from the TCP stream in real time:

![Sniffer output: individual characters 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', '1', '2', '3', '3' extracted from TCP payload — the password is fully visible](assets/screenshot-53.png)

**Conclusion:** Telnet is fundamentally insecure for any environment where the network is not fully trusted. The sniffer required no keys or decryption — the password was read directly from raw TCP bytes.

---

## Task 2.2A: Raw Socket UDP Spoofing in C

### Objective

Write a C program that constructs and sends a spoofed UDP packet entirely from scratch using Raw Sockets, with an arbitrary source IP (`1.2.3.4`), to demonstrate full control over IP header fields.

### Implementation

The program creates a Raw Socket with `IPPROTO_RAW`, manually fills IP and UDP header structs, and sends via `sendto()`.

![spoofer.c Part 1: Raw socket creation, struct ip and struct udphdr mapping, IP header fields (src=1.2.3.4, dst=8.8.8.8)](assets/screenshot-54.png)

![spoofer.c Part 2: UDP header fields (src port=9999, dst port=9090), payload filled with custom text](assets/screenshot-55.png)

![spoofer.c Part 3: byte order conversion with htons()/inet_addr(), sendto() call](assets/screenshot-56.png)

Wireshark was listening with filter `udp port 9090` before the program was run:

![Attacker terminal: gcc compilation and sudo ./spoofer — program reports packet sent](assets/screenshot-57.png)

Wireshark confirmed all fields:

![Wireshark: Source = 1.2.3.4 (forged), Destination = 8.8.8.8, UDP src port=9999, dst port=9090, Hex Dump shows "Spoofed UDP Packet!" payload](assets/screenshot-58.png)

![Wireshark packet details expanded](assets/screenshot-59.png)

![Full Wireshark view of the captured packet](assets/screenshot-60.png)

**Key insight — Endianness:** Multi-byte fields must be converted from host byte order (little-endian on x86) to network byte order (big-endian) using `htons()` for 16-bit values and `htonl()` for 32-bit values before filling the struct fields. Failing to do so produces malformed packets that routers and the destination discard.

---

## Task 2.2B: Raw Socket ICMP Spoofing in C

### Objective

Spoof an ICMP Echo Request from a non-existent source (`10.0.2.99`) to `8.8.8.8`, demonstrating the requirement to manually compute the ICMP Checksum when using Raw Sockets.

### Implementation

Unlike UDP (where checksum is optional in IPv4), ICMP requires a valid checksum or the destination discards the packet. A helper function `in_cksum()` computes the standard Internet checksum over the ICMP header and payload.

![icmp_spoofer.c Part 1: in_cksum() checksum helper function — standard one's complement sum algorithm](assets/screenshot-61.png)

![icmp_spoofer.c Part 2: Raw socket setup, buffer cleared, IP and ICMP struct mapping](assets/screenshot-62.png)

![icmp_spoofer.c Part 3: ICMP type=8 (Echo Request), ID and Sequence set, in_cksum() called to fill checksum field, src=10.0.2.99, sendto() call](assets/screenshot-63.png)

Wireshark with `icmp` filter ran while the program executed:

![Attacker terminal: "Spoofed ICMP Echo Request sent successfully" — no errors from sendto()](assets/screenshot-64.png)

![Wireshark: Source = 10.0.2.99 (forged), Destination = 8.8.8.8, Protocol = ICMP Echo (ping) request — packet confirmed on wire](assets/screenshot-65.png)

**Answers to conceptual questions:**
- **Can the IP Total Length field be set to an arbitrary value?** No. If set smaller than actual size, the packet is truncated. If set larger, the receiver discards it as malformed. Under `IPPROTO_RAW` on Linux, the kernel overwrites the length field with the correct value at transmission time.
- **Does the IP Checksum need manual computation?** No — the Linux kernel computes and fills the IP header checksum automatically when using `IPPROTO_RAW`. Only transport-layer checksums (ICMP, TCP) must be computed manually.
- **Why is root required for Raw Sockets?** Raw Sockets bypass the OS networking stack and allow full IP address spoofing. Without root/`CAP_NET_RAW`, `socket()` returns `-1` with `"Operation not permitted"`.

---

## Task 2.3: Sniff-and-Spoof in C

### Objective

Combine `libpcap` sniffing with Raw Socket spoofing in a single C program that intercepts ICMP Echo Requests on the LAN and immediately injects forged Echo Replies — this time at the C level for maximum performance.

### Implementation

The program uses `pcap_loop()` with a callback that:
1. Casts raw bytes to Ethernet/IP/ICMP structs
2. Swaps source and destination IPs
3. Changes ICMP type from 8 to 0 (Reply)
4. Copies the original Payload using `memcpy()` (including ping timestamps)
5. Recomputes the ICMP Checksum
6. Sends via Raw Socket

Copying the payload (including the ping timestamps embedded by the client's `ping` utility) is critical. Without it, the `ping` command rejects the reply because the round-trip time cannot be computed.

![sniff_spoof.c Part 1: pcap setup, struct definitions, Raw Socket creation](assets/screenshot-66.png)

![sniff_spoof.c Part 2: callback function — IP layer swap, ICMP type=0, ID/Sequence copy](assets/screenshot-67.png)

![sniff_spoof.c Part 3: payload copy via memcpy(), ICMP checksum recomputation](assets/screenshot-68.png)

![sniff_spoof.c Part 4: sendto() via Raw Socket, pcap_loop() call in main()](assets/screenshot-69.png)

![sniff_spoof.c Part 5: compilation and sudo execution on Attacker VM](assets/screenshot-70.png)

The Attacker program was started. From a second VM (Server), `ping 1.2.3.4` was run:

![Attacker terminal: sniff_spoof running, printing each detected Echo Request and confirming reply injection](assets/screenshot-71.png)

![Server terminal: ping 1.2.3.4 receives full replies — "64 bytes from 1.2.3.4" with valid RTT times](assets/screenshot-72.png)

![Server terminal continued: consistent replies with natural RTT variation](assets/screenshot-73.png)

![Server terminal: ping statistics showing 0% packet loss against a non-existent address](assets/screenshot-74.png)

![Attacker terminal: confirming each round of sniff (Echo Request detected) followed by spoof (Reply sent)](assets/screenshot-75.png)

### Summary

**What was learned?** Writing sniff-and-spoof at the C level required understanding every byte of the packet: struct layout, pointer arithmetic, byte order, and checksum computation. The C implementation is significantly more performant than the Python/Scapy version, making it suitable for high-speed attacks. Correctly copying the ping payload (timestamps) was the critical detail that made the forged replies indistinguishable from legitimate ones.

---

## Lab Summary

### Dual Implementation Comparison

| Capability | Python/Scapy | C/libpcap/Raw Sockets |
|---|---|---|
| Development speed | Fast — high-level abstractions | Slow — manual struct/pointer work |
| Packet construction | Automatic layer stacking | Manual field-by-field filling |
| Checksum handling | Automatic | Must be computed manually (ICMP, TCP) |
| Byte order | Handled automatically | Must use `htons()`/`htonl()` |
| Performance | Moderate — Python overhead | High — near-kernel speed |
| Best use | Precise, surgical packet crafting | Flood attacks, high-throughput scenarios |

### Core Security Findings

1. **Root/CAP\_NET\_RAW is the only gate.** Both sniffing and spoofing require root. A machine whose root account is compromised can silently intercept and forge any unencrypted LAN traffic.
2. **IPv4 source addresses are trivially forgeable.** The OS applies no validation before transmitting a packet with a spoofed source — it is the responsibility of network perimeter devices (uRPF, ingress filtering) to detect and block spoofed traffic.
3. **Unencrypted protocols expose everything.** Telnet password capture required no decryption — raw TCP payload bytes contained the credentials directly.
4. **Pointer arithmetic is the core skill.** Navigating through a raw packet buffer in C requires precise understanding of each protocol header size and the order of layer encapsulation.

### Beyond Lab Requirements: Reverse Path Filtering (RPF)

During spoofing experiments, packets sent from a forged source on the same subnet were sometimes silently dropped by the Linux kernel before reaching the application. Investigation revealed the **Reverse Path Filtering (rp\_filter)** mechanism:

- **Strict RPF (`rp_filter=1`):** When a packet arrives on an interface, the kernel checks: "Would a packet back to this source IP exit via the same interface?" If not, the packet is dropped. This blocks asymmetrically-routed spoofed packets.
- **Loose RPF (`rp_filter=2`):** Only checks that the source IP exists somewhere in the routing table — does not require the same interface. This is used in multi-homed environments with asymmetric routing, but opens a spoofing path for an attacker who can craft packets whose source IP is routable.
- **Bypassing Strict RPF:** IP-in-IP encapsulation was tested as a bypass but failed on stock Linux — the kernel does not auto-decapsulate inner IP headers without explicit tunnel interface configuration.

Understanding RPF was critical for diagnosing why some spoofed packets were discarded at the kernel level even when the C code was correct, distinguishing application logic bugs from kernel security enforcement.
