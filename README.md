# SEED Labs — Network Security Research

> Hands-on network security labs from the [SEED (Security Education) Project](https://seedsecuritylabs.org/) curriculum.  
> All labs completed **above requirements**, with dual implementations and extended research where applicable.

## Team

| Name | Student ID |
|---|---|
| **Bar Sberro** | 314683665 |
| Shalev Cohen | 314745456 |
| Noam Hadad | 3147014118 |

---

## Labs Overview

| Lab | Topic | Key Technologies | Status |
|---|---|---|---|
| [Lab 0](./lab-0/) | Packet Sniffing & Spoofing | Python/Scapy · C/libpcap · Raw Sockets | ✅ Complete |
| [Lab 1](./lab-1/) | ARP Cache Poisoning | Scapy · ARP · MITM | ✅ Complete |
| [Lab 2](./lab-2/) | IP / ICMP Attacks | Scapy · C/Raw Sockets · ICMP · DoS | ✅ Complete |
| [Lab 3](./lab-3/) | Local DNS Attacks | BIND9 · Scapy · Cache Poisoning | ✅ Complete |
| [Lab 4](./lab-4/) | Remote DNS Cache Poisoning | Kaminsky Attack · BIND9 · UDP | ✅ Complete |

---

## What is SEED Labs?

SEED (Security Education) is a project funded by the US National Science Foundation.  
The labs provide hands-on experience with real-world attacks in isolated VM environments (VirtualBox).  
Each lab requires building attack tools from scratch, analyzing packet captures, and documenting findings in depth.

## Environment

All labs were performed in a **VirtualBox** multi-VM setup (Ubuntu 16.04):
- **Client VM** (10.0.2.7) — victim / user machine
- **Attacker VM** (10.0.2.6) — attack machine running our scripts
- **Server VM** (10.0.2.8) — target server

Tools used across all labs: Wireshark, Scapy (Python), libpcap (C), Raw Sockets (C), BIND9, dig, netstat, iptables.

---

## Beyond Requirements

Each lab includes tasks that go beyond the official SEED instructions:

- **Lab 0**: Full C implementation (pcap + Raw Sockets pipeline), Promiscuous mode analysis, RPF deep dive  
- **Lab 1**: Tested `arpspoof` + `ettercap` in practice; documented Dynamic ARP Inspection (DAI) defenses  
- **Lab 2**: 5-terminal parallel C DoS attack, IP-in-IP encapsulation to bypass Strict RPF, Loose RPF analysis  
- **Lab 3**: AAAA/IPv6 race condition exploit, decoupled Bailiwick bypass, DNSSEC configuration research  
- **Lab 4**: Full Kaminsky Attack implementation with source port analysis and forged NS injection  
