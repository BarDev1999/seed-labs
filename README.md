# SEED Labs : Network Security Research

![Labs](https://img.shields.io/badge/labs-6%2F6%20complete-success)
![Platform](https://img.shields.io/badge/platform-VirtualBox%20%7C%20Ubuntu%2016.04-blue)
![Language](https://img.shields.io/badge/languages-Python%20%7C%20C-yellow)
![Tooling](https://img.shields.io/badge/tooling-Scapy%20%7C%20libpcap%20%7C%20BIND9%20%7C%20Wireshark-lightgrey)

> Hands on network security and cryptography labs from the [SEED (Security Education) Project](https://seedsecuritylabs.org/) curriculum.
> All six labs completed **above requirements**, with dual Python and C implementations and extended research where applicable.

## Team

**Bar Sberro** · Shalev Cohen · Noam Hadad

> Student IDs are recorded in the per lab `.docx` reports for grading; they are intentionally omitted from this public README.

---

## Labs Overview

| Lab | Topic | Key Technologies | Status |
|---|---|---|---|
| [Lab 0](./lab-0/) | Packet Sniffing and Spoofing | Python / Scapy · C / libpcap · Raw Sockets | Complete |
| [Lab 1](./lab-1/) | ARP Cache Poisoning | Scapy · ARP · MITM | Complete |
| [Lab 2](./lab-2/) | IP / ICMP Attacks | Scapy · C / Raw Sockets · ICMP · DoS | Complete |
| [Lab 3](./lab-3/) | Local DNS Attacks | BIND9 · Scapy · Cache Poisoning | Complete |
| [Lab 4](./lab-4/) | Remote DNS Cache Poisoning (Kaminsky) | BIND9 · C · UDP · DNSSEC | Complete |
| [Lab 5](./lab-5/) | RSA Public Key Encryption and Signatures | OpenSSL BIGNUM · C · X.509 · SHA-256 | Complete |

---

## How to Read This Repo

Each `lab-N/` directory contains:

* `README.md` : the technical writeup of the lab (this is the canonical record; everything renders inline on GitHub)
* `assets/` : screenshots referenced from the README
* `Lab-N-Report.docx` : the formal academic report submitted for grading (mirrors the README with extra commentary)

> [!NOTE]
> All experiments were performed in isolated VirtualBox VMs on a private host only network. No public infrastructure was attacked. The labs intentionally weaken some defenses (fixed source ports, disabled DNSSEC, disabled RPF) so the underlying mechanism can be observed; production systems retain those defenses by default.

---

## What is SEED Labs?

SEED (Security Education) is a project funded by the US National Science Foundation, hosted by Syracuse University.
The labs provide hands on experience with real world attacks in isolated VM environments.
Each lab requires building attack tools from scratch, analyzing packet captures, and documenting findings in depth.

## Environment

Labs 0 to 2 use a standard three VM topology on a private NAT network:

| Role | IP | Purpose |
|---|---|---|
| Client VM | 10.0.2.7 | victim / user machine |
| Attacker VM | 10.0.2.6 | attack machine running our scripts |
| Server VM | 10.0.2.8 | target server |

Labs 3 and 4 use a DNS specific topology with a dedicated BIND9 resolver (`Apollo`, 10.0.2.20); see each lab's README for the exact layout.

**Toolchain:** Wireshark, Scapy (Python), libpcap (C), Raw Sockets (C), BIND9, `dig`, `arp`, `netstat`, `iptables`, `rndc`.

---

## Beyond Requirements

Each lab includes tasks that go beyond the official SEED instructions:

* **Lab 0:** Full C implementation (pcap plus Raw Sockets pipeline), Promiscuous mode analysis, Reverse Path Filtering deep dive
* **Lab 1:** Tested `arpspoof` plus `ettercap` in practice; documented Dynamic ARP Inspection (DAI) defenses
* **Lab 2:** 5 terminal parallel C DoS attack, IP in IP encapsulation against Strict RPF, Loose RPF bypass analysis
* **Lab 3:** AAAA / IPv6 race condition exploit, decoupled Bailiwick bypass, DNSSEC configuration research
* **Lab 4:** Full Kaminsky attack implementation with source port analysis and forged NS injection; DNSSEC defense verification
* **Lab 5:** End to end manual verification of a live `www.reddit.com` X.509 certificate plus a Factoring Attack using FactorDB that recovers `d` from `(n, e)` alone

---

## License and Use

This repository documents coursework. The scripts target lab VMs only.
Do not run the code against any system you do not own or have explicit written authorization to test.
