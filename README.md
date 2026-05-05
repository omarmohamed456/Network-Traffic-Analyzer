# Network Traffic Analyzer & IDS

A from-scratch network intrusion detection system built in Python. Captures live traffic using Scapy, parses every packet across all network layers, logs to multiple formats simultaneously, and detects attacks in real time using a custom rule engine.

---

## Lab Architecture

```
192.168.10.10   Kali Linux      Attacker — nmap, hping3, hydra, nikto
192.168.10.20   Ubuntu          Victim   — Apache, SSH, FTP, DNS
192.168.10.30   Ubuntu          IDS      — Scapy sniffer, rule engine, dashboard
```

All three machines run on an isolated VirtualBox Host-Only network. No internet exposure.

---

## Project Structure

```
network-traffic-analyzer/
│
├── core/
│   ├── capture.py          Scapy sniffer — packet queue and processing loop
│   ├── parser.py           Protocol dissector — Layer 2 through Layer 7
│   ├── rule_engine.py      Real-time rule evaluator — reads .rule files
│   └── logger.py           Multi-format writer — JSON, CSV, SQLite
│
├── rules/
│   ├── port_scan.rule      Horizontal SYN scan detection
│   ├── syn_flood.rule      DoS SYN flood detection
│   ├── ssh_brute.rule      SSH brute force detection
│   ├── dns_tunnel.rule     DNS tunneling detection
│   ├── web_scan.rule       HTTP directory scan detection
│   └── misc.rule           ICMP flood, ARP scan, high entropy payload
│
├── storage/                Auto-created on first run
│   ├── traffic.json        Newline-delimited JSON — Splunk ingestion
│   ├── traffic.csv         Labeled packet records 
│   └── alerts.db           SQLite — dashboard backend
│
├── config.py               Interface name, paths, feature flags
├── main.py                 Entry point
└── requirements.txt
```

---

## How It Works

### Capture Layer
Scapy listens on the Host-Only network interface in promiscuous mode. Every packet that crosses the virtual switch — including traffic between Kali and the Victim — is captured and placed into a thread-safe queue.

### Parse Layer
A worker thread pulls packets from the queue and dissects them through every network layer:
- **Layer 2** — MAC addresses, OUI vendor, VLAN tags
- **Layer 3** — src/dst IP, TTL, fragmentation flags
- **Layer 4** — TCP flags, sequence numbers, window size, UDP/ICMP fields
- **Layer 7** — DNS queries, HTTP method/path/host/user-agent, TLS detection, payload entropy

### Rule Engine
Every parsed packet is evaluated against all loaded `.rule` files. Rules define protocol, flags, port, and threshold conditions. When a source IP exceeds a packet count threshold within a time window, an alert fires instantly — before the packet is written to disk.

```
RULE ssh_brute_force
  DESCRIPTION "SSH brute force — repeated connection attempts to port 22"
  PROTOCOL TCP
  DST_PORT 22
  FLAGS S
  THRESHOLD 10 packets FROM same_src IN 60 seconds
  ACTION alert HIGH
```

### Logger
Every packet is written simultaneously to three formats. JSON feeds Splunk. CSV accumulates labeled training data for the ML model. SQLite serves the live dashboard.

---

## Getting Started

### Requirements

```
Python 3.10+
Root / sudo access for packet capture
VirtualBox with Host-Only adapter configured
```

### Install

```bash
git clone https://github.com/yourname/network-traffic-analyzer
cd network-traffic-analyzer
pip install -r requirements.txt
```

### Configure

Edit `config.py` before running:

```python
INTERFACE = "enp0s3"    # run 'ip a' to find your Host-Only interface name
HOME_NET  = "192.168.10.0/24"
```

### Run

```bash
# Terminal 1 — start the IDS (requires root for raw socket access)
sudo python3 main.py

```

### Generate Attack Traffic (from Kali VM)

```bash
# Port scan — triggers port_scan rule
nmap -sS 192.168.10.20

# SYN flood — triggers syn_flood rule
sudo hping3 -S --flood -p 80 192.168.10.20

# SSH brute force — triggers ssh_brute_force rule
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.10.20

# Web scan — triggers web_scan rule
nikto -h http://192.168.10.20
```

---

## Detection Rules

| Rule | Protocol | Condition | Severity |
|---|---|---|---|
| port_scan | TCP | 20 SYN packets from same src in 3s | HIGH |
| syn_flood | TCP | 200 SYN packets from same src in 1s | CRITICAL |
| ssh_brute_force | TCP | 10 SYN to port 22 from same src in 60s | HIGH |
| ftp_brute_force | TCP | 10 SYN to port 21 from same src in 60s | HIGH |
| web_scan | TCP | 30 SYN to port 80 from same src in 5s | MEDIUM |
| dns_tunneling | DNS | query length > 50 chars, 5 packets in 10s | HIGH |
| icmp_flood | ICMP | 50 packets from same src in 2s | HIGH |
| arp_scan | ARP | 20 ARP requests from same src in 5s | MEDIUM |

---

## Logged Fields

Every captured packet record includes:

```
timestamp, label, src_mac, dst_mac, src_mac_oui,
src_ip, dst_ip, ip_version, ttl, ip_flags,
packet_length, protocol, src_port, dst_port,
tcp_flags, seq_number, ack_number, window_size,
payload_size, payload_entropy, payload_printable,
dns_query, dns_query_length, http_method,
http_host, http_path, http_user_agent, tls_detected
```

---
