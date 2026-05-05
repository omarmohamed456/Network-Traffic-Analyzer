# core/parser.py
# Dissects raw Scapy packets into structured dicts
# Covers Layer 2 (MAC), Layer 3 (IP), Layer 4 (TCP/UDP/ICMP),
# and Layer 7 (DNS, HTTP)
# ─────────────────────────────────────────────────────────────

import math
from datetime import datetime, timezone
from scapy.all import (
    IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
    Ether, Dot1Q, Raw, ARP
)


def payload_entropy(data: bytes) -> float:
    """
    Shannon entropy of raw bytes.
    0.0  = completely uniform (empty or repeated bytes)
    8.0  = maximum randomness (encrypted / compressed data)
    High entropy on port 80 = suspicious (should be readable HTML)
    """
    if not data or len(data) == 0:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def parse_packet(pkt, label: str = "normal") -> dict | None:
    """
    Parse a raw Scapy packet into a flat structured dict.
    Returns None if packet has no IP layer (e.g. pure ARP).
    label: set by session manager during training sessions
    """

    record = {
        # ── Meta ──────────────────────────────────────────────
        "timestamp":          datetime.now(timezone.utc).isoformat(),
        "label":              label,

        # ── Layer 2 — Ethernet ────────────────────────────────
        "src_mac":            None,
        "dst_mac":            None,
        "src_mac_oui":        None,
        "dst_mac_oui":        None,
        "vlan_tag":           None,

        # ── Layer 3 — IP ──────────────────────────────────────
        "src_ip":             None,
        "dst_ip":             None,
        "ip_version":         None,
        "ttl":                None,
        "ip_flags":           None,
        "fragment_offset":    None,
        "packet_length":      len(pkt),
        "protocol":           None,

        # ── Layer 4 — TCP ─────────────────────────────────────
        "src_port":           None,
        "dst_port":           None,
        "tcp_flags":          None,
        "seq_number":         None,
        "ack_number":         None,
        "window_size":        None,
        "tcp_checksum":       None,
        "urgent_pointer":     None,

        # ── Layer 4 — UDP ─────────────────────────────────────
        "udp_length":         None,
        "udp_checksum":       None,

        # ── Layer 7 — Application ─────────────────────────────
        "payload_size":       0,
        "payload_entropy":    0.0,
        "payload_printable":  False,
        "dns_query":          None,
        "dns_query_length":   None,
        "dns_response":       None,
        "dns_rcode":          None,
        "http_method":        None,
        "http_host":          None,
        "http_path":          None,
        "http_user_agent":    None,
        "http_status_code":   None,
        "tls_detected":       False,

        # ── ARP ───────────────────────────────────────────────
        "arp_op":             None,
        "arp_src_ip":         None,
        "arp_dst_ip":         None,
        "arp_src_mac":        None,
    }

    # ── Layer 2 — Ethernet ────────────────────────────────────
    if pkt.haslayer(Ether):
        record["src_mac"]     = pkt[Ether].src
        record["dst_mac"]     = pkt[Ether].dst
        record["src_mac_oui"] = pkt[Ether].src[:8].upper()
        record["dst_mac_oui"] = pkt[Ether].dst[:8].upper()

    if pkt.haslayer(Dot1Q):
        record["vlan_tag"] = pkt[Dot1Q].vlan

    # ── ARP (no IP layer) ─────────────────────────────────────
    if pkt.haslayer(ARP):
        record["protocol"]    = "ARP"
        record["arp_op"]      = "request" if pkt[ARP].op == 1 else "reply"
        record["arp_src_ip"]  = pkt[ARP].psrc
        record["arp_dst_ip"]  = pkt[ARP].pdst
        record["arp_src_mac"] = pkt[ARP].hwsrc
        record["src_ip"]      = pkt[ARP].psrc
        record["dst_ip"]      = pkt[ARP].pdst
        return record

    # ── Require IP layer for everything below ─────────────────
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    record["src_ip"]          = ip.src
    record["dst_ip"]          = ip.dst
    record["ip_version"]      = ip.version
    record["ttl"]             = ip.ttl
    record["ip_flags"]        = str(ip.flags)
    record["fragment_offset"] = ip.frag

    # ── Layer 4 — TCP ─────────────────────────────────────────
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        record["protocol"]       = "TCP"
        record["src_port"]       = tcp.sport
        record["dst_port"]       = tcp.dport
        record["tcp_flags"]      = str(tcp.flags)
        record["seq_number"]     = tcp.seq
        record["ack_number"]     = tcp.ack
        record["window_size"]    = tcp.window
        record["tcp_checksum"]   = tcp.chksum
        record["urgent_pointer"] = tcp.urgptr

        if tcp.dport == 443 or tcp.sport == 443:
            record["tls_detected"] = True

    # ── Layer 4 — UDP ─────────────────────────────────────────
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        record["protocol"]     = "UDP"
        record["src_port"]     = udp.sport
        record["dst_port"]     = udp.dport
        record["udp_length"]   = udp.len
        record["udp_checksum"] = udp.chksum

    # ── Layer 4 — ICMP ────────────────────────────────────────
    elif pkt.haslayer(ICMP):
        record["protocol"] = "ICMP"

    # ── Layer 7 — DNS ─────────────────────────────────────────
    if pkt.haslayer(DNS):
        record["protocol"] = "DNS"
        dns = pkt[DNS]
        record["dns_rcode"] = dns.rcode

        if pkt.haslayer(DNSQR):
            try:
                query = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                record["dns_query"]        = query
                record["dns_query_length"] = len(query)
            except Exception:
                pass

        if dns.an and pkt.haslayer(DNSRR):
            try:
                record["dns_response"] = str(pkt[DNSRR].rdata)
            except Exception:
                pass

    # ── Layer 7 — HTTP / Raw payload ──────────────────────────
    if pkt.haslayer(Raw):
        raw_bytes = pkt[Raw].load
        record["payload_size"]    = len(raw_bytes)
        record["payload_entropy"] = payload_entropy(raw_bytes)

        try:
            decoded = raw_bytes.decode("utf-8", errors="ignore")
            record["payload_printable"] = True

            # HTTP request
            if decoded.startswith(("GET ", "POST ", "PUT ",
                                   "DELETE ", "HEAD ", "OPTIONS ",
                                   "PATCH ")):
                lines = decoded.split("\r\n")
                first_line = lines[0].split()
                if len(first_line) >= 2:
                    record["http_method"] = first_line[0]
                    record["http_path"]   = first_line[1]

                for line in lines[1:]:
                    low = line.lower()
                    if low.startswith("host:"):
                        record["http_host"] = line.split(":", 1)[1].strip()
                    elif low.startswith("user-agent:"):
                        record["http_user_agent"] = line.split(":", 1)[1].strip()[:200]

            # HTTP response
            elif decoded.startswith("HTTP/"):
                parts = decoded.split()
                if len(parts) >= 2:
                    record["http_status_code"] = parts[1]

        except Exception:
            record["payload_printable"] = False

    return record
