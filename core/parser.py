# core/parser.py
# Dissects raw Scapy packets into structured dicts.
# Covers Layer 2 (MAC), Layer 3 (IP), Layer 4 (TCP/UDP/ICMP),
# and Layer 7 (DNS, HTTP, ARP).
#
# Direction-aware CIC-IDS fields (fwd_*/bwd_*) are NOT set here.
# FlowTracker resolves direction from the canonical 5-tuple key
# and accumulates those values itself.  Parser only provides the
# raw per-packet values that FlowTracker reads:
#   - tcp_header_length  (neutral; FlowTracker routes to fwd/bwd)
#   - window_size        (FlowTracker tracks init_win_fwd/bwd)
#   - psh_flag, urg_flag (FlowTracker routes to fwd_*/bwd_*)
#   - min_seg_size_fwd   (set here for fwd packets only by convention;
#                         FlowTracker ignores it for bwd packets)
#
# DNS-over-TCP fix:
#   BIND9 falls back to TCP for responses > 512 bytes (zone transfers,
#   large DNSSEC). When src_port or dst_port is 53 on a TCP packet,
#   the protocol field is overridden to "DNS" so DNS rules fire correctly.
# ─────────────────────────────────────────────────────────────

import math
from datetime import datetime, timezone
from scapy.all import (
    IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
    Ether, Dot1Q, Raw, ARP
)
from config import MAX_PAYLOAD_BYTES


def payload_entropy(data: bytes) -> float:
    """
    Shannon entropy of raw bytes.
    0.0  = completely uniform (empty or repeated bytes)
    8.0  = maximum randomness (encrypted / compressed data)
    High entropy on port 80 is suspicious (should be readable HTML).
    """
    if not data or len(data) == 0:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    length  = len(data)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def parse_packet(pkt, label: str = "normal") -> dict | None:
    """
    Parse a raw Scapy packet into a flat structured dict.
    Returns None if the packet has no IP layer and is not ARP.

    label: set by Capture.set_label() during training sessions.
    """

    record = {
        # ── Meta ──────────────────────────────────────────────
        "timestamp":         datetime.now(timezone.utc).isoformat(),
        "label":             label,

        # ── Layer 2 — Ethernet ────────────────────────────────
        "src_mac":           None,
        "dst_mac":           None,

        # ── Layer 3 — IP ──────────────────────────────────────
        "src_ip":            None,
        "dst_ip":            None,
        "ttl":               None,
        "ip_flags":          None,
        "packet_length":     len(pkt),
        "protocol":          None,

        # ── KDD ───────────────────────────────────────────────
        "land":              0,
        "wrong_fragment":    0,

        # ── Layer 4 — TCP/UDP ─────────────────────────────────
        "src_port":          None,
        "dst_port":          None,
        "tcp_flags":         None,
        "seq_number":        None,
        "ack_number":        None,
        "window_size":       None,
        "tcp_checksum":      None,
        "urgent":            0,

        # ── CIC-IDS — TCP flag bits ───────────────────────────
        "fin_flag":          0,
        "syn_flag":          0,
        "rst_flag":          0,
        "psh_flag":          0,
        "ack_flag":          0,
        "urg_flag":          0,
        "cwe_flag":          0,
        "ece_flag":          0,

        # ── CIC-IDS — raw header length ───────────────────────
        "tcp_header_length": None,
        "min_seg_size_fwd":  None,

        # ── Layer 7 — payload ─────────────────────────────────
        "payload_size":      0,
        "payload_entropy":   0.0,

        # ── Layer 7 — DNS ─────────────────────────────────────
        "dns_query":         None,
        "dns_query_length":  None,
        "dns_response":      None,
        "dns_rcode":         None,

        # ── Layer 7 — HTTP ────────────────────────────────────
        "http_method":       None,
        "http_host":         None,
        "http_path":         None,
        "http_user_agent":   None,

        # ── ARP ───────────────────────────────────────────────
        "arp_op":            None,
        "arp_src_ip":        None,
        "arp_dst_ip":        None,
        "arp_src_mac":       None,
    }

    # ── Layer 2 — Ethernet ────────────────────────────────────
    if pkt.haslayer(Ether):
        record["src_mac"] = pkt[Ether].src
        record["dst_mac"] = pkt[Ether].dst

    # ── ARP (no IP layer needed) ──────────────────────────────
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
    record["src_ip"]   = ip.src
    record["dst_ip"]   = ip.dst
    record["ttl"]      = ip.ttl
    record["ip_flags"] = str(ip.flags)

    # KDD: wrong_fragment — non-zero fragment offset
    if ip.frag > 0:
        record["wrong_fragment"] = 1

    # ── Layer 4 — TCP ─────────────────────────────────────────
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        record["protocol"]     = "TCP"
        record["src_port"]     = tcp.sport
        record["dst_port"]     = tcp.dport
        record["tcp_flags"]    = str(tcp.flags)
        record["seq_number"]   = tcp.seq
        record["ack_number"]   = tcp.ack
        record["window_size"]  = tcp.window
        record["tcp_checksum"] = tcp.chksum

        # KDD: urgent pointer active
        if tcp.urgptr > 0:
            record["urgent"] = 1

        # CIC-IDS: individual flag bits
        flags = int(tcp.flags)
        record["fin_flag"] = 1 if flags & 0x01 else 0
        record["syn_flag"] = 1 if flags & 0x02 else 0
        record["rst_flag"] = 1 if flags & 0x04 else 0
        record["psh_flag"] = 1 if flags & 0x08 else 0
        record["ack_flag"] = 1 if flags & 0x10 else 0
        record["urg_flag"] = 1 if flags & 0x20 else 0
        record["ece_flag"] = 1 if flags & 0x40 else 0
        record["cwe_flag"] = 1 if flags & 0x80 else 0

        tcp_header_len = tcp.dataofs * 4 if tcp.dataofs else 20
        record["tcp_header_length"] = tcp_header_len
        record["min_seg_size_fwd"]  = tcp_header_len

        # ── DNS-over-TCP fix ───────────────────────────────────
        # BIND9 uses TCP for responses > 512 bytes (zone transfers,
        # DNSSEC). Override protocol to "DNS" so DNS rules fire.
        # Checked here while we still have the port values in scope.
        if tcp.dport == 53 or tcp.sport == 53:
            record["protocol"] = "DNS"

    # ── Layer 4 — UDP ─────────────────────────────────────────
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        record["protocol"]          = "UDP"
        record["src_port"]          = udp.sport
        record["dst_port"]          = udp.dport
        record["tcp_header_length"] = 8   # neutral; FlowTracker routes it

    # ── Layer 4 — ICMP ────────────────────────────────────────
    elif pkt.haslayer(ICMP):
        record["protocol"] = "ICMP"

    # ── KDD: land — same src/dst IP and port ──────────────────
    if (record["src_ip"] and record["dst_ip"] and
            record["src_ip"] == record["dst_ip"] and
            record["src_port"] is not None and
            record["src_port"] == record["dst_port"]):
        record["land"] = 1

    # ── Layer 7 — DNS ─────────────────────────────────────────
    # Runs for both UDP DNS (protocol already "DNS" from layer above)
    # and TCP DNS (protocol overridden to "DNS" in TCP block above).
    if pkt.haslayer(DNS):
        record["protocol"] = "DNS"   # ensure set even if TCP block ran
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
        record["payload_entropy"] = payload_entropy(raw_bytes[:MAX_PAYLOAD_BYTES])

        try:
            decoded = raw_bytes.decode("utf-8", errors="ignore")

            if decoded.startswith(("GET ", "POST ", "PUT ",
                                   "DELETE ", "HEAD ", "OPTIONS ",
                                   "PATCH ")):
                lines      = decoded.split("\r\n")
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

        except Exception:
            pass

    return record
