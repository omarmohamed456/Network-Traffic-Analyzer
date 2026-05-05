# core/rule_engine.py
# Loads all .rule files from rules/ directory
# Evaluates every parsed packet against every rule in real time
# Fires alerts when thresholds are exceeded
# ─────────────────────────────────────────────────────────────

import os
import time
from collections import defaultdict
from datetime import datetime, timezone


class Rule:
    """Represents one parsed rule from a .rule file."""
    def __init__(self):
        self.name        = ""
        self.description = ""
        self.protocol    = None     # TCP / UDP / DNS / ICMP / ARP / None (any)
        self.flags       = None     # TCP flags to match e.g. "S"
        self.dst_port    = None     # specific destination port
        self.src_port    = None     # specific source port
        self.threshold_count  = None   # packet count threshold
        self.threshold_window = None   # time window in seconds
        self.dns_query_len_op  = None  # ">" or "<"
        self.dns_query_len_val = None  # value to compare against
        self.payload_entropy_op  = None
        self.payload_entropy_val = None
        self.arp_op      = None     # "request" or "reply"
        self.severity    = "MEDIUM"
        self.action      = "alert"


class RuleEngine:
    def __init__(self, rules_dir: str = "rules/", alert_callback=None):
        """
        rules_dir:       folder containing .rule files
        alert_callback:  function to call when rule fires
                         receives (packet_dict, rule) as args
        """
        self.rules          = []
        self.alert_callback = alert_callback
        # counters[rule_name][src_ip] = [timestamp, timestamp, ...]
        self.counters       = defaultdict(lambda: defaultdict(list))

        self.load_rules(rules_dir)

    # ── Rule loading ──────────────────────────────────────────
    def load_rules(self, rules_dir: str):
        if not os.path.exists(rules_dir):
            print(f"[RuleEngine] Rules directory not found: {rules_dir}")
            return

        count = 0
        for fname in sorted(os.listdir(rules_dir)):
            if fname.endswith(".rule"):
                path = os.path.join(rules_dir, fname)
                loaded = self._parse_rule_file(path)
                self.rules.extend(loaded)
                count += len(loaded)

        print(f"[RuleEngine] Loaded {count} rules from {rules_dir}")

    def _parse_rule_file(self, path: str) -> list[Rule]:
        """Parse one .rule file — may contain multiple RULE blocks."""
        rules = []
        try:
            with open(path) as f:
                content = f.read()
        except Exception as e:
            print(f"[RuleEngine] Could not read {path}: {e}")
            return rules

        # Split on RULE keyword — first element before any RULE is discarded
        blocks = content.split("RULE ")
        for block in blocks[1:]:
            rule = Rule()
            lines = block.strip().splitlines()
            if not lines:
                continue

            rule.name = lines[0].strip()

            for line in lines[1:]:
                line = line.strip()

                # Skip comments and blank lines
                if not line or line.startswith("#"):
                    continue

                parts = line.split()
                keyword = parts[0].upper()

                if keyword == "DESCRIPTION":
                    rule.description = line.split('"')[1] if '"' in line else ""

                elif keyword == "PROTOCOL":
                    rule.protocol = parts[1].upper()

                elif keyword == "FLAGS":
                    rule.flags = parts[1]

                elif keyword == "DST_PORT":
                    rule.dst_port = int(parts[1])

                elif keyword == "SRC_PORT":
                    rule.src_port = int(parts[1])

                elif keyword == "THRESHOLD":
                    # THRESHOLD 20 packets FROM same_src IN 3 seconds
                    try:
                        rule.threshold_count  = int(parts[1])
                        rule.threshold_window = int(parts[6])
                    except (IndexError, ValueError):
                        pass

                elif keyword == "DNS_QUERY_LEN":
                    # DNS_QUERY_LEN > 50
                    rule.dns_query_len_op  = parts[1]
                    rule.dns_query_len_val = int(parts[2])

                elif keyword == "PAYLOAD_ENTROPY":
                    # PAYLOAD_ENTROPY > 7.0
                    rule.payload_entropy_op  = parts[1]
                    rule.payload_entropy_val = float(parts[2])

                elif keyword == "ARP_OP":
                    rule.arp_op = parts[1].lower()

                elif keyword == "ACTION":
                    rule.action   = parts[1].lower()
                    rule.severity = parts[2].upper() if len(parts) > 2 else "MEDIUM"

            rules.append(rule)

        return rules

    # ── Packet evaluation ─────────────────────────────────────
    def evaluate(self, packet: dict):
        """
        Run every rule against this packet.
        Called for every parsed packet from the sniffer.
        """
        for rule in self.rules:
            if self._matches(packet, rule):
                if self._threshold_check(packet, rule):
                    self._fire_alert(packet, rule)

    def _matches(self, pkt: dict, rule: Rule) -> bool:
        """Check if packet matches rule conditions (excluding threshold)."""

        # Protocol
        if rule.protocol and pkt.get("protocol") != rule.protocol:
            return False

        # TCP flags — packet flags must CONTAIN the rule flag
        if rule.flags:
            pkt_flags = pkt.get("tcp_flags") or ""
            if rule.flags not in str(pkt_flags):
                return False

        # Destination port
        if rule.dst_port and pkt.get("dst_port") != rule.dst_port:
            return False

        # Source port
        if rule.src_port and pkt.get("src_port") != rule.src_port:
            return False

        # DNS query length
        if rule.dns_query_len_op:
            qlen = pkt.get("dns_query_length") or 0
            if rule.dns_query_len_op == ">" and not qlen > rule.dns_query_len_val:
                return False
            if rule.dns_query_len_op == "<" and not qlen < rule.dns_query_len_val:
                return False

        # Payload entropy
        if rule.payload_entropy_op:
            entropy = pkt.get("payload_entropy") or 0.0
            if rule.payload_entropy_op == ">" and not entropy > rule.payload_entropy_val:
                return False
            if rule.payload_entropy_op == "<" and not entropy < rule.payload_entropy_val:
                return False

        # ARP operation type
        if rule.arp_op and pkt.get("arp_op") != rule.arp_op:
            return False

        return True

    def _threshold_check(self, pkt: dict, rule: Rule) -> bool:
        """
        Track packet count from src_ip per rule.
        Returns True if threshold exceeded (or no threshold set).
        """
        if rule.threshold_count is None:
            return True     # no threshold — always alert on match

        src_ip = pkt.get("src_ip", "unknown")
        now    = time.time()
        window = rule.threshold_window

        # Add current timestamp
        self.counters[rule.name][src_ip].append(now)

        # Remove timestamps outside the window
        self.counters[rule.name][src_ip] = [
            t for t in self.counters[rule.name][src_ip]
            if now - t <= window
        ]

        count = len(self.counters[rule.name][src_ip])
        return count >= rule.threshold_count

    def _fire_alert(self, pkt: dict, rule: Rule):
        """Build alert dict and send to callback."""
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule_name": rule.name,
            "severity":  rule.severity,
            "src_ip":    pkt.get("src_ip"),
            "dst_ip":    pkt.get("dst_ip"),
            "src_port":  pkt.get("src_port"),
            "dst_port":  pkt.get("dst_port"),
            "protocol":  pkt.get("protocol"),
            "detail":    rule.description,
        }

        # Print to terminal with color coding
        colors = {
            "CRITICAL": "\033[91m",   # red
            "HIGH":     "\033[93m",   # yellow
            "MEDIUM":   "\033[94m",   # blue
            "LOW":      "\033[92m",   # green
        }
        reset = "\033[0m"
        color = colors.get(rule.severity, "")
        ts    = datetime.now(timezone.utc).strftime("%H:%M:%S")

        print(
            f"{color}[ALERT] [{ts}] {rule.severity} | "
            f"{rule.name} | "
            f"{pkt.get('src_ip')} → {pkt.get('dst_ip')} "
            f"port {pkt.get('dst_port')}{reset}"
        )

        if self.alert_callback:
            self.alert_callback(alert)
