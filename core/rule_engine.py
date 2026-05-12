# core/rule_engine.py
# Loads all .rule files from rules/ directory.
# Evaluates every completed FLOW record against every rule.
# Fires alerts when conditions are met.
#
# NOTE: evaluate() is called once per completed flow (not per packet).
# Threshold rules count flows from the same src_ip within a time window.
#
# ── Supported rule keywords ───────────────────────────────────
#
#   PROTOCOL            TCP | UDP | ICMP | DNS | ARP
#   FLAGS               S | SA | R | FPU | etc  (exact match on tcp_flags string)
#                       FLAGS NONE  → matches flows with no TCP flags set (NULL scan)
#   DST_PORT            <int>
#   SRC_PORT            <int>
#   SRC_IP_NOT          <ip> | $IDS_IP | $VICTIM_IP | $VICTIM_IP_2 | $VICTIM_IP_3
#                       | $VICTIM_IP_4 | $ATTACKER_IP
#                       Multiple SRC_IP_NOT lines are all respected (OR logic —
#                       flow is excluded if src_ip matches ANY of the listed IPs)
#   DST_IP              <ip> | $IDS_IP | $VICTIM_IP | $ATTACKER_IP
#                       (match a specific destination IP)
#   DST_IP_NOT          <ip> | $IDS_IP | $VICTIM_IP | $ATTACKER_IP
#                       (exclude a destination IP)
#   DNS_QUERY_LEN       > | < <int>
#   PAYLOAD_ENTROPY     > | < <float>
#   ARP_OP              request | reply
#   WRONG_FRAGMENT      1      (matches flows with non-zero IP fragment offset)
#   FLOW_IAT_STD        > | < <float>   (ms — inter-arrival time std dev)
#   PAYLOAD_SIZE        > | < <int>     (bytes — payload of first packet)
#   TOTAL_BWD_BYTES     > | < <int>     (bytes — total backward direction)
#   FLOW_DURATION       > | < <float>   (microseconds)
#   TOTAL_FWD_PACKETS   > | < <int>
#   TOTAL_FWD_BYTES     > | < <int>     (bytes — total forward direction)
#   AVG_PACKET_SIZE     > | < <float>   (bytes — mean packet size across flow)
#   SYN_FLAG_COUNT      > | < <int>     (SYN packets seen in flow)
#   ACK_FLAG_COUNT      > | < <int>     (ACK packets seen in flow)
#   TTL                 > | < <int>     (IP time-to-live from first packet)
#   LAND                1              (src IP+port == dst IP+port)
#   ARP_MAC_MISMATCH    true           (arp_src_mac != src_mac — ARP spoofing)
#   HTTP_USER_AGENT     null           (no User-Agent header present)
#   INIT_WIN_FWD        > | < | = <int> (initial TCP window size, forward)
#   COUNT               > | < <int>     (flows to same dst_ip in last 2s)
#   SRV_COUNT           > | < <int>     (flows to same dst_port in last 2s)
#   SERROR_RATE         > | < <float>   (fraction of count flows with SYN errors, 0.0–1.0)
#   UNIQUE_DST_PORTS    > | < <int>     (distinct dst ports from this src in window)
#   UNIQUE_SRC_IPS      > | < <int>     (distinct src IPs to this dst in window)
#   WINDOW              <int> seconds   (time window for UNIQUE_* checks when no
#                                        THRESHOLD is present)
#   THRESHOLD           <int> flows FROM same_src IN <int> seconds
#   ACTION              alert CRITICAL | HIGH | MEDIUM | LOW
#
# ── Config token resolution ───────────────────────────────────
# Any IP value in a rule file can use a token instead of a literal address.
# Tokens are resolved once at load time from config.py:
#   $IDS_IP      → config.IDS_IP
#   $VICTIM_IP   → config.VICTIM_IP
#   $VICTIM_IP_2 → config.VICTIM_IP_2
#   $VICTIM_IP_3 → config.VICTIM_IP_3
#   $VICTIM_IP_4 → config.VICTIM_IP_4
#   $ATTACKER_IP → config.ATTACKER_IP
# This means no IP addresses are ever hardcoded in rule files.
#
# ── FLAGS matching ────────────────────────────────────────────
# FLAGS uses EXACT string match against the Scapy tcp_flags string
# (e.g. "S", "SA", "FA", "FPU"). Substring matching caused false positives:
#   FLAGS S would match "SA" (SYN-ACK), firing scan rules on victim responses.
#   FLAGS A would match "SA", "RA", "PA", firing ack_flood on normal traffic.
#   FLAGS R would match "RA", firing rst_flood on normal RST+ACK teardowns.
#   FLAGS F would match "FA", "FPU", conflating fin_scan with XMAS scan.
# Exact match eliminates all of these false positives.
# ─────────────────────────────────────────────────────────────

import os
import time
from collections import defaultdict
from datetime import datetime, timezone

import config


# Build the token resolution table once at import time.
# Rules use $TOKEN; the engine substitutes the real IP from config.
# CHANGE: added $VICTIM_IP_2, $VICTIM_IP_3, $VICTIM_IP_4 for the new victim VMs.
_IP_TOKENS = {
    "$IDS_IP":      getattr(config, "IDS_IP",      None),
    "$VICTIM_IP":   getattr(config, "VICTIM_IP",   None),
    "$VICTIM_IP_2": getattr(config, "VICTIM_IP_2", None),
    "$VICTIM_IP_3": getattr(config, "VICTIM_IP_3", None),
    "$VICTIM_IP_4": getattr(config, "VICTIM_IP_4", None),
    "$ATTACKER_IP": getattr(config, "ATTACKER_IP", None),
}


def _resolve_ip(value: str) -> str:
    """
    Substitute a config token for its real IP address.
    e.g. "$IDS_IP" → "192.168.10.30"
    If the value is a literal IP it is returned unchanged.
    If a token is used but the corresponding config value is None,
    a warning is printed and the token string is kept (rule will never match).
    """
    if value.startswith("$"):
        resolved = _IP_TOKENS.get(value)
        if resolved is None:
            print(
                f"[RuleEngine] WARNING: token '{value}' not defined in config.py "
                f"— rule condition will never match"
            )
            return value   # keep as-is; _matches will never equal a real IP
        return resolved
    return value


class Rule:
    """Represents one parsed rule from a .rule file."""
    def __init__(self):
        self.name        = ""
        self.description = ""

        # ── Conditions ────────────────────────────────────────
        self.protocol             = None
        self.flags                = None    # None = not checked
                                            # "NONE" = must have zero/empty flags
                                            # any other string = EXACT match on tcp_flags
        self.dst_port             = None
        self.src_port             = None
        self.src_ip_not           = []     # list of excluded src IPs (resolved)
        self.dst_ip               = None    # match this resolved dst IP
        self.dst_ip_not           = None    # exclude this resolved dst IP
        self.threshold_count      = None
        self.threshold_window     = None
        self.window               = None    # standalone window for UNIQUE_* only
        self.dns_query_len_op     = None
        self.dns_query_len_val    = None
        self.payload_entropy_op   = None
        self.payload_entropy_val  = None
        self.arp_op               = None
        self.wrong_fragment       = None    # True = require wrong_fragment == 1

        self.flow_iat_std_op       = None
        self.flow_iat_std_val      = None
        self.payload_size_op       = None
        self.payload_size_val      = None
        self.total_bwd_bytes_op    = None
        self.total_bwd_bytes_val   = None
        self.flow_duration_op      = None
        self.flow_duration_val     = None
        self.total_fwd_packets_op  = None
        self.total_fwd_packets_val = None
        self.unique_dst_ports_op   = None
        self.unique_dst_ports_val  = None
        self.unique_src_ips_op     = None
        self.unique_src_ips_val    = None

        # ── New conditions ────────────────────────────────────
        self.total_fwd_bytes_op    = None
        self.total_fwd_bytes_val   = None
        self.avg_packet_size_op    = None
        self.avg_packet_size_val   = None
        self.syn_flag_count_op     = None
        self.syn_flag_count_val    = None
        self.ack_flag_count_op     = None
        self.ack_flag_count_val    = None
        self.ttl_op                = None
        self.ttl_val               = None
        self.land                  = None   # True = require land == 1
        self.arp_mac_mismatch      = None   # True = require arp_src_mac != src_mac
        self.http_user_agent_null  = None   # True = require http_user_agent is None
        self.init_win_fwd_op       = None
        self.init_win_fwd_val      = None
        self.count_op              = None
        self.count_val             = None
        self.srv_count_op          = None
        self.srv_count_val         = None
        self.serror_rate_op        = None
        self.serror_rate_val       = None

        # ── Action ────────────────────────────────────────────
        self.severity = "MEDIUM"
        self.action   = "alert"


class RuleEngine:
    def __init__(self, rules_dir: str = "rules/", alert_callback=None):
        self.rules          = []
        self.alert_callback = alert_callback

        # Flow count per rule per src_ip — for THRESHOLD
        self.counters = defaultdict(lambda: defaultdict(list))

        # Unique dst ports seen per rule per src_ip within window
        self.dst_port_sets = defaultdict(lambda: defaultdict(list))

        # Unique src IPs seen per rule per dst_ip within window
        self.src_ip_sets = defaultdict(lambda: defaultdict(list))

        self.load_rules(rules_dir)

    # ── Rule loading ──────────────────────────────────────────
    def load_rules(self, rules_dir: str):
        if not os.path.exists(rules_dir):
            print(f"[RuleEngine] Rules directory not found: {rules_dir}")
            return

        count = 0
        for fname in sorted(os.listdir(rules_dir)):
            if fname.endswith(".rule"):
                path   = os.path.join(rules_dir, fname)
                loaded = self._parse_rule_file(path)
                self.rules.extend(loaded)
                count += len(loaded)

        print(f"[RuleEngine] Loaded {count} rules from {rules_dir}")

    def _parse_rule_file(self, path: str) -> list:
        rules = []
        try:
            with open(path) as f:
                content = f.read()
        except Exception as e:
            print(f"[RuleEngine] Could not read {path}: {e}")
            return rules

        blocks = content.split("RULE ")
        for block in blocks[1:]:
            rule  = Rule()
            lines = block.strip().splitlines()
            if not lines:
                continue

            rule.name = lines[0].strip()

            for line in lines[1:]:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts   = line.split()
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

                elif keyword == "SRC_IP_NOT":
                    # Append — multiple SRC_IP_NOT lines are all respected
                    rule.src_ip_not.append(_resolve_ip(parts[1]))

                elif keyword == "DST_IP":
                    rule.dst_ip = _resolve_ip(parts[1])

                elif keyword == "DST_IP_NOT":
                    rule.dst_ip_not = _resolve_ip(parts[1])

                elif keyword == "THRESHOLD":
                    # THRESHOLD 20 flows FROM same_src IN 3 seconds
                    try:
                        rule.threshold_count  = int(parts[1])
                        rule.threshold_window = int(parts[6])
                    except (IndexError, ValueError):
                        pass

                elif keyword == "WINDOW":
                    # WINDOW 60 seconds  — for UNIQUE_* rules without a THRESHOLD
                    try:
                        rule.window = int(parts[1])
                    except (IndexError, ValueError):
                        pass

                elif keyword == "DNS_QUERY_LEN":
                    rule.dns_query_len_op  = parts[1]
                    rule.dns_query_len_val = int(parts[2])

                elif keyword == "PAYLOAD_ENTROPY":
                    rule.payload_entropy_op  = parts[1]
                    rule.payload_entropy_val = float(parts[2])

                elif keyword == "ARP_OP":
                    rule.arp_op = parts[1].lower()

                elif keyword == "WRONG_FRAGMENT":
                    rule.wrong_fragment = True

                elif keyword == "UNIQUE_DST_PORTS":
                    rule.unique_dst_ports_op  = parts[1]
                    rule.unique_dst_ports_val = int(parts[2])

                elif keyword == "UNIQUE_SRC_IPS":
                    rule.unique_src_ips_op  = parts[1]
                    rule.unique_src_ips_val = int(parts[2])

                elif keyword == "FLOW_IAT_STD":
                    rule.flow_iat_std_op  = parts[1]
                    rule.flow_iat_std_val = float(parts[2])

                elif keyword == "PAYLOAD_SIZE":
                    rule.payload_size_op  = parts[1]
                    rule.payload_size_val = int(parts[2])

                elif keyword == "TOTAL_BWD_BYTES":
                    rule.total_bwd_bytes_op  = parts[1]
                    rule.total_bwd_bytes_val = int(parts[2])

                elif keyword == "FLOW_DURATION":
                    rule.flow_duration_op  = parts[1]
                    rule.flow_duration_val = float(parts[2])

                elif keyword == "TOTAL_FWD_PACKETS":
                    rule.total_fwd_packets_op  = parts[1]
                    rule.total_fwd_packets_val = int(parts[2])

                elif keyword == "TOTAL_FWD_BYTES":
                    rule.total_fwd_bytes_op  = parts[1]
                    rule.total_fwd_bytes_val = int(parts[2])

                elif keyword == "AVG_PACKET_SIZE":
                    rule.avg_packet_size_op  = parts[1]
                    rule.avg_packet_size_val = float(parts[2])

                elif keyword == "SYN_FLAG_COUNT":
                    rule.syn_flag_count_op  = parts[1]
                    rule.syn_flag_count_val = int(parts[2])

                elif keyword == "ACK_FLAG_COUNT":
                    rule.ack_flag_count_op  = parts[1]
                    rule.ack_flag_count_val = int(parts[2])

                elif keyword == "TTL":
                    rule.ttl_op  = parts[1]
                    rule.ttl_val = int(parts[2])

                elif keyword == "LAND":
                    rule.land = True

                elif keyword == "ARP_MAC_MISMATCH":
                    rule.arp_mac_mismatch = True

                elif keyword == "HTTP_USER_AGENT":
                    # Only supported value is "null" — checks field is None
                    if parts[1].lower() == "null":
                        rule.http_user_agent_null = True

                elif keyword == "INIT_WIN_FWD":
                    rule.init_win_fwd_op  = parts[1]
                    rule.init_win_fwd_val = int(parts[2])

                elif keyword == "COUNT":
                    rule.count_op  = parts[1]
                    rule.count_val = int(parts[2])

                elif keyword == "SRV_COUNT":
                    rule.srv_count_op  = parts[1]
                    rule.srv_count_val = int(parts[2])

                elif keyword == "SERROR_RATE":
                    rule.serror_rate_op  = parts[1]
                    rule.serror_rate_val = float(parts[2])

                elif keyword == "ACTION":
                    rule.action   = parts[1].lower()
                    rule.severity = parts[2].upper() if len(parts) > 2 else "MEDIUM"

            rules.append(rule)

        return rules

    # ── Flow evaluation ───────────────────────────────────────
    def evaluate(self, flow: dict):
        for rule in self.rules:
            if self._matches(flow, rule):
                if self._threshold_check(flow, rule):
                    self._fire_alert(flow, rule)

    def _cmp(self, op: str, actual, threshold) -> bool:
        """Apply > or < comparison. Returns False if actual is None."""
        if actual is None:
            return False
        if op == ">":
            return actual > threshold
        if op == "<":
            return actual < threshold
        return False

    def _matches(self, flow: dict, rule: Rule) -> bool:
        """Check all conditions. Returns False on first failure (AND logic)."""

        if rule.protocol and flow.get("protocol") != rule.protocol:
            return False

        # FLAGS matching — EXACT string comparison against Scapy's tcp_flags string.
        #
        # CHANGE: was `rule.flags not in flow_flags` (substring match).
        # Substring match caused widespread false positives:
        #   "S" matched "SA" → scan rules fired on victim SYN-ACK responses
        #   "A" matched "SA","RA","PA" → ack_flood fired on all ACK-bearing packets
        #   "R" matched "RA" → rst_flood fired on normal RST+ACK teardowns
        #   "F" matched "FA","FPU" → fin_scan conflated with XMAS scan
        # Exact match (`==`) fires only when the flag combination is precisely as
        # specified in the rule, which is always the intent.
        if rule.flags is not None:
            flow_flags = str(flow.get("tcp_flags") or "")
            if rule.flags.upper() == "NONE":
                # NULL scan: must have no flags at all
                if flow_flags and flow_flags != "0":
                    return False
            else:
                # EXACT match — "S" only matches "S", not "SA" or "SYN"
                if flow_flags != rule.flags:
                    return False

        # CHANGE: was `if rule.dst_port and ...` — falsy check silently skipped
        # port 0 (valid crafted-packet value). Use `is not None` instead.
        if rule.dst_port is not None and flow.get("dst_port") != rule.dst_port:
            return False

        # CHANGE: same fix for src_port.
        if rule.src_port is not None and flow.get("src_port") != rule.src_port:
            return False

        # IP filters — all resolved from config tokens at load time, no literals here
        if rule.src_ip_not and flow.get("src_ip") in rule.src_ip_not:
            return False

        if rule.dst_ip and flow.get("dst_ip") != rule.dst_ip:
            return False

        if rule.dst_ip_not and flow.get("dst_ip") == rule.dst_ip_not:
            return False

        if rule.dns_query_len_op:
            if not self._cmp(rule.dns_query_len_op,
                             flow.get("dns_query_length"),
                             rule.dns_query_len_val):
                return False

        if rule.payload_entropy_op:
            if not self._cmp(rule.payload_entropy_op,
                             flow.get("payload_entropy"),
                             rule.payload_entropy_val):
                return False

        if rule.arp_op and flow.get("arp_op") != rule.arp_op:
            return False

        if rule.wrong_fragment and not flow.get("wrong_fragment"):
            return False

        if rule.flow_iat_std_op:
            if not self._cmp(rule.flow_iat_std_op,
                             flow.get("flow_iat_std"),
                             rule.flow_iat_std_val):
                return False

        if rule.payload_size_op:
            if not self._cmp(rule.payload_size_op,
                             flow.get("payload_size"),
                             rule.payload_size_val):
                return False

        if rule.total_bwd_bytes_op:
            if not self._cmp(rule.total_bwd_bytes_op,
                             flow.get("total_bwd_bytes"),
                             rule.total_bwd_bytes_val):
                return False

        if rule.flow_duration_op:
            if not self._cmp(rule.flow_duration_op,
                             flow.get("flow_duration"),
                             rule.flow_duration_val):
                return False

        if rule.total_fwd_packets_op:
            if not self._cmp(rule.total_fwd_packets_op,
                             flow.get("total_fwd_packets"),
                             rule.total_fwd_packets_val):
                return False

        # ── New conditions ────────────────────────────────────

        if rule.total_fwd_bytes_op:
            if not self._cmp(rule.total_fwd_bytes_op,
                             flow.get("total_fwd_bytes"),
                             rule.total_fwd_bytes_val):
                return False

        if rule.avg_packet_size_op:
            if not self._cmp(rule.avg_packet_size_op,
                             flow.get("avg_packet_size"),
                             rule.avg_packet_size_val):
                return False

        if rule.syn_flag_count_op:
            if not self._cmp(rule.syn_flag_count_op,
                             flow.get("syn_flag_count"),
                             rule.syn_flag_count_val):
                return False

        if rule.ack_flag_count_op:
            if not self._cmp(rule.ack_flag_count_op,
                             flow.get("ack_flag_count"),
                             rule.ack_flag_count_val):
                return False

        if rule.ttl_op:
            if not self._cmp(rule.ttl_op,
                             flow.get("ttl"),
                             rule.ttl_val):
                return False

        if rule.land and not flow.get("land"):
            return False

        if rule.arp_mac_mismatch:
            arp_mac = flow.get("arp_src_mac")
            eth_mac = flow.get("src_mac")
            # Only check if both fields are present — non-ARP flows have no arp_src_mac
            if arp_mac is None or eth_mac is None:
                return False
            if arp_mac == eth_mac:
                return False

        if rule.http_user_agent_null:
            # Fires only when HTTP method is present but User-Agent is absent
            if flow.get("http_method") is None:
                return False
            if flow.get("http_user_agent") is not None:
                return False

        if rule.init_win_fwd_op:
            val = flow.get("init_win_bytes_fwd")
            if val is None:
                return False
            op  = rule.init_win_fwd_op
            thr = rule.init_win_fwd_val
            if op == ">":
                if not (val > thr): return False
            elif op == "<":
                if not (val < thr): return False
            elif op == "=":
                if not (val == thr): return False

        if rule.count_op:
            if not self._cmp(rule.count_op,
                             flow.get("count"),
                             rule.count_val):
                return False

        if rule.srv_count_op:
            if not self._cmp(rule.srv_count_op,
                             flow.get("srv_count"),
                             rule.srv_count_val):
                return False

        if rule.serror_rate_op:
            if not self._cmp(rule.serror_rate_op,
                             flow.get("serror_rate"),
                             rule.serror_rate_val):
                return False

        return True

    def _threshold_check(self, flow: dict, rule: Rule) -> bool:
        """
        Three jobs:
        1. Standard flow count threshold (THRESHOLD keyword).
        2. UNIQUE_DST_PORTS — count distinct dst ports from this src in window.
        3. UNIQUE_SRC_IPS  — count distinct src IPs to this dst in window.

        Window resolution priority:
          threshold_window (from THRESHOLD keyword)
          > rule.window    (from standalone WINDOW keyword)
          > 60s default
        """
        now    = time.time()
        src_ip = flow.get("src_ip", "unknown")
        dst_ip = flow.get("dst_ip", "unknown")
        window = rule.threshold_window or rule.window or 60

        # ── 1. Standard flow-count threshold ──────────────────
        if rule.threshold_count is not None:
            self.counters[rule.name][src_ip].append(now)
            self.counters[rule.name][src_ip] = [
                t for t in self.counters[rule.name][src_ip]
                if now - t <= window
            ]
            if len(self.counters[rule.name][src_ip]) < rule.threshold_count:
                return False

        # ── 2. Unique destination ports from this src ──────────
        if rule.unique_dst_ports_op is not None:
            dst_port = flow.get("dst_port")
            if dst_port is not None:
                self.dst_port_sets[rule.name][src_ip].append((now, dst_port))

            self.dst_port_sets[rule.name][src_ip] = [
                (t, p) for t, p in self.dst_port_sets[rule.name][src_ip]
                if now - t <= window
            ]

            unique_count = len({
                p for _, p in self.dst_port_sets[rule.name][src_ip]
            })

            if not self._cmp(rule.unique_dst_ports_op,
                             unique_count,
                             rule.unique_dst_ports_val):
                return False

        # ── 3. Unique source IPs to this dst ──────────────────
        if rule.unique_src_ips_op is not None:
            self.src_ip_sets[rule.name][dst_ip].append((now, src_ip))

            self.src_ip_sets[rule.name][dst_ip] = [
                (t, ip) for t, ip in self.src_ip_sets[rule.name][dst_ip]
                if now - t <= window
            ]

            unique_count = len({
                ip for _, ip in self.src_ip_sets[rule.name][dst_ip]
            })

            if not self._cmp(rule.unique_src_ips_op,
                             unique_count,
                             rule.unique_src_ips_val):
                return False

        # No threshold or unique-count condition → always fire
        if (rule.threshold_count is None and
                rule.unique_dst_ports_op is None and
                rule.unique_src_ips_op is None):
            return True

        return True

    def _fire_alert(self, flow: dict, rule: Rule):
        alert = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "flow_id":   flow.get("flow_id"),
            "rule_name": rule.name,
            "severity":  rule.severity,
            "src_ip":    flow.get("src_ip"),
            "dst_ip":    flow.get("dst_ip"),
            "src_port":  flow.get("src_port"),
            "dst_port":  flow.get("dst_port"),
            "protocol":  flow.get("protocol"),
            "detail":    rule.description,
        }

        # Stamp verdict — keep highest severity if multiple rules fire
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        current_rank  = severity_rank.get(
            flow.get("rule_verdict", "BENIGN").split(":")[0], 0
        )
        if severity_rank.get(rule.severity, 0) > current_rank:
            flow["rule_verdict"] = f"{rule.severity}:{rule.name}"

        colors = {
            "CRITICAL": "\033[91m",
            "HIGH":     "\033[93m",
            "MEDIUM":   "\033[94m",
            "LOW":      "\033[92m",
        }
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        print(
            f"{colors.get(rule.severity, '')}[ALERT] [{ts}] {rule.severity} | "
            f"{rule.name} | "
            f"{flow.get('src_ip')} → {flow.get('dst_ip')} "
            f"port {flow.get('dst_port')}\033[0m"
        )

        if self.alert_callback:
            self.alert_callback(alert)
