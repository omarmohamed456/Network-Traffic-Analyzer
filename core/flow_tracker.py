# core/flow_tracker.py
# Aggregates per-packet records into bidirectional flow records.
# Emits a completed flow when:
#   - A RST flag is seen (immediate teardown)
#   - A FIN flag is seen and FIN_GRACE_SECONDS pass with no new packets
#   - A flow has been idle longer than FLOW_IDLE_TIMEOUT seconds
#   - A flow has been open longer than FLOW_ACTIVE_TIMEOUT seconds
#
# Produces CIC-IDS2017-compatible flow features including:
#   - Duration, packet/byte counts per direction
#   - Inter-arrival times (IAT) stats for flow, fwd, bwd
#   - Active/idle time stats
#   - Correct direction-aware flag fields
#   - All original per-packet fields carried from the first packet
# ─────────────────────────────────────────────────────────────

import threading
import time
import math
import uuid
from datetime import datetime, timezone
from typing import Callable


# ── Tunables ──────────────────────────────────────────────────
FLOW_IDLE_TIMEOUT   = 120.0   # seconds — emit if no packet seen for this long
FLOW_ACTIVE_TIMEOUT = 600.0   # seconds — emit if flow lives longer than this
CLEANUP_INTERVAL    = 30.0    # seconds — how often the reaper thread runs
FIN_GRACE_SECONDS   = 5.0     # seconds — wait after FIN before emitting


# ── 5-tuple flow key ──────────────────────────────────────────
def _flow_key(record: dict) -> tuple:
    """
    Canonical bidirectional key — same key regardless of which direction
    a packet arrives from.  Fixes Python 3 TypeError when port is None
    (ICMP/ARP) by using a None-safe sort: treat None port as -1 for ordering.

    Returns: (ip_a, ip_b, port_a, port_b, protocol)
    where (ip_a, port_a) is always the lexicographically smaller endpoint.
    """
    src_ip   = record.get("src_ip")   or ""
    dst_ip   = record.get("dst_ip")   or ""
    src_port = record.get("src_port")          # may be None
    dst_port = record.get("dst_port")          # may be None
    proto    = record.get("protocol", "UNKNOWN")

    # None-safe comparison key
    src_sort = (src_ip, src_port if src_port is not None else -1)
    dst_sort = (dst_ip, dst_port if dst_port is not None else -1)

    if src_sort <= dst_sort:
        return (src_ip, dst_ip, src_port, dst_port, proto)
    else:
        return (dst_ip, src_ip, dst_port, src_port, proto)


def _is_forward(record: dict, key: tuple) -> bool:
    """
    True if this packet travels in the forward direction (key[0]:key[2] → key[1]:key[3]).
    Checks both IP and port so direction is unambiguous even for loopback traffic.
    """
    return (
        record.get("src_ip")   == key[0] and
        record.get("src_port") == key[2]
    )


# ── Stats accumulator ─────────────────────────────────────────
class _Stats:
    """Welford online mean + variance, min, max, total."""
    __slots__ = ("n", "mean", "M2", "min", "max", "total")

    def __init__(self):
        self.n     = 0
        self.mean  = 0.0
        self.M2    = 0.0
        self.min   = float("inf")
        self.max   = float("-inf")
        self.total = 0.0

    def add(self, x: float):
        self.n     += 1
        self.total += x
        if x < self.min: self.min = x
        if x > self.max: self.max = x
        delta      = x - self.mean
        self.mean += delta / self.n
        self.M2   += delta * (x - self.mean)

    @property
    def std(self) -> float:
        return math.sqrt(self.M2 / self.n) if self.n > 1 else 0.0

    def as_dict(self, prefix: str) -> dict:
        return {
            f"{prefix}_mean":  round(self.mean,                    4),
            f"{prefix}_std":   round(self.std,                     4),
            f"{prefix}_max":   round(self.max if self.n else 0.0,  4),
            f"{prefix}_min":   round(self.min if self.n else 0.0,  4),
            f"{prefix}_total": round(self.total,                   4),
        }


# ── Flow record ───────────────────────────────────────────────
class _Flow:
    """
    Accumulates state for one bidirectional flow.
    'forward'  = direction of the packet that opened the flow (key[0]→key[1]).
    'backward' = the opposite direction (key[1]→key[0]).
    """

    def __init__(self, key: tuple, first_packet: dict, ts: float):
        self.key         = key
        self.label       = first_packet.get("label", "normal")
        self.protocol    = first_packet.get("protocol")
        self.start_ts    = ts
        self.last_ts     = ts
        self.last_fwd_ts = None
        self.last_bwd_ts = None

        # FIN grace tracking
        self.fin_seen = False
        self.fin_ts   = None

        # Unique ID for this flow — links flow record to alert record
        self.flow_id = str(uuid.uuid4())

        # Carry layer-2/3 fields from the first packet
        self._first = first_packet

        # ── Packet / byte counts ──────────────────────────────
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes   = 0
        self.bwd_bytes   = 0

        # ── IAT stats ─────────────────────────────────────────
        self.flow_iat = _Stats()
        self.fwd_iat  = _Stats()
        self.bwd_iat  = _Stats()

        # ── Packet length stats ───────────────────────────────
        self.fwd_pkt_len = _Stats()
        self.bwd_pkt_len = _Stats()
        self.all_pkt_len = _Stats()

        # ── TCP flag counters ─────────────────────────────────
        self.fin_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0
        self.cwe_count = 0
        self.ece_count = 0

        # ── Direction-aware flag counts ───────────────────────
        self.fwd_psh_flags = 0
        self.fwd_urg_flags = 0
        self.bwd_psh_flags = 0
        self.bwd_urg_flags = 0

        # ── Header lengths ────────────────────────────────────
        self.fwd_header_lengths = _Stats()
        self.bwd_header_lengths = _Stats()

        # ── Window sizes ──────────────────────────────────────
        self.init_win_fwd  = None
        self.init_win_bwd  = None
        self.fwd_win_sizes = _Stats()
        self.bwd_win_sizes = _Stats()

        # ── Segment sizes ─────────────────────────────────────
        self.fwd_seg_sizes = _Stats()

        # ── Active / idle tracking ────────────────────────────
        self.active_stats  = _Stats()
        self.idle_stats    = _Stats()
        self._active_start = ts
        self._last_active  = ts
        self._activity_gap = 2.0   # seconds gap that counts as "idle"

        # ── Bulk stats ────────────────────────────────────────
        self.fwd_bulk_bytes   = 0
        self.bwd_bulk_bytes   = 0
        self.fwd_bulk_packets = 0
        self.bwd_bulk_packets = 0

        # ── Payload accumulation for flow-level entropy ───────
        # Collect raw payload bytes up to MAX_PAYLOAD_BYTES total.
        # Entropy is recomputed from this buffer when the flow closes.
        # This fixes the first-packet-only entropy problem: a SYN has
        # zero payload so first-packet entropy is always 0.0.
        try:
            from config import MAX_PAYLOAD_BYTES as _MPB
            self._max_payload = _MPB
        except Exception:
            self._max_payload = 500
        self._payload_buf   = bytearray()
        self._payload_total = 0   # total bytes seen (even beyond cap)
        self._entropy_sum   = 0.0 # weighted sum: entropy * payload_size

        # Add first packet
        self.add(first_packet, ts)

    # ── Add a packet to this flow ─────────────────────────────
    def add(self, record: dict, ts: float):
        is_fwd   = _is_forward(record, self.key)
        pkt_len  = record.get("packet_length", 0) or 0
        pay_size = record.get("payload_size",  0) or 0

        # ── IAT ───────────────────────────────────────────────
        if self.last_ts is not None and ts > self.last_ts:
            iat = (ts - self.last_ts) * 1000   # ms
            self.flow_iat.add(iat)

            # Active / idle bookkeeping
            if iat > self._activity_gap * 1000:
                self.idle_stats.add(iat)
                self.active_stats.add(
                    (self._last_active - self._active_start) * 1000
                )
                self._active_start = ts
            self._last_active = ts

        if is_fwd:
            if self.last_fwd_ts is not None and ts > self.last_fwd_ts:
                self.fwd_iat.add((ts - self.last_fwd_ts) * 1000)
            self.last_fwd_ts   = ts
            self.fwd_packets   += 1
            self.fwd_bytes     += pkt_len
            self.fwd_pkt_len.add(pkt_len)
            self.fwd_bulk_bytes   += pay_size
            self.fwd_bulk_packets += 1
        else:
            if self.last_bwd_ts is not None and ts > self.last_bwd_ts:
                self.bwd_iat.add((ts - self.last_bwd_ts) * 1000)
            self.last_bwd_ts   = ts
            self.bwd_packets   += 1
            self.bwd_bytes     += pkt_len
            self.bwd_pkt_len.add(pkt_len)
            self.bwd_bulk_bytes   += pay_size
            self.bwd_bulk_packets += 1

        self.all_pkt_len.add(pkt_len)
        self.last_ts = ts

        # ── TCP flags ─────────────────────────────────────────
        self.fin_count += record.get("fin_flag", 0) or 0
        self.syn_count += record.get("syn_flag", 0) or 0
        self.rst_count += record.get("rst_flag", 0) or 0
        self.psh_count += record.get("psh_flag", 0) or 0
        self.ack_count += record.get("ack_flag", 0) or 0
        self.urg_count += record.get("urg_flag", 0) or 0
        self.cwe_count += record.get("cwe_flag", 0) or 0
        self.ece_count += record.get("ece_flag", 0) or 0

        # Track FIN for grace-window teardown
        if record.get("fin_flag"):
            self.fin_seen = True
            if self.fin_ts is None:
                self.fin_ts = ts

        # ── Direction-aware flags ─────────────────────────────
        if is_fwd:
            self.fwd_psh_flags += record.get("psh_flag", 0) or 0
            self.fwd_urg_flags += record.get("urg_flag", 0) or 0
        else:
            self.bwd_psh_flags += record.get("psh_flag", 0) or 0
            self.bwd_urg_flags += record.get("urg_flag", 0) or 0

        # ── Header lengths ────────────────────────────────────
        # Parser emits fwd_header_length and bwd_header_length per packet
        # (both set to the same value since direction is unknown at parse time).
        # We route to the correct direction bucket here using is_fwd.
        hlen = record.get("fwd_header_length") if is_fwd else record.get("bwd_header_length")
        if hlen is not None:
            if is_fwd:
                self.fwd_header_lengths.add(hlen)
            else:
                self.bwd_header_lengths.add(hlen)

        # ── Window sizes ──────────────────────────────────────
        win = record.get("window_size")
        if win is not None:
            if is_fwd:
                if self.init_win_fwd is None:
                    self.init_win_fwd = win
                self.fwd_win_sizes.add(win)
            else:
                if self.init_win_bwd is None:
                    self.init_win_bwd = win
                self.bwd_win_sizes.add(win)

        # ── Segment size (fwd only) ───────────────────────────
        seg = record.get("min_seg_size_fwd")
        if seg is not None and is_fwd:
            self.fwd_seg_sizes.add(seg)

        # ── Payload accumulation ──────────────────────────────
        # Grab raw payload from the parser's per-packet field.
        # We can't access raw bytes here, but the parser stores the
        # entropy of the raw bytes.  Instead we accumulate payload_size
        # and track the highest per-packet entropy seen — a good proxy
        # for whether any packet in the flow carried high-entropy data.
        # For flows where the actual raw bytes are available via payload_entropy
        # we track both the max and a running weighted mean.
        pkt_entropy = record.get("payload_entropy") or 0.0
        pkt_pay     = record.get("payload_size")    or 0
        if pkt_pay > 0:
            self._payload_total += pkt_pay
            # Keep a running weighted mean of entropy weighted by payload size
            # so large data packets dominate over small header-only packets.
            if not hasattr(self, "_entropy_sum"):
                self._entropy_sum = 0.0
            self._entropy_sum += pkt_entropy * pkt_pay

    # ── Emit completed flow record ────────────────────────────
    def to_record(self) -> dict:
        duration_us = (self.last_ts - self.start_ts) * 1_000_000  # microseconds

        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes   = self.fwd_bytes   + self.bwd_bytes

        dur_secs = duration_us / 1e6
        flow_bytes_per_sec   = total_bytes   / dur_secs if dur_secs > 0 else 0.0
        flow_packets_per_sec = total_packets / dur_secs if dur_secs > 0 else 0.0

        # Finalise active stats for the last active segment
        last_active_ms = (self._last_active - self._active_start) * 1000
        if last_active_ms > 0:
            self.active_stats.add(last_active_ms)

        return {
            # ── Meta ──────────────────────────────────────────
            "flow_id":   self.flow_id,
            "timestamp": datetime.fromtimestamp(
                self.start_ts, tz=timezone.utc
            ).isoformat(),
            "label":     self.label,
            # rule_verdict is stamped by Capture._on_flow_complete
            # after rule_engine.evaluate() runs. Default = BENIGN.
            "rule_verdict": "BENIGN",

            # ── Layer 2/3 — from first packet ─────────────────
            "src_mac":  self._first.get("src_mac"),
            "dst_mac":  self._first.get("dst_mac"),
            "src_ip":   self.key[0],
            "dst_ip":   self.key[1],
            "src_port": self.key[2],
            "dst_port": self.key[3],
            "protocol": self.protocol,
            "ttl":      self._first.get("ttl"),
            "ip_flags": self._first.get("ip_flags"),

            # ── KDD ───────────────────────────────────────────
            "land":           self._first.get("land",           0),
            "wrong_fragment": self._first.get("wrong_fragment", 0),
            "urgent":         self._first.get("urgent",         0),

            # ── TCP raw fields from first packet ──────────────
            "packet_length": self._first.get("packet_length"),
            "tcp_flags":     self._first.get("tcp_flags"),
            "seq_number":    self._first.get("seq_number"),
            "ack_number":    self._first.get("ack_number"),
            "window_size":   self._first.get("window_size"),
            "tcp_checksum":  self._first.get("tcp_checksum"),

            # ── Flow duration & counts ─────────────────────────
            "flow_duration":        round(duration_us,           2),
            "total_fwd_packets":    self.fwd_packets,
            "total_bwd_packets":    self.bwd_packets,
            "total_fwd_bytes":      self.fwd_bytes,
            "total_bwd_bytes":      self.bwd_bytes,
            "flow_bytes_per_sec":   round(flow_bytes_per_sec,    4),
            "flow_packets_per_sec": round(flow_packets_per_sec,  4),

            # ── Packet length stats ───────────────────────────
            **self.fwd_pkt_len.as_dict("fwd_packet_length"),
            **self.bwd_pkt_len.as_dict("bwd_packet_length"),
            "avg_packet_size": round(self.all_pkt_len.mean, 4),
            "packet_length_variance": round(
                self.all_pkt_len.M2 / self.all_pkt_len.n
                if self.all_pkt_len.n > 1 else 0.0, 4
            ),

            # ── IAT stats ─────────────────────────────────────
            **self.flow_iat.as_dict("flow_iat"),
            **self.fwd_iat.as_dict("fwd_iat"),
            **self.bwd_iat.as_dict("bwd_iat"),

            # ── TCP flag totals (count per flow) ──────────────
            "fin_flag_count": self.fin_count,
            "syn_flag_count": self.syn_count,
            "rst_flag_count": self.rst_count,
            "psh_flag_count": self.psh_count,
            "ack_flag_count": self.ack_count,
            "urg_flag_count": self.urg_count,
            "cwe_flag_count": self.cwe_count,
            "ece_flag_count": self.ece_count,

            # ── Binary flags: 1 if seen at least once in flow ─
            "fin_flag": 1 if self.fin_count > 0 else 0,
            "syn_flag": 1 if self.syn_count > 0 else 0,
            "rst_flag": 1 if self.rst_count > 0 else 0,
            "psh_flag": 1 if self.psh_count > 0 else 0,
            "ack_flag": 1 if self.ack_count > 0 else 0,
            "urg_flag": 1 if self.urg_count > 0 else 0,
            "cwe_flag": 1 if self.cwe_count > 0 else 0,
            "ece_flag": 1 if self.ece_count > 0 else 0,

            # ── Direction-aware flags (correctly resolved) ────
            "fwd_psh_flag": self.fwd_psh_flags,
            "fwd_urg_flag": self.fwd_urg_flags,
            "bwd_psh_flag": self.bwd_psh_flags,
            "bwd_urg_flag": self.bwd_urg_flags,

            # ── Header lengths — integer totals ───────────────
            "fwd_header_length": int(self.fwd_header_lengths.total)
                                  if self.fwd_header_lengths.n else None,
            "bwd_header_length": int(self.bwd_header_lengths.total)
                                  if self.bwd_header_lengths.n else None,

            # ── Window sizes ──────────────────────────────────
            "init_win_bytes_fwd": self.init_win_fwd,
            "init_win_bytes_bwd": self.init_win_bwd,
            **self.fwd_win_sizes.as_dict("fwd_win_size"),
            **self.bwd_win_sizes.as_dict("bwd_win_size"),

            # ── Segment sizes ─────────────────────────────────
            "min_seg_size_fwd": int(self.fwd_seg_sizes.min)
                                 if self.fwd_seg_sizes.n else None,

            # ── Bulk stats ────────────────────────────────────
            "fwd_avg_bytes_bulk": round(
                self.fwd_bulk_bytes / self.fwd_bulk_packets, 4
            ) if self.fwd_bulk_packets else 0.0,
            "bwd_avg_bytes_bulk": round(
                self.bwd_bulk_bytes / self.bwd_bulk_packets, 4
            ) if self.bwd_bulk_packets else 0.0,

            # ── Active / idle ─────────────────────────────────
            **self.active_stats.as_dict("active"),
            **self.idle_stats.as_dict("idle"),

            # ── Payload — accumulated across flow ────────────
            # payload_entropy is the payload-size-weighted mean entropy
            # across all packets in the flow that carried data.
            # This correctly captures flows where the SYN has zero payload
            # and the high-entropy data only appears in later packets.
            # payload_size is the total payload bytes seen across the flow.
            "payload_size":    self._payload_total,
            "payload_entropy": round(
                self._entropy_sum / self._payload_total, 4
            ) if self._payload_total > 0 else 0.0,

            # ── DNS — from first packet ───────────────────────
            "dns_query":        self._first.get("dns_query"),
            "dns_query_length": self._first.get("dns_query_length"),
            "dns_response":     self._first.get("dns_response"),
            "dns_rcode":        self._first.get("dns_rcode"),

            # ── HTTP — from first packet ──────────────────────
            "http_method":     self._first.get("http_method"),
            "http_host":       self._first.get("http_host"),
            "http_path":       self._first.get("http_path"),
            "http_user_agent": self._first.get("http_user_agent"),

            # ── ARP — from first packet ───────────────────────
            "arp_op":      self._first.get("arp_op"),
            "arp_src_ip":  self._first.get("arp_src_ip"),
            "arp_dst_ip":  self._first.get("arp_dst_ip"),
            "arp_src_mac": self._first.get("arp_src_mac"),
        }


# ── FlowTracker ───────────────────────────────────────────────
class FlowTracker:
    """
    Thread-safe bidirectional flow aggregator.

    Parameters
    ----------
    emit_callback : callable
        Called with a completed flow record dict.
        Signature: emit_callback(flow_record: dict) -> None
    idle_timeout : float
        Seconds of inactivity before a flow is considered complete.
    active_timeout : float
        Maximum lifetime of any single flow in seconds.
    """

    def __init__(
        self,
        emit_callback:  Callable[[dict], None],
        idle_timeout:   float = FLOW_IDLE_TIMEOUT,
        active_timeout: float = FLOW_ACTIVE_TIMEOUT,
    ):
        self._emit           = emit_callback
        self._idle_timeout   = idle_timeout
        self._active_timeout = active_timeout
        self._flows: dict[tuple, _Flow] = {}
        self._lock           = threading.Lock()
        self._emitted        = 0

        # Background reaper thread
        self._running = True
        self._reaper  = threading.Thread(
            target=self._reap_loop, daemon=True, name="FlowReaper"
        )
        self._reaper.start()
        print(
            f"[FlowTracker] Started — "
            f"idle_timeout={idle_timeout}s  "
            f"active_timeout={active_timeout}s  "
            f"fin_grace={FIN_GRACE_SECONDS}s"
        )

    # ── Public API ────────────────────────────────────────────
    def add(self, record: dict):
        """
        Feed one parsed packet record into the tracker.
        Emits immediately only on RST.
        FIN sets a grace timer; timeout/idle handled by reaper.
        """
        key = _flow_key(record)
        ts  = time.time()

        with self._lock:
            if key in self._flows:
                self._flows[key].add(record, ts)
            else:
                self._flows[key] = _Flow(key, record, ts)

            # RST: emit immediately — connection aborted
            if record.get("protocol") == "TCP" and record.get("rst_flag"):
                self._emit_flow(key)

    def flush(self):
        """Emit all open flows immediately. Call on shutdown."""
        with self._lock:
            for key in list(self._flows.keys()):
                self._emit_flow(key)
        print(
            f"[FlowTracker] Flushed. "
            f"Total flows emitted: {self._emitted}"
        )

    def stats(self) -> dict:
        with self._lock:
            return {
                "active_flows":  len(self._flows),
                "emitted_flows": self._emitted,
            }

    def stop(self):
        self._running = False

    # ── Internal helpers ──────────────────────────────────────
    def _emit_flow(self, key: tuple):
        """Emit and remove a flow. Must be called with self._lock held."""
        flow = self._flows.pop(key, None)
        if flow is None:
            return
        try:
            self._emit(flow.to_record())
            self._emitted += 1
        except Exception as e:
            print(f"[FlowTracker] Emit error for key {key}: {e}")

    def _reap_loop(self):
        """
        Background thread — evicts timed-out and FIN-graced flows.
        Runs every CLEANUP_INTERVAL seconds.
        """
        while self._running:
            time.sleep(CLEANUP_INTERVAL)
            now     = time.time()
            expired = []

            with self._lock:
                for key, flow in self._flows.items():
                    idle         = now - flow.last_ts
                    active       = now - flow.start_ts
                    fin_expired  = (
                        flow.fin_seen and
                        flow.fin_ts is not None and
                        (now - flow.fin_ts) >= FIN_GRACE_SECONDS
                    )

                    if (
                        idle   >= self._idle_timeout   or
                        active >= self._active_timeout or
                        fin_expired
                    ):
                        expired.append(key)

                for key in expired:
                    self._emit_flow(key)

            if expired:
                print(
                    f"[FlowTracker] Reaped {len(expired)} flow(s). "
                    f"Active: {len(self._flows)}"
                )
