# core/logger.py
# Writes every completed flow record to three formats simultaneously:
#   JSON   → Splunk / SIEM ingestion (newline-delimited)
#   CSV    → ML training dataset
#   SQLite → dashboard queries
# ─────────────────────────────────────────────────────────────

import json
import csv
import sqlite3
import os
import threading
from datetime import datetime, timezone
from config import DB_PATH, JSON_LOG_PATH, CSV_LOG_PATH


# ── CSV column order ──────────────────────────────────────────
# Must exactly match the keys emitted by flow_tracker.to_record()
CSV_FIELDS = [
    # ── Meta ──────────────────────────────────────────────────
    "flow_id", "timestamp", "label", "rule_verdict",

    # ── Layer 2 ───────────────────────────────────────────────
    "src_mac", "dst_mac",

    # ── Layer 3 ───────────────────────────────────────────────
    "src_ip", "dst_ip", "ttl", "ip_flags",
    "packet_length", "protocol",

    # ── KDD per-packet features ───────────────────────────────
    "land", "wrong_fragment", "urgent",

    # ── KDD sliding-window (stamped by ConnectionTracker) ─────
    "count", "srv_count", "serror_rate",

    # ── Layer 4 — TCP first-packet raw values ─────────────────
    "src_port", "dst_port",
    "tcp_flags", "seq_number", "ack_number",
    "window_size", "tcp_checksum",

    # ── CIC-IDS — binary TCP flag (seen anywhere in flow) ─────
    "fin_flag", "syn_flag", "rst_flag", "psh_flag",
    "ack_flag", "urg_flag", "cwe_flag", "ece_flag",

    # ── CIC-IDS — TCP flag totals across flow ─────────────────
    "fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count",
    "ack_flag_count", "urg_flag_count", "cwe_flag_count", "ece_flag_count",

    # ── CIC-IDS — direction-aware flags ───────────────────────
    "fwd_psh_flag", "fwd_urg_flag",
    "bwd_psh_flag", "bwd_urg_flag",

    # ── CIC-IDS — header / window / segment ───────────────────
    "fwd_header_length", "bwd_header_length",
    "init_win_bytes_fwd", "init_win_bytes_bwd",
    "min_seg_size_fwd",

    # ── Flow duration & volume ─────────────────────────────────
    "flow_duration",
    "total_fwd_packets", "total_bwd_packets",
    "total_fwd_bytes",   "total_bwd_bytes",
    "flow_bytes_per_sec", "flow_packets_per_sec",

    # ── Packet length stats ───────────────────────────────────
    "fwd_packet_length_mean", "fwd_packet_length_std",
    "fwd_packet_length_max",  "fwd_packet_length_min",
    "fwd_packet_length_total",
    "bwd_packet_length_mean", "bwd_packet_length_std",
    "bwd_packet_length_max",  "bwd_packet_length_min",
    "bwd_packet_length_total",
    "avg_packet_size", "packet_length_variance",

    # ── IAT stats ─────────────────────────────────────────────
    "flow_iat_mean", "flow_iat_std", "flow_iat_max",
    "flow_iat_min",  "flow_iat_total",
    "fwd_iat_mean",  "fwd_iat_std",  "fwd_iat_max",
    "fwd_iat_min",   "fwd_iat_total",
    "bwd_iat_mean",  "bwd_iat_std",  "bwd_iat_max",
    "bwd_iat_min",   "bwd_iat_total",

    # ── Window size stats ─────────────────────────────────────
    "fwd_win_size_mean", "fwd_win_size_std",
    "fwd_win_size_max",  "fwd_win_size_min", "fwd_win_size_total",
    "bwd_win_size_mean", "bwd_win_size_std",
    "bwd_win_size_max",  "bwd_win_size_min", "bwd_win_size_total",

    # ── Bulk stats ────────────────────────────────────────────
    "fwd_avg_bytes_bulk", "bwd_avg_bytes_bulk",

    # ── Active / idle stats ───────────────────────────────────
    "active_mean", "active_std", "active_max", "active_min", "active_total",
    "idle_mean",   "idle_std",   "idle_max",   "idle_min",   "idle_total",

    # ── Layer 7 — payload ─────────────────────────────────────
    "payload_size", "payload_entropy",

    # ── Layer 7 — DNS ─────────────────────────────────────────
    "dns_query", "dns_query_length", "dns_response", "dns_rcode",

    # ── Layer 7 — HTTP ────────────────────────────────────────
    "http_method", "http_host", "http_path", "http_user_agent",

    # ── ARP ───────────────────────────────────────────────────
    "arp_op", "arp_src_ip", "arp_dst_ip", "arp_src_mac",
]


class Logger:
    def __init__(self):
        self.current_label = "normal"
        self._lock         = threading.Lock()

        # Ensure storage directory exists
        os.makedirs("storage", exist_ok=True)

        # Set up SQLite
        self.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        self._init_db()

        # Set up CSV — write header only for new files
        csv_is_new = not os.path.exists(CSV_LOG_PATH)
        self._csv_file   = open(CSV_LOG_PATH, "a", newline="")
        self._csv_writer = csv.DictWriter(
            self._csv_file,
            fieldnames=CSV_FIELDS,
            extrasaction="ignore"   # silently drop keys not in CSV_FIELDS
        )
        if csv_is_new:
            self._csv_writer.writeheader()

        # JSON file — newline-delimited JSON (one object per line)
        self._json_file = open(JSON_LOG_PATH, "a")

        print(f"[Logger] Writing to:")
        print(f"         JSON   → {JSON_LOG_PATH}")
        print(f"         CSV    → {CSV_LOG_PATH}")
        print(f"         SQLite → {DB_PATH}")

    # ── Label management ──────────────────────────────────────
    def set_label(self, label: str):
        """
        Call before each attack phase in training sessions.
        e.g.  logger.set_label("port_scan")
        Only affects packets captured AFTER this call;
        flows already open keep the label they were opened with.
        """
        self.current_label = label
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        print(f"[Logger] [{ts}] Label → {label.upper()}")

    # ── Main write method ─────────────────────────────────────
    def write_flow(self, record: dict):
        """
        Write one completed flow record to all three stores.

        The label is taken from the record itself (set at packet-capture
        time by FlowTracker) rather than overwriting with current_label.
        This ensures flows that started before a label change keep their
        original label — critical for training data integrity.

        If the record has no label (shouldn't happen), falls back to
        current_label as a safety net.
        """
        if not record.get("label"):
            record["label"] = self.current_label

        with self._lock:
            self._write_json(record)
            self._write_csv(record)
            self._write_sqlite_flow(record)

    # Keep old name as alias so any external callers don't break
    def write_packet(self, record: dict):
        self.write_flow(record)

    def write_alert(self, alert: dict):
        """Write a rule engine alert to the SQLite alerts table."""
        with self._lock:
            self._write_sqlite_alert(alert)

    # ── Internal writers ──────────────────────────────────────
    def _write_json(self, record: dict):
        try:
            self._json_file.write(json.dumps(record) + "\n")
            self._json_file.flush()
        except Exception as e:
            print(f"[Logger] JSON write error: {e}")

    def _write_csv(self, record: dict):
        try:
            self._csv_writer.writerow(record)
            self._csv_file.flush()
        except Exception as e:
            print(f"[Logger] CSV write error: {e}")

    def _write_sqlite_flow(self, record: dict):
        # CHANGE: the original INSERT column list was missing seq_number and
        # ack_number, while the VALUES tuple included them. This caused a
        # 3-way mismatch (117 columns, 115 ? marks, 119 values) and SQLite
        # raised OperationalError: wrong number of bindings on every call.
        # The except block silently swallowed it, leaving the DB permanently
        # empty. Fixed by adding seq_number and ack_number to the INSERT
        # column list (after serror_rate, before window_size) and updating
        # the ? count to match. All three numbers now agree at 119.
        try:
            self.db.execute("""
                INSERT INTO flows (
                    flow_id, timestamp, label, rule_verdict,
                    src_mac, dst_mac,
                    src_ip, dst_ip, src_port, dst_port,
                    protocol, ttl, ip_flags,
                    packet_length,
                    land, wrong_fragment, urgent,
                    count, srv_count, serror_rate,
                    tcp_flags, seq_number, ack_number,
                    window_size, tcp_checksum,
                    fin_flag, syn_flag, rst_flag, psh_flag,
                    ack_flag, urg_flag, cwe_flag, ece_flag,
                    fin_flag_count, syn_flag_count, rst_flag_count, psh_flag_count,
                    ack_flag_count, urg_flag_count, cwe_flag_count, ece_flag_count,
                    fwd_psh_flag, fwd_urg_flag,
                    bwd_psh_flag, bwd_urg_flag,
                    fwd_header_length, bwd_header_length,
                    init_win_bytes_fwd, init_win_bytes_bwd,
                    min_seg_size_fwd,
                    flow_duration,
                    total_fwd_packets, total_bwd_packets,
                    total_fwd_bytes,   total_bwd_bytes,
                    flow_bytes_per_sec, flow_packets_per_sec,
                    fwd_packet_length_mean, fwd_packet_length_std,
                    fwd_packet_length_max,  fwd_packet_length_min,
                    fwd_packet_length_total,
                    bwd_packet_length_mean, bwd_packet_length_std,
                    bwd_packet_length_max,  bwd_packet_length_min,
                    bwd_packet_length_total,
                    avg_packet_size, packet_length_variance,
                    flow_iat_mean, flow_iat_std, flow_iat_max,
                    flow_iat_min,  flow_iat_total,
                    fwd_iat_mean,  fwd_iat_std,  fwd_iat_max,
                    fwd_iat_min,   fwd_iat_total,
                    bwd_iat_mean,  bwd_iat_std,  bwd_iat_max,
                    bwd_iat_min,   bwd_iat_total,
                    fwd_win_size_mean, fwd_win_size_std,
                    fwd_win_size_max,  fwd_win_size_min, fwd_win_size_total,
                    bwd_win_size_mean, bwd_win_size_std,
                    bwd_win_size_max,  bwd_win_size_min, bwd_win_size_total,
                    fwd_avg_bytes_bulk, bwd_avg_bytes_bulk,
                    active_mean, active_std, active_max, active_min, active_total,
                    idle_mean,   idle_std,   idle_max,   idle_min,   idle_total,
                    payload_size, payload_entropy,
                    dns_query, dns_query_length, dns_response, dns_rcode,
                    http_method, http_host, http_path, http_user_agent,
                    arp_op, arp_src_ip, arp_dst_ip, arp_src_mac
                ) VALUES (
                    ?,?,?,?,?,?,?,?,?,?,
                    ?,?,?,?,?,?,?,?,?,?,
                    ?,?,?,?,?,?,?,?,?,?,
                    ?,?,?,?,?,?,?,?,?,?,
                    ?,?,?,?,?,?,?,?,?,?,
                    ?,?,?,?,?,?,?,?,?,?,
                    ?,?,?,?,?,?,?,?,?,?,
                    ?,?,?,?,?,?,?,?,?,?,
                    ?,?,?,?,?,?,?,?,?,?,
                    ?,?,?,?,?,?,?,?,?,?,
                    ?,?,?,?,?,?,?,?,?,?,
                    ?,?,?,?,?,?,?,?,?,?
                )
            """, (
                record.get("flow_id"),
                record.get("timestamp"),
                record.get("label"),
                record.get("rule_verdict", "BENIGN"),
                record.get("src_mac"),
                record.get("dst_mac"),
                record.get("src_ip"),
                record.get("dst_ip"),
                record.get("src_port"),
                record.get("dst_port"),
                record.get("protocol"),
                record.get("ttl"),
                record.get("ip_flags"),
                record.get("packet_length"),
                record.get("land"),
                record.get("wrong_fragment"),
                record.get("urgent"),
                record.get("count",       0),
                record.get("srv_count",   0),
                record.get("serror_rate", 0.0),
                record.get("tcp_flags"),
                record.get("seq_number"),
                record.get("ack_number"),
                record.get("window_size"),
                record.get("tcp_checksum"),
                record.get("fin_flag"),
                record.get("syn_flag"),
                record.get("rst_flag"),
                record.get("psh_flag"),
                record.get("ack_flag"),
                record.get("urg_flag"),
                record.get("cwe_flag"),
                record.get("ece_flag"),
                record.get("fin_flag_count"),
                record.get("syn_flag_count"),
                record.get("rst_flag_count"),
                record.get("psh_flag_count"),
                record.get("ack_flag_count"),
                record.get("urg_flag_count"),
                record.get("cwe_flag_count"),
                record.get("ece_flag_count"),
                record.get("fwd_psh_flag"),
                record.get("fwd_urg_flag"),
                record.get("bwd_psh_flag"),
                record.get("bwd_urg_flag"),
                record.get("fwd_header_length"),
                record.get("bwd_header_length"),
                record.get("init_win_bytes_fwd"),
                record.get("init_win_bytes_bwd"),
                record.get("min_seg_size_fwd"),
                record.get("flow_duration"),
                record.get("total_fwd_packets"),
                record.get("total_bwd_packets"),
                record.get("total_fwd_bytes"),
                record.get("total_bwd_bytes"),
                record.get("flow_bytes_per_sec"),
                record.get("flow_packets_per_sec"),
                record.get("fwd_packet_length_mean"),
                record.get("fwd_packet_length_std"),
                record.get("fwd_packet_length_max"),
                record.get("fwd_packet_length_min"),
                record.get("fwd_packet_length_total"),
                record.get("bwd_packet_length_mean"),
                record.get("bwd_packet_length_std"),
                record.get("bwd_packet_length_max"),
                record.get("bwd_packet_length_min"),
                record.get("bwd_packet_length_total"),
                record.get("avg_packet_size"),
                record.get("packet_length_variance"),
                record.get("flow_iat_mean"),
                record.get("flow_iat_std"),
                record.get("flow_iat_max"),
                record.get("flow_iat_min"),
                record.get("flow_iat_total"),
                record.get("fwd_iat_mean"),
                record.get("fwd_iat_std"),
                record.get("fwd_iat_max"),
                record.get("fwd_iat_min"),
                record.get("fwd_iat_total"),
                record.get("bwd_iat_mean"),
                record.get("bwd_iat_std"),
                record.get("bwd_iat_max"),
                record.get("bwd_iat_min"),
                record.get("bwd_iat_total"),
                record.get("fwd_win_size_mean"),
                record.get("fwd_win_size_std"),
                record.get("fwd_win_size_max"),
                record.get("fwd_win_size_min"),
                record.get("fwd_win_size_total"),
                record.get("bwd_win_size_mean"),
                record.get("bwd_win_size_std"),
                record.get("bwd_win_size_max"),
                record.get("bwd_win_size_min"),
                record.get("bwd_win_size_total"),
                record.get("fwd_avg_bytes_bulk"),
                record.get("bwd_avg_bytes_bulk"),
                record.get("active_mean"),
                record.get("active_std"),
                record.get("active_max"),
                record.get("active_min"),
                record.get("active_total"),
                record.get("idle_mean"),
                record.get("idle_std"),
                record.get("idle_max"),
                record.get("idle_min"),
                record.get("idle_total"),
                record.get("payload_size"),
                record.get("payload_entropy"),
                record.get("dns_query"),
                record.get("dns_query_length"),
                record.get("dns_response"),
                record.get("dns_rcode"),
                record.get("http_method"),
                record.get("http_host"),
                record.get("http_path"),
                record.get("http_user_agent"),
                record.get("arp_op"),
                record.get("arp_src_ip"),
                record.get("arp_dst_ip"),
                record.get("arp_src_mac"),
            ))
            self.db.commit()
        except Exception as e:
            print(f"[Logger] SQLite flow write error: {e}")

    def _write_sqlite_alert(self, alert: dict):
        try:
            self.db.execute("""
                INSERT INTO alerts (
                    flow_id, timestamp, rule_name, severity,
                    src_ip, dst_ip, protocol, detail
                ) VALUES (?,?,?,?,?,?,?,?)
            """, (
                alert.get("flow_id"),
                alert.get("timestamp"),
                alert.get("rule_name"),
                alert.get("severity"),
                alert.get("src_ip"),
                alert.get("dst_ip"),
                alert.get("protocol"),
                json.dumps(alert),
            ))
            self.db.commit()
        except Exception as e:
            print(f"[Logger] SQLite alert write error: {e}")

    # ── Database schema ───────────────────────────────────────
    def _init_db(self):
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id                 TEXT UNIQUE,
                timestamp               TEXT,
                label                   TEXT,
                rule_verdict            TEXT DEFAULT 'BENIGN',
                src_mac                 TEXT,
                dst_mac                 TEXT,
                src_ip                  TEXT,
                dst_ip                  TEXT,
                src_port                INTEGER,
                dst_port                INTEGER,
                protocol                TEXT,
                ttl                     INTEGER,
                ip_flags                TEXT,
                packet_length           INTEGER,
                land                    INTEGER,
                wrong_fragment          INTEGER,
                urgent                  INTEGER,
                count                   INTEGER,
                srv_count               INTEGER,
                serror_rate             REAL,
                tcp_flags               TEXT,
                seq_number              INTEGER,
                ack_number              INTEGER,
                window_size             INTEGER,
                tcp_checksum            INTEGER,
                fin_flag                INTEGER,
                syn_flag                INTEGER,
                rst_flag                INTEGER,
                psh_flag                INTEGER,
                ack_flag                INTEGER,
                urg_flag                INTEGER,
                cwe_flag                INTEGER,
                ece_flag                INTEGER,
                fin_flag_count          INTEGER,
                syn_flag_count          INTEGER,
                rst_flag_count          INTEGER,
                psh_flag_count          INTEGER,
                ack_flag_count          INTEGER,
                urg_flag_count          INTEGER,
                cwe_flag_count          INTEGER,
                ece_flag_count          INTEGER,
                fwd_psh_flag            INTEGER,
                fwd_urg_flag            INTEGER,
                bwd_psh_flag            INTEGER,
                bwd_urg_flag            INTEGER,
                fwd_header_length       INTEGER,
                bwd_header_length       INTEGER,
                init_win_bytes_fwd      INTEGER,
                init_win_bytes_bwd      INTEGER,
                min_seg_size_fwd        INTEGER,
                flow_duration           REAL,
                total_fwd_packets       INTEGER,
                total_bwd_packets       INTEGER,
                total_fwd_bytes         INTEGER,
                total_bwd_bytes         INTEGER,
                flow_bytes_per_sec      REAL,
                flow_packets_per_sec    REAL,
                fwd_packet_length_mean  REAL,
                fwd_packet_length_std   REAL,
                fwd_packet_length_max   REAL,
                fwd_packet_length_min   REAL,
                fwd_packet_length_total REAL,
                bwd_packet_length_mean  REAL,
                bwd_packet_length_std   REAL,
                bwd_packet_length_max   REAL,
                bwd_packet_length_min   REAL,
                bwd_packet_length_total REAL,
                avg_packet_size         REAL,
                packet_length_variance  REAL,
                flow_iat_mean           REAL,
                flow_iat_std            REAL,
                flow_iat_max            REAL,
                flow_iat_min            REAL,
                flow_iat_total          REAL,
                fwd_iat_mean            REAL,
                fwd_iat_std             REAL,
                fwd_iat_max             REAL,
                fwd_iat_min             REAL,
                fwd_iat_total           REAL,
                bwd_iat_mean            REAL,
                bwd_iat_std             REAL,
                bwd_iat_max             REAL,
                bwd_iat_min             REAL,
                bwd_iat_total           REAL,
                fwd_win_size_mean       REAL,
                fwd_win_size_std        REAL,
                fwd_win_size_max        REAL,
                fwd_win_size_min        REAL,
                fwd_win_size_total      REAL,
                bwd_win_size_mean       REAL,
                bwd_win_size_std        REAL,
                bwd_win_size_max        REAL,
                bwd_win_size_min        REAL,
                bwd_win_size_total      REAL,
                fwd_avg_bytes_bulk      REAL,
                bwd_avg_bytes_bulk      REAL,
                active_mean             REAL,
                active_std              REAL,
                active_max              REAL,
                active_min              REAL,
                active_total            REAL,
                idle_mean               REAL,
                idle_std                REAL,
                idle_max                REAL,
                idle_min                REAL,
                idle_total              REAL,
                payload_size            INTEGER,
                payload_entropy         REAL,
                dns_query               TEXT,
                dns_query_length        INTEGER,
                dns_response            TEXT,
                dns_rcode               INTEGER,
                http_method             TEXT,
                http_host               TEXT,
                http_path               TEXT,
                http_user_agent         TEXT,
                arp_op                  TEXT,
                arp_src_ip              TEXT,
                arp_dst_ip              TEXT,
                arp_src_mac             TEXT
            )
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id     TEXT,
                timestamp   TEXT,
                rule_name   TEXT,
                severity    TEXT,
                src_ip      TEXT,
                dst_ip      TEXT,
                protocol    TEXT,
                detail      TEXT
            )
        """)
        self.db.commit()

    def close(self):
        self._csv_file.close()
        self._json_file.close()
        self.db.close()
