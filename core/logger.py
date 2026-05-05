# core/logger.py
# Writes every parsed packet to three formats simultaneously:
#   JSON  → Splunk ingestion
#   CSV   → ML training
#   SQLite → dashboard queries
# ─────────────────────────────────────────────────────────────

import json
import csv
import sqlite3
import os
import threading
from datetime import datetime, timezone
from config import DB_PATH, JSON_LOG_PATH, CSV_LOG_PATH


# All fields in the order they appear in CSV
CSV_FIELDS = [
    "timestamp", "label",
    "src_mac", "dst_mac", "src_mac_oui", "dst_mac_oui", "vlan_tag",
    "src_ip", "dst_ip", "ip_version", "ttl", "ip_flags",
    "fragment_offset", "packet_length", "protocol",
    "src_port", "dst_port",
    "tcp_flags", "seq_number", "ack_number",
    "window_size", "tcp_checksum", "urgent_pointer",
    "udp_length", "udp_checksum",
    "payload_size", "payload_entropy", "payload_printable",
    "dns_query", "dns_query_length", "dns_response", "dns_rcode",
    "http_method", "http_host", "http_path",
    "http_user_agent", "http_status_code", "tls_detected",
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

        # Set up CSV — write header if file is new
        csv_is_new = not os.path.exists(CSV_LOG_PATH)
        self._csv_file   = open(CSV_LOG_PATH, "a", newline="")
        self._csv_writer = csv.DictWriter(
            self._csv_file,
            fieldnames=CSV_FIELDS,
            extrasaction="ignore"
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
        Call this before each attack phase in training sessions.
        e.g. logger.set_label("port_scan")
        """
        self.current_label = label
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        print(f"[Logger] [{ts}] Label → {label.upper()}")

    # ── Main write method ─────────────────────────────────────
    def write_packet(self, record: dict):
        """Write one parsed packet record to all three stores."""
        record["label"] = self.current_label

        with self._lock:
            self._write_json(record)
            self._write_csv(record)
            self._write_sqlite_packet(record)

    def write_alert(self, alert: dict):
        """Write a rule engine alert to SQLite alerts table."""
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

    def _write_sqlite_packet(self, record: dict):
        try:
            self.db.execute("""
                INSERT INTO packets (
                    timestamp, label, src_ip, dst_ip,
                    src_port, dst_port, protocol,
                    tcp_flags, packet_length, payload_entropy,
                    dns_query, http_method, http_path
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                record.get("timestamp"),
                record.get("label"),
                record.get("src_ip"),
                record.get("dst_ip"),
                record.get("src_port"),
                record.get("dst_port"),
                record.get("protocol"),
                record.get("tcp_flags"),
                record.get("packet_length"),
                record.get("payload_entropy"),
                record.get("dns_query"),
                record.get("http_method"),
                record.get("http_path"),
            ))
            self.db.commit()
        except Exception as e:
            print(f"[Logger] SQLite packet write error: {e}")

    def _write_sqlite_alert(self, alert: dict):
        try:
            self.db.execute("""
                INSERT INTO alerts (
                    timestamp, rule_name, severity,
                    src_ip, dst_ip, protocol, detail
                ) VALUES (?,?,?,?,?,?,?)
            """, (
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
            CREATE TABLE IF NOT EXISTS packets (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT,
                label           TEXT,
                src_ip          TEXT,
                dst_ip          TEXT,
                src_port        INTEGER,
                dst_port        INTEGER,
                protocol        TEXT,
                tcp_flags       TEXT,
                packet_length   INTEGER,
                payload_entropy REAL,
                dns_query       TEXT,
                http_method     TEXT,
                http_path       TEXT
            )
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
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
