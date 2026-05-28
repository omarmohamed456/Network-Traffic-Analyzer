# core/capture.py
# Main sniffer — ties parser, logger, flow_tracker, and rule engine together
# Run with: sudo python3 main.py
# ─────────────────────────────────────────────────────────────

import threading
import queue
import signal
import sys
from scapy.all import sniff

from core.parser              import parse_packet
from core.logger              import Logger
from core.flow_tracker        import FlowTracker
from core.connection_tracker  import ConnectionTracker
from core.rule_engine         import RuleEngine
from config                   import INTERFACE, LOG_EVERY_PACKET


class Capture:
    def __init__(self):
        self.logger      = Logger()

        # Rule engine — alert_callback increments self.stats["alerts"]
        self.rule_engine = RuleEngine(
            rules_dir="rules/",
            alert_callback=self._on_alert
        )

        # ConnectionTracker sits between FlowTracker and _on_flow_complete.
        # FlowTracker emits completed flows → ConnectionTracker stamps
        # count/srv_count/serror_rate → _on_flow_complete runs rules + logging.
        self.conn_tracker = ConnectionTracker(
            downstream=self._on_flow_complete,
        )

        # FlowTracker aggregates packets into flows.
        # It calls conn_tracker.stamp() — NOT _on_flow_complete directly.
        self.flow_tracker = FlowTracker(
            emit_callback=self.conn_tracker.stamp,
        )

        self.packet_queue = queue.Queue(maxsize=10000)
        self.running      = True
        self.stats        = {
            "total":   0,
            "parsed":  0,
            "flows":   0,
            "alerts":  0,
            "dropped": 0,
        }

        # Handle Ctrl+C cleanly
        signal.signal(signal.SIGINT, self._shutdown)

    # ── Public interface ──────────────────────────────────────
    def start(self):
        """Start capture. Blocks until Ctrl+C."""
        print(f"\n{'─'*55}")
        print(f"  IDS — Network Intrusion Detection System")
        print(f"{'─'*55}")
        print(f"  Interface : {INTERFACE}")
        print(f"  Rules     : {len(self.rule_engine.rules)} loaded")
        print(f"  Log mode  : {'all flows' if LOG_EVERY_PACKET else 'alerts only'}")
        print(f"{'─'*55}\n")
        print("  Press Ctrl+C to stop\n")

        # Start packet processing thread
        processor = threading.Thread(
            target=self._process_loop,
            daemon=True
        )
        processor.start()

        # Start stats thread
        stats_thread = threading.Thread(
            target=self._stats_loop,
            daemon=True
        )
        stats_thread.start()

        # Start sniffing — this blocks
        sniff(
            iface=INTERFACE,
            prn=self._enqueue,
            store=False,
            stop_filter=lambda _: not self.running
        )


    # ── Callbacks ─────────────────────────────────────────────
    def _on_flow_complete(self, flow_record: dict):
        """
        Called by FlowTracker when a flow is complete.
        1. Runs rule engine (may fire alerts and mutate rule_verdict).
        2. Writes the flow — including its final rule_verdict — to storage.
        Order matters: evaluate first so verdict is set before logging.
        """
        self.stats["flows"] += 1
        self.rule_engine.evaluate(flow_record)

        # Always write flows that triggered a rule so alerts have context.
        # When LOG_EVERY_PACKET=False, suppress only benign flows.
        if LOG_EVERY_PACKET or flow_record.get("rule_verdict") != "BENIGN":
            self.logger.write_flow(flow_record)

    def _on_alert(self, alert: dict):
        """
        Called by RuleEngine when a rule fires.
        Stamps the verdict onto the flow record in-place (flow_record is
        still alive in _on_flow_complete's stack frame at this point),
        increments the alert counter, and persists the alert.
        The alert carries the flow_id so the two records can be joined.
        """
        self.stats["alerts"] += 1
        # alert dict already has flow_id injected by rule_engine.evaluate()
        self.logger.write_alert(alert)

    # ── Internal methods ──────────────────────────────────────
    def _enqueue(self, pkt):
        """Called by Scapy for every captured packet. Never blocks."""
        try:
            self.packet_queue.put_nowait(pkt)
            self.stats["total"] += 1
        except queue.Full:
            self.stats["dropped"] += 1

    def _process_loop(self):
        """
        Worker thread: takes raw packets from queue, parses them,
        feeds them into FlowTracker (which aggregates and emits flows).
        Never calls logger directly — that is FlowTracker's job.
        """
        while self.running:
            try:
                raw_pkt = self.packet_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                record = parse_packet(raw_pkt)

                if record is None:
                    continue

                self.stats["parsed"] += 1

                # Hand off to FlowTracker — do NOT write to logger here
                self.flow_tracker.add(record)

            except Exception as e:
                print(f"[Capture] Processing error: {e}")

    def _stats_loop(self):
        """Print a stats line every 30 seconds."""
        import time
        while self.running:
            time.sleep(30)
            ft = self.flow_tracker.stats()
            print(
                f"[Stats] Captured: {self.stats['total']} | "
                f"Parsed: {self.stats['parsed']} | "
                f"Flows emitted: {ft['emitted_flows']} | "
                f"Active flows: {ft['active_flows']} | "
                f"Alerts: {self.stats['alerts']} | "
                f"Dropped: {self.stats['dropped']}"
            )

    def _shutdown(self, sig, frame):
        print("\n\n[Capture] Shutting down...")
        self.running = False

        # Flush all open flows before closing
        self.flow_tracker.flush()
        self.flow_tracker.stop()

        self.logger.close()
        print(f"[Capture] Final stats: {self.stats}")
        sys.exit(0)
