# core/capture.py
# Main sniffer — ties parser, logger, and rule engine together
# Run with: sudo python3 main.py
# ─────────────────────────────────────────────────────────────

import threading
import queue
import signal
import sys
from scapy.all import sniff

from core.parser      import parse_packet
from core.logger      import Logger
from core.rule_engine import RuleEngine
from config           import INTERFACE, LOG_EVERY_PACKET


class Capture:
    def __init__(self):
        self.logger       = Logger()
        self.rule_engine  = RuleEngine(
            rules_dir="rules/",
            alert_callback=self.logger.write_alert
        )
        self.packet_queue = queue.Queue(maxsize=10000)
        self.running      = True
        self.stats        = {
            "total":    0,
            "parsed":   0,
            "alerts":   0,
            "dropped":  0,
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
        print(f"  Log every : {'all packets' if LOG_EVERY_PACKET else 'alerts only'}")
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

    def set_label(self, label: str):
        """Change the label applied to all captured packets."""
        self.logger.set_label(label)

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
        Worker thread: takes packets from queue,
        parses them, logs them, runs rule engine.
        Separate thread so Scapy capture never blocks.
        """
        while self.running:
            try:
                raw_pkt = self.packet_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                record = parse_packet(raw_pkt, self.logger.current_label)

                if record is None:
                    continue

                self.stats["parsed"] += 1

                # Save to storage
                if LOG_EVERY_PACKET:
                    self.logger.write_packet(record)

                # Run rule engine
                self.rule_engine.evaluate(record)

            except Exception as e:
                print(f"[Capture] Processing error: {e}")

    def _stats_loop(self):
        """Print a stats line every 30 seconds."""
        import time
        while self.running:
            time.sleep(30)
            print(
                f"[Stats] Captured: {self.stats['total']} | "
                f"Parsed: {self.stats['parsed']} | "
                f"Dropped: {self.stats['dropped']}"
            )

    def _shutdown(self, sig, frame):
        print("\n\n[Capture] Shutting down...")
        self.running = False
        self.logger.close()
        print(f"[Capture] Final stats: {self.stats}")
        sys.exit(0)
