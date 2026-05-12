#!/usr/bin/env python3
# main.py — entry point for the IDS
# Run with: sudo python3 main.py
#
# Optional args:
#   --interface eth0        override interface from config.py
#   --label port_scan       start with a specific label
#   --no-log                don't log every packet (alerts only)
# ─────────────────────────────────────────────────────────────

import argparse
import os
import sys


def check_root():
    if os.geteuid() != 0:
        print("[!] Scapy requires root to capture packets.")
        print("    Run with: sudo python3 main.py")
        sys.exit(1)


def check_interface(iface: str):
    import subprocess
    result = subprocess.run(
        ["ip", "link", "show", iface],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"[!] Interface '{iface}' not found.")
        print("    Run 'ip a' to see available interfaces.")
        print("    Edit INTERFACE in config.py")
        sys.exit(1)


def main():
    # ── 1. Root check first — before any file handles or threads open ──
    check_root()

    parser = argparse.ArgumentParser(description="Network IDS")
    parser.add_argument("--interface", help="Network interface to capture on")
    parser.add_argument("--label",     help="Initial label for packets",
                        default="normal")
    parser.add_argument("--no-log",    action="store_true",
                        help="Only log alerts, skip per-flow logging")
    args = parser.parse_args()

    # ── 2. Apply CLI overrides to config module BEFORE any other import ──
    # capture.py / logger.py use  `from config import X`  which binds the
    # name at import time.  We must mutate config BEFORE those modules are
    # imported, otherwise the overrides are silently ignored.
    import config
    if args.interface:
        config.INTERFACE = args.interface
    if args.no_log:
        config.LOG_EVERY_PACKET = False

    # ── 3. Interface check (uses the possibly-overridden value) ───────
    check_interface(config.INTERFACE)

    # ── 4. Import Capture only now — after config overrides are applied ─
    from core.capture import Capture

    capture = Capture()
    capture.set_label(args.label)
    capture.start()


if __name__ == "__main__":
    main()
