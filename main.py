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
    result = subprocess.run(["ip", "link", "show", iface],
                           capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] Interface '{iface}' not found.")
        print("    Run 'ip a' to see available interfaces.")
        print("    Edit INTERFACE in config.py")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Network IDS")
    parser.add_argument("--interface", help="Network interface to capture on")
    parser.add_argument("--label",     help="Initial label for packets", default="normal")
    parser.add_argument("--no-log",    action="store_true", help="Only log alerts")
    args = parser.parse_args()

    # Override config if args provided
    if args.interface:
        import config
        config.INTERFACE = args.interface
    if args.no_log:
        import config
        config.LOG_EVERY_PACKET = False

    # Import after potential config override
    import config
    from core.capture import Capture

    check_root()
    check_interface(config.INTERFACE)

    capture = Capture()
    capture.set_label(args.label)
    capture.start()


if __name__ == "__main__":
    main()
