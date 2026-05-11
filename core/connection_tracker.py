# core/connection_tracker.py
# Maintains a sliding 2-second window of recently completed flows.
# Stamps three KDD-style features onto every flow record before it
# reaches the rule engine and logger:
#
#   count        — flows from this src_ip to the same dst_ip
#                  in the last COUNT_WINDOW seconds
#   srv_count    — flows from this src_ip to the same dst_port
#                  in the last COUNT_WINDOW seconds
#   serror_rate  — fraction of 'count' flows that had a SYN error
#                  (SYN sent, no ACK seen = half-open / rejected)
#
# These are the two most discriminating KDD99 features for detecting
# port scans and floods. They require cross-flow state — something the
# FlowTracker cannot compute because it only sees one flow at a time.
#
# ── Architecture ──────────────────────────────────────────────
# Capture._process_loop
#   → FlowTracker.add(packet)
#       → FlowTracker emits completed flow
#           → ConnectionTracker.stamp(flow)   ← this file
#               → Capture._on_flow_complete(flow)
#                   → RuleEngine.evaluate(flow)
#                   → Logger.write_flow(flow)
# ─────────────────────────────────────────────────────────────

import threading
import time
from collections import defaultdict
from typing import Callable


# Sliding window size in seconds — matches KDD99 definition
COUNT_WINDOW = 2.0


def _is_serror(flow: dict) -> bool:
    """
    True if this flow looks like a SYN error:
    - SYN was sent (syn_flag_count >= 1)
    - No ACK was ever received (ack_flag_count == 0)
    - Very little or no data came back (total_bwd_bytes < 100)

    This catches:
    - Port scan probes hitting closed ports (RST reply, no ACK)
    - Port scan probes hitting filtered ports (no reply at all)
    - SYN flood flows that never complete the handshake
    """
    syn = flow.get("syn_flag_count") or 0
    ack = flow.get("ack_flag_count") or 0
    bwd = flow.get("total_bwd_bytes") or 0
    return syn >= 1 and ack == 0 and bwd < 100


class ConnectionTracker:
    """
    Thread-safe sliding-window connection counter.

    Usage
    -----
    Wrap your FlowTracker emit callback:

        conn_tracker = ConnectionTracker(on_flow_complete)
        flow_tracker = FlowTracker(emit_callback=conn_tracker.stamp)

    Every time FlowTracker emits a flow, ConnectionTracker.stamp()
    is called first. It adds the flow to its window, computes the
    three features, writes them into the flow dict, then calls
    the real downstream callback.
    """

    def __init__(self, downstream: Callable[[dict], None]):
        self._downstream = downstream
        self._lock       = threading.Lock()

        # Each entry: (timestamp, dst_ip, dst_port, is_serror)
        # Keyed by src_ip so lookups are O(n) only over that src's flows
        self._window: dict[str, list] = defaultdict(list)

    # ── Public API ────────────────────────────────────────────
    def stamp(self, flow: dict):
        """
        Called by FlowTracker for every completed flow.
        1. Prunes entries older than COUNT_WINDOW from this src.
        2. Computes count, srv_count, serror_rate.
        3. Stamps the three values into the flow dict.
        4. Appends this flow to the window.
        5. Calls downstream callback.
        """
        now      = time.time()
        src_ip   = flow.get("src_ip") or "unknown"
        dst_ip   = flow.get("dst_ip") or "unknown"
        dst_port = flow.get("dst_port")
        is_serr  = _is_serror(flow)

        with self._lock:
            # ── Prune expired entries for this src ────────────
            self._window[src_ip] = [
                e for e in self._window[src_ip]
                if now - e[0] <= COUNT_WINDOW
            ]

            recent = self._window[src_ip]

            # ── count: flows to same dst_ip ───────────────────
            count = sum(1 for e in recent if e[1] == dst_ip)

            # ── srv_count: flows to same dst_port ─────────────
            srv_count = sum(
                1 for e in recent
                if dst_port is not None and e[2] == dst_port
            )

            # ── serror_rate: fraction of count that were SYN errors
            if count > 0:
                serror_count = sum(
                    1 for e in recent
                    if e[1] == dst_ip and e[3]   # same dst, was serror
                )
                serror_rate = round(serror_count / count, 4)
            else:
                serror_rate = 0.0

            # ── Stamp onto flow ───────────────────────────────
            flow["count"]       = count
            flow["srv_count"]   = srv_count
            flow["serror_rate"] = serror_rate

            # ── Append this flow to window ────────────────────
            self._window[src_ip].append((now, dst_ip, dst_port, is_serr))

        # Call downstream outside the lock — no re-entrancy issues
        self._downstream(flow)

    def clear(self):
        """Wipe all window state. Useful for testing."""
        with self._lock:
            self._window.clear()
