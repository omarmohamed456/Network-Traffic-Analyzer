# config.py — edit these before running
# ─────────────────────────────────────────────────────────────

# ── Network ───────────────────────────────────────────────────
INTERFACE      = "enp0s3"       # run 'ip a' on IDS VM to find yours
HOME_NET       = "192.168.56.0/24"

# ── Storage paths ─────────────────────────────────────────────
DB_PATH        = "storage/alerts.db"
JSON_LOG_PATH  = "storage/traffic.json"
CSV_LOG_PATH   = "storage/traffic.csv"

# ── Logging ───────────────────────────────────────────────────
LOG_EVERY_PACKET = True         # False = only log alerts (saves space)
MAX_PAYLOAD_BYTES = 500         # cap payload capture size
