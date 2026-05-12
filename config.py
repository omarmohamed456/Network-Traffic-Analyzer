# config.py — edit these before running
# ─────────────────────────────────────────────────────────────

# ── Network interface ─────────────────────────────────────────
INTERFACE      = "enp0s3"       # run 'ip a' on IDS VM to find yours

# ── Lab host addresses ────────────────────────────────────────
# Used by the rule engine to resolve $IDS_IP, $VICTIM_IP, $ATTACKER_IP
# tokens in rule files. No IPs are hardcoded in the rules themselves.
# Update these if you rebuild the lab or clone the victim VM.
IDS_IP         = "192.168.10.30"   # this machine — excluded from false-positive rules
VICTIM_IP      = "192.168.10.20"   # primary victim (Apache, SSH, FTP, DNS, MySQL)
VICTIM_IP_2    = "192.168.10.21"   # victim clone 2
VICTIM_IP_3    = "192.168.10.22"   # victim clone 3
VICTIM_IP_4    = "192.168.10.23"   # victim clone 4
ATTACKER_IP    = "192.168.10.10"   # Kali attacker

# ── Network scope ─────────────────────────────────────────────
HOME_NET       = "192.168.10.0/24"  # lab subnet — traffic inside this is internal

# ── Storage paths ─────────────────────────────────────────────
DB_PATH        = "storage/alerts.db"
JSON_LOG_PATH  = "storage/traffic.json"
CSV_LOG_PATH   = "storage/traffic.csv"

# ── Logging ───────────────────────────────────────────────────
LOG_EVERY_PACKET  = True    # False = only log alerts (saves space)
MAX_PAYLOAD_BYTES = 500     # cap raw payload captured per packet in parser.py
