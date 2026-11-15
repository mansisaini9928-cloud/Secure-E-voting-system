"""Shared constants for the ML security module.

ASSUMPTION (the shared contract was not available when this was written):
  * Backend: Flask + SQLite.  Change DB_PATH / EVOTING_DB if your team uses another file.
  * Member 1's table `activity_log` has the columns listed in ACTIVITY_LOG_COLUMNS.
    If the real column names differ, edit ONLY the ACTIVITY_LOG_MAP dict below.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "dataset.csv"
MODEL_PATH = BASE_DIR / "model.pkl"
OUTPUT_DIR = BASE_DIR / "outputs"
DB_PATH = Path(os.environ.get("EVOTING_DB", BASE_DIR / "evoting.db"))

RANDOM_SEED = 42

# 8 model features: no personal data, no candidate or ballot content.
FEATURES = [
    "failed_logins",
    "requests_per_minute",
    "login_attempts",
    "token_requests",
    "distinct_accounts_per_ip",
    "avg_gap_between_requests",
    "session_duration",
    "off_hours_flag",
]

ATTACK_TYPES = ["brute_force", "token_replay", "bot_traffic", "credential_stuffing"]

SIM_NOTICE = "SIMULATED DATA - synthetic attacks generated for this project, not real traffic"
ETHICS_NOTICE = (
    "Advisory only. This module never blocks, delays or invalidates a vote. "
    "Alerts are for human review."
)

# --- Mapping to Member 1's activity_log (edit here if their schema differs) ---------
ACTIVITY_LOG_MAP = {
    "event_type": "event_type",    # login_success | login_failed | token_request | vote_cast | request
    "account_ref": "account_ref",  # hashed/opaque account id (NEVER a name or voter id in clear)
    "ip_hash": "ip_hash",          # hashed IP
    "created_at": "created_at",    # 'YYYY-MM-DD HH:MM:SS' (UTC)
}
LOGIN_EVENTS = ("login_success", "login_failed")
FAILED_EVENT = "login_failed"
TOKEN_EVENT = "token_request"

OFF_HOURS_START = 22  # 22:00 inclusive
OFF_HOURS_END = 6     # 06:00 exclusive

SEVERITY_LEVELS = ("low", "medium", "high")
