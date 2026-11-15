"""Cron-style live scoring: build feature windows from the REAL activity_log (Member 1) and
score them with the trained model.

    python machine_larning/live_windows.py --once                 # score the last window once
    python machine_larning/live_windows.py --every 60             # repeat every 60 s (cron-style)
    python machine_larning/live_windows.py --seed-demo --once     # add SIMULATED demo traffic first

Windows are grouped by ip_hash. Alerts are de-duplicated per (ip_hash, window_start).
The job only READS activity_log and WRITES security_alerts. It never touches votes.
"""
import argparse
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np

from machine_larning import config, db
from machine_larning.detection import score_activity

FMT = "%Y-%m-%d %H:%M:%S"
M = config.ACTIVITY_LOG_MAP


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts[:19].replace("T", " "), FMT)


def window_features(events, window_seconds):
    """events: list of (event_type, account_ref, created_at datetime) for ONE ip in ONE window."""
    events = sorted(events, key=lambda e: e[2])
    times = [e[2] for e in events]
    n = len(events)
    span = (times[-1] - times[0]).total_seconds()
    duration = max(span, 1.0)
    rpm = n / (max(span, 60.0) / 60.0)
    gaps = np.diff([t.timestamp() for t in times]) if n > 1 else np.array([])
    avg_gap = float(gaps.mean()) if len(gaps) else 60.0  # single event: neutral 60 s
    hour = times[0].hour
    off = 1 if (hour >= config.OFF_HOURS_START or hour < config.OFF_HOURS_END) else 0
    accounts = {e[1] for e in events if e[1]}
    return {
        "failed_logins": sum(e[0] == config.FAILED_EVENT for e in events),
        "requests_per_minute": round(rpm, 2),
        "login_attempts": sum(e[0] in config.LOGIN_EVENTS for e in events),
        "token_requests": sum(e[0] == config.TOKEN_EVENT for e in events),
        # An IP is at least one actor; training data never has 0 (avoids train/serve skew)
        "distinct_accounts_per_ip": max(1, len(accounts)),
        "avg_gap_between_requests": round(avg_gap, 2),
        "session_duration": round(duration, 1),
        "off_hours_flag": off,
    }


def build_windows(conn, window_minutes=5, now=None):
    """Return a list of {ip_hash, window_start, window_end, features} for the last window."""
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    start = now - timedelta(minutes=window_minutes)
    rows = conn.execute(
        f"SELECT {M['event_type']} AS et, {M['account_ref']} AS acct, {M['ip_hash']} AS ip, "
        f"{M['created_at']} AS ts FROM activity_log WHERE {M['created_at']} >= ? "
        f"AND {M['created_at']} <= ?", (start.strftime(FMT), now.strftime(FMT))).fetchall()
    by_ip: dict = {}
    for r in rows:
        by_ip.setdefault(r["ip"], []).append((r["et"], r["acct"], _parse(r["ts"])))
    return [{
        "ip_hash": ip,
        "window_start": start.strftime(FMT),
        "window_end": now.strftime(FMT),
        "features": window_features(ev, window_minutes * 60),
    } for ip, ev in by_ip.items()]


def run_live_scoring(conn, window_minutes=5, now=None, model_path=None, persist=True):
    """Score every window; save medium/high ones as 'new' alerts. Returns a small summary."""
    windows = build_windows(conn, window_minutes, now)
    scored = new_alerts = 0
    for w in windows:
        result = score_activity(w["features"], model_path=model_path)
        scored += 1
        if persist and result["severity"] in ("medium", "high"):
            alert_id = db.insert_alert(
                conn, result, w["features"], session_id=f"LIVE-{w['ip_hash']}-{w['window_start']}",
                ip_hash=w["ip_hash"], window_start=w["window_start"], window_end=w["window_end"],
                is_simulated=str(w["ip_hash"]).startswith("sim-"))
            new_alerts += alert_id is not None
    return {"windows_scored": scored, "new_alerts": new_alerts, "notice": config.ETHICS_NOTICE}


def start_background_scheduler(interval_seconds=60, window_minutes=5, db_path=None, model_path=None):
    """Cron-style loop in a daemon thread. Returns (thread, stop_event)."""
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            conn = db.get_conn(db_path)
            try:
                run_live_scoring(conn, window_minutes, model_path=model_path)
            except Exception as exc:  # keep the monitor alive; it is advisory only
                print(f"[live-scoring] error: {exc}", file=sys.stderr)
            finally:
                conn.close()
            stop.wait(interval_seconds)

    t = threading.Thread(target=loop, name="security-live-scoring", daemon=True)
    t.start()
    return t, stop


def seed_demo_traffic(conn, now=None):
    """Insert SIMULATED traffic (ip_hash starts with 'sim-') so the demo has something to score."""
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    rng = np.random.default_rng(config.RANDOM_SEED)
    rows = []

    def add(ip, etype, acct, secs_ago):
        rows.append((etype, acct, ip, (now - timedelta(seconds=float(secs_ago))).strftime(FMT)))

    for k in range(6):  # normal users
        ip = f"sim-normal-{k}"
        add(ip, "login_success", f"sim-acct-n{k}", rng.uniform(200, 280))
        add(ip, "token_request", f"sim-acct-n{k}", rng.uniform(100, 190))
        add(ip, "vote_cast", f"sim-acct-n{k}", rng.uniform(20, 90))
    for s in range(30):  # brute force: one account, many failures
        add("sim-attacker-bruteforce", "login_failed", "sim-acct-victim", 240 - s * 4)
    add("sim-attacker-bot", "login_success", "sim-acct-bot", 75)
    for s in range(299):  # bot: ~300 requests/min, evenly spaced (0.2 s)
        add("sim-attacker-bot", "request", "sim-acct-bot", 70 - s * 0.2)
    for s in range(25):  # credential stuffing: many accounts, one IP
        add("sim-attacker-stuffing", "login_failed", f"sim-acct-s{s}", 230 - s * 5)
    add("sim-attacker-replay", "login_success", "sim-acct-r1", 110)
    for s in range(30):  # token replay: same account asks for a vote token again and again
        add("sim-attacker-replay", "token_request", "sim-acct-r1", 100 - s * 2)
    conn.executemany(
        f"INSERT INTO activity_log ({M['event_type']},{M['account_ref']},{M['ip_hash']},"
        f"{M['created_at']}) VALUES (?,?,?,?)", rows)
    conn.commit()
    return len(rows)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--once", action="store_true")
    p.add_argument("--every", type=int, default=0, help="repeat every N seconds")
    p.add_argument("--window-minutes", type=int, default=5)
    p.add_argument("--seed-demo", action="store_true", help="insert SIMULATED traffic first")
    a = p.parse_args()

    conn = db.get_conn()
    if a.seed_demo:
        print(f"Inserted {seed_demo_traffic(conn)} SIMULATED activity_log rows")
    while True:
        print(run_live_scoring(conn, a.window_minutes))
        if not a.every:
            break
        time.sleep(a.every)


if __name__ == "__main__":
    main()
