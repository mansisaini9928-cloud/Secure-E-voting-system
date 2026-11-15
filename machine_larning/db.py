"""SQLite helpers: creates activity_log (if Member 1 has not) and security_alerts."""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from machine_larning import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS activity_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type   TEXT NOT NULL,
    account_ref  TEXT,
    ip_hash      TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_log(created_at);

CREATE TABLE IF NOT EXISTS security_alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    TEXT NOT NULL,
    session_id    TEXT,
    ip_hash       TEXT,
    window_start  TEXT,
    window_end    TEXT,
    anomaly_score REAL NOT NULL,
    severity      TEXT NOT NULL CHECK (severity IN ('low','medium','high')),
    reason        TEXT NOT NULL,
    features_json TEXT NOT NULL,
    is_simulated  INTEGER NOT NULL DEFAULT 0,
    status        TEXT NOT NULL DEFAULT 'new',
    reviewed_by   TEXT,
    reviewed_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_alert_status ON security_alerts(status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_window
    ON security_alerts(ip_hash, window_start);
"""


def utc_now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def get_conn(db_path=None) -> sqlite3.Connection:
    path = Path(db_path or config.DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    init_db(conn)
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def insert_alert(conn, result: dict, features: dict, session_id=None, ip_hash=None,
                 window_start=None, window_end=None, is_simulated=False):
    """Insert a new alert with status 'new'. Returns the id, or None if it is a duplicate window."""
    try:
        cur = conn.execute(
            """INSERT INTO security_alerts
               (created_at, session_id, ip_hash, window_start, window_end, anomaly_score,
                severity, reason, features_json, is_simulated, status)
               VALUES (?,?,?,?,?,?,?,?,?,?, 'new')""",
            (utc_now_str(), session_id, ip_hash, window_start, window_end,
             float(result["anomaly_score"]), result["severity"], result["reason"],
             json.dumps(features, default=float), 1 if is_simulated else 0),
        )
        conn.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        conn.rollback()
        return None


def _row_to_dict(row) -> dict:
    d = dict(row)
    d["features"] = json.loads(d.pop("features_json"))
    d["is_simulated"] = bool(d["is_simulated"])
    return d


def list_alerts(conn, status=None, severity=None, limit=50, offset=0):
    sql, args = "SELECT * FROM security_alerts WHERE 1=1", []
    if status:
        sql += " AND status = ?"
        args.append(status)
    if severity:
        sql += " AND severity = ?"
        args.append(severity)
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    args += [int(limit), int(offset)]
    return [_row_to_dict(r) for r in conn.execute(sql, args).fetchall()]


def alert_summary(conn) -> dict:
    def counts(col, levels):
        out = {k: 0 for k in levels}
        for r in conn.execute(f"SELECT {col} AS k, COUNT(*) AS n FROM security_alerts GROUP BY {col}"):
            out[r["k"]] = r["n"]
        return out

    total = conn.execute("SELECT COUNT(*) FROM security_alerts").fetchone()[0]
    last24 = conn.execute(
        "SELECT COUNT(*) FROM security_alerts WHERE created_at >= datetime('now','-1 day')"
    ).fetchone()[0]
    simulated = conn.execute(
        "SELECT COUNT(*) FROM security_alerts WHERE is_simulated = 1").fetchone()[0]
    latest = conn.execute("SELECT * FROM security_alerts ORDER BY id DESC LIMIT 1").fetchone()
    log_rows = conn.execute("SELECT COUNT(*) FROM activity_log").fetchone()[0]
    return {
        "total_alerts": total,
        "alerts_last_24h": last24,
        "simulated_alerts": simulated,
        "by_severity": counts("severity", config.SEVERITY_LEVELS),
        "by_status": counts("status", ("new", "reviewed", "dismissed")),
        "activity_log_rows": log_rows,
        "latest_alert": _row_to_dict(latest) if latest else None,
    }
