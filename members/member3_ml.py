"""Human-review-only anomaly scoring for ephemeral application activity windows.

The 60-second window is an integration demo convention. The synthetic training
dataset describes session windows but does not specify their duration.
"""
from collections import deque
from datetime import datetime, timezone
import hashlib
import hmac
import logging
import math
import os
from pathlib import Path
import secrets
import threading
import time
from bisect import bisect_right

from flask import Blueprint, current_app, g, jsonify

bp = Blueprint("member3_ml", __name__)
logger = logging.getLogger(__name__)

WINDOW_SECONDS = 60.0
FEATURE_COLUMNS = (
    "failed_logins",
    "requests_per_minute",
    "login_attempts",
    "token_requests",
    "distinct_accounts_per_ip",
    "avg_gap_between_requests",
    "session_duration",
    "off_hours_flag",
)
MAX_SESSIONS = 1024
MAX_SOURCES = 1024
MAX_RECORDED_EVENTS = 20_000
_DEFAULT_SCORER = None
_SCORER_LOCK = threading.Lock()


class ActivityAggregator:
    """Bounded process-local windows keyed only by ephemeral HMAC pseudonyms."""

    def __init__(self, secret=None, clock=None):
        self._secret = secret or secrets.token_bytes(32)
        self._clock = clock or time.monotonic
        self._sessions = {}
        self._sources = {}
        self._event_count = 0
        self._lock = threading.RLock()

    def _pseudonym(self, domain, value):
        if value is None:
            return None
        raw = str(value).encode("utf-8", errors="replace")
        return hmac.new(self._secret, domain.encode() + b":" + raw, hashlib.sha256).hexdigest()

    @staticmethod
    def _prune(events, cutoff):
        while events and (events[0]["mono"] if isinstance(events[0], dict) else events[0][0]) < cutoff:
            events.popleft()

    def record(self, *, session_value, source_value, account_value, category,
               failed_login=False, timestamp=None, monotonic_time=None):
        """Record one completed dynamic request; return a complete feature map or None."""
        wall = timestamp or datetime.now(timezone.utc)
        if wall.tzinfo is None:
            return None
        wall = wall.astimezone(timezone.utc)
        mono = self._clock() if monotonic_time is None else float(monotonic_time)
        if not math.isfinite(mono):
            return None

        session_key = self._pseudonym("session", session_value)
        source_key = self._pseudonym("source", source_value)
        account_key = self._pseudonym("account", account_value)
        if session_key is None or source_key is None:
            return None
        if category not in {"general", "login", "token"}:
            return None

        event = {
            "mono": mono,
            "utc": wall,
            "category": category,
            "failed_login": bool(failed_login),
            "account": account_key,
        }
        with self._lock:
            # A lifetime cap also bounds high-volume bursts. Resetting all state
            # deliberately makes the next windows incomplete until observations accrue.
            if self._event_count >= MAX_RECORDED_EVENTS:
                self._sessions.clear()
                self._sources.clear()
                self._event_count = 0
            if session_key not in self._sessions:
                if len(self._sessions) >= MAX_SESSIONS:
                    self._sessions.clear()
                    self._sources.clear()
                    self._event_count = 0
                self._sessions[session_key] = deque()
            if source_key not in self._sources:
                if len(self._sources) >= MAX_SOURCES:
                    self._sessions.clear()
                    self._sources.clear()
                    self._event_count = 0
                    self._sessions[session_key] = deque()
                self._sources[source_key] = deque()
            session_events = self._sessions[session_key]
            source_events = self._sources[source_key]
            cutoff = mono - WINDOW_SECONDS
            self._prune(session_events, cutoff)
            self._prune(source_events, cutoff)
            session_rows = list(session_events)
            session_at = bisect_right([item["mono"] for item in session_rows], mono)
            session_rows.insert(session_at, event)
            session_events.clear()
            session_events.extend(session_rows)
            source_rows = list(source_events)
            source_at = bisect_right([item[0] for item in source_rows], mono)
            source_rows.insert(source_at, (mono, account_key))
            source_events.clear()
            source_events.extend(source_rows)
            self._event_count += 1

            if len(session_events) < 2:
                return None
            times = [item["mono"] for item in session_events]
            gaps = [later - earlier for earlier, later in zip(times, times[1:])]
            if not gaps or any(not math.isfinite(gap) or gap < 0 for gap in gaps):
                return None
            distinct_accounts = {account for _, account in source_events if account is not None}
            features = {
                "failed_logins": sum(item["failed_login"] for item in session_events),
                "requests_per_minute": len(session_events),
                "login_attempts": sum(item["category"] == "login" for item in session_events),
                "token_requests": sum(item["category"] == "token" for item in session_events),
                "distinct_accounts_per_ip": len(distinct_accounts),
                "avg_gap_between_requests": sum(gaps) / len(gaps),
                "session_duration": times[-1] - times[0],
                "off_hours_flag": int(
                    session_events[-1]["utc"].hour >= 22 or session_events[-1]["utc"].hour < 6
                ),
            }
            if tuple(features) != FEATURE_COLUMNS:
                return None
            if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)
                   for value in features.values()):
                return None
            return features

    def cleanup(self, now=None):
        """Expire stale windows without retaining any raw identifiers."""
        cutoff = (self._clock() if now is None else float(now)) - WINDOW_SECONDS
        with self._lock:
            for key, events in list(self._sessions.items()):
                self._prune(events, cutoff)
                if not events:
                    del self._sessions[key]
            for key, events in list(self._sources.items()):
                self._prune(events, cutoff)
                if not events:
                    del self._sources[key]


def _artifact_directory():
    configured = os.environ.get("ML_ARTIFACT_DIR")
    if configured:
        return Path(configured)
    # The supplied standalone project is a sibling of this team workspace.
    return Path(__file__).resolve().parents[1] / "machine_learning"


def _load_scorer():
    import joblib
    import numpy as np
    import pandas as pd

    model_path = _artifact_directory() / "model.pkl"
    bundle = joblib.load(model_path)
    required = {"isolation_forest", "preprocessor", "feature_columns"}
    if not isinstance(bundle, dict) or not required.issubset(bundle):
        raise ValueError("model.pkl is missing required model components")
    if tuple(bundle["feature_columns"]) != FEATURE_COLUMNS:
        raise ValueError("model feature order does not match the application feature order")
    estimator = bundle["isolation_forest"]
    preprocessor = bundle["preprocessor"]
    if getattr(estimator, "n_features_in_", None) != len(FEATURE_COLUMNS):
        raise ValueError("Isolation Forest feature dimension is incompatible")
    fitted_names = getattr(preprocessor, "feature_names_in_", None)
    if fitted_names is None or tuple(fitted_names) != FEATURE_COLUMNS:
        raise ValueError("Preprocessing feature names or order are incompatible")
    if getattr(preprocessor, "n_features_in_", None) != len(FEATURE_COLUMNS):
        raise ValueError("Preprocessing feature dimension is incompatible")

    def score(features):
        frame = pd.DataFrame([[features[name] for name in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)
        transformed = preprocessor.transform(frame)
        if transformed.shape != (1, len(FEATURE_COLUMNS)) or not np.isfinite(transformed).all():
            raise ValueError("Preprocessor returned an incomplete or non-finite vector")
        decision = float(estimator.decision_function(transformed)[0])
        anomaly_score = float(1.0 / (1.0 + np.exp(np.clip(decision * 12.0, -60, 60))))
        flagged = bool(estimator.predict(transformed)[0] == -1)
        severity = "high" if anomaly_score >= 0.70 else "medium" if anomaly_score >= 0.40 else "low"
        reason = (
            "Isolation Forest flags an unusual pattern for human review."
            if flagged else "No strong simulated anomaly pattern was identified; routine review still applies."
        )
        return {"anomaly_score": anomaly_score, "severity": severity, "reason": reason}

    return score


def _default_scorer():
    global _DEFAULT_SCORER
    if _DEFAULT_SCORER is None:
        with _SCORER_LOCK:
            if _DEFAULT_SCORER is None:
                _DEFAULT_SCORER = _load_scorer()
    return _DEFAULT_SCORER


def init_app(app):
    app.extensions["member3_activity_aggregator"] = ActivityAggregator()
    app.extensions["member3_model_scorer"] = app.config.get("MEMBER3_SCORER")


def mark_login_outcome(outcome):
    """Attach an explicit login result to the current request, without identity data."""
    if outcome in {"success", "failure"}:
        g.member3_login_outcome = outcome


def before_application_request():
    """Capture transient request metadata after routing and user loading."""
    from flask import request, session

    endpoint = request.endpoint or ""
    aggregator = current_app.extensions.get("member3_activity_aggregator")
    if aggregator is not None:
        aggregator.cleanup()
    if endpoint.startswith("member3_ml.") or endpoint in {"static"}:
        g.member3_activity_request = None
        return
    if endpoint in {"member1_auth.health", "member2_crypto.health"}:
        g.member3_activity_request = None
        return

    category = "general"
    account = None
    if endpoint == "login" and request.method == "POST":
        category = "login"
        account = request.form.get("identity", "").strip().casefold()
    elif endpoint == "request_vote_token" and request.method == "POST":
        category = "token"
    elif endpoint == "vote_page" and request.method == "POST" and request.form.get("action") == "request_token":
        category = "token"
    else:
        user = getattr(g, "user", None)
        if user is not None:
            account = user["id"]

    # Flask signs and refreshes its cookie frequently, so key the window with
    # a random per-session pseudonym rather than hashing the changing cookie.
    session_value = session.get("_member3_nonce")
    if not session_value:
        session_value = secrets.token_urlsafe(24)
        session["_member3_nonce"] = session_value
    source = request.remote_addr
    if not source:
        g.member3_activity_request = None
        return
    g.member3_activity_request = {
        "session_value": session_value,
        "source_value": source,
        "account_value": account,
        "category": category,
        "monotonic_time": time.monotonic(),
        "timestamp": datetime.now(timezone.utc),
    }


def after_application_request(response):
    """Score best-effort after the application has already chosen its response."""
    event = getattr(g, "member3_activity_request", None)
    if event is None:
        return response
    db = None
    try:
        aggregator = current_app.extensions["member3_activity_aggregator"]
        outcome = getattr(g, "member3_login_outcome", None)
        features = aggregator.record(
            **event,
            failed_login=(event["category"] == "login" and outcome == "failure"),
        )
        if features is None:
            return response
        scorer = current_app.extensions.get("member3_model_scorer") or _default_scorer()
        result = scorer(features)
        score = float(result["anomaly_score"])
        severity = result["severity"]
        reason = result["reason"]
        if not math.isfinite(score) or not 0 <= score <= 1 or severity not in {"low", "medium", "high"}:
            raise ValueError("Scorer returned an invalid alert")
        from database.db import get_db
        db = get_db()
        db.execute(
            "INSERT INTO security_events(kind,severity,message,score,simulated) VALUES(?,?,?,?,1)",
            ("ml_anomaly", severity, str(reason)[:500], score),
        )
        db.commit()
    except Exception:
        # Do not expose details or alter the response/authentication/vote decision.
        try:
            if db is not None:
                db.rollback()
        except Exception:
            pass
        logger.warning("Member 3 activity scoring or alert persistence failed")
    return response


@bp.get("/health")
def health():
    return jsonify(module="machine-learning", status="ready", simulated=True,
                   window_seconds=WINDOW_SECONDS)


@bp.get("/alerts")
def alerts():
    from database.db import get_db
    rows = get_db().execute(
        "SELECT id,kind,severity,message,score,simulated,reviewed,created_at "
        "FROM security_events WHERE kind='ml_anomaly' ORDER BY id DESC LIMIT 100"
    ).fetchall()
    return jsonify(alerts=[dict(row) for row in rows])


@bp.get("/summary")
def summary():
    from database.db import get_db
    db = get_db()
    total = db.execute("SELECT COUNT(*) FROM security_events WHERE kind='ml_anomaly'").fetchone()[0]
    grouped = db.execute(
        "SELECT severity,COUNT(*) AS count FROM security_events "
        "WHERE kind='ml_anomaly' GROUP BY severity"
    ).fetchall()
    counts = {name: 0 for name in ("low", "medium", "high")}
    counts.update({row["severity"]: row["count"] for row in grouped if row["severity"] in counts})
    return jsonify(total_alerts=total, severity_counts=counts, human_review_only=True)
