"""Real-time scoring: score_activity(record) -> anomaly_score, severity, reason.

ETHICS: this module only *describes* how unusual a session window looks. It never blocks a
user, never touches votes, tokens or ballots, and every alert is for human review.
"""
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from machine_learning import config
from machine_learning.preprocessing import load_bundle

import numpy as np
import pandas as pd

_CACHE: dict = {}

# (feature, direction, plain-English hint)
_HINTS = {
    "failed_logins": (+1, "many failed logins", "brute-force login"),
    "login_attempts": (+1, "many login attempts", "brute-force login"),
    "token_requests": (+1, "repeated vote-token requests", "token replay"),
    "requests_per_minute": (+1, "very high request rate", "bot traffic"),
    "distinct_accounts_per_ip": (+1, "many accounts from one IP", "credential stuffing"),
    "avg_gap_between_requests": (-1, "very short, even gaps between requests", "bot traffic"),
    "session_duration": (+1, "unusually long session", "automation"),
    "off_hours_flag": (+1, "off-hours activity", "unusual timing"),
}


def get_bundle(model_path=None):
    path = str(model_path or config.MODEL_PATH)
    if path not in _CACHE:
        _CACHE[path] = load_bundle(path)
    return _CACHE[path]


def clear_cache():
    _CACHE.clear()


def _to_frame(record: dict, features) -> pd.DataFrame:
    row = {}
    for f in features:
        v = record.get(f)
        if v is None:
            row[f] = np.nan
            continue
        if isinstance(v, bool) or not isinstance(v, (int, float, np.integer, np.floating)):
            raise ValueError(f"Feature '{f}' must be a number, got {type(v).__name__}")
        if not math.isfinite(v):
            raise ValueError(f"Feature '{f}' must be finite")
        row[f] = float(v)
    if all(math.isnan(v) for v in row.values()):
        raise ValueError("record contains none of the required features: " + ", ".join(features))
    return pd.DataFrame([row], columns=features)


def _severity(score, thresholds):
    if score >= thresholds["high"]:
        return "high"
    if score >= thresholds["medium"]:
        return "medium"
    return "low"


def _explain(bundle, frame, severity):
    if severity == "low":
        return "Within normal range for simulated-normal baseline."
    z = bundle["isolation_forest"].named_steps["prep"].transform(frame)[0]
    flagged = []
    for name, zi in zip(bundle["features"], z):
        direction, text, pattern = _HINTS[name]
        if name == "off_hours_flag":
            continue
        if direction * zi >= 2.0:
            flagged.append((abs(zi), name, zi, text, pattern))
    flagged.sort(reverse=True)
    if not flagged:
        return "Unusual combination of features (no single feature stands out)."
    top = flagged[:2]
    parts = [f"{t[3]} ({t[1]}, z={t[2]:+.1f})" for t in top]
    return f"{'; '.join(parts)}; resembles {top[0][4]}."


def score_activity(record: dict, model_path=None) -> dict:
    """Score one session-window record (dict of the 8 features).

    Returns: anomaly_score (0..1, higher = more anomalous), severity (low|medium|high),
    reason (short text) plus advisory fields. Missing features are median-imputed.
    """
    bundle = get_bundle(model_path)
    frame = _to_frame(record, bundle["features"])
    score = float(-bundle["isolation_forest"].score_samples(frame)[0])
    severity = _severity(score, bundle["thresholds"])
    return {
        "anomaly_score": round(score, 4),
        "severity": severity,
        "reason": _explain(bundle, frame, severity),
        "action": "none" if severity == "low" else "human_review",
        "advisory_only": True,
        "thresholds": {k: round(v, 4) for k, v in bundle["thresholds"].items()},
        "model": "isolation_forest",
        "data_source": bundle["meta"]["data_source"],
    }
