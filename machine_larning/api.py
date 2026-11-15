"""Flask endpoints for the security monitor.

Team integration (in the main app):
    from machine_larning.api import security_bp
    app.register_blueprint(security_bp)

Stand-alone demo:
    python machine_larning/api.py
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from flask import Blueprint, Flask, current_app, jsonify, request

from machine_larning import config, db
from machine_larning.detection import get_bundle, score_activity

security_bp = Blueprint("security", __name__, url_prefix="/api/security")

ALLOWED_KEYS = set(config.FEATURES) | {"session_id", "ip_hash", "window_start", "window_end",
                                       "simulated"}


def _conn():
    return db.get_conn(current_app.config.get("SECURITY_DB_PATH"))


def _model_path():
    return current_app.config.get("SECURITY_MODEL_PATH")


def _validate(payload):
    errors = []
    if not isinstance(payload, dict):
        return ["JSON body must be an object"]
    unknown = sorted(set(payload) - ALLOWED_KEYS)
    if unknown:
        errors.append("unexpected field(s): " + ", ".join(unknown)
                      + " (only the 8 numeric features plus session_id/ip_hash are accepted; "
                        "no personal, candidate or ballot data)")
    present = [f for f in config.FEATURES if payload.get(f) is not None]
    if not present:
        errors.append("provide at least one feature: " + ", ".join(config.FEATURES))
    for f in present:
        v = payload[f]
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            errors.append(f"{f} must be a number")
        elif v < 0:
            errors.append(f"{f} must be >= 0")
    if "off_hours_flag" in present and payload["off_hours_flag"] not in (0, 1):
        errors.append("off_hours_flag must be 0 or 1")
    return errors


@security_bp.post("/score")
def score():
    payload = request.get_json(silent=True)
    errors = _validate(payload)
    if errors:
        return jsonify({"error": "invalid_request", "details": errors}), 400

    result = score_activity(payload, model_path=_model_path())
    features = {f: payload.get(f) for f in config.FEATURES}
    ip_hash = payload.get("ip_hash")
    simulated = bool(payload.get("simulated")) or str(ip_hash or "").startswith("sim-")

    alert_id = None
    if result["severity"] in ("medium", "high"):
        conn = _conn()
        try:
            alert_id = db.insert_alert(
                conn, result, features, session_id=payload.get("session_id"), ip_hash=ip_hash,
                window_start=payload.get("window_start"), window_end=payload.get("window_end"),
                is_simulated=simulated)
        finally:
            conn.close()

    return jsonify({
        "session_id": payload.get("session_id"),
        "anomaly_score": result["anomaly_score"],
        "severity": result["severity"],
        "reason": result["reason"],
        "action": result["action"],
        "alert_id": alert_id,
        "alert_status": "new" if alert_id else None,
        "advisory_only": True,
        "simulated": simulated,
        "notice": config.ETHICS_NOTICE,
    })


@security_bp.get("/alerts")
def alerts():
    status = request.args.get("status")
    severity = request.args.get("severity")
    if status and status not in ("new", "reviewed", "dismissed"):
        return jsonify({"error": "invalid_request", "details": ["bad status"]}), 400
    if severity and severity not in config.SEVERITY_LEVELS:
        return jsonify({"error": "invalid_request", "details": ["bad severity"]}), 400
    try:
        limit = max(1, min(int(request.args.get("limit", 50)), 200))
        offset = max(0, int(request.args.get("offset", 0)))
    except ValueError:
        return jsonify({"error": "invalid_request", "details": ["limit/offset must be integers"]}), 400
    conn = _conn()
    try:
        rows = db.list_alerts(conn, status, severity, limit, offset)
    finally:
        conn.close()
    return jsonify({"count": len(rows), "alerts": rows, "notice": config.ETHICS_NOTICE})


@security_bp.get("/summary")
def summary():
    conn = _conn()
    try:
        data = db.alert_summary(conn)
    finally:
        conn.close()
    bundle = get_bundle(_model_path())
    data.update({
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "model": {
            "type": "isolation_forest",
            "trained_on": bundle["meta"]["data_source"],
            "contamination": bundle["contamination"],
            "thresholds": {k: round(v, 4) for k, v in bundle["thresholds"].items()},
        },
        "notice": config.ETHICS_NOTICE,
    })
    return jsonify(data)


def create_app(db_path=None, model_path=None):
    app = Flask(__name__)
    if db_path:
        app.config["SECURITY_DB_PATH"] = str(db_path)
    if model_path:
        app.config["SECURITY_MODEL_PATH"] = str(model_path)
    app.register_blueprint(security_bp)
    return app


if __name__ == "__main__":
    # use_reloader=False so a background live-scoring thread is not started twice
    create_app().run(host="127.0.0.1", port=5003, debug=False, use_reloader=False)
