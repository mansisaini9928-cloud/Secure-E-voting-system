from datetime import datetime, timedelta, timezone

import pytest
from werkzeug.security import generate_password_hash

from app import create_app
from database.db import get_db
from members.member3_ml import ActivityAggregator, FEATURE_COLUMNS


@pytest.fixture
def member3_app(tmp_path):
    database = tmp_path / "member3.sqlite"

    def scoring_result(_features):
        return {
            "anomaly_score": 0.82,
            "severity": "high",
            "reason": "Isolation Forest flags an unusual pattern for human review.",
        }

    app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": "member3-test-secret",
        "DATABASE": str(database),
        "MEMBER3_SCORER": scoring_result,
    })
    with app.app_context():
        db = get_db()
        db.execute("INSERT INTO candidates(name,party,symbol) VALUES('Candidate','Demo','C')")
        db.execute(
            "INSERT INTO users(username,email,password_hash,eligible) VALUES(?,?,?,1)",
            ("voter", "voter@example.test", generate_password_hash("LongDemoPass!123")),
        )
        db.execute(
            "INSERT INTO users(username,email,password_hash,role) VALUES(?,?,?,'admin')",
            ("admin", "admin@example.test", generate_password_hash("LongDemoPass!123")),
        )
        db.commit()
    return app


def _event(aggregator, *, session="cookie-session-a", source="192.0.2.10",
           account="account-a", category="general", failed=False, second=0,
           hour=12):
    return aggregator.record(
        session_value=session,
        source_value=source,
        account_value=account,
        category=category,
        failed_login=failed,
        timestamp=datetime(2026, 11, 15, hour, 0, tzinfo=timezone.utc) + timedelta(seconds=second),
        monotonic_time=float(second),
    )


def test_features_follow_exact_order_and_60_second_window():
    aggregator = ActivityAggregator(secret=b"test-key")
    assert tuple(FEATURE_COLUMNS) == (
        "failed_logins", "requests_per_minute", "login_attempts", "token_requests",
        "distinct_accounts_per_ip", "avg_gap_between_requests", "session_duration",
        "off_hours_flag",
    )
    assert _event(aggregator, category="token", second=58, hour=23) is None
    # A second ephemeral session on the same source contributes an account to the
    # source-level distinct-account count, but not the first session's request count.
    _event(aggregator, session="cookie-session-b", account="account-b", second=59, hour=23)
    features = _event(
        aggregator, category="login", failed=True, second=60, hour=23
    )
    assert tuple(features) == FEATURE_COLUMNS
    assert features == {
        "failed_logins": 1,
        "requests_per_minute": 2,
        "login_attempts": 1,
        "token_requests": 1,
        "distinct_accounts_per_ip": 2,
        "avg_gap_between_requests": 2.0,
        "session_duration": 2.0,
        "off_hours_flag": 1,
    }
    # The event at t=0 has expired at t=61; only the current event remains.
    assert _event(aggregator, second=121, hour=12) is None


def test_pseudonyms_keep_raw_identifiers_out_of_aggregator_state():
    aggregator = ActivityAggregator(secret=b"privacy-test")
    raw_values = ("cookie-session-secret", "203.0.113.77", "person@example.test")
    _event(
        aggregator, session=raw_values[0], source=raw_values[1], account=raw_values[2], second=1
    )
    state = repr((aggregator._sessions, aggregator._sources))
    for raw in raw_values:
        assert raw not in state


def test_cleanup_expires_session_and_source_buckets():
    aggregator = ActivityAggregator(secret=b"cleanup-test")
    _event(aggregator, second=1)
    assert aggregator._sessions and aggregator._sources
    aggregator.cleanup(now=62)
    assert not aggregator._sessions
    assert not aggregator._sources


def test_member3_alert_and_summary_require_admin(member3_app):
    anonymous = member3_app.test_client()
    assert anonymous.get("/member3/alerts").status_code == 302
    assert anonymous.get("/member3/summary").status_code == 302

    voter = member3_app.test_client()
    voter.post("/login", data={"identity": "voter", "password": "LongDemoPass!123"})
    assert voter.get("/member3/alerts").status_code == 403
    assert voter.get("/member3/summary").status_code == 403

    admin = member3_app.test_client()
    admin.post("/login", data={"identity": "admin", "password": "LongDemoPass!123"})
    assert admin.get("/member3/alerts").status_code == 200
    assert admin.get("/member3/summary").status_code == 200


def test_complete_activity_is_persisted_in_existing_security_events(member3_app):
    client = member3_app.test_client()
    client.post("/login", data={"identity": "admin", "password": "LongDemoPass!123"})
    client.get("/admin")
    client.get("/admin")
    alerts = client.get("/member3/alerts").get_json()["alerts"]
    assert len(alerts) == 1
    assert alerts[0]["kind"] == "ml_anomaly"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["score"] == pytest.approx(0.82)
    assert alerts[0]["simulated"] == 1
    summary = client.get("/member3/summary").get_json()
    assert summary["total_alerts"] == 1
    assert summary["severity_counts"] == {"low": 0, "medium": 0, "high": 1}
    assert summary["human_review_only"] is True


def test_ml_failure_does_not_change_vote_token_or_ballot_outcomes(member3_app):
    def unavailable(_features):
        raise RuntimeError("simulated model failure")

    member3_app.extensions["member3_model_scorer"] = unavailable
    client = member3_app.test_client()
    client.post("/login", data={"identity": "voter", "password": "LongDemoPass!123"})
    token_response = client.post("/api/vote/token")
    assert token_response.status_code == 200
    token = token_response.get_json()["token"]
    cast_response = client.post(
        "/api/vote/cast", data={"candidate_id": "1", "token": token}
    )
    assert cast_response.status_code == 201
    assert set(cast_response.get_json()["receipt"]) == {"ballot_id", "ballot_hash"}
