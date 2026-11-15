"""Tests for the ML security module. Run from the project root:  pytest -v
They train a small model into a temp folder, so your real model.pkl is never touched."""
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from machine_learning import config, db, detection, live_windows
from machine_learning.api import create_app
from machine_learning.evaluate import compute
from machine_learning.generate_dataset import generate
from machine_learning.preprocessing import build_preprocessor, split_data
from machine_learning.train_model import train

NORMAL = {"failed_logins": 0, "requests_per_minute": 5, "login_attempts": 1, "token_requests": 1,
          "distinct_accounts_per_ip": 1, "avg_gap_between_requests": 12, "session_duration": 240,
          "off_hours_flag": 0}
BRUTE = dict(NORMAL, failed_logins=30, login_attempts=31, requests_per_minute=40,
             avg_gap_between_requests=1.5, session_duration=90)
STUFFING = dict(NORMAL, distinct_accounts_per_ip=30, failed_logins=28, login_attempts=32,
                requests_per_minute=50, avg_gap_between_requests=1.2)
BOT = dict(NORMAL, requests_per_minute=250, avg_gap_between_requests=0.24)
REPLAY = dict(NORMAL, token_requests=25, requests_per_minute=35, avg_gap_between_requests=1.7)


@pytest.fixture(scope="session")
def small_df():
    return generate(n_rows=4000, seed=7)


@pytest.fixture(scope="session")
def model_path(tmp_path_factory, small_df):
    path = tmp_path_factory.mktemp("model") / "model.pkl"
    train(small_df, model_path=path, verbose=False)
    detection.clear_cache()
    return path


# ---------------------------------------------------------------- dataset
def test_default_dataset_is_big_and_simulated():
    df = generate()
    assert len(df) >= 10_000
    assert set(df["data_source"]) == {"SIMULATED"}
    assert set(config.ATTACK_TYPES) <= set(df["attack_type"])
    assert 0.045 <= df["label"].mean() <= 0.055


def test_dataset_is_reproducible_with_fixed_seed():
    pd.testing.assert_frame_equal(generate(n_rows=1000, seed=1), generate(n_rows=1000, seed=1))
    assert not generate(n_rows=1000, seed=1).equals(generate(n_rows=1000, seed=2))


def test_dataset_has_no_personal_or_ballot_columns(small_df):
    forbidden = {"name", "email", "voter_id", "ip", "ip_address", "candidate", "candidate_id",
                 "vote", "ballot", "password", "phone", "address"}
    assert forbidden.isdisjoint(c.lower() for c in small_df.columns)
    assert set(config.FEATURES) <= set(small_df.columns)


def test_label_matches_attack_type_and_has_missing_values(small_df):
    assert ((small_df["attack_type"] != "none").astype(int) == small_df["label"]).all()
    assert small_df[config.FEATURES].isna().any().any()


def test_normal_rows_follow_spec(small_df):
    n = small_df[(small_df.label == 0)]
    assert n["login_attempts"].median() <= 2
    assert n["failed_logins"].median() <= 1
    assert n["requests_per_minute"].median() < 15


# ---------------------------------------------------------------- preprocessing
def test_split_is_stratified(small_df):
    tr, te = split_data(small_df)
    assert abs(tr["label"].mean() - te["label"].mean()) < 0.005
    assert set(tr["session_id"]).isdisjoint(te["session_id"])


def test_preprocessor_imputes_and_scales(small_df):
    X = small_df[config.FEATURES]
    out = build_preprocessor().fit_transform(X)
    assert not np.isnan(out).any()
    assert np.allclose(out.mean(axis=0), 0, atol=1e-6)


# ---------------------------------------------------------------- models
def test_models_are_good_but_not_perfect(model_path, small_df):
    bundle = detection.get_bundle(model_path)
    _, test_df = split_data(small_df)
    res, *_ = compute(bundle, test_df)
    assert res["random_forest"]["recall"] >= 0.7
    assert res["isolation_forest"]["recall"] >= 0.5
    assert res["isolation_forest"]["roc_auc"] > 0.9
    assert res["random_forest"]["f1"] < 1.0, "overlap/noise should prevent a perfect score"
    assert res["random_forest"]["accuracy"] > res["majority_class_baseline_accuracy"]


def test_bundle_contents(model_path):
    b = detection.get_bundle(model_path)
    assert {"isolation_forest", "random_forest", "thresholds", "features"} <= set(b)
    assert b["thresholds"]["high"] > b["thresholds"]["medium"]
    assert b["meta"]["data_source"] == "SIMULATED"


# ---------------------------------------------------------------- detection
def test_normal_session_is_low(model_path):
    r = detection.score_activity(NORMAL, model_path=model_path)
    assert r["severity"] == "low" and r["action"] == "none"


@pytest.mark.parametrize("record,hint", [
    (BRUTE, "failed_logins"), (STUFFING, "distinct_accounts_per_ip"),
    (BOT, "requests_per_minute"), (REPLAY, "token_requests")])
def test_attacks_are_flagged_with_reason(model_path, record, hint):
    r = detection.score_activity(record, model_path=model_path)
    assert r["severity"] in ("medium", "high")
    assert r["action"] == "human_review" and r["advisory_only"] is True
    assert hint in r["reason"]
    assert 0 < r["anomaly_score"] < 1


def test_attack_scores_higher_than_normal(model_path):
    a = detection.score_activity(BOT, model_path=model_path)["anomaly_score"]
    n = detection.score_activity(NORMAL, model_path=model_path)["anomaly_score"]
    assert a > n


def test_missing_feature_is_imputed_and_bad_input_rejected(model_path):
    partial = {k: v for k, v in NORMAL.items() if k != "avg_gap_between_requests"}
    assert detection.score_activity(partial, model_path=model_path)["severity"] == "low"
    with pytest.raises(ValueError):
        detection.score_activity({"failed_logins": "lots"}, model_path=model_path)
    with pytest.raises(ValueError):
        detection.score_activity({}, model_path=model_path)


# ---------------------------------------------------------------- API
@pytest.fixture()
def client(tmp_path, model_path):
    app = create_app(db_path=tmp_path / "t.db", model_path=model_path)
    app.testing = True
    return app.test_client()


def test_score_endpoint_creates_new_alert(client):
    r = client.post("/api/security/score", json=dict(BOT, session_id="SIM-X", ip_hash="sim-bot"))
    body = r.get_json()
    assert r.status_code == 200 and body["alert_id"] and body["alert_status"] == "new"
    assert body["simulated"] is True and body["advisory_only"] is True


def test_low_score_creates_no_alert(client):
    body = client.post("/api/security/score", json=NORMAL).get_json()
    assert body["severity"] == "low" and body["alert_id"] is None
    assert client.get("/api/security/alerts").get_json()["count"] == 0


def test_alerts_and_summary_endpoints(client):
    client.post("/api/security/score", json=dict(BRUTE, session_id="SIM-1"))
    client.post("/api/security/score", json=dict(STUFFING, session_id="SIM-2"))
    alerts = client.get("/api/security/alerts?status=new").get_json()
    assert alerts["count"] == 2 and all(a["status"] == "new" for a in alerts["alerts"])
    assert client.get("/api/security/alerts?severity=bogus").status_code == 400
    s = client.get("/api/security/summary").get_json()
    assert s["total_alerts"] == 2 and s["by_status"]["new"] == 2
    assert s["model"]["trained_on"] == "SIMULATED"


@pytest.mark.parametrize("payload", [
    {}, {"failed_logins": -1}, {"failed_logins": "x"}, {"off_hours_flag": 2},
    dict(NORMAL, email="a@b.com"), dict(NORMAL, candidate="X")])
def test_bad_payloads_rejected(client, payload):
    assert client.post("/api/security/score", json=payload).status_code == 400


# ---------------------------------------------------------------- live windows
def _log(conn, rows):
    conn.executemany("INSERT INTO activity_log (event_type, account_ref, ip_hash, created_at) "
                     "VALUES (?,?,?,?)", rows)
    conn.commit()


def test_window_features_and_live_scoring(tmp_path, model_path):
    conn = db.get_conn(tmp_path / "live.db")
    now = datetime(2026, 11, 15, 14, 0, 0)
    f = lambda s: (now - timedelta(seconds=s)).strftime(live_windows.FMT)
    rows = [("login_failed", f"sim-a{i}", "sim-stuffer", f(240 - i * 5)) for i in range(25)]
    rows += [("login_success", "sim-u", "sim-user", f(100)), ("token_request", "sim-u", "sim-user", f(60))]
    _log(conn, rows)

    windows = {w["ip_hash"]: w["features"] for w in live_windows.build_windows(conn, 5, now)}
    assert windows["sim-stuffer"]["failed_logins"] == 25
    assert windows["sim-stuffer"]["distinct_accounts_per_ip"] == 25
    assert windows["sim-user"]["login_attempts"] == 1 and windows["sim-user"]["token_requests"] == 1

    out = live_windows.run_live_scoring(conn, 5, now, model_path=model_path)
    assert out["windows_scored"] == 2 and out["new_alerts"] >= 1
    again = live_windows.run_live_scoring(conn, 5, now, model_path=model_path)
    assert again["new_alerts"] == 0, "same window must not create duplicate alerts"
    alerts = db.list_alerts(conn)
    assert alerts and all(a["status"] == "new" and a["is_simulated"] for a in alerts)


def test_demo_seed_is_flagged_simulated(tmp_path, model_path):
    conn = db.get_conn(tmp_path / "demo.db")
    now = datetime(2026, 11, 15, 14, 0, 0)
    assert live_windows.seed_demo_traffic(conn, now) > 300
    out = live_windows.run_live_scoring(conn, 5, now, model_path=model_path)
    assert out["new_alerts"] >= 2
    assert all(a["is_simulated"] for a in db.list_alerts(conn))


# ---------------------------------------------------------------- ethics
def test_module_never_touches_votes():
    """The ML module may read activity_log and write security_alerts only."""
    forbidden = ("insert into votes", "update votes", "delete from votes", "drop table",
                 "update users", "delete from users", "block_user", "invalidate_vote",
                 "disable_user", "ban_ip")
    for py in Path(config.BASE_DIR).glob("*.py"):
        text = py.read_text().lower()
        for bad in forbidden:
            assert bad not in text, f"{py.name} contains '{bad}'"


def test_responses_carry_advisory_notice(client):
    body = client.post("/api/security/score", json=BOT).get_json()
    assert "never blocks" in body["notice"]
