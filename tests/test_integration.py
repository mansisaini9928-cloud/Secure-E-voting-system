import hashlib

import pytest
from werkzeug.security import generate_password_hash

from app import create_app
from database.db import get_db


@pytest.fixture
def app(tmp_path):
    database = tmp_path / "integration.db"
    app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False, "SECRET_KEY": "integration-test-key", "DATABASE": str(database)})
    with app.app_context():
        db = get_db()
        db.execute("INSERT INTO candidates(name,party,symbol) VALUES('Test Candidate','Demo','T')")
        db.execute("INSERT INTO users(username,email,password_hash) VALUES('voter','voter@test.local',?)", (generate_password_hash("LongDemoPass!123"),))
        db.execute("INSERT INTO users(username,email,password_hash,role) VALUES('admin','admin@test.local',?,'admin')", (generate_password_hash("LongDemoPass!123"),))
        db.execute("INSERT INTO security_events(kind,severity,message,score,simulated) VALUES('test','high','Suspicious test signal',0.91,1)")
        db.commit()
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def login(client, identity, password="LongDemoPass!123"):
    return client.post("/login", data={"identity": identity, "password": password}, follow_redirects=True)


def test_register_login_token_vote_double_vote_tally_results_and_tamper(client, app):
    response = client.post("/register", data={"username":"newvoter", "email":"new@test.local", "password":"LongPassword!123"})
    assert response.status_code == 302
    assert login(client, "voter").status_code == 200
    token_response = client.post("/api/vote/token")
    assert token_response.status_code == 200
    token = token_response.get_json()["token"]
    cast = client.post("/api/vote/cast", data={"candidate_id":"1", "token":token})
    assert cast.status_code == 201
    receipt = cast.get_json()["receipt"]
    assert set(receipt) == {"ballot_id", "ballot_hash"}
    assert client.post("/api/vote/cast", data={"candidate_id":"1", "token":token}).status_code == 409

    login(client, "admin")
    assert client.post("/admin/tally").status_code == 302
    assert client.get("/results").status_code == 200
    assert b"Results are not available" in client.get("/results").data
    client.post("/admin/election/close")
    client.post("/admin/tally")
    results = client.get("/results")
    assert b"Verified outcome" in results.data
    assert b">1<" in results.data
    assert b"Test Candidate" in results.data

    with app.app_context():
        db = get_db()
        db.execute("UPDATE ballots SET chain_hash=? WHERE id=?", ("f" * 64, receipt["ballot_id"]))
        db.commit()
    tampered_results = client.get("/results")
    assert b"INTEGRITY FAILURE" in tampered_results.data
    assert b"CHAIN-INVALID" in tampered_results.data
    assert b"Test Candidate" not in tampered_results.data


def test_anomaly_alert_appears_in_security_dashboard(client):
    login(client, "admin")
    response = client.get("/security")
    assert response.status_code == 200
    assert b"Suspicious test signal" in response.data
    assert b"SIMULATED DATA" in response.data
