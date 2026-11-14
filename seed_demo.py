"""Create a local demo election. Passwords are printed once for classroom use."""
import os
import random
from pathlib import Path

from werkzeug.security import generate_password_hash

from app import create_app
from database.db import get_db, init_db


def seed():
    app = create_app()
    with app.app_context():
        init_db()
        db = get_db()
        db.execute("DELETE FROM security_events")
        db.execute("DELETE FROM vote_tokens")
        db.execute("DELETE FROM ballots")
        db.execute("DELETE FROM tally_counts")
        db.execute("DELETE FROM candidates")
        db.execute("DELETE FROM users")
        db.execute("UPDATE election SET status='open' WHERE id=1")
        candidates = [("Aarav Mehta", "Unity", "◉"), ("Diya Rao", "Forward", "✦"), ("Kabir Shah", "Green Future", "⬟")]
        db.executemany("INSERT INTO candidates(name,party,symbol) VALUES(?,?,?)", candidates)
        admin_password = os.environ.get("DEMO_ADMIN_PASSWORD", "AdminDemo!2026")
        db.execute("INSERT INTO users(username,email,password_hash,role) VALUES(?,?,?,?)", ("admin", "admin@demo.local", generate_password_hash(admin_password), "admin"))
        voter_password = os.environ.get("DEMO_VOTER_PASSWORD", "VoterDemo!2026")
        db.executemany("INSERT INTO users(username,email,password_hash) VALUES(?,?,?)", [(f"voter{i:02d}", f"voter{i:02d}@demo.local", generate_password_hash(voter_password)) for i in range(1, 21)])
        samples = [("login_burst", "high", "Repeated failed sign-in attempts", .86, 1), ("unusual_rate", "medium", "Request rate above baseline", .64, 1), ("normal_login", "low", "Successful sign-in from known device", .08, 1), ("token_replay", "critical", "Duplicate token use was blocked", .97, 1), ("normal_vote", "low", "Voting flow completed normally", .12, 1)]
        db.executemany("INSERT INTO security_events(kind,severity,message,score,simulated) VALUES(?,?,?,?,?)", samples)
        db.commit()
    print("Demo seed complete. Admin: admin /", admin_password)
    print("Voters: voter01 through voter20 /", voter_password)
    print("Change demo passwords before sharing this app outside your machine.")


if __name__ == "__main__":
    seed()
