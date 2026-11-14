
import sqlite3
import os
from flask import current_app, g


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DATABASE"],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")

    return g.db


def close_db(error=None):
    db = g.pop("db", None)

    if db is not None:
        db.close()


def init_db():
    db = get_db()

    with current_app.open_resource("database/schema.sql") as file:
        db.executescript(file.read().decode("utf8"))

    columns = [
        row["name"]
        for row in db.execute("PRAGMA table_info(users)").fetchall()
    ]

    if "failed_login_attempts" not in columns:
        db.execute("""
            ALTER TABLE users
            ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0
        """)

    if "locked_until" not in columns:
        db.execute("""
            ALTER TABLE users
            ADD COLUMN locked_until TEXT
        """)

    if "eligible" not in columns:
        db.execute("""
            ALTER TABLE users
            ADD COLUMN eligible INTEGER NOT NULL DEFAULT 0
            CHECK(eligible IN (0,1))
        """)

    db.commit()


def init_app(app):
    app.teardown_appcontext(close_db)

    with app.app_context():
        db_path = app.config["DATABASE"]

        if db_path != ":memory:":
            os.makedirs(os.path.dirname(db_path), exist_ok=True)

        init_db()
