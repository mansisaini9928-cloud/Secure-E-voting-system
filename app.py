import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config
from database.db import get_db, init_app as init_db_app, init_db

csrf = CSRFProtect()


def _now():
    return datetime.now(timezone.utc)


def _hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _chain_state(db):
    previous = "0" * 64
    valid_ids = []
    rows = db.execute("SELECT id,ballot_hash,previous_hash,chain_hash FROM ballots ORDER BY rowid").fetchall()
    for row in rows:
        expected = _hash(f"{previous}:{row['id']}:{row['ballot_hash']}")
        if row["previous_hash"] != previous or row["chain_hash"] != expected:
            return False, valid_ids
        valid_ids.append(row["id"])
        previous = row["chain_hash"]
    return True, valid_ids


def _create_blueprints(app):
    """Member integration points. Member 1/2/3 implementations can replace these modules."""
    from members.member1_auth import bp as member1_bp
    from members.member2_crypto import bp as member2_bp
    from members.member3_ml import bp as member3_bp
    app.register_blueprint(member1_bp, url_prefix="/member1")
    app.register_blueprint(member2_bp, url_prefix="/member2")
    app.register_blueprint(member3_bp, url_prefix="/member3")


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    csrf.init_app(app)
    init_db_app(app)
    _create_blueprints(app)

    @app.before_request
    def load_user():
        gdb = get_db()
        init_db()
        uid = session.get("user_id")
        session_user = gdb.execute("SELECT id,username,role,has_voted FROM users WHERE id=?", (uid,)).fetchone() if uid else None
        from flask import g
        g.user = session_user

    @app.context_processor
    def inject_globals():
        return {"election_status": get_db().execute("SELECT status FROM election WHERE id=1").fetchone()[0]}

    def login_required(role=None):
        def decorator(view):
            @wraps(view)
            def wrapped(*args, **kwargs):
                from flask import g
                if g.user is None:
                    flash("Please sign in to continue.", "warning")
                    return redirect(url_for("login", next=request.path))
                if role and g.user["role"] != role:
                    abort(403)
                return view(*args, **kwargs)
            return wrapped
        return decorator

    app.login_required = login_required

    @app.route("/")
    def home():
        return render_template("home.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            if len(username) < 3 or "@" not in email or len(password) < 10:
                flash("Enter a username (3+ characters), valid email, and password (10+ characters).", "danger")
            else:
                try:
                    db = get_db()
                    db.execute("INSERT INTO users(username,email,password_hash) VALUES(?,?,?)", (username, email, generate_password_hash(password)))
                    db.commit()
                    flash("Account created. You can now sign in.", "success")
                    return redirect(url_for("login"))
                except Exception:
                    get_db().rollback()
                    flash("That username or email is already registered.", "danger")
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE username=? OR email=?", (request.form.get("identity", "").strip(), request.form.get("identity", "").strip().lower())).fetchone()
            if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
                session.clear()
                session["user_id"] = user["id"]
                flash("Welcome back.", "success")
                return redirect(url_for("admin_dashboard" if user["role"] == "admin" else "voter_dashboard"))
            flash("Sign in failed. Check your credentials and try again.", "danger")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        flash("You have signed out.", "success")
        return redirect(url_for("home"))

    @app.route("/dashboard")
    @login_required("voter")
    def voter_dashboard():
        return render_template("voter_dashboard.html", user=__import__("flask").g.user)

    @app.route("/vote", methods=["GET", "POST"])
    @login_required("voter")
    def vote_page():
        db = get_db()
        candidates = db.execute("SELECT id,name,party,symbol FROM candidates WHERE active=1 ORDER BY id").fetchall()
        token = session.get("vote_token")
        if request.method == "POST" and request.form.get("action") == "request_token":
            if db.execute("SELECT status FROM election WHERE id=1").fetchone()[0] != "open":
                flash("Voting is closed.", "danger")
            elif __import__("flask").g.user["has_voted"]:
                flash("A ballot has already been submitted for this account.", "warning")
            else:
                raw = secrets.token_urlsafe(32)
                expiry = (_now() + timedelta(minutes=10)).isoformat()
                db.execute("INSERT OR REPLACE INTO vote_tokens(token_hash,user_id,expires_at,consumed) VALUES(?,?,?,0)", (_hash(raw), __import__("flask").g.user["id"], expiry))
                db.commit()
                session["vote_token"] = raw
                token = raw
                flash("A short-lived voting token is ready.", "success")
        return render_template("vote.html", candidates=candidates, has_voted=bool(__import__("flask").g.user["has_voted"]), token_ready=bool(token))

    @app.post("/api/vote/token")
    @login_required("voter")
    def request_vote_token():
        db = get_db()
        user_id = __import__("flask").g.user["id"]
        if db.execute("SELECT status FROM election WHERE id=1").fetchone()[0] != "open":
            return jsonify(error="Voting is closed."), 409
        if __import__("flask").g.user["has_voted"]:
            return jsonify(error="A ballot has already been submitted."), 409
        token = secrets.token_urlsafe(32)
        db.execute("INSERT OR REPLACE INTO vote_tokens(token_hash,user_id,expires_at,consumed) VALUES(?,?,?,0)", (_hash(token), user_id, (_now()+timedelta(minutes=10)).isoformat()))
        db.commit()
        session["vote_token"] = token
        return jsonify(token=token, expires_in=600)

    @app.post("/api/vote/cast")
    @login_required("voter")
    def cast_vote():
        db = get_db()
        from flask import g
        user_id = g.user["id"]
        candidate_id = request.form.get("candidate_id", type=int)
        token = request.form.get("token", "")
        if db.execute("SELECT status FROM election WHERE id=1").fetchone()[0] != "open":
            return jsonify(error="Voting is closed."), 409
        candidate = db.execute("SELECT id FROM candidates WHERE id=? AND active=1", (candidate_id,)).fetchone()
        token_row = db.execute("SELECT * FROM vote_tokens WHERE token_hash=? AND user_id=? AND consumed=0", (_hash(token), user_id)).fetchone()
        if not candidate or not token_row or token_row["expires_at"] < _now().isoformat():
            return jsonify(error="The candidate selection or voting token is invalid or expired."), 400
        if g.user["has_voted"]:
            return jsonify(error="A ballot has already been submitted."), 409
        ballot_id = str(uuid.uuid4())
        # The choice is used only in this request to update an unlinked aggregate.
        ballot_hash = _hash(f"{secrets.token_hex(32)}:{ballot_id}")
        tail = db.execute("SELECT chain_hash FROM ballots ORDER BY rowid DESC LIMIT 1").fetchone()
        previous = tail[0] if tail else "0" * 64
        chain_hash = _hash(f"{previous}:{ballot_id}:{ballot_hash}")
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO ballots(id,ballot_hash,previous_hash,chain_hash) VALUES(?,?,?,?)", (ballot_id, ballot_hash, previous, chain_hash))
            db.execute("INSERT OR IGNORE INTO tally_counts(candidate_id,vote_count) VALUES(?,0)", (candidate_id,))
            db.execute("UPDATE tally_counts SET vote_count=vote_count+1 WHERE candidate_id=?", (candidate_id,))
            db.execute("UPDATE users SET has_voted=1 WHERE id=? AND has_voted=0", (user_id,))
            if db.execute("SELECT changes()").fetchone()[0] != 1:
                db.rollback()
                return jsonify(error="A ballot has already been submitted."), 409
            db.execute("UPDATE vote_tokens SET consumed=1 WHERE token_hash=?", (_hash(token),))
            db.commit()
        except Exception:
            db.rollback()
            return jsonify(error="We could not record your ballot. Please try again."), 500
        session.pop("vote_token", None)
        # Do not return, log, or persist candidate_id. Response contains receipt metadata only.
        return jsonify(receipt={"ballot_id": ballot_id, "ballot_hash": ballot_hash}), 201

    @app.route("/receipt")
    @login_required("voter")
    def receipt_page():
        receipt = session.pop("receipt", None)
        return render_template("receipt.html", receipt=receipt)

    @app.route("/admin")
    @login_required("admin")
    def admin_dashboard():
        db = get_db()
        stats = {"voters": db.execute("SELECT COUNT(*) FROM users WHERE role='voter'").fetchone()[0], "votes": db.execute("SELECT COUNT(*) FROM ballots").fetchone()[0], "status": db.execute("SELECT status FROM election WHERE id=1").fetchone()[0]}
        candidates = db.execute("SELECT c.*, COALESCE(t.vote_count,0) votes FROM candidates c LEFT JOIN tally_counts t ON t.candidate_id=c.id ORDER BY c.id").fetchall()
        valid, _ = _chain_state(db)
        return render_template("admin_dashboard.html", stats=stats, candidates=candidates, chain_valid=valid)

    @app.post("/admin/election/<action>")
    @login_required("admin")
    def election_action(action):
        if action not in ("open", "close"):
            abort(404)
        db = get_db()
        db.execute("UPDATE election SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=1", (action,))
        db.commit()
        flash(f"Election {action}ed.", "success")
        return redirect(url_for("admin_dashboard"))

    @app.post("/admin/tally")
    @login_required("admin")
    def tally():
        db = get_db()
        if db.execute("SELECT status FROM election WHERE id=1").fetchone()[0] != "closed":
            flash("Close the election before tallying.", "warning")
        elif not _chain_state(db)[0]:
            flash("Chain verification failed. The tally is withheld.", "danger")
        else:
            session["tally_ready"] = True
            flash("Verified aggregate tally is ready.", "success")
        return redirect(url_for("results"))

    @app.post("/admin/verify")
    @login_required("admin")
    def verify_chain():
        valid, _ = _chain_state(get_db())
        flash("Ballot chain verified." if valid else "Ballot chain integrity check failed.", "success" if valid else "danger")
        return redirect(url_for("admin_dashboard"))

    @app.route("/security")
    @login_required("admin")
    def security_dashboard():
        db = get_db()
        events = db.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT 100").fetchall()
        normal = db.execute("SELECT COUNT(*) FROM security_events WHERE severity='low'").fetchone()[0]
        suspicious = db.execute("SELECT COUNT(*) FROM security_events WHERE severity IN ('medium','high','critical')").fetchone()[0]
        chart = db.execute("SELECT id,score FROM security_events ORDER BY id DESC LIMIT 20").fetchall()[::-1]
        return render_template("security_dashboard.html", events=events, normal=normal, suspicious=suspicious, chart=chart)

    @app.post("/security/events/<int:event_id>/review")
    @login_required("admin")
    def mark_reviewed(event_id):
        db = get_db()
        db.execute("UPDATE security_events SET reviewed=1 WHERE id=?", (event_id,))
        db.commit()
        flash("Security event marked as reviewed.", "success")
        return redirect(url_for("security_dashboard"))

    @app.route("/results")
    @login_required("admin")
    def results():
        db = get_db()
        valid, _ = _chain_state(db)
        released = db.execute("SELECT status FROM election WHERE id=1").fetchone()[0] == "closed" and session.get("tally_ready") and valid
        rows = db.execute("SELECT c.name,c.party,COALESCE(t.vote_count,0) votes FROM candidates c LEFT JOIN tally_counts t ON t.candidate_id=c.id WHERE c.active=1 ORDER BY c.id").fetchall() if released else []
        rejects = [] if valid else [{"id":"CHAIN-INVALID", "reason":"Ballot chain hash or previous hash did not match."}]
        return render_template("results.html", rows=rows, released=released, valid=valid, total=sum(r["votes"] for r in rows), rejects=rejects)

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", code=403, message="You do not have access to this page."), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="We could not find that page."), 404

    @app.errorhandler(500)
    def server_error(_error):
        return render_template("error.html", code=500, message="Something went wrong. Please try again."), 500

    return app


if __name__ == "__main__":
    create_app().run(debug=False)
