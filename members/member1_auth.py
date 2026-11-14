import hashlib
from datetime import datetime, timezone

from flask import Blueprint, jsonify

bp = Blueprint("member1_auth", __name__)


def verify_and_consume_token(token, db_connection):
    """
    Verify a voting token and consume it so it cannot be reused.
    Returns True if valid, otherwise False.
    """

    if not token:
        return False

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    current_time = datetime.now(timezone.utc).isoformat()

    cursor = db_connection.execute(
        """
        UPDATE vote_tokens
        SET consumed = 1
        WHERE token_hash = ?
        AND consumed = 0
        AND expires_at > ?
        """,
        (token_hash, current_time)
    )

    if cursor.rowcount == 1:
        db_connection.commit()
        return True

    return False


@bp.get("/health")
def health():
    return jsonify(module="auth", status="stub-ready")