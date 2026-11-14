from flask import Blueprint, jsonify

bp = Blueprint("member1_auth", __name__)


@bp.get("/health")
def health():
    return jsonify(module="auth", status="stub-ready")
