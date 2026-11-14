from flask import Blueprint, jsonify

bp = Blueprint("member3_ml", __name__)


@bp.get("/health")
def health():
    return jsonify(module="machine-learning", status="stub-ready", simulated=True)
