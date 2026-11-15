"""Score one activity window and return a human-review-only alert."""
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from preprocessing import FEATURE_COLUMNS

MODEL_PATH = Path(__file__).resolve().with_name("model.pkl")


def _load_bundle():
    if not MODEL_PATH.exists():
        raise FileNotFoundError("model.pkl not found. Run: py train_model.py")
    bundle = joblib.load(MODEL_PATH)
    needed = {"isolation_forest", "random_forest", "preprocessor", "feature_columns"}
    if not needed.issubset(bundle):
        raise ValueError("model.pkl is missing required model components")
    return bundle


def score_activity(record):
    """Return anomaly score, severity, and short reason for human review only.

    `anomaly_score` ranks how unusual a window looks; it is not a probability.
    This function never changes a vote or blocks a request.
    """
    missing = [feature for feature in FEATURE_COLUMNS if feature not in record]
    if missing:
        raise ValueError(f"Activity record is missing required features: {missing}")
    values = {}
    for feature in FEATURE_COLUMNS:
        try:
            value = float(record[feature])
        except (TypeError, ValueError) as error:
            raise ValueError(f"Feature '{feature}' must be a finite number") from error
        if not np.isfinite(value):
            raise ValueError(f"Feature '{feature}' must be a finite number")
        values[feature] = value

    bundle = _load_bundle()
    frame = pd.DataFrame([values], columns=FEATURE_COLUMNS)
    transformed = bundle["preprocessor"].transform(frame)

    forest = bundle["random_forest"]
    attack_column = list(forest.classes_).index(1)
    forest_attack_score = float(forest.predict_proba(transformed)[0, attack_column])

    isolation = bundle["isolation_forest"]
    decision = float(isolation.decision_function(transformed)[0])
    # Map the Isolation Forest margin to a smooth 0..1 ranking score.
    isolation_score = float(1.0 / (1.0 + np.exp(np.clip(decision * 12.0, -60, 60))))
    anomaly_score = max(forest_attack_score, isolation_score)

    isolation_flag = isolation.predict(transformed)[0] == -1
    forest_flag = forest_attack_score >= 0.5
    if isolation_flag and forest_flag:
        reason = "Both models flag unusual security-event patterns."
    elif isolation_flag:
        reason = "Isolation Forest flags an unusual pattern for human review."
    elif forest_flag:
        reason = "Random Forest flags a pattern resembling simulated attacks."
    else:
        reason = "No strong simulated attack pattern was identified; routine review still applies."

    if anomaly_score >= 0.70:
        severity = "high"
    elif anomaly_score >= 0.40:
        severity = "medium"
    else:
        severity = "low"

    return {
        "anomaly_score": round(anomaly_score, 4),
        "severity": severity,
        "reason": reason,
    }
