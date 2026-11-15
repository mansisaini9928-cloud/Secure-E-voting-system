"""Train Isolation Forest (unsupervised) and Random Forest (supervised comparison).

Run:  python machine_learning/train_model.py
Saves model.pkl (joblib) containing both full Pipelines (imputer -> scaler -> model).
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import sklearn
from sklearn.metrics import fbeta_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from machine_learning import config
from machine_learning.preprocessing import (build_isolation_forest_pipeline,
                                            build_random_forest_pipeline, load_dataset,
                                            save_bundle, split_data)

CONTAMINATION_GRID = [0.01, 0.02, 0.03, 0.05, 0.07, 0.10, 0.15]
ATTACK_LEAK = 0.01  # Isolation Forest sees ~99% normal rows (like real unlabeled logs with a few attacks)


def isolation_forest_training_rows(X, y, leak=ATTACK_LEAK, seed=config.RANDOM_SEED):
    """Mostly normal rows plus a tiny fraction of attacks (unsupervised = labels are not used to fit)."""
    normal = X[y == 0]
    attacks = X[y == 1]
    n_leak = min(len(attacks), int(round(leak * len(normal))))
    leaked = attacks.sample(n=n_leak, random_state=seed) if n_leak else attacks.iloc[:0]
    return normal.__class__(np.vstack([normal.values, leaked.values]), columns=X.columns)


def tune_contamination(X_train, y_train, seed=config.RANDOM_SEED, grid=CONTAMINATION_GRID):
    """Pick contamination on a validation slice of the TRAINING data (never the test set).
    Criterion: F2 score, which weights recall twice as much as precision."""
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_train, y_train, test_size=0.25, stratify=y_train, random_state=seed)
    fit_rows = isolation_forest_training_rows(X_fit, y_fit, seed=seed)
    table = []
    for c in grid:
        pipe = build_isolation_forest_pipeline(c, seed).fit(fit_rows)
        pred = (pipe.predict(X_val) == -1).astype(int)
        table.append({
            "contamination": c,
            "precision": float(precision_score(y_val, pred, zero_division=0)),
            "recall": float(recall_score(y_val, pred, zero_division=0)),
            "f2": float(fbeta_score(y_val, pred, beta=2, zero_division=0)),
        })
    best = max(table, key=lambda r: r["f2"])
    return best["contamination"], table


def train(df, model_path=config.MODEL_PATH, seed=config.RANDOM_SEED, verbose=True):
    train_df, _ = split_data(df, seed=seed)
    X, y = train_df[config.FEATURES], train_df["label"]

    contamination, tuning = tune_contamination(X, y, seed)
    if verbose:
        print("Contamination tuning (validation slice of training data):")
        for r in tuning:
            print(f"  c={r['contamination']:<5} precision={r['precision']:.3f} "
                  f"recall={r['recall']:.3f} F2={r['f2']:.3f}")
        print(f"Chosen contamination: {contamination}")

    fit_rows = isolation_forest_training_rows(X, y, seed=seed)
    iso = build_isolation_forest_pipeline(contamination, seed).fit(fit_rows)

    # Severity thresholds on the anomaly score s = -score_samples (0..1, higher = more anomalous)
    normal_scores = -iso.score_samples(X[y == 0])
    boundary = float(-iso.named_steps["model"].offset_)
    high = float(max(np.percentile(normal_scores, 99), boundary + 0.03))
    thresholds = {"medium": boundary, "high": high}

    rf = build_random_forest_pipeline(seed).fit(X, y)

    bundle = {
        "isolation_forest": iso,
        "random_forest": rf,
        "features": list(config.FEATURES),
        "thresholds": thresholds,
        "contamination": contamination,
        "tuning": tuning,
        "meta": {
            "data_source": "SIMULATED",
            "notice": config.SIM_NOTICE,
            "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "seed": seed,
            "sklearn_version": sklearn.__version__,
            "train_rows": int(len(train_df)),
        },
    }
    save_bundle(bundle, model_path)
    return bundle


def main():
    df = load_dataset()
    bundle = train(df)
    config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (config.OUTPUT_DIR / "contamination_tuning.json").write_text(
        json.dumps(bundle["tuning"], indent=2))
    print(f"Thresholds: {bundle['thresholds']}")
    print(f"Saved {config.MODEL_PATH}")
    print(config.SIM_NOTICE)


if __name__ == "__main__":
    main()
