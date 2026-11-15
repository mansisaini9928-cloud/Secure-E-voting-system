"""Train unsupervised and supervised models on simulated event records."""
from pathlib import Path

import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from preprocessing import FEATURE_COLUMNS, fit_preprocessing_pipeline, split_dataset

HERE = Path(__file__).resolve().parent
MODEL_PATH = HERE / "model.pkl"
PREPROCESSOR_PATH = HERE / "preprocessing_pipeline.pkl"
RANDOM_STATE = 42
EXPECTED_ATTACK_RATE = 0.05


def train_models():
    """Fit transforms on train rows, then fit both models without test leakage."""
    x_train, _x_test, y_train, _y_test = split_dataset()
    preprocessor = fit_preprocessing_pipeline(x_train, PREPROCESSOR_PATH)
    x_train_scaled = preprocessor.transform(x_train)

    # Isolation Forest learns the normal pattern only. Its contamination is the
    # expected anomaly fraction and affects its decision threshold.
    normal_rows = y_train.to_numpy() == 0
    isolation_forest = IsolationForest(
        n_estimators=250,
        contamination=EXPECTED_ATTACK_RATE,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    isolation_forest.fit(x_train_scaled[normal_rows])

    # Random Forest is a supervised comparison trained on both classes.
    random_forest = RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced_subsample",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    random_forest.fit(x_train_scaled, y_train)

    bundle = {
        "isolation_forest": isolation_forest,
        "random_forest": random_forest,
        "preprocessor": preprocessor,
        "feature_columns": FEATURE_COLUMNS,
        "expected_attack_rate": EXPECTED_ATTACK_RATE,
        "random_state": RANDOM_STATE,
    }
    joblib.dump(bundle, MODEL_PATH)

    print(f"Training rows: {len(y_train):,}")
    print("Training class distribution:", y_train.value_counts().sort_index().to_dict())
    print(f"Isolation Forest normal-only training rows: {int(normal_rows.sum()):,}")
    print(f"Isolation Forest contamination: {EXPECTED_ATTACK_RATE:.2%}")
    print(f"Saved fitted preprocessing pipeline: {PREPROCESSOR_PATH}")
    print(f"Saved both models and pipeline: {MODEL_PATH}")
    return bundle


if __name__ == "__main__":
    train_models()
