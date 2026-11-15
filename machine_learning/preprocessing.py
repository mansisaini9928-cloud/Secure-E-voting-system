"""Dataset validation, leakage-safe splitting, and fitted preprocessing."""
from pathlib import Path

import joblib
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

FEATURE_COLUMNS = [
    "failed_logins", "requests_per_minute", "login_attempts", "token_requests",
    "distinct_accounts_per_ip", "avg_gap_between_requests", "session_duration",
    "off_hours_flag",
]
TARGET_COLUMNS = ["attack_type", "label"]
REQUIRED_COLUMNS = FEATURE_COLUMNS + TARGET_COLUMNS
RANDOM_STATE = 42


def validate_dataset(data):
    """Check schema and target values; numeric feature gaps are imputed later."""
    missing_columns = [name for name in REQUIRED_COLUMNS if name not in data.columns]
    if missing_columns:
        raise ValueError(f"Dataset is missing required columns: {missing_columns}")
    if data["label"].isna().any() or data["attack_type"].isna().any():
        raise ValueError("Target columns 'label' and 'attack_type' cannot be missing")
    labels = set(pd.to_numeric(data["label"], errors="raise").unique())
    if not labels.issubset({0, 1}) or not labels:
        raise ValueError("label must contain only 0 (normal) and 1 (attack)")
    # Convert numeric columns carefully so malformed values fail with a useful message.
    for feature in FEATURE_COLUMNS:
        try:
            data[feature] = pd.to_numeric(data[feature], errors="raise")
        except (TypeError, ValueError) as error:
            raise ValueError(f"Feature '{feature}' must contain numeric values") from error
    return data


def load_dataset(path=None):
    """Read and validate the simulated CSV next to this module by default."""
    csv_path = Path(path) if path else Path(__file__).resolve().with_name("dataset.csv")
    return validate_dataset(pd.read_csv(csv_path))


def split_dataset(data=None, test_size=0.20, random_state=RANDOM_STATE):
    """Split before fitting transforms; stratification preserves class balance."""
    dataset = validate_dataset(data.copy() if data is not None else load_dataset())
    x_train, x_test, y_train, y_test = train_test_split(
        dataset[FEATURE_COLUMNS], dataset["label"].astype(int),
        test_size=test_size, random_state=random_state, stratify=dataset["label"].astype(int),
    )
    return x_train, x_test, y_train, y_test


def build_preprocessing_pipeline():
    """Return imputation and scaling steps; fit only on training data."""
    return Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
    ])


def fit_preprocessing_pipeline(x_train, artifact_path=None):
    """Fit and optionally save preprocessing using training rows only."""
    pipeline = build_preprocessing_pipeline()
    pipeline.fit(x_train[FEATURE_COLUMNS])
    if artifact_path is not None:
        joblib.dump(pipeline, artifact_path)
    return pipeline
