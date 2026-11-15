"""Loading, splitting and the preprocessing Pipeline (impute -> scale)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from machine_learning import config


def load_dataset(path=config.DATASET_PATH) -> pd.DataFrame:
    return pd.read_csv(path)


def split_data(df: pd.DataFrame, test_size=0.25, seed=config.RANDOM_SEED):
    """Stratified train/test split on the binary label. Returns two DataFrames."""
    return train_test_split(df, test_size=test_size, stratify=df["label"], random_state=seed)


def build_preprocessor() -> Pipeline:
    """Median-impute missing values, then StandardScaler (fit only on training data)."""
    return Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
    ])


def build_isolation_forest_pipeline(contamination=0.05, seed=config.RANDOM_SEED) -> Pipeline:
    return Pipeline([
        ("prep", build_preprocessor()),
        ("model", IsolationForest(n_estimators=200, max_samples=512, contamination=contamination,
                                  random_state=seed, n_jobs=-1)),
    ])


def build_random_forest_pipeline(seed=config.RANDOM_SEED) -> Pipeline:
    return Pipeline([
        ("prep", build_preprocessor()),
        ("model", RandomForestClassifier(n_estimators=300, min_samples_leaf=2,
                                         class_weight="balanced_subsample",
                                         random_state=seed, n_jobs=-1)),
    ])


def save_bundle(bundle: dict, path=config.MODEL_PATH):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)


def load_bundle(path=config.MODEL_PATH) -> dict:
    return joblib.load(path)
