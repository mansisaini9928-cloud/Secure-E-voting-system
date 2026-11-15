"""Evaluate both models and write actual metrics and plots for review."""
import json
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.decomposition import PCA
from sklearn.metrics import (
    confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score,
)

from preprocessing import FEATURE_COLUMNS, split_dataset

HERE = Path(__file__).resolve().parent
MODEL_PATH = HERE / "model.pkl"
METRICS_PATH = HERE / "evaluation_metrics.json"


def _metrics(y_true, y_pred, scores):
    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, scores)),
        "confusion_matrix_labels_0_then_1": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
    }


def evaluate_models():
    """Evaluate trained models on the same stratified holdout set."""
    if not MODEL_PATH.exists():
        raise FileNotFoundError("model.pkl not found. Run: py train_model.py")
    bundle = joblib.load(MODEL_PATH)
    _x_train, x_test, _y_train, y_test = split_dataset()
    x_scaled = bundle["preprocessor"].transform(x_test)

    forest = bundle["random_forest"]
    forest_attack_index = list(forest.classes_).index(1)
    forest_scores = forest.predict_proba(x_scaled)[:, forest_attack_index]
    forest_pred = (forest_scores >= 0.5).astype(int)

    isolation = bundle["isolation_forest"]
    # Higher score means more anomalous; this is a ranking score, not a probability.
    anomaly_scores = -isolation.decision_function(x_scaled)
    isolation_pred = (isolation.predict(x_scaled) == -1).astype(int)

    results = {
        "dataset_note": "Synthetic simulated data only; results do not predict real election activity.",
        "test_rows": int(len(y_test)),
        "test_class_counts": {str(k): int(v) for k, v in y_test.value_counts().sort_index().items()},
        "models": {
            "isolation_forest": _metrics(y_test, isolation_pred, anomaly_scores),
            "random_forest": _metrics(y_test, forest_pred, forest_scores),
        },
    }
    METRICS_PATH.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    _plot_feature_distributions()
    _plot_confusion_matrices(y_test, isolation_pred, forest_pred)
    _plot_anomaly_histogram(y_test, anomaly_scores)
    _plot_pca(x_scaled, y_test)
    _write_report(results)

    for name, metrics in results["models"].items():
        print(f"{name}: precision={metrics['precision']:.3f}, recall={metrics['recall']:.3f}, "
              f"F1={metrics['f1_score']:.3f}, ROC-AUC={metrics['roc_auc']:.3f}")
        print("  Confusion matrix [true normal, true attack] x [pred normal, pred attack]:")
        print(np.array(metrics["confusion_matrix_labels_0_then_1"]))
    print(f"Saved metrics to {METRICS_PATH}")
    print("Saved feature_distributions.png, confusion_matrices.png, anomaly_score_histogram.png, pca_scatter.png")
    return results


def _plot_feature_distributions():
    """Plot train-independent dataset distributions by simulated class."""
    from preprocessing import load_dataset
    data = load_dataset()
    fig, axes = plt.subplots(2, 4, figsize=(16, 8))
    for axis, feature in zip(axes.flat, FEATURE_COLUMNS):
        for label, name in ((0, "normal"), (1, "simulated attack")):
            axis.hist(data.loc[data.label == label, feature], bins=24, alpha=0.55, label=name, density=True)
        axis.set_title(feature.replace("_", " "))
        axis.legend(fontsize=7)
    fig.suptitle("Synthetic feature distributions (descriptive only)")
    fig.tight_layout()
    fig.savefig(HERE / "feature_distributions.png", dpi=140)
    plt.close(fig)


def _plot_confusion_matrices(y_true, isolation_pred, forest_pred):
    fig, axes = plt.subplots(1, 2, figsize=(9, 4))
    for axis, name, predictions in zip(
        axes, ("Isolation Forest", "Random Forest"), (isolation_pred, forest_pred)
    ):
        matrix = confusion_matrix(y_true, predictions, labels=[0, 1])
        image = axis.imshow(matrix, cmap="Blues")
        axis.set_title(name)
        axis.set_xticks([0, 1], labels=["normal", "attack"])
        axis.set_yticks([0, 1], labels=["normal", "attack"])
        axis.set_xlabel("Predicted")
        axis.set_ylabel("True")
        for (row, col), value in np.ndenumerate(matrix):
            axis.text(col, row, str(value), ha="center", va="center")
    fig.colorbar(image, ax=axes.ravel().tolist(), shrink=0.8)
    fig.suptitle("Held-out synthetic test confusion matrices")
    fig.savefig(HERE / "confusion_matrices.png", dpi=140, bbox_inches="tight")
    plt.close(fig)


def _plot_anomaly_histogram(y_true, scores):
    fig, axis = plt.subplots(figsize=(8, 5))
    for label, name in ((0, "normal"), (1, "simulated attack")):
        axis.hist(scores[np.asarray(y_true) == label], bins=35, alpha=0.6, label=name, density=True)
    axis.set_xlabel("Anomaly score (higher means more unusual; not a probability)")
    axis.set_ylabel("Density")
    axis.set_title("Isolation Forest scores on held-out synthetic data")
    axis.legend()
    fig.tight_layout()
    fig.savefig(HERE / "anomaly_score_histogram.png", dpi=140)
    plt.close(fig)


def _plot_pca(x_scaled, y_true):
    points = PCA(n_components=2, random_state=42).fit_transform(x_scaled)
    fig, axis = plt.subplots(figsize=(8, 6))
    for label, name in ((0, "normal"), (1, "simulated attack")):
        mask = np.asarray(y_true) == label
        axis.scatter(points[mask, 0], points[mask, 1], s=12, alpha=0.55, label=name)
    axis.set_title("PCA view of held-out synthetic sessions")
    axis.set_xlabel("Principal component 1")
    axis.set_ylabel("Principal component 2")
    axis.legend()
    fig.tight_layout()
    fig.savefig(HERE / "pca_scatter.png", dpi=140)
    plt.close(fig)


def _write_report(results):
    lines = [
        "# ML Evaluation Report", "",
        "## Dataset and method", "",
        f"Evaluation used {results['test_rows']} held-out records from the reproducible synthetic dataset. ",
        "The training/evaluation split is stratified and the fitted imputer/scaler use training rows only. ",
        "Isolation Forest was fitted to normal training samples only; Random Forest was trained with labels.",
        "The anomaly score is a ranking score, not a calibrated probability.", "",
        "## Measured holdout results", "",
        "These metrics were measured by `evaluate.py`; they are not estimates of real election performance.", "",
        "| Model | Precision | Recall | F1 | ROC-AUC | Confusion matrix (true rows 0,1; predicted columns 0,1) |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for name, metrics in results["models"].items():
        matrix = metrics["confusion_matrix_labels_0_then_1"]
        lines.append(
            f"| {name} | {metrics['precision']:.4f} | {metrics['recall']:.4f} | "
            f"{metrics['f1_score']:.4f} | {metrics['roc_auc']:.4f} | `{matrix}` |"
        )
    lines += [
        "", "## Limitations", "",
        "- Every record is simulated; real users, election systems, and attackers may behave differently.",
        "- Labels and feature patterns were generated by code, so model scores reflect these assumptions.",
        "- Results depend on the chosen synthetic distributions, class balance, split, and thresholds.",
        "- Isolation Forest contamination is configured near the dataset's expected attack fraction.",
        "- Alerts are only security signals for human review. They must never block, reject, or invalidate votes.",
        "- Do not use voter names, personal information, candidate information, or ballot contents as model features.",
        "", "Plots: `feature_distributions.png`, `confusion_matrices.png`, `anomaly_score_histogram.png`, and `pca_scatter.png`.",
    ]
    (HERE / "evaluation_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    evaluate_models()
