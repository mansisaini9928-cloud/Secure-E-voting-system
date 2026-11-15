"""Evaluate both models on the held-out stratified test set and save charts (PNG).

Run:  python machine_learning/evaluate.py
All metrics and charts are computed on SIMULATED data and labelled as such.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.decomposition import PCA
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)

from machine_learning import config
from machine_learning.preprocessing import load_bundle, load_dataset, split_data

C_NORMAL, C_ATTACK, INK = "#0072B2", "#D55E00", "#333333"
SIM_TAG = "SIMULATED DATA"


def _style():
    plt.rcParams.update({
        "figure.facecolor": "white", "axes.facecolor": "white", "axes.edgecolor": "#999999",
        "axes.labelcolor": INK, "xtick.color": INK, "ytick.color": INK, "text.color": INK,
        "axes.spines.top": False, "axes.spines.right": False, "font.size": 10,
    })


def _footer(fig):
    fig.text(0.5, 0.005, f"{SIM_TAG} - simulated attacks, not real traffic",
             ha="center", fontsize=8, color="#666666")


def _metrics(y, pred, score):
    return {
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, score)),
        "accuracy": float(accuracy_score(y, pred)),
        "confusion_matrix": confusion_matrix(y, pred, labels=[0, 1]).tolist(),
    }


def _per_attack_recall(test_df, pred):
    out = {}
    for kind in config.ATTACK_TYPES:
        m = (test_df["attack_type"] == kind).values
        out[kind] = float(pred[m].mean()) if m.any() else None
    return out


def compute(bundle, test_df):
    X, y = test_df[config.FEATURES], test_df["label"].values
    iso, rf = bundle["isolation_forest"], bundle["random_forest"]

    iso_scores = -iso.score_samples(X)
    iso_pred = (iso.predict(X) == -1).astype(int)
    rf_proba = rf.predict_proba(X)[:, 1]
    rf_pred = rf.predict(X)

    results = {
        "data_source": "SIMULATED",
        "test_rows": int(len(test_df)),
        "test_attack_share": float(y.mean()),
        "majority_class_baseline_accuracy": float(1 - y.mean()),
        "contamination": bundle["contamination"],
        "thresholds": bundle["thresholds"],
        "isolation_forest": _metrics(y, iso_pred, iso_scores),
        "random_forest": _metrics(y, rf_pred, rf_proba),
    }
    results["isolation_forest"]["recall_by_attack_type"] = _per_attack_recall(test_df, iso_pred)
    results["random_forest"]["recall_by_attack_type"] = _per_attack_recall(test_df, rf_pred)
    return results, iso_scores, iso_pred, rf_pred


def plot_feature_distributions(df, out):
    fig, axes = plt.subplots(2, 4, figsize=(15, 6.5))
    for ax, feat in zip(axes.ravel(), config.FEATURES):
        vals = df[feat].dropna()
        hi = vals.quantile(0.995)
        bins = np.linspace(vals.min(), max(hi, vals.min() + 1), 35)
        for lbl, color, name in ((0, C_NORMAL, "Normal"), (1, C_ATTACK, "Simulated attack")):
            ax.hist(df.loc[df["label"] == lbl, feat].dropna().clip(upper=hi), bins=bins,
                    density=True, alpha=0.6, color=color, label=name)
        ax.set_title(feat, fontsize=10)
        ax.set_yticks([])
    axes[0, 0].legend(frameon=False, fontsize=8)
    fig.suptitle(f"Feature distributions: normal vs simulated attacks  [{SIM_TAG}]", fontsize=12)
    _footer(fig)
    fig.tight_layout(rect=(0, 0.02, 1, 0.96))
    fig.savefig(out, dpi=140)
    plt.close(fig)


def plot_confusion_matrices(results, out):
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.4))
    for ax, key, title in ((axes[0], "isolation_forest", "Isolation Forest (unsupervised)"),
                           (axes[1], "random_forest", "Random Forest (supervised)")):
        cm = np.array(results[key]["confusion_matrix"])
        ax.imshow(cm, cmap="Blues")
        for (i, j), v in np.ndenumerate(cm):
            ax.text(j, i, f"{v:,}", ha="center", va="center", fontsize=13,
                    color="white" if v > cm.max() / 2 else INK)
        ax.set_xticks([0, 1], ["Pred normal", "Pred attack"])
        ax.set_yticks([0, 1], ["True normal", "True attack"])
        ax.set_title(f"{title}\nrecall {results[key]['recall']:.2f} | precision "
                     f"{results[key]['precision']:.2f}", fontsize=10)
        for s in ax.spines.values():
            s.set_visible(False)
    fig.suptitle(f"Confusion matrices on held-out test set  [{SIM_TAG}]", fontsize=12)
    _footer(fig)
    fig.tight_layout(rect=(0, 0.03, 1, 0.94))
    fig.savefig(out, dpi=140)
    plt.close(fig)


def plot_score_histogram(test_df, iso_scores, thresholds, out):
    y = test_df["label"].values
    fig, ax = plt.subplots(figsize=(9, 4.8))
    bins = np.linspace(iso_scores.min(), iso_scores.max(), 50)
    ax.hist(iso_scores[y == 0], bins=bins, color=C_NORMAL, alpha=0.65, label="Normal")
    ax.hist(iso_scores[y == 1], bins=bins, color=C_ATTACK, alpha=0.75, label="Simulated attack")
    ax.axvline(thresholds["medium"], color=INK, ls="--", lw=1.2)
    ax.axvline(thresholds["high"], color=INK, ls=":", lw=1.2)
    ymax = ax.get_ylim()[1]
    ax.text(thresholds["medium"], ymax * 0.95, " medium", fontsize=8, va="top")
    ax.text(thresholds["high"], ymax * 0.85, " high", fontsize=8, va="top")
    ax.set_yscale("log")
    ax.set_xlabel("Anomaly score (higher = more anomalous)")
    ax.set_ylabel("Sessions (log scale)")
    ax.legend(frameon=False)
    ax.set_title(f"Isolation Forest anomaly scores  [{SIM_TAG}]", fontsize=12)
    _footer(fig)
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    fig.savefig(out, dpi=140)
    plt.close(fig)


def plot_pca(bundle, test_df, iso_pred, out):
    prep = bundle["isolation_forest"].named_steps["prep"]
    Z = PCA(n_components=2, random_state=config.RANDOM_SEED).fit(
        prep.transform(test_df[config.FEATURES]))
    pts = Z.transform(prep.transform(test_df[config.FEATURES]))
    y = test_df["label"].values
    fig, axes = plt.subplots(1, 2, figsize=(12, 5), sharex=True, sharey=True)
    for ax, labels, title in ((axes[0], y, "True label"),
                              (axes[1], iso_pred, "Isolation Forest verdict")):
        ax.scatter(pts[labels == 0, 0], pts[labels == 0, 1], s=6, alpha=0.3, color=C_NORMAL,
                   label="Normal")
        ax.scatter(pts[labels == 1, 0], pts[labels == 1, 1], s=14, alpha=0.8, color=C_ATTACK,
                   marker="D", label="Attack" if title == "True label" else "Flagged anomalous")
        ax.set_title(title, fontsize=10)
        ax.set_xlabel(f"PC1 ({Z.explained_variance_ratio_[0]:.0%} variance)")
        ax.legend(frameon=False, fontsize=8, loc="upper right")
    axes[0].set_ylabel(f"PC2 ({Z.explained_variance_ratio_[1]:.0%} variance)")
    fig.suptitle(f"PCA 2D projection: normal vs anomalous  [{SIM_TAG}]", fontsize=12)
    _footer(fig)
    fig.tight_layout(rect=(0, 0.03, 1, 0.95))
    fig.savefig(out, dpi=140)
    plt.close(fig)


def evaluate(model_path=config.MODEL_PATH, dataset_path=config.DATASET_PATH,
             output_dir=config.OUTPUT_DIR, make_plots=True):
    _style()
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    df = load_dataset(dataset_path)
    _, test_df = split_data(df)
    bundle = load_bundle(model_path)
    results, iso_scores, iso_pred, _ = compute(bundle, test_df)
    (output_dir / "metrics.json").write_text(json.dumps(results, indent=2))
    if make_plots:
        plot_feature_distributions(df, output_dir / "feature_distributions.png")
        plot_confusion_matrices(results, output_dir / "confusion_matrices.png")
        plot_score_histogram(test_df, iso_scores, bundle["thresholds"],
                             output_dir / "anomaly_score_histogram.png")
        plot_pca(bundle, test_df, iso_pred, output_dir / "pca_scatter.png")
    return results


def main():
    r = evaluate()
    print(config.SIM_NOTICE)
    print(f"Test rows: {r['test_rows']:,}  attack share: {r['test_attack_share']:.2%}  "
          f"(always-'normal' accuracy would be {r['majority_class_baseline_accuracy']:.2%})")
    for key in ("isolation_forest", "random_forest"):
        m = r[key]
        print(f"\n{key}: precision={m['precision']:.3f} recall={m['recall']:.3f} "
              f"f1={m['f1']:.3f} roc_auc={m['roc_auc']:.3f} accuracy={m['accuracy']:.3f}")
        print(f"  confusion matrix [[TN, FP], [FN, TP]] = {m['confusion_matrix']}")
        print(f"  recall by attack type: { {k: round(v, 3) for k, v in m['recall_by_attack_type'].items()} }")
    print(f"\nCharts saved in {config.OUTPUT_DIR}")


if __name__ == "__main__":
    main()
