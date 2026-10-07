"""Reproduce the benchmark overlap diagnostic as a publication-ready figure.

Run from any directory with the project's Python environment:
    .venv/bin/python paper/figures/plot_overlap.py

Class probabilities and the 60-bin histogram-intersection coefficients match
analysis/06_overlap.py. The handle-count display uses 60 common geometric bins
across both classes, retaining every record including the extreme outlier;
these display bins do not alter the overlap-coefficient calculations.
The fitted probabilities describe class separation in the recorded feature
space; they are not estimates of capture protocol or causal propensity.
"""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter, MaxNLocator
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_predict
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = Path(__file__).resolve().parent


def overlap(a, b, bins=60):
    """Histogram intersection using the original shared 60-bin definition."""
    lo, hi = min(a.min(), b.min()), max(a.max(), b.max())
    if lo == hi:
        return 1.0
    edges = np.linspace(lo, hi, bins + 1)
    ha, _ = np.histogram(a, edges, density=False)
    hb, _ = np.histogram(b, edges, density=False)
    ha = ha / ha.sum()
    hb = hb / hb.sum()
    return float(np.minimum(ha, hb).sum())


def main():
    df = pd.read_csv(ROOT / "Obfuscated-MalMem2022.csv")
    y = (df["Class"] == "Malware").astype(int).values
    features = [
        c for c in df.columns
        if c not in ("Category", "Class") and df[c].nunique() > 1
    ]
    rows = [
        (c, overlap(df.loc[y == 0, c].values, df.loc[y == 1, c].values))
        for c in features
    ]
    ov = pd.DataFrame(rows, columns=["feature", "overlap"]).sort_values("overlap")
    probabilities = cross_val_predict(
        make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000)),
        df[features], y, cv=5, method="predict_proba",
    )[:, 1]
    middle = (probabilities > 0.1) & (probabilities < 0.9)
    print(f"Records: {len(df):,}; nonconstant features: {len(features)}")
    print(f"Records with 0.1 < e(x) < 0.9: {middle.sum():,} ({100 * middle.mean():.2f}%)")
    print(f"Records outside that band: {100 * (1 - middle.mean()):.2f}%")

    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 8,
        "axes.labelsize": 8,
        "axes.titlesize": 8,
        "axes.titleweight": "normal",
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "legend.fontsize": 7,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.linewidth": 0.6,
        "xtick.major.width": 0.6,
        "ytick.major.width": 0.6,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "savefig.facecolor": "white",
    })
    fig, axes = plt.subplots(
        1, 3, figsize=(7, 3.1), layout="constrained",
        gridspec_kw={"width_ratios": [1, 1, 1.15]},
    )
    colors = ("#2878B5", "#C85A17")
    labels = ("Benign", "Malware")
    handles = df["handles.nhandles"]
    if handles.min() <= 0:
        raise ValueError("Geometric handle-count bins require positive values.")
    handle_edges = np.geomspace(handles.min(), handles.max(), 61)
    handle_edges[[0, -1]] = [handles.min(), handles.max()]
    # Probability histograms retain the original 50-bin display. The handle
    # histograms share 60 geometric bins so classes are compared on equal terms.
    for class_value, label, color in zip((0, 1), labels, colors):
        selected = y == class_value
        axes[0].hist(
            probabilities[selected], bins=50, alpha=0.72,
            label=label, color=color, linewidth=0,
        )
        handle_counts, _, _ = axes[1].hist(
            handles[selected], bins=handle_edges,
            label=label, color=color, histtype="step", linewidth=1,
        )
        if int(handle_counts.sum()) != int(selected.sum()):
            raise RuntimeError(f"The displayed handle histogram lost {label} records.")
        print(f"Handle histogram ({label}): {int(handle_counts.sum()):,} records in 60 common bins")

    axes[0].set_title("(a) Out-of-fold\nclass probabilities", pad=9)
    axes[0].set_xlabel("Predicted malware\n" + r"probability $e(x)$")
    axes[0].set_xlim(-0.025, 1.025)
    axes[0].set_xticks([0, 0.5, 1])
    axes[0].text(
        0.5, 0.68,
        f"{100 * middle.mean():.2f}% of records\nin 0.1 < e(x) < 0.9",
        transform=axes[0].transAxes, ha="center", va="center", fontsize=7,
    )
    axes[0].legend(loc="upper center", frameon=False, handlelength=1.1)
    axes[1].set_title("(b) Handle-count\ndistributions", pad=9)
    for ax in axes[:2]:
        ax.set_ylabel("Records")
        ax.yaxis.set_major_locator(MaxNLocator(4, integer=True))
        ax.yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value / 1000:g}k" if value else "0"))
        ax.grid(axis="y", color="#dddddd", linewidth=0.45, zorder=0)
        ax.set_axisbelow(True)
    # Common geometric display bins resolve the lower handle counts while
    # logarithmic axes retain visibility of the full range and sparse tail.
    axes[1].set_xscale("log")
    axes[1].set_yscale("log")
    axes[1].set_xlim(3000, 1_500_000)
    axes[1].set_ylim(0.8, 60_000)
    axes[1].set_xticks([1e4, 1e5, 1e6], labels=["10k", "100k", "1M"])
    axes[1].set_yticks([1, 100, 10_000], labels=["1", "100", "10k"])
    axes[1].minorticks_off()
    axes[1].set_xlabel("handles.nhandles\n(log scale)")
    axes[1].set_ylabel("Records (log scale)")

    smallest = ov.head(15)
    axes[2].barh(smallest.feature, smallest.overlap, color="#438873", height=0.7)
    axes[2].invert_yaxis()
    axes[2].set_title("(c) Smallest\ndistributional overlap", pad=9)
    axes[2].set_xlabel("Histogram overlap\ncoefficient")
    axes[2].tick_params(axis="y", labelsize=6.7, length=0, pad=3)
    axes[2].xaxis.set_major_locator(MaxNLocator(3))
    axes[2].grid(axis="x", color="#dddddd", linewidth=0.45)
    axes[2].set_axisbelow(True)
    for suffix in ("pdf", "png"):
        destination = OUTPUT / f"feature_overlap.{suffix}"
        fig.savefig(destination, dpi=300)
        print(f"Saved {destination}")
    plt.close(fig)


if __name__ == "__main__":
    main()
