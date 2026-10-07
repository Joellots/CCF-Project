"""Reproduce the pilot tables and score summaries without acquiring memory.

Run with the project environment: .venv/bin/python paper/verify_pilot.py
Only existing feature CSVs are read; no model or dataset files are modified.
The reference scores are in-sample, as stated in the manuscript.
"""

from pathlib import Path
import sys

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from pipeline.baseline_diff import BaselineModel, META


def main():
    valid = pd.read_csv(ROOT / "pipeline/paired_dataset_valid.csv")
    contaminated = pd.read_csv(ROOT / "pipeline/paired_dataset_contaminated.csv")
    threshold = 6.0
    for name, frame in (("Retained trials 1–6", valid),
                        ("Excluded trials 7–10", contaminated)):
        for label, subset in (("pre-test", frame[frame.label == "clean"]),
                              ("all captures", frame)):
            values = subset["malfind.commitCharge"]
            print(f"{name}, {label}: commitCharge {values.min()}–{values.max()}")

    for name, columns in (
        ("All 44 features", list(valid.columns)),
        ("Restricted 11 features", [c for c in valid if c in META or
                                  c.startswith(("malfind.", "ldrmodules."))]),
    ):
        frame = valid[columns]
        model = BaselineModel.fit(frame[frame.label == "clean"])
        scores = model.score(frame)
        results = pd.concat([valid[["image", "label"]], scores], axis=1)
        results["alert_at_6"] = scores.score_max >= threshold
        print(f"\n{name}; fitted on the six pre-test captures:")
        print(results.to_string(index=False, float_format=lambda x: f"{x:.6f}"))
        for label, subset in results.groupby("label", sort=False):
            print(f"  {label}: {int(subset.alert_at_6.sum())} / {len(subset)} alerts")

    frame = valid.assign(trial=valid.image.str.extract(r"_(\d+)\.raw$", expand=False).astype(int))
    pre = frame[frame.label == "clean"].set_index("trial")
    post = frame[frame.label == "infected"].set_index("trial")
    features = ["malfind.ninjections", "malfind.commitCharge",
                "ldrmodules.not_in_load", "ldrmodules.not_in_mem"]
    deltas = post[features] - pre[features]
    print("\nPost-minus-pre deltas, paired by trial number:")
    print(deltas.to_string())
    gap_minutes = (pd.to_datetime(post.ts) - pd.to_datetime(pre.ts)).dt.total_seconds() / 60
    print("\nFeature-extraction timestamp gaps (minutes, not acquisition latency):")
    print(gap_minutes.to_string(float_format=lambda x: f"{x:.2f}"))


if __name__ == "__main__":
    main()
