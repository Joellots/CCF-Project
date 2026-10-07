#!/usr/bin/env python3
"""
Baseline-differential memory features + one-class detector.

Rationale
---------
Absolute memory counters (nservices, ndlls, nhandles, ...) are dominated by the
host's configuration and workload, not by malicious behaviour. Training on them
teaches a model to fingerprint the capture environment -- the failure mode that
makes CIC-MalMem-2022 separable by a zero-parameter rule at 99.6% accuracy.

This module instead scores a memory image against a baseline distribution
collected FROM THE SAME HOST while clean. Features become host-relative:

    z_i = (x_i - median_i) / (1.4826 * MAD_i + eps)     robust deviation
    r_i = (x_i + 1) / (median_i + 1)                    scale-free ratio

Only clean captures are needed to fit the detector; malware samples are used for
evaluation, never for training. That removes the label-vs-environment collinearity
by construction rather than by assuming a dataset is clean.
"""
import argparse
import json
import sys

import numpy as np
import pandas as pd

EPS = 1e-9
META = ("ts", "host", "label", "tag", "image", "image_bytes")


def _numeric(df):
    cols = [c for c in df.columns if c not in META]
    return df[cols].apply(pd.to_numeric, errors="coerce")


class BaselineModel:
    """Per-host robust baseline fitted on clean captures only."""

    def __init__(self, features, median, mad):
        self.features = list(features)
        self.median = np.asarray(median, float)
        self.mad = np.asarray(mad, float)

    @classmethod
    def fit(cls, clean_df):
        X = _numeric(clean_df)
        X = X.loc[:, X.notna().any()]
        med = X.median().values
        mad = (X - X.median()).abs().median().values * 1.4826
        # a feature that never moves on a clean host gets a floor, so a single
        # unit of change is not scored as infinite deviation
        mad = np.where(mad < 1e-6, np.maximum(np.abs(med) * 0.01, 1.0), mad)
        return cls(X.columns, med, mad)

    def transform(self, df):
        X = _numeric(df).reindex(columns=self.features)
        z = (X.values - self.median) / (self.mad + EPS)
        r = (X.values + 1.0) / (self.median + 1.0)
        out = pd.DataFrame(
            np.hstack([z, r]),
            columns=[f"z::{c}" for c in self.features] + [f"r::{c}" for c in self.features],
            index=df.index,
        )
        return out

    def score(self, df):
        """Anomaly score = robust max-deviation, plus how many features moved."""
        z = np.abs(self.transform(df).values[:, : len(self.features)])
        z = np.nan_to_num(z, nan=0.0, posinf=0.0)
        return pd.DataFrame({
            "score_max":  z.max(axis=1),
            "score_mean": z.mean(axis=1),
            "n_features_beyond_3mad": (z > 3).sum(axis=1),
            "top_feature": [self.features[i] for i in z.argmax(axis=1)],
        }, index=df.index)

    def save(self, path):
        json.dump({"features": self.features,
                   "median": self.median.tolist(),
                   "mad": self.mad.tolist()}, open(path, "w"), indent=1)

    @classmethod
    def load(cls, path):
        d = json.load(open(path))
        return cls(d["features"], d["median"], d["mad"])


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fit", help="fit a baseline from clean captures")
    f.add_argument("csv"); f.add_argument("--host"); f.add_argument("--out", default="baseline.json")

    s = sub.add_parser("score", help="score captures against a fitted baseline")
    s.add_argument("csv"); s.add_argument("--model", default="baseline.json")
    s.add_argument("--threshold", type=float, default=6.0)

    a = p.parse_args()
    df = pd.read_csv(a.csv)

    if a.cmd == "fit":
        clean = df[df.get("label", "clean") == "clean"]
        if a.host:
            clean = clean[clean["host"] == a.host]
        if len(clean) < 5:
            print(f"[!] only {len(clean)} clean captures -- baseline will be unstable; "
                  f"collect >=10 across reboots and workloads", file=sys.stderr)
        m = BaselineModel.fit(clean)
        m.save(a.out)
        print(f"[+] baseline over {len(clean)} clean captures, "
              f"{len(m.features)} features -> {a.out}")
    else:
        m = BaselineModel.load(a.model)
        sc = m.score(df)
        res = pd.concat([df[[c for c in ("host", "label", "tag") if c in df]], sc], axis=1)
        res["verdict"] = np.where(sc.score_max >= a.threshold, "SUSPICIOUS", "normal")
        print(res.to_string(index=False))


if __name__ == "__main__":
    main()
