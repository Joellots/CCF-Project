"""Audit CIC-MalMem-2022 for capture-environment leakage across ALL features."""
import pandas as pd, numpy as np
from sklearn.metrics import roc_auc_score

df = pd.read_csv('Obfuscated-MalMem2022.csv')
y = (df['Class'] == 'Malware').astype(int)
fam = df['Category'].str.split('-').str[0]
sub = df['Category'].str.split('-').str[:2].str.join('-')
feats = [c for c in df.columns if c not in ('Category', 'Class')]

print(f"rows={len(df)}  features={len(feats)}  malware={y.sum()}  benign={(1-y).sum()}")
print(f"families: {dict(fam.value_counts())}")
print(f"distinct subtypes: {sub.nunique()}")

# ---- 1. constant / near-constant features
print("\n=== CONSTANT FEATURES ===")
for c in feats:
    if df[c].nunique() == 1:
        print(f"  {c:45s} constant = {df[c].iloc[0]}")

# ---- 2. univariate separability of every feature
print("\n=== UNIVARIATE AUC (per feature, single-feature separability) ===")
rows = []
for c in feats:
    if df[c].nunique() < 2:
        continue
    a = roc_auc_score(y, df[c])
    rows.append((c, max(a, 1 - a), df[c].nunique()))
uni = pd.DataFrame(rows, columns=['feature', 'auc', 'nuniq']).sort_values('auc', ascending=False)
print(uni.head(20).to_string(index=False))
print(f"\nfeatures with AUC>=0.95: {(uni.auc>=0.95).sum()} | >=0.90: {(uni.auc>=0.90).sum()} "
      f"| >=0.80: {(uni.auc>=0.80).sum()} | <0.60: {(uni.auc<0.60).sum()}")

# ---- 3. exact duplicate feature vectors (train/test leakage source)
print("\n=== DUPLICATE FEATURE VECTORS (full 55-dim) ===")
dup_all = df.duplicated(subset=feats).sum()
print(f"exact duplicate rows on all {len(feats)} features: {dup_all} ({100*dup_all/len(df):.1f}%)")
grp = df.groupby(feats, dropna=False).size()
print(f"distinct full-feature vectors: {len(grp)} for {len(df)} rows")
print(f"rows sharing their vector with >=1 other row: {grp[grp>1].sum()} ({100*grp[grp>1].sum()/len(df):.1f}%)")
# do duplicate vectors span both classes?
lab_per_vec = df.groupby(feats, dropna=False)['Class'].nunique()
print(f"vectors appearing in BOTH classes: {(lab_per_vec>1).sum()}")

# ---- 4. how many features are pure host-configuration counts?
print("\n=== WITHIN-CLASS DISPERSION (environment fingerprint test) ===")
print("A feature that is near-constant WITHIN benign but differs from malware's")
print("centre is a capture-baseline fingerprint, not a behavioural signal.\n")
res = []
for c in uni.feature.head(25):
    b, m = df.loc[y == 0, c], df.loc[y == 1, c]
    res.append((c, b.nunique(), m.nunique(), b.median(), m.median(),
                b.std(), m.std()))
d = pd.DataFrame(res, columns=['feature', 'nuniq_ben', 'nuniq_mal',
                               'med_ben', 'med_mal', 'std_ben', 'std_mal'])
print(d.to_string(index=False))
uni.to_csv('analysis/univariate_auc.csv', index=False)
