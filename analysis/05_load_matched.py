"""
LOAD-MATCHED EVALUATION
=======================
The confound is system workload: benign captures come from a busy desktop
(higher on 22/22 counters), malware captures from a freshly-reverted VM.
Controlling it means comparing benign and malware ONLY within strata of equal
system load -- the standard remedy for a confounded observational comparison.

If genuine malicious signal exists, accuracy inside matched strata stays high.
If the signal was the confound, accuracy collapses toward chance.
"""
import pandas as pd, numpy as np, warnings; warnings.filterwarnings('ignore')
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, roc_auc_score
import xgboost as xgb
rng = np.random.default_rng(7)

df = pd.read_csv('Obfuscated-MalMem2022.csv')
df['y'] = (df['Class']=='Malware').astype(int)
allf = [c for c in df.columns if c not in ('Category','Class','y') and df[c].nunique()>1]

LOAD = 'handles.nhandles'          # workload proxy: total open handles
print(f"Workload proxy: {LOAD}")
for k,g in df.groupby('Class')[LOAD]:
    print(f"  {k:8s} p5={g.quantile(.05):8.0f} median={g.median():8.0f} p95={g.quantile(.95):8.0f}")

# --- common support: where do the two classes actually overlap?
lo = max(df[df.y==0][LOAD].quantile(.02), df[df.y==1][LOAD].quantile(.02))
hi = min(df[df.y==0][LOAD].quantile(.98), df[df.y==1][LOAD].quantile(.98))
ov = df[(df[LOAD]>=lo)&(df[LOAD]<=hi)]
print(f"\nCommon-support region [{lo:.0f}, {hi:.0f}]: {len(ov)} of {len(df)} rows "
      f"({100*len(ov)/len(df):.1f}%)  benign={int((ov.y==0).sum())} malware={int((ov.y==1).sum())}")

# --- 1:1 match benign<->malware inside narrow load bins
bins = np.quantile(ov[LOAD], np.linspace(0,1,41))
ov = ov.assign(_bin=pd.cut(ov[LOAD], np.unique(bins), include_lowest=True))
keep=[]
for b,g in ov.groupby('_bin', observed=True):
    nb,nm = (g.y==0).sum(), (g.y==1).sum()
    n = min(nb,nm)
    if n==0: continue
    keep.append(g[g.y==0].sample(n, random_state=7))
    keep.append(g[g.y==1].sample(n, random_state=7))
M = pd.concat(keep) if keep else pd.DataFrame()
print(f"Load-matched subset: {len(M)} rows ({int((M.y==0).sum())} benign / {int((M.y==1).sum())} malware)")
if len(M):
    print(f"  median {LOAD}: benign={M[M.y==0][LOAD].median():.0f} "
          f"malware={M[M.y==1][LOAD].median():.0f}  (matched)")

def run(data, cols, name):
    if len(data) < 200:
        print(f"  {name:34s} SKIPPED (only {len(data)} rows)"); return
    X,yy = data[cols], data.y.values
    Xtr,Xte,ytr,yte = train_test_split(X,yy,test_size=.3,random_state=7,stratify=yy)
    s=StandardScaler().fit(Xtr)
    m=xgb.XGBClassifier(n_estimators=300,max_depth=6,verbosity=0).fit(s.transform(Xtr),ytr)
    p=m.predict(s.transform(Xte)); pr=m.predict_proba(s.transform(Xte))[:,1]
    print(f"  {name:34s} acc={accuracy_score(yte,p):.4f}  auc={roc_auc_score(yte,pr):.4f}  n={len(data)}")

print("\n=== RESULTS ===")
run(df, allf, 'UNMATCHED (published protocol)')
run(M,  allf, 'LOAD-MATCHED, all features')
run(M,  [c for c in allf if c!=LOAD], 'LOAD-MATCHED, proxy removed')
INJ=[c for c in allf if any(k in c for k in ('malfind','ldrmodules','psxview','callbacks'))]
run(M,  INJ, 'LOAD-MATCHED, injection/hiding only')
