"""
BASELINE TRANSPLANT TEST
========================
If the classifier learned malicious BEHAVIOUR, then moving a malware sample onto
a different host baseline must not change its verdict -- the behaviour is the same.
If it learned the CAPTURE ENVIRONMENT, transplanting the baseline flips the verdict.

We take held-out malware rows and overwrite only the host-configuration counters
with the benign host's values, leaving every behavioural feature untouched.
"""
import pandas as pd, numpy as np, warnings; warnings.filterwarnings('ignore')
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, recall_score
import xgboost as xgb

df = pd.read_csv('Obfuscated-MalMem2022.csv')
y = (df['Class']=='Malware').astype(int).values
allf = [c for c in df.columns if c not in ('Category','Class') and df[c].nunique()>1]

HOST = ['svcscan.nservices','svcscan.kernel_drivers','svcscan.shared_process_services',
        'callbacks.ncallbacks','modules.nmodules','svcscan.nactive','svcscan.process_services']
HOST = [c for c in HOST if c in allf]

Xtr,Xte,ytr,yte = train_test_split(df[allf],y,test_size=.3,random_state=7,stratify=y)
sc = StandardScaler().fit(Xtr)
clf = xgb.XGBClassifier(n_estimators=300,max_depth=6,verbosity=0).fit(sc.transform(Xtr),ytr)

base = accuracy_score(yte, clf.predict(sc.transform(Xte)))
mal_mask = yte==1
rec0 = recall_score(yte, clf.predict(sc.transform(Xte)))
print(f"Baseline (same capture environment as training)")
print(f"  overall accuracy      = {base:.4f}")
print(f"  malware recall        = {rec0:.4f}\n")

ben_med = df.loc[y==0, HOST].median()
print("TRANSPLANT: malware rows given the BENIGN host's configuration counters")
print("            (all behavioural features left untouched)\n")
Xt = Xte.copy()
Xt.loc[mal_mask, HOST] = ben_med.values
rec1 = recall_score(yte[mal_mask], clf.predict(sc.transform(Xt))[mal_mask])
print(f"  malware recall after transplant = {rec1:.4f}   (was {rec0:.4f})")
print(f"  --> {100*(rec0-rec1)/rec0:.1f}% of detections lost by changing "
      f"{len(HOST)} configuration counters alone\n")

# incremental: which single counter carries the verdict?
print("Per-counter transplant (change ONE host counter, keep the rest):")
for c in HOST:
    Xs = Xte.copy(); Xs.loc[mal_mask, c] = ben_med[c]
    r = recall_score(yte[mal_mask], clf.predict(sc.transform(Xs))[mal_mask])
    print(f"  {c:36s} recall {rec0:.4f} -> {r:.4f}   (drop {rec0-r:+.4f})")

# robustness curve: sweep a service-count offset, as a different host would have
print("\nHOST-SHIFT ROBUSTNESS CURVE (simulating deployment on another machine)")
print("  offset applied to svcscan.nservices on ALL test rows:")
rows=[]
for off in [-15,-10,-6,-3,0,3,6,10,15]:
    Xs = Xte.copy(); Xs['svcscan.nservices'] = Xs['svcscan.nservices'] + off
    a = accuracy_score(yte, clf.predict(sc.transform(Xs)))
    rows.append((off,a)); print(f"    {off:+3d} services -> accuracy {a:.4f}")
pd.DataFrame(rows,columns=['offset','accuracy']).to_csv('analysis/host_shift_curve.csv',index=False)
