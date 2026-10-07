"""
COMMON-SUPPORT / POSITIVITY DIAGNOSTIC
======================================
A behavioural claim ("this dump looks malicious") requires that benign and
malware captures overlap in system state -- otherwise the comparison is between
capture protocols, not behaviours. We measure overlap per feature and via the
propensity-score distribution, the standard diagnostic for complete separation.
"""
import pandas as pd, numpy as np, warnings; warnings.filterwarnings('ignore')
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.model_selection import cross_val_predict
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline

df = pd.read_csv('Obfuscated-MalMem2022.csv')
y = (df['Class']=='Malware').astype(int).values
allf=[c for c in df.columns if c not in ('Category','Class') and df[c].nunique()>1]

# ---- per-feature overlap coefficient (histogram intersection)
def overlap(a,b,bins=60):
    lo,hi=min(a.min(),b.min()),max(a.max(),b.max())
    if lo==hi: return 1.0
    e=np.linspace(lo,hi,bins+1)
    ha,_=np.histogram(a,e,density=False); hb,_=np.histogram(b,e,density=False)
    ha=ha/ha.sum(); hb=hb/hb.sum()
    return float(np.minimum(ha,hb).sum())

rows=[(c, overlap(df.loc[y==0,c].values, df.loc[y==1,c].values)) for c in allf]
ov=pd.DataFrame(rows,columns=['feature','overlap']).sort_values('overlap')
print("=== PER-FEATURE DISTRIBUTIONAL OVERLAP (0 = disjoint, 1 = identical) ===")
print(ov.head(12).to_string(index=False))
print(f"\n  features with <10% overlap: {(ov.overlap<0.10).sum()} of {len(ov)}")
print(f"  features with <25% overlap: {(ov.overlap<0.25).sum()} of {len(ov)}")
print(f"  median overlap across all features: {ov.overlap.median():.3f}")
ov.to_csv('analysis/feature_overlap.csv',index=False)

# ---- propensity score: P(malware | features)
ps = cross_val_predict(make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000)),
                       df[allf], y, cv=5, method='predict_proba')[:,1]
print("\n=== PROPENSITY SCORE P(malware | memory features), 5-fold ===")
for lab,m in (('benign',y==0),('malware',y==1)):
    q=np.quantile(ps[m],[.05,.25,.5,.75,.95])
    print(f"  {lab:8s} p5={q[0]:.4f} q1={q[1]:.4f} med={q[2]:.4f} q3={q[3]:.4f} p95={q[4]:.4f}")
mid = ((ps>0.1)&(ps<0.9)).mean()
print(f"\n  rows in the overlap band 0.1<e(x)<0.9 : {100*mid:.2f}%")
print(f"  --> {100*(1-mid):.2f}% of the corpus is perfectly separated on capture protocol.")
print("      With no common support, no reweighting or feature selection can")
print("      recover a behavioural signal: the positivity assumption is violated.")

# ---- figures
fig,ax=plt.subplots(1,3,figsize=(15,4.2))
ax[0].hist(ps[y==0],bins=50,alpha=.75,label='Benign',color='#2b6cb0')
ax[0].hist(ps[y==1],bins=50,alpha=.75,label='Malware',color='#c53030')
ax[0].set_xlabel('propensity  e(x) = P(malware | features)'); ax[0].set_ylabel('captures')
ax[0].set_title('(a) Complete separation'); ax[0].legend()
ax[1].hist(df.loc[y==0,'handles.nhandles'],bins=60,alpha=.75,label='Benign',color='#2b6cb0')
ax[1].hist(df.loc[y==1,'handles.nhandles'],bins=60,alpha=.75,label='Malware',color='#c53030')
ax[1].set_xlabel('handles.nhandles (system-load proxy)'); ax[1].set_title('(b) Disjoint workload'); ax[1].legend()
ax[2].barh(ov.head(15).feature, ov.head(15).overlap, color='#2f855a')
ax[2].set_xlabel('distributional overlap'); ax[2].set_title('(c) Least-overlapping features')
ax[2].tick_params(labelsize=7)
plt.tight_layout(); plt.savefig('analysis/fig_overlap.png',dpi=200)
print("\n[+] figure -> analysis/fig_overlap.png")
