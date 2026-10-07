"""Does the 55-feature model know anything the host fingerprint doesn't?"""
import pandas as pd, numpy as np, warnings
warnings.filterwarnings('ignore')
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, roc_auc_score
import xgboost as xgb

df = pd.read_csv('Obfuscated-MalMem2022.csv')
y = (df['Class']=='Malware').astype(int).values
fam = df['Category'].str.split('-').str[0]
allf=[c for c in df.columns if c not in ('Category','Class') and df[c].nunique()>1]

# feature groups
HOST = ['svcscan.nservices','svcscan.kernel_drivers','svcscan.shared_process_services',
        'callbacks.ncallbacks','modules.nmodules','svcscan.nactive']          # pure host config
BEHAV= [c for c in allf if any(k in c for k in ('malfind','ldrmodules','psxview'))]  # injection/hiding
TWO  = ['svcscan.nservices','svcscan.process_services']                        # the project's model

def fit_eval(cols, name, Xtr,Xte,ytr,yte):
    s=StandardScaler(); a=s.fit_transform(Xtr[cols]); b=s.transform(Xte[cols])
    m=xgb.XGBClassifier(n_estimators=200, max_depth=6, verbosity=0).fit(a,ytr)
    p=m.predict(b); pr=m.predict_proba(b)[:,1]
    print(f"  {name:42s} n_feat={len(cols):3d}  acc={accuracy_score(yte,p):.4f}  auc={roc_auc_score(yte,pr):.4f}")

X=df[allf]
Xtr,Xte,ytr,yte = train_test_split(X,y,test_size=.3,random_state=7,stratify=y)
print("=== RANDOM SPLIT (the protocol used in the report and in the literature) ===")
fit_eval(allf,'ALL 55 features',Xtr,Xte,ytr,yte)
fit_eval(HOST,'HOST-CONFIG only (service/driver counts)',Xtr,Xte,ytr,yte)
fit_eval(BEHAV,'BEHAVIOURAL only (malfind/ldrmodules/psxview)',Xtr,Xte,ytr,yte)
fit_eval(TWO,'THE PROJECT MODEL (2 svcscan features)',Xtr,Xte,ytr,yte)
print("\n  Zero-parameter rule 'nservices<=391 or >1000 -> malware': "
      f"acc={(((df['svcscan.nservices']<=391)|(df['svcscan.nservices']>1000)).astype(int)==y).mean():.4f}")

print("\n=== LEAVE-ONE-FAMILY-OUT (train on 2 malware families, test on the held-out one) ===")
print("  If the model learned malware behaviour, unseen families should be HARDER.")
print("  If it learned the capture baseline, unseen families cost nothing.\n")
for held in ['Ransomware','Spyware','Trojan']:
    tr = ~((fam==held))
    te =  ((fam==held) | (fam=='Benign'))
    s=StandardScaler(); a=s.fit_transform(df.loc[tr,allf]); b=s.transform(df.loc[te,allf])
    m=xgb.XGBClassifier(n_estimators=200,max_depth=6,verbosity=0).fit(a,y[tr.values])
    p=m.predict(b)
    mal_recall = accuracy_score(y[te.values][ (fam[te]==held).values ], p[(fam[te]==held).values])
    print(f"  held-out {held:12s} recall on UNSEEN family = {mal_recall:.4f}")
