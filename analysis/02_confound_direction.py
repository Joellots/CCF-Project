"""Test: is separability explained by capture CONDITION (busy desktop vs fresh
snapshot) rather than malicious behaviour? If so, benign should be systematically
LARGER on nearly every count feature -- the opposite of what injection/hooking
malware would produce."""
import pandas as pd, numpy as np
df = pd.read_csv('Obfuscated-MalMem2022.csv')
y = (df['Class']=='Malware').astype(int)
feats=[c for c in df.columns if c not in ('Category','Class') and df[c].nunique()>1]

print("=== DIRECTION OF EVERY COUNT FEATURE (benign median vs malware median) ===")
count_feats=[c for c in feats if any(k in c for k in
   ('nproc','ndlls','nhandles','nthread','nevent','nkey','nfile','nsection',
    'nmutant','nsemaphore','ntimer','ndesktop','ndirectory','nservices',
    'nactive','kernel_drivers','ncallbacks','not_in_load','not_in_mem','ninjections'))]
higher_in_benign=0; higher_in_malware=0
for c in sorted(count_feats):
    b,m = df.loc[y==0,c].median(), df.loc[y==1,c].median()
    arrow = 'BENIGN higher' if b>m else ('MALWARE higher' if m>b else 'equal')
    if b>m: higher_in_benign+=1
    elif m>b: higher_in_malware+=1
    ratio = (b/m) if m else float('nan')
    print(f"  {c:38s} ben={b:10.1f} mal={m:10.1f}  x{ratio:5.2f}  {arrow}")
print(f"\n  --> benign higher on {higher_in_benign}/{len(count_feats)} count features, "
      f"malware higher on {higher_in_malware}")

print("\n=== SYSTEM LOAD PROXY: number of running processes ===")
for c in ['pslist.nproc','pslist.nppid','handles.nhandles','dlllist.ndlls']:
    if c in df:
        print(f"  {c:20s} benign median={df.loc[y==0,c].median():9.1f} "
              f"malware median={df.loc[y==1,c].median():9.1f}")

print("\n=== DO THE THREE MALWARE FAMILIES SHARE ONE BASELINE? ===")
fam = df['Category'].str.split('-').str[0]
keep = fam.isin(['Benign','Spyware','Ransomware','Trojan'])
for c in ['pslist.nproc','svcscan.nservices','svcscan.kernel_drivers',
          'handles.nhandles','dlllist.ndlls','callbacks.ncallbacks']:
    if c in df:
        g = df[keep].groupby(fam[keep])[c].median()
        print(f"  {c:26s} " + "  ".join(f"{k}={v:.0f}" for k,v in g.items()))

print("\n=== BENIGN HOMOGENEITY: distinct values per feature within benign ===")
hom = sorted(((df.loc[y==0,c].nunique(), c) for c in feats))[:15]
for n,c in hom: print(f"  {c:40s} only {n} distinct values across 29,298 benign samples")
