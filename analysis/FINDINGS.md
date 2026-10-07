# Findings: capture-protocol confounding in CIC-MalMem-2022

All numbers reproduce via `analysis/0*.py` (venv: scikit-learn 1.9.0, xgboost 3.4.1).

## F1 — Reported accuracy is matched by a zero-parameter rule

| Feature set | n | Accuracy |
|---|---|---|
| All 55 features | 52 | 0.9999 |
| Host-config counters only | 6 | 0.9998 |
| Injection/hiding features only | 24 | 0.9998 |
| Project model (2 svcscan features) | 2 | 0.9984 |
| `nservices<=391 or >1000 -> malware` | **0** | **0.9963** |

Six configuration counters equal the full model to within 1e-4.

## F2 — Effect directions are physically backwards

Benign captures are higher on **22 of 22** count features, zero exceptions:

| Feature | Benign | Malware | Expected under a malware hypothesis |
|---|---|---|---|
| `malfind.ninjections` | 4 | 3 | malware higher |
| `ldrmodules.not_in_load` | 74 | 46 | malware higher |
| `handles.nsection` | 415 | 177 | — |
| `dlllist.ndlls` | 2086 | 1557 | — |

The two canonical injection/hiding indicators point the wrong way. Consistent with
benign = busy desktop, malware = freshly-reverted VM plus one process.

## F3 — Benign class has near-zero dispersion

Across 29,298 benign captures: `svcscan.kernel_drivers` takes **3** distinct values,
`svcscan.process_services` **4**, `callbacks.ncallbacks` **2**. The benign class is
effectively one machine state replicated.

## F4 — Unseen malware families cost nothing

Leave-one-family-out recall: Ransomware 0.9950, Spyware 0.9940, Trojan 0.9983.
A model that never saw ransomware detects it at 99.5% — transfer this clean
indicates a shared capture baseline, not learned behaviour. All three families
share one baseline (nservices=389, kernel_drivers=221, nproc=40) against
benign's (395, 222, 42).

## F5 — No common support (the blocking result)

- Benign p5 of `handles.nhandles` = 10,350 **exceeds** malware p95 = 9,111.
- 1:1 load-matching leaves **148 of 58,596** rows.
- Propensity `e(x)=P(malware|features)`: only **0.92%** of rows fall in 0.1<e(x)<0.9.
- 10 of 52 features have <10% distributional overlap.

**99.08% of the corpus is perfectly separated on capture protocol.** The positivity
assumption fails, so no reweighting, matching, feature selection or model class can
recover a behavioural estimand. The dataset cannot support a deployable detector.

Figure: `analysis/fig_overlap.png`

## Consequence for deployment

A detector trained on this corpus keys on absolute host counters. On a different
machine — any machine whose service/handle counts differ from the capture VMs —
the verdict is decided by that host's configuration, not by infection state. The
WannaCry detection reported in the course project is therefore not evidence the
classifier works.

## Remedy adopted

Baseline-differential features (`pipeline/baseline_diff.py`): score each capture
against the same host's own clean baseline (robust z / ratio), fitted on clean
captures only. Paired within-subject collection (`pipeline/collect_paired.sh`)
holds host state fixed across the pre/post detonation boundary, so class and
capture protocol are no longer collinear.

---

# Provenance: where the flaw comes from

Checked 2026-09-06 against the CIC source page, the originating paper, and the
local Kaggle copy.

## The Kaggle file is a faithful copy of CIC's

| Property | CIC published | Local file |
|---|---|---|
| Records | 58,596 | 58,596 |
| Benign / malicious | 29,298 / 29,298 | 29,298 / 29,298 |
| Malware families | 15, five per category | 15, names match exactly |

Malware rows carry `family-subfamily-sha256-dumpindex.raw`. Benign rows carry the
single literal string `Benign`, with no per-capture identity at all.

Kaggle added exactly one defect: row 58,595 reads
`Ran+A58597:AV58597somware-Shade-...`, a spreadsheet range reference spliced into
the word "Ransomware" on the file's last line. One text label, no numeric change.

## The originating paper states the cause

Carrier, Victor, Tekeoglu and Lashkari, ICISSP 2022, section 4.1:

> "For benign dumps, normal user behaviour is captured by using different
> applications in the machine and performed oversampling using SMOTE algorithm
> to make the dataset balanced."

and:

> "A python code and a bash script are used to execute the malware samples on a
> 64-bit Windows 10 isolated virtual machine inside Oracle Virtual Box"
> ... "executed in a VM with 2 GigaBytes of memory."

So: 2,916 samples x 10 dumps at 15-second intervals gives ~29,160 real malicious
captures. The benign side is an unstated, much smaller number of real captures
inflated to 29,298 by SMOTE.

## Two independent defects, both from the source

**D1. SMOTE applied before any split.** The class had to reach 29,298 before the
file was written, so synthetic benign rows and the real rows they interpolate sit
in the same CSV. Any random train/test split puts a synthetic row in test whose
parents are in train. Every published random-split result on this corpus inherits
this.

Empirical confirmation, `malfind.uniqueInjections`:
- malware: 209 distinct values, all small-integer ratios (1.0, 1.1, 1.125, 10/9, 12/11)
- benign: 5,337 distinct values densely packed above 1.0 (1.000433596, 1.001479908)

Real captures give small rationals. Interpolation gives a continuum.

**D2. Unequal capture conditions.** Benign came from a user desktop running
applications; malware from a 2 GB Windows 10 VirtualBox VM. A 2 GB VM simply
holds fewer processes, handles and DLLs than a working desktop, which is why
benign is higher on 22 of 22 counters and why the injection and hidden-module
counts run backwards.

The paper shows the authors anticipated this and tried to mitigate it: "it is
important to have some benign processes executed during the malicious memory dump
creation ... so that the classifier is not able to determine the difference just
based on the benign processes alone." The measurements show the mitigation did
not hold.

## Prior criticism

A literature search found none. Published work on this corpus concerns poisoning
attacks and feature selection, not the collection protocol. Treat the diagnosis
as new until a reviewer shows otherwise.
