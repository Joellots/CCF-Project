# Briefing for Codex — SIBIRCON 2026 paper

> **Current author direction:** This is primarily a **systems and application
> paper**. Lead with the automated forensic pipeline, its implementation, and
> the WannaCry case study. Treat the dataset audit and baseline-differential
> pilot as supporting deployment assessments. This explicit direction
> supersedes the emphasis and section plan in the historical briefing below.

> **Revision note, 9 September 2026:** The manuscript has since been revised
> against the code, CSVs, course report, and primary publications. Several
> interpretations below were not supported by those sources. Read
> [REVISION_NOTES.md](REVISION_NOTES.md) before editing; its evidence corrections
> supersede the corresponding historical claims in this briefing. The original
> manuscript is preserved in `archive/main-before-2026-09-09.tex`.

You're picking up a conference paper draft in `paper/main.tex`. This document
gives you the context you need to improve its writing without accidentally
touching its substance. Read this fully before editing.

## What this paper is

A submission to **2026 IEEE SIBIRCON** (Novosibirsk, Oct 11–12 2026),
targeting **Symposium 5: Data Analysis Technologies with Applications**
(relevant CFP bullets: Data Fusion/Mining/Predictive Modelling; Big Data and
Exploratory Data Analysis; Data Quality, Integrity). Final paper deadline is
**2026-09-15** — check today's date against that before doing anything else,
this is time-critical. Format is the standard IEEE two-column conference
template (`IEEEtran.cls`, included in `paper/`); no hard page count was given
in the CFP beyond "per template," so ~6 pages is a reasonable unstated target.
Submission requires English, ≤20% similarity score, self-citations capped at
3 references / 50% of total references. Presentation is hybrid but requires
either in-person or live oral attendance — no virtual poster option.

The paper began life as a course project (Computer Forensics and Incident
Response) and grew a second, larger contribution during review. It now makes
**two separate claims**, and both are real, both are backed by artefacts in
this repo, and neither should be softened, exaggerated, or merged into the
other:

1. **A working system.** An automated pipeline (Wazuh SIEM → WinPMEM memory
   acquisition → Volatility3 analysis → ML classifier → SOAR-style
   containment/Slack alert), validated end-to-end against a live WannaCry
   infection in a two-VM testbed. This is the original course project. Source:
   `COMPUTER_FORENSIC_AND_INCIDENT_RESPONSE-Report.pdf`, `predict.py`,
   `response.py`, `trigger_memdump.sh`, `extract_features.py`, `README.md`.

2. **A dataset critique + proposed fix + small pilot.** The classifier in (1)
   was trained on CIC-MalMem-2022 and hit ~99.8% accuracy. Investigation
   found this accuracy is an artefact of how the dataset was collected, not
   of malware-detection ability — full diagnosis below. This is the paper's
   main intellectual contribution. It proposes a "baseline-differential"
   fix (score a capture against the *same host's own* clean baseline instead
   of absolute counts) and validates it with a small paired pilot using
   Atomic Red Team injection techniques on a cloud VM (real malware wasn't
   available for this iteration — lab access fell through, see Limitations).

## Ground-truth numbers — do not alter without re-deriving

Everything below was computed from real data in this repo, not estimated or
invented. If you touch a sentence containing one of these numbers, the number
must still match its source after your edit. If you think a number is wrong,
say so and point at the script that produced it — don't silently change it.

**Dataset diagnosis** (source: `analysis/FINDINGS.md`, `analysis/01_leakage_audit.py`
through `analysis/06_overlap.py`, all rerunnable via `.venv/bin/python analysis/0N_*.py`):
- CIC-MalMem-2022: 58,596 rows, 29,298 benign / 29,298 malicious, 55 features.
- 2-feature deployed model: 99.84% accuracy. Full 55-feature model: 0.9999.
  Host-config-only (6 features): 0.9998. Zero-parameter rule
  (`nservices <= 391 or > 1000`): 99.63%.
- 22 of 22 count-based features have a *higher* median in the benign class.
  `malfind.ninjections`: benign=4, malicious=3. `ldrmodules.not_in_load`:
  benign=74, malicious=46.
- Propensity-score overlap: only 0.92% of rows fall in 0.1 < e(x) < 0.9;
  99.08% are perfectly separated by capture protocol alone.
- Load-matching on `handles.nhandles` leaves 148 of 58,596 rows in common
  support; benign p5 exceeds malicious p95.
- Provenance, quoted directly from the dataset's own methodology paper
  (Carrier et al., ICISSP 2022 — PDF was fetched and read in full, quotes are
  verbatim): benign captures used SMOTE oversampling applied *before* the
  train/test split existed; malicious captures came from a 2GB VirtualBox VM
  versus benign's active desktop.
- Independent confirmation: `malfind.uniqueInjections` has 209 distinct
  values in the malicious class (small-integer ratios, consistent with real
  counting) vs 5,337 in the benign class (dense irrational-looking decimals,
  consistent with SMOTE interpolation).

**Pilot evaluation** (source: `pipeline/paired_dataset_valid.csv`,
`pipeline/paired_dataset_contaminated.csv`, `pipeline/baseline_diff.py`):
- Collected on a GCP Windows Server 2022 VM (`e2-medium`) using Atomic Red
  Team implementations of MITRE ATT&CK T1055.001/.002/.003/.004/.012.
- 10 paired trials run sequentially. From trial 7 onward, `malfind.commitCharge`
  jumped from a stable 259–265 baseline to a stable 773–778 baseline and
  **stayed elevated in every subsequent capture, clean and infected alike** —
  a persistence artefact from an incompletely-cleaned T1055.001 injection.
  Trials 1–6 (n=6 pairs, `paired_dataset_valid.csv`) are the valid dataset
  used for the paper's quantitative claims. Trials 7–10
  (`paired_dataset_contaminated.csv`) are reported separately as a case
  study, not folded into the main result.
- Per-pair deltas (exact numbers already in `main.tex` Table VI, cross-check
  against `paired_dataset_valid.csv` if in doubt): T1055.004 and T1055.012
  show strong, consistent increases in `malfind`-family features; T1055.001,
  .002, .003 show flat or near-zero deltas on those same features.
- Mechanistic explanation (this is a real, checkable claim, not
  speculation): T1055.004 and T1055.012's Atomic Red Team implementations
  call `VirtualAllocEx`/`WriteProcessMemory`/`VirtualProtectEx` — this is
  visible directly in the raw PowerShell transcript from the actual run, not
  inferred — which produces private, anonymous, executable memory, exactly
  what Volatility's `malfind` plugin is built to catch. T1055.001/.002/.003
  inject via DLL loading, file-backed PE sections, or thread hijacking, none
  of which `malfind` is designed to flag. This is a known, citable limitation
  of the `malfind` heuristic, not a paper-specific finding — treat it as such
  in tone (matter-of-fact, not triumphant).

## Repo map

```
README.md                          original course project readme
COMPUTER_FORENSIC_AND_INCIDENT_RESPONSE-Report.pdf   original course report (WannaCry validation, Wazuh rules)
predict.py, response.py, trigger_memdump.sh, extract_features.py   original pipeline scripts (security-hardened: secrets now env vars, eval() replaced with json)
Deep_Learning_&_obfuscated_malware_memory_2022_cic.ipynb   original model training notebook
Obfuscated-MalMem2022.csv          raw CIC-MalMem-2022 dataset
xgb_model.pkl                      the CONFOUNDED trained model — do not treat its output as evidence of anything in this paper
analysis/                          dataset diagnosis: 01–06 numbered scripts, FINDINGS.md (full write-up with citations), fig_overlap.png (the paper's Fig. 1)
pipeline/                          extract_features_v2.py (44-feature extractor), baseline_diff.py (baseline-differential scorer), paired_dataset*.csv (pilot data), baseline*.json (fitted models)
lab/                               cloud provisioning + collection scripts (GCP is what actually worked); useful only if you need to understand how paired_dataset_valid.csv was produced, not paper content itself
paper/main.tex                     the paper
paper/IEEEtran.cls                 IEEE class file
Images/                            original course-project screenshots — NOT YET PLACED in the paper, see open items below
.venv/                             python env (pandas, numpy, scikit-learn, xgboost) if you need to rerun any analysis script to double check a number
```

## Current state of `paper/main.tex`

Sections, in order: Abstract, Intro (4 numbered contributions), Related Work
(3 short paragraphs), System Architecture (§III, the pipeline — subsections
on trigger/extraction/response), Diagnosis (§IV, the dataset critique — four
subsections: zero-parameter baseline, inverted effect directions, no common
support, provenance), Baseline-Differential Method (§V, the fix + the paired
collection protocol design), Pilot Evaluation (§VI — data collection
integrity/contamination case study, paired deltas table, mechanistic
detectability boundary), Limitations (§VII, honest and specific — small n,
single host image, Atomic Red Team not full malware, composite score not yet
validated), Conclusion, References (4 entries).

## Open items — things you can help with, or should leave alone

**Author block**: has been hand-edited by the user to add two co-authors
(Andrei Petrovski, Igor V. Kotenko — Innopolis University / SPC RAS). Not
your call to change the author list. Do flag the LaTeX structural bug
described in the note above this briefing if the user hasn't fixed it yet —
it's a real defect, not a style question.

**References**: 4 entries currently. Two (`carrier2022`, `abid2024`) were
extracted verbatim from primary sources fetched during this project and are
solid. Two (`lashkari2019`, `atomicredteam`) were written from general
knowledge, not a live lookup, and are flagged `% TODO(Joel)` in the file for
verification against the actual publisher/GitHub record before submission.
Missing entries noted in the same TODO: Volatility3 docs, Wazuh active-response
docs, MITRE ATT&CK T1055 reference. If you add these, cite real, checkable
sources — do not fabricate a citation to fill a gap.

**Figures**: `analysis/fig_overlap.png` is placed (Fig. 1, §IV). A second
`% TODO(Joel)` marks where 1–2 architecture screenshots from `Images/` should
go in §III — the user hasn't picked which ones yet. `Images/wazuh_alert_final.png`
and `Images/response_and_pred_trig.png` were suggested as candidates but not
confirmed.

**What "improve the writing" means here**: prose quality, clarity, sentence-
level flow, transitions between subsections, redundancy, IEEE-appropriate
academic register, tightening for length if the compiled PDF runs long.
It does **not** mean: changing any number, softening or inflating any claim,
altering the structure of the argument, adding citations you haven't
verified, or smoothing over the paper's own stated limitations (§VII exists
on purpose — this is a small pilot and the paper says so plainly; that
honesty is a feature of the argument, not a weakness to write around).

## Compiling

No local LaTeX engine with the full base distribution is installed in this
environment (`pdftex` binary exists but `texlive-latex-base` does not, and
`sudo` isn't available non-interactively). The user has been pointed at
Overleaf as the practical path to compile and check page count. If you have
LaTeX tooling available in your own environment, compiling to check for
errors introduced by an edit is worthwhile — the file has not yet been
successfully compiled by anyone on this project as of this writing.
