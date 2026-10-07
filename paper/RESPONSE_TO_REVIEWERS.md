# Response to Reviewers

**Paper:** Automated Memory Forensics for Malware Detection and Incident Response
**Authors:** J. C. Okore, A. Petrovski, I. V. Kotenko
**Venue:** IEEE SIBIRCON 2026

We thank both reviewers for their comments. Both independently identified the
same core gap — evidence integrity and chain of custody are not addressed in
the original submission — and we have revised the paper to address this
directly, with concrete implementation changes to the pipeline backing the
textual revisions, not only added discussion. A summary of every change is
below, organized by reviewer and keyed to the specific comment it answers.

## Reviewer 2 (numbered recommendations)

**1. Add hash computation for all artifacts.**
Implemented. The acquisition script now computes a SHA-256 digest of the
memory image as soon as it is visible to the manager; the extraction script
computes a second, independent digest of the same image immediately before
Volatility analysis, and a digest of the feature CSV immediately after
writing it; the classifier and the response script each compute a digest of
the classification decision. All digests are appended to a shared,
append-only integrity log. This is described in a new paragraph in
Section III-D ("Response Policy and Operational Records") and is reflected
in the accompanying code (`extract_features.py`, `predict.py`,
`response.py`, `trigger_memdump.sh`).

**2. Discuss evidence integrity during acquisition.**
Added. A new paragraph in Section III-B acknowledges that WinPMEM loads a
kernel driver to obtain physical memory access, that this is an inherent
precondition of live acquisition rather than a passive read, and states
explicitly that the resulting image should be treated as a best-effort
forensically sound capture rather than a snapshot unaffected by the act of
acquiring it.

**3. Verify that the active-response scripts do not tamper with memory
before acquisition.**
Addressed. The same paragraph in Section III-B describes the execution path
precisely: the acquisition script runs on the manager and issues a single
remote command; the only endpoint-side component involved before WinPMEM
begins writing is the WinRM execution host required to invoke that command,
not an additional process of our own. This is accurate to the actual script
(`trigger_memdump.sh`), which we re-verified while making this revision.

**4. Replace file-modification triggers with atomic publication.**
Implemented, not merely discussed. Both the memory image and the feature
CSV are now written to a staging path and atomically renamed onto the path
Wazuh FIM watches only once writing is complete, so FIM never observes a
partially written artifact. This is described in Section III-B
("Event-Driven Orchestration") and reflected in `trigger_memdump.sh`
(two-stage acquire-then-publish) and `extract_features.py`
(write-then-`os.replace`). The corresponding text in Section VI-B
("Reliability Requirements") is updated from a forward-looking
recommendation to a description of the implemented fix. Duplicate-event
suppression for repeated FIM events on an already-complete file remains an
open limitation and is stated as such.

**5. Clarify the role of GRR.**
Added. A sentence immediately following the introduction of GRR Rapid Team
in Related Work now states explicitly that GRR is discussed as related work
on distributed evidence collection and is not part of the implemented
system, which instead uses Wazuh active response and WinPMEM.

**6. Qualify the classifier result.**
Addressed at first mention. The sentence reporting 99.84% accuracy in
Section III-C now states directly that this is a benchmark result on a
public dataset, not a measurement of accuracy on deployment endpoints, and
points to Section V, which already examines what the result depends on
(Section V was present in the original submission; the revision ensures the
caveat is visible where the number first appears rather than only several
paragraphs later).

## Reviewer 1

Reviewer 1's comments raise the same concerns as Reviewer 2's numbered list,
in less formal terms; each is answered by the corresponding item above.

- *"Third-party tool which spawns new processes... damages the integrity of
  the evidence"* and *"have you checked that your script does not tamper
  with memory during acquisition"* — addressed by the new Section III-B
  paragraph on acquisition-stage integrity (Reviewer 2, items 2 and 3).
- *"Wazuh alerts trigger... WinPMEM; but... GRR Rapid Response... that
  contradicts"* — GRR is related work, not part of the implementation; now
  stated explicitly (Reviewer 2, item 5).
- *"it does not [seem] possible to achieve 99% accuracy because... more new
  processes are spawning in the memory"* — this concern about process churn
  and representativeness is precisely what Section V (Classifier Assessment)
  investigates; the 99.84% figure is now explicitly flagged as a benchmark
  result, not a deployment measurement, at first mention (Reviewer 2,
  item 6).
- *"make sure to take hashes... what about if the original evidence
  corrupts"* — addressed by the SHA-256 chain now implemented across all
  four pipeline stages (Reviewer 2, item 1).

## Summary of changes by location

| Section | Change |
|---|---|
| Related Work | Added sentence clarifying GRR is related work, not implemented (Rev. 2 #5) |
| III-B, Alert-Driven Memory Acquisition | New paragraph: no extra process spawned before WinPMEM; WinPMEM's kernel driver and its effect on evidentiary weight (Rev. 2 #2, #3) |
| III-B, Event-Driven Orchestration | Revised to describe implemented staging-then-atomic-rename publication (Rev. 2 #4) |
| III-C, Forensic Feature Representation | Qualifier added at first mention of 99.84% accuracy (Rev. 2 #6) |
| III-D, Response Policy and Operational Records | New paragraph describing the SHA-256 integrity chain across all stages (Rev. 2 #1) |
| VI-B, Reliability Requirements | Updated to describe atomic publication and exit-status checking as implemented, not only recommended (Rev. 2 #4; isolation exit-status check also newly implemented in `response.py`) |
| `extract_features.py`, `predict.py`, `response.py`, `trigger_memdump.sh` | Code changes implementing the integrity log, atomic artifact publication, and isolation-command exit-status verification |

We believe these revisions address the integrity concerns raised by both
reviewers directly and concretely, and we thank the reviewers for pointing
to a genuine gap in the original submission.
