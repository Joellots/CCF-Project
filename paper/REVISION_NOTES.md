# Manuscript revision notes

## Reference verification — 12 September 2026

All thirteen entries were checked against live destinations and primary
publication records. All seven existing website URLs work and identify the
intended resources; all five DOIs resolve to the corresponding publisher
records and match Crossref metadata. IEEE restricted automated article-page
access, but its DOI redirects and registered metadata confirm both IEEE papers.
The complete results and access qualifications are in `REFERENCE_AUDIT.md`.

The five DOIs are now clickable. The official USENIX link has been added to
reference [9], and the USBEREIT page range (1–4) is now verified and included,
superseding the earlier note about omitted pagination. No existing DOI or URL
required replacement. The missing `arch_diag.png` filename was also corrected
to the existing `SIBIRCON_arch_diag.png` for compilation, retaining the figure
size and placement. The pre-audit source is preserved in
`archive/main-before-reference-audit-2026-09-12.tex`.

## Substantive expansion and final-page layout — 12 September 2026

Approximately 340 words were added to the implementation, timing, and
discussion sections to meet the author's request for at least 75% final-page
coverage. The additions explain central maintenance of the analysis components,
the extractor's handling of unsuccessful or empty scans, notification delivery
records, proposed timing instrumentation, and recovery after adapter disabling.
Implementation claims were checked against the current scripts; future timing
and recovery procedures are explicitly identified as proposed work. Classifier
assessment, reported measurements, and references are unchanged.

The former column break before the bibliography was moved before the
conclusion, keeping the conclusion together in the right column. Standard
IEEE margins, font sizes, and spacing are unchanged. The six-page PDF's last
columns extend through approximately 90% (left) and 96% (right) of the printable
text height, both beyond three quarters of the physical page height. The
rendered layout was checked, and all thirteen references resolve without
overfull boxes. The previous source is preserved in
`archive/main-before-page-expansion-2026-09-12.tex`.

## Related work and classifier clarity — 12 September 2026

Related Work now covers forensic automation and system integration, followed
by malware classification and analyst support. New references are GRR
(Cohen, Bilby, and Caronni, 2011), SPECTRE (Syed et al., 2026), and the
author's USBEREIT paper (Okore, Womoakor, and Kotenko, 2026), cited as [8].
The USBEREIT description follows the supplied author PDF and uses the DOI
provided by the author: `10.1109/USBEREIT70063.2026.11580625`. Its unverified
page range is omitted. The comparison describes complementary evidence sources
and operational roles; it does not claim detector reuse or prior containment.

Primary sources for the added systems literature:

- [GRR paper, DFRWS](https://dfrws.org/sites/default/files/session-files/2011_USA_paper-distributed_forensics_and_incident_response_in_the_enterprise.pdf)
- [SPECTRE, publisher record and full text](https://link.springer.com/article/10.1007/s10207-026-01212-6)

Section V now separates benchmark performance, implications for deployment,
and host-relative scoring. The revision retains the reported numerical results
and scoring equation, explains the matching procedure and probability band,
and distinguishes the separately evaluated scorer from the containment path.
The 148 matched records comprise 74 from each class. Possible dependencies
from synthetic augmentation remain unconfirmed, and pilot reference scores
remain unsuitable for estimating an independent false-positive rate.

The user's pre-edit source is preserved at
`archive/main-before-related-work-and-classifier-2026-09-12.tex`. Other prose
is unchanged. The missing `arch_diag.png` reference was corrected to the
existing `SIBIRCON_arch_diag.png`, retaining the user's single-column placement
and fitting the image to the column width. The manuscript compiles to six
pages with thirteen references; all six pages were visually checked. The
source package contains the two figure files referenced by the manuscript.

## Follow-up refinements — 12 September 2026

The conclusion now emphasizes the implemented system, the WannaCry application
result, and the requirements for broader deployment. Section III-A cites the
author-provided GitHub source repository, with a new bibliography entry for
CCF-Project; the paper now has ten references. Local repository metadata
confirms the source URL and author. No release version or full reproducibility
claim is added. Earlier follow-up edits reduced the architecture figure to
65% of the text width and clarified orchestration, timing, and classifier
assessment. The PDF and source archive include these refinements.

The Discussion now progresses through operational value and response ordering,
reliability requirements, and evaluation scope and further validation. This
separates the engineering controls needed for deployment from the limits of
the current evidence. Analyst-workload effects remain unmeasured, and command
status remains distinct from independent verification of containment.

## Implementation and application prose — 12 September 2026

The author's edited prose through Section III-B is preserved exactly. The
architecture figure is the only change within those earlier sections:
`figures/SIBIRCON_arch_diag.png` replaces the previous TikZ diagram as Figure 1.
The supplied PNG is included without modification. Its caption identifies
network quarantine as adapter disabling over WinRM, matching the implementation.
The image's older “WinRM Firewall” label should be corrected in its editable
source when available; the two VM headings also have unfinished parentheses.

From the former “Artifact-Based Stage Transitions” subsection onward, the
revision emphasizes design, representation, evaluation, and application:

- “Event-Driven Orchestration” explains the control/data interfaces and their
  design implications rather than narrating individual script invocations.
- Feature representation, classification, and response are described as
  implemented components with defined inputs, outputs, and decision policies.
- “Experimental Evaluation” defines functional criteria, reports the observed
  results, and distinguishes workflow latency from full containment latency.
- Classifier assessment remains a supporting section. Its numerical findings
  and scoring definition are retained.
- Discussion consolidates operational tradeoffs and evaluation limits; the
  conclusion leads with the implemented forensic response pipeline.

The complete user-edited draft is preserved at
`archive/main-before-implementation-edit-2026-09-12.tex`. No changes were made
to the author block, earlier prose, data, or pipeline code. The current source
package includes both the supplied architecture PNG and response-log PNG.

## Systems emphasis — 9 September 2026

The current revision follows the author's request for a systems and application
paper. System design, implementation, and the WannaCry case study are the main
contribution. The CIC-MalMem-2022 audit and baseline-differential pilot support
the deployment assessment and do not lead the title, abstract, or argument.
The formal register follows the USBEREIT paper. Author names, affiliations,
and email addresses are unchanged.

Recommended title, used in `main.tex`:

**Automated Memory Forensics for Malware Detection and Incident Response**

The previous analysis-focused manuscript is preserved at
`archive/main-before-system-refocus.tex`, including its full audit and pilot
tables. It should not be used as the template for the paper's current emphasis.

## Systems and application focus

- Rewrote the title, abstract, introduction, contributions, related work, and
  conclusion around the integrated forensic response workflow.
- Expanded the main implementation section to cover component placement,
  alert parsing, WinRM acquisition, FIM handoffs, feature/model interfaces,
  containment ordering, notification, and operational observability.
- Added a dedicated WannaCry application section with functional evidence and
  timestamp tables. The reconstructed intervals are 60 seconds from acquisition
  start to extraction start, then 111 seconds to response start, totaling 171
  seconds. These are stage-start intervals, not standalone processing times or
  completed containment latency.
- Replaced the compact flow diagram with a two-role architecture diagram and
  included the original response-log screenshot. All figures and tables in the
  main paper now concern the system or application case study.
- Consolidated the audit and host-relative pilot into one supporting section;
  retained their measured results and the prior evidence corrections below.
- Added system deployment requirements grounded in the scripts: completed-file
  handoff, incident-specific artifacts, duplicate-trigger handling, and response
  verification. These are identified as future work, not implemented capabilities.

New application evidence comes from the course report, especially pp. 4–12,
and `Images/response_and_pred_trig.png`, `Images/wazuh_alert_final.png`, and
`Images/network_failure_final.png`. The included screenshot is copied without
modification to `figures/response_execution.png`. Its historical serialization
is distinguished from the current JSON interface in the text. Four local
transmit failures support the connectivity observation; they are not presented
as exhaustive network-isolation testing.

Primary project references for [WinPMEM](https://github.com/Velocidex/WinPmem)
and the [Volatility3 framework](https://volatility3.readthedocs.io/en/latest/)
were checked and added for the system description.

## Earlier writing and evidence revision

- Replaced dramatic headings, discovery narrative, and unsupported novelty claims
  with descriptive headings and result-led explanations.
- Shortened the abstract and introduction; removed repeated caveats and logistical
  details about cloud subscriptions and unavailable lab access.
- Defined the actual score, fitting data, feature sets, and threshold before the
  pilot results. Used pre-test/post-test labels to describe attack emulation.
- Added a vector architecture diagram and regenerated the overlap figure with
  accurate labels. Its handle histograms now share 60 logarithmically spaced
  bins and retain every record, including the outlier; overlap coefficients
  still use the original 60-bin linear calculation.
- Repaired the figure path, simplified table headings, removed an extra table
  column, and ordered references by first citation.
- Added verified references for security-ML evaluation, Wazuh, Volatility3,
  Atomic Red Team, MITRE ATT&CK, and the dataset landing page.

## Evidence corrections that go beyond tone

Several statements in the original draft and briefing did not match the
available code, data, or primary sources. These changes are deliberate and
should not be reverted merely to match the earlier briefing.

| Original statement | Revised interpretation and evidence |
|---|---|
| 55 features in the ablation | 55 raw features, **52 nonconstant predictors**. See `analysis/03_ablation.py`. |
| Two features match the full model within 0.0001 | The 0.9998 host-counter model is within 0.0001 of 0.9999; the two-service-feature model is 0.9984. |
| Zero-feature rule, statistically indistinguishable from the model | The rule uses **one feature** and no fitted classifier; its 99.63% is a **full-corpus** result. No equivalence test is available. |
| The table reruns the deployed estimator | It retrains XGBoost with the same two-feature set on the audit split. The original notebook used deduplication and a different split. |
| All count features have higher benign medians | The direction script selects **22 count and count-derived features**, including two normalized indicators; it does not enumerate every counter. See `analysis/02_confound_direction.py`. |
| 99.08% perfectly separated by capture protocol | 99.08% lie outside a class-probability band. Inputs include behavioral features, and 1,533 outside-band predictions are wrong. This does not identify a causal protocol effect. See `analysis/06_overlap.py`. |
| Only 148 records have common support | The matching procedure retains **148 records** after trimming and bin matching. Its trimmed overlap interval contains 1,000 records. See `analysis/05_load_matched.py`. |
| Benign captures came from a different, larger physical desktop | The dataset paper does not establish different benign hardware. It describes normal applications and deliberately running benign applications during malicious collection. |
| SMOTE parent leakage proved across the train/test split | Pre-release augmentation creates a dependence risk; exact original/synthetic relationships are not available to establish or quantify it. |
| All first-six captures have commit charge 259–265 | **Pre-test** captures span 259–265; **all** captures span 259–272. Values in trials 7–10 span 773–778. |
| A specific persistent DLL caused the later baseline shift | The aggregate records establish a persistent shift. The responsible process and injection are not recoverable from the retained evidence. |
| The restricted score detects APC injection and hollowing | Their scores increase, but **no retained post-test capture reaches the default threshold of 6**. Reference scores reuse the six fitting captures, so they do not establish a held-out false-positive rate. |
| The full-feature reference alert is driven by `svcscan.nactive` | The alert is driven by **`handles.nkey`**. See `paper/verify_pilot.py`. |
| MAD is always floored at 1% of the median or 1 | The code applies that fallback **only when scaled MAD is below 1e-6**. The revised equation matches `pipeline/baseline_diff.py`. |
| Browser and office workloads were actual application sessions | These are script labels for Notepad/Paint/Calculator/Explorer combinations. Technique and workload use the same fixed rotation. |
| Raw run transcript proves a universal `malfind` detection boundary | No execution transcript is present in this checkout, including ignored lab/pipeline files. Current official `malfind` code also examines some non-private mappings. |
| Completed containment took under three minutes | Course-report p. 12 timestamps support **171 seconds from acquisition-script start to response-script start**. A separate containment-completion timestamp is unavailable. |
| Response disables the firewall or inserts firewall rules | `response.py` invokes `Get-NetAdapter` and `Disable-NetAdapter`; the manuscript now describes adapter disabling. |

Benchmark and pilot measurements are unchanged; the full paired-delta table
is retained in the archived analysis-focused draft and is reproduced by
`verify_pilot.py`. Pipeline/model code, data, and the historical
`analysis/FINDINGS.md` are unchanged. The original pre-revision manuscript is
retained at `archive/main-before-2026-09-09.tex`.

## Verified source corrections

- [Carrier publisher record](https://www.scitepress.org/Link.aspx?doi=10.5220/0010908200003120):
  99.00% accuracy and 99.02% F1, rather than an accuracy range.
- [Carrier methodology](https://www.scitepress.org/PublishedPapers/2022/109082/pdf/index.html):
  used to check capture conditions and the reported SMOTE step.
- [VolMemLyzer maintainer citation](https://pypi.org/project/volmemlyzer/#copyright-c-2020-and-citation):
  corrected 2019 to **2021**, P. Kaur to **G. Kaur**, and added pages and DOI.
- [Arp et al., USENIX Security 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/arp):
  provides the general evaluation-validity reference.
- [Official Volatility3 implementation](https://volatility3.readthedocs.io/en/latest/_modules/volatility3/plugins/windows/malware/malfind.html):
  supports the discussion of heuristic sensitivity, not a universal
  sub-technique-level detectability boundary.

The Abid citation was omitted because publisher metadata could not be
independently verified in this pass and the accessible author text did not
support the draft's PCA claim. The earlier revision did not include a USBEREIT
self-citation; the author's subsequent requested addition is documented above.
Online documentation is cited as accessed on 9 September 2026; the exact
Atomic Red Team revision and executed test identifiers remain unavailable.

## Reproduction and compilation

From the project root:

```bash
.venv/bin/python paper/verify_pilot.py
.venv/bin/python paper/figures/plot_overlap.py
.venv/bin/python analysis/03_ablation.py
.venv/bin/python analysis/02_confound_direction.py
.venv/bin/python analysis/05_load_matched.py
```

The pilot checker reads existing CSVs and refits models in memory. The figure
script writes only the paper's figure PDF/PNG. Original analysis scripts keep
their historical commentary; the interpretation in this note and the revised
paper reflects the source audit.

For an ordinary LaTeX installation, compile from `paper/`:

```bash
pdflatex -interaction=nonstopmode -halt-on-error main.tex
pdflatex -interaction=nonstopmode -halt-on-error main.tex
```

The source requires IEEEtran, cite, amsmath, amssymb, graphicx, booktabs, TikZ,
url, and hyperref. `submission-source.zip` contains `main.tex`, `IEEEtran.cls`,
and both diagram/screenshot PNGs for direct upload to Overleaf. The architecture
diagram is the supplied `figures/SIBIRCON_arch_diag.png`. The compiled reading copy is `main.pdf`. The
overlap figure and its reproduction script remain available as supporting
project artifacts but are not included in the systems paper or source package.

For this revision, missing LaTeX packages were downloaded and extracted under
`/tmp/sibircon-tex`; no system packages were installed. No submission or
similarity-check service was used.

The source uses the standard IEEE conference layout and embedded fonts. The
PDF is compiled and visually checked after each substantive revision. The pilot
checker reproduces the supporting score summaries without running collection
or response scripts.

The 9 September systems revision compiled to five pages with nine cited references, two
system figures, and three implementation/case-study tables. All references
resolved and no overfull boxes were reported. All five rendered pages were
visually inspected. The 12 September revision uses the larger supplied
architecture diagram and compiles to six pages; it retains nine references,
two figures, and three tables.
