# Reference verification — 12 September 2026

All 13 bibliography entries were checked. The seven existing website URLs
returned HTTP 200 and identified the intended resources. All five DOI
identifiers resolved to the corresponding publisher records, and Crossref
metadata matched the cited publications. Reference [9] had neither a URL nor
a DOI; its official USENIX page was verified and added.

## Results by reference

| Ref. | Cited resource and verified link | Result |
| --- | --- | --- |
| [1] | [Wazuh: Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html) | Valid. Official Wazuh documentation for the cited capability. |
| [2] | [Velocidex: WinPmem](https://github.com/Velocidex/WinPmem) | Valid. The tool's official source repository. |
| [3] | [Volatility 3 Documentation](https://volatility3.readthedocs.io/en/latest/) | Valid. The documentation site identifies Volatility 3. |
| [4] | Cohen, Bilby, and Caronni, *Distributed forensics and incident response in the enterprise*: [10.1016/j.diin.2011.05.012](https://doi.org/10.1016/j.diin.2011.05.012) | Valid DOI. Resolves to Elsevier's record for PII S1742287611000363. Crossref matches the title, authors, *Digital Investigation*, volume 8, 2011, and pp. S101–S110. |
| [5] | Syed et al., *SPECTRE: a hybrid and adaptive cyber threats detection and response in volatile memory*: [10.1007/s10207-026-01212-6](https://doi.org/10.1007/s10207-026-01212-6) | Valid DOI. Springer and Crossref match the title, four authors, *International Journal of Information Security*, volume 25, article 52, and 2026. |
| [6] | Lashkari et al., *VolMemLyzer: Volatile Memory Analyzer for Malware Classification using Feature Engineering*: [10.1109/RDAAPS48126.2021.9452028](https://doi.org/10.1109/RDAAPS48126.2021.9452028) | Valid DOI. Resolves to IEEE document 9452028. Crossref matches the title, authors, RDAAPS 2021, and pp. 1–8. See the IEEE access qualification below. |
| [7] | Carrier et al., *Detecting Obfuscated Malware using Memory Feature Engineering*: [10.5220/0010908200003120](https://doi.org/10.5220/0010908200003120) | Valid DOI. SciTePress and Crossref identify the cited ICISSP 2022 paper, pp. 177–188. |
| [8] | Okore, Womoakor, and Kotenko, *Explainable Machine Learning for Effective Malware Detection in Encrypted Network Traffic*: [10.1109/USBEREIT70063.2026.11580625](https://doi.org/10.1109/USBEREIT70063.2026.11580625) | Valid DOI. Resolves to IEEE document 11580625. Crossref matches the title, all three authors, USBEREIT 2026, and pp. 1–4. The page range has been added to the manuscript. See the IEEE access qualification below. |
| [9] | Arp et al., [*Dos and Don'ts of Machine Learning in Computer Security*](https://www.usenix.org/conference/usenixsecurity22/presentation/arp) | Valid official publication page. The publisher's citation confirms all eight authors, USENIX Security 2022, and pp. 3971–3988. Its citation supplies no DOI; the official URL has been added instead. |
| [10] | [Joel C. Okore: CCF-Project](https://github.com/Joellots/CCF-project) | Valid. The page and GitHub API identify Joellots/CCF-Project. The lowercase `project` spelling in the manuscript resolves correctly. |
| [11] | [Canadian Institute for Cybersecurity: CIC-MalMem-2022](https://www.unb.ca/cic/datasets/malmem-2022.html) | Valid. Official University of New Brunswick page for the cited memory-analysis dataset. |
| [12] | [Red Canary: Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | Valid. The project's official source repository. |
| [13] | [MITRE ATT&CK: Process Injection, T1055](https://attack.mitre.org/techniques/T1055/) | Valid. Official entry for the parent technique T1055, containing the referenced subtechniques. |

## Verification method and access qualifications

The checks followed live HTTP redirects and compared destination identity,
rather than treating a successful status code alone as evidence of a match.
For the five papers with DOIs, the title, authors, venue, year, and available
pagination were also compared with the publisher-deposited Crossref records:

- [Cohen et al.: Crossref record](https://api.crossref.org/works/10.1016%2Fj.diin.2011.05.012)
- [Syed et al.: Crossref record](https://api.crossref.org/works/10.1007%2Fs10207-026-01212-6)
- [Lashkari et al.: Crossref record](https://api.crossref.org/works/10.1109%2FRDAAPS48126.2021.9452028)
- [Carrier et al.: Crossref record](https://api.crossref.org/works/10.5220%2F0010908200003120)
- [Okore et al.: Crossref record](https://api.crossref.org/works/10.1109%2FUSBEREIT70063.2026.11580625)

Both IEEE DOI resolvers returned HTTP 302 redirects to the expected document
identifiers. IEEE Xplore then returned HTTP 202 without article content to the
automated client. Consequently, this audit confirms their registration,
bibliographic identity, and publisher destination through the DOI redirects
and matching Crossref records; it does not claim that IEEE full text was
retrieved. The [VolMemLyzer author's repository citation](https://github.com/ahlashkari/VolMemLyzer#copyright-c-2020-and-citation)
also corroborates reference [6].

The Elsevier destination returned a redirect landing page rather than the
article text. Its PII matches the Crossref publisher destination and the
[ScienceDirect publication record](https://www.sciencedirect.com/science/article/pii/S1742287611000363).
The paper is also available from [DFRWS](https://dfrws.org/sites/default/files/session-files/2011_USA_paper-distributed_forensics_and_incident_response_in_the_enterprise.pdf).
Springer and SciTePress returned publication pages identifying the cited papers.

## Manuscript changes

- Kept all existing DOI identifiers and website URLs; none required replacement.
- Made the five DOI identifiers clickable in the PDF.
- Added the verified USBEREIT page range, pp. 1–4.
- Added the official USENIX publication URL to reference [9].
- Preserved the existing access dates; this audit records the later verification date separately.

During compilation, the missing figure filename `arch_diag.png` was corrected
to the existing `SIBIRCON_arch_diag.png`, preserving the figure's size and
placement. The paper's prose and scientific results were not changed by this
reference audit. The pre-audit source is saved in
`archive/main-before-reference-audit-2026-09-12.tex`.
