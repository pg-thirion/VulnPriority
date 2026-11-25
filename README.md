# VulnPriority

Risk-based vulnerability prioritisation for security operations teams. Rank individual asset findings using exploitation evidence, technical severity, asset criticality, business impact and exposure. Designed as an explainable, local-first portfolio prototype for defensive security.

## Run

Requires Python 3.10+; no third-party dependencies or API keys.

```sh
python app.py
```

Open http://127.0.0.1:8000. Load the synthetic demo, enter findings or import a CSV. Search and filter the ranked queue, inspect scoring explanations and export a remediation CSV. Data stays in the browser session and local application, with no external network calls.

```sh
python -m unittest discover -v
```

## CSV schema

```csv
cve,asset,cvss,epss,kev,criticality,impact,exposure
CVE-2025-12345,example-gateway,8.1,0.4,true,5,5,internet
```

EPSS is a probability from 0 to 1; blank means unknown. CVSS is 0 to 10. Criticality and impact are integers from 1 (low) to 5 (essential). Exposure is internal, restricted or internet. KEV must be true, false or blank (unknown). Each CVE/asset pair must be unique. Use validated evidence from your scanner and asset inventory. The example is illustrative, not real intelligence.

## Scoring policy (v1)

Weighted components: 30% exploitation likelihood (EPSS), 20% technical severity (CVSS), 20% asset criticality, 20% business impact and 10% exposure. Unknown EPSS uses a neutral policy placeholder of 0.5 and is flagged; it is not an estimated probability. Exposure values are 0.2 internal, 0.6 restricted and 1 internet. Criticality and impact are divided by 5.

Confirmed KEV imposes a score floor of 85, or 95 for internet-facing findings. Unknown KEV is flagged. P1 >= 85 (24 hours), P2 >= 65 (7 days), P3 >= 40 (30 days), otherwise P4 (90 days). Scores are rounded to one decimal before applying bands. SLAs are illustrative remediation targets, not legal requirements. Ties favour confirmed KEV, then CVE and asset identifiers. Every row includes a component breakdown and any override.

The score is a heuristic policy index, not a calibrated likelihood or monetary loss estimate. Validate and tune weights, SLAs and unknown-data handling against your environment. A missing KEV listing does not prove a vulnerability has never been exploited.

## References

- [FIRST EPSS](https://www.first.org/epss/) (ML-based probability of exploitation activity in the next 30 days)
- [FIRST CVSS](https://www.first.org/cvss/) (technical severity)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

## Scope

Offline, synthetic demonstration by default. No live threat feed ingestion, authentication, persistent database, scanning or exploitation. Do not expose the local development server to the internet. Use only authorised vulnerability inventory data. Real deployment needs access controls, audit trails, feed freshness checks, asset inventory integration and organisational SLA approval.
