![VulnOps Pipeline](https://github.com/ericskulee/vulnops-pipeline/actions/workflows/vulnops.yml/badge.svg)

## What this demonstrates
- Vulnerability intake + normalization (scan findings)
- Risk-based prioritization (CVSS + asset context + known-exploited flag)
- Remediation SLAs + due dates
- Executive + technical reporting outputs

## Proof (GitHub Actions)
This pipeline runs in CI and generates:
- `outputs/prioritized_findings.csv`
- `reports/executive-summary.md`
- `reports/technical-remediation.md`

To verify: Actions → latest successful run → download `vulnops-artifacts`.


# VulnOps Pipeline — Scan → Normalize → Prioritize → Track → Report

## What this is
A practical vulnerability operations workflow that turns scan findings into:
- normalized results
- risk-based prioritization
- remediation SLAs
- executive + technical reports

## Project structure
- `sample_data/` — sample assets + scan findings (sanitized/demo)
- `src/` — parsing, scoring, SLA assignment, report generation
- `outputs/` — prioritized CSV outputs
- `reports/` — executive and technical markdown reports
- `docs/` — triage workflow, false-positive handling, verification notes

## Run it locally (optional)
```bash
python src/generate_reports.py \
  --findings sample_data/scans/scan_findings.csv \
  --assets sample_data/assets.csv \
  --outdir outputs \
  --reportdir reports
