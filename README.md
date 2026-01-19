![VulnOps Pipeline](https://github.com/ericskulee/vulnops-pipeline/actions/workflows/vulnops.yml/badge.svg)

# VulnOps Pipeline — Scan → Normalize → Prioritize → Track → Report

## What this demonstrates
- Vulnerability intake + normalization (scan findings)
- Risk-based prioritization (CVSS + asset context + known-exploited flag)
- Remediation SLAs + due dates
- Executive + technical reporting outputs
- Proof (GitHub Actions)

---

## What this is
A practical vulnerability operations workflow that turns scan findings into:
- normalized results
- risk-based prioritization
- remediation SLAs
- executive + technical reports

---

## Outputs (what gets generated)
This pipeline runs in CI and generates:

- `outputs/prioritized_findings.csv`
- `reports/executive-summary.md`
- `reports/technical-remediation.md`

**To verify:** GitHub **Actions** → latest successful run → download **vulnops-artifacts**.

---

## How it works (high-level)
1. **Scan** a target system to collect exposed services and versions (example: Nmap XML).
2. **Normalize** results into a clean, consistent findings format (CSV).
3. **Prioritize** using risk signals (CVSS + asset importance + known-exploited indicator).
4. **Assign SLAs** and due dates to drive remediation timelines.
5. **Report** in two formats: an executive summary and a technical remediation plan.
6. **Prove it in CI**: GitHub Actions runs the pipeline and publishes downloadable artifacts.

---

## Lab setup (what I used)
A small, isolated VMware Fusion lab:
- **Ubuntu** (main workstation + pipeline runner)
- **Kali** (scanner)
- Internal network for safe testing

## Architecture Diagram
```mermaid
flowchart LR
  K["Kali VM<br/>Scanner"] -->|Nmap scan → XML| X["scan.xml"]
  X -->|SCP over SSH| U["Ubuntu VM<br/>Workstation"]
  U -->|Python parse| F["scan_findings.csv"]
  U -->|Python prioritize| P["prioritized_findings.csv"]
  U -->|Generate reports| R["executive-summary.md<br/>technical-remediation.md"]
  U -->|Git (SSH) push| G["GitHub Repo"]
```

---

## Project structure
- `sample_data/` — sample assets + scan findings (sanitized/demo)
- `src/` — parsing, scoring, SLA assignment, report generation
- `outputs/` — prioritized CSV outputs
- `reports/` — executive and technical markdown reports
- `docs/` — triage workflow, false-positive handling, verification notes

---

## Run it locally (optional)
```bash
python3 src/generate_reports.py \
  --findings sample_data/scans/scan_findings.csv \
  --assets sample_data/assets.csv \
  --outdir outputs \
  --reportdir reports
