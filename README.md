![VulnOps Pipeline](https://github.com/ericskulee/vulnops-pipeline/actions/workflows/vulnops.yml/badge.svg)

# VulnOps Pipeline — Scan → Normalize → Prioritize → Track → Report

A practical vulnerability operations workflow that turns raw scan output into **risk-based remediation priorities**, **SLA tracking**, and **executive + technical reports** — with evidence you can show in GitHub.

> **Lab note:** Built and validated in a small VMware Fusion lab using Kali (scanner) + Ubuntu (workstation).

---

## What this demonstrates

- **Vulnerability intake + normalization** (scan results → structured findings)
- **Risk-based prioritization** (CVSS + asset context + known-exploited signal)
- **Remediation SLAs + due dates** (clear timelines for fixing)
- **Executive + technical reporting** (two audiences, two deliverables)
- **Proof via GitHub Actions** (pipeline can run automatically in CI)

---

## Outputs (what gets generated)

This pipeline generates:

- `outputs/prioritized_findings.csv`
- `reports/executive-summary.md`
- `reports/technical-remediation.md`

If GitHub Actions is enabled, the workflow can also publish downloadable artifacts.

---

## Lab setup (my test environment)

Built and validated inside an isolated VMware Fusion lab:

- **Ubuntu VM** — main workstation (runs the Python pipeline + Git pushes)
- **Kali VM** — scanner (runs Nmap and exports results)
- **Internal / NAT networking** — safe test network between VMs

---

## How it works (end-to-end)

### 1) Run a scan (Kali → Nmap XML)

From **Kali**, scan the Ubuntu target and export to XML:

```bash
sudo nmap -sV -O -Pn 172.16.135.130 -oX scan.xml

---

# 2) Transfer scan output (Kali → Ubuntu)

## Copy the scan XML from **Kali** to **Ubuntu** over SSH:

```bash
scp scan.xml cyberic@172.16.135.130:~/vulnops-pipeline/sample_data/scans/scan.xml

---

# 3) Convert XML → normalized findings CSV (Ubuntu)

## On Ubuntu inside the repo:

cd ~/vulnops-pipeline
$)

## If you already have Python 3 installed:

python3 src/generate_reports.py \
  --findings sample_data/scans/scan_findings.csv \
  --assets sample_data/assets.csv \
  --known-exploited sample_data/known_exploited_cves.txt \
  --outdir outputs \
  --reportdir reports

