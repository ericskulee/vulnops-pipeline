![VulnOps Pipeline](https://github.com/ericskulee/vulnops-pipeline/actions/workflows/vulnops.yml/badge.svg)

# VulnOps Pipeline — Scan → Normalize → Prioritize → Track → Report

A practical vulnerability operations workflow that turns raw scan output into **risk-based remediation priorities**, **SLA tracking**, and **executive + technical reports** — with evidence you can show in GitHub.

> **Lab note:** Built and validated in a small VMware Fusion lab using **Kali (scanner)** + **Ubuntu (workstation/runner)**.

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
- *(Host)* macOS running VMware Fusion (no dependency on host files)

---

## How it works (end-to-end)

### 1) Run a scan (Kali → Nmap XML)

From **Kali**, scan the Ubuntu target and export results to XML:

```bash
# Replace with your target IP
TARGET="172.16.135.130"

# Simple output name
sudo nmap -sV -O -Pn --reason "$TARGET" -oX scan.xml

# Optional: timestamped output (nice for keeping history)
# sudo nmap -sV -O -Pn --reason "$TARGET" -oX "scan_$(date +%F_%H%M).xml"

---

```
## 2) Transfer scan output (Kali → Ubuntu
Copy the XML from Kali to Ubuntu over SSH:
```
scp scan.xml cyberic@172.16.135.130:~/vulnops-pipeline/sample_data/scans/scan.xml
```
---

## 3) Convert XML → normalized findings CSV (Ubuntu
On **Ubuntu**, inside the repo:
```
cd ~/vulnops-pipeline

python3 src/nmap_xml_to_findings.py \
  --xml sample_data/scans/scan.xml \
  --out sample_data/scans/scan_findings.csv
```
---

## 4) Prioritize + generate reports (Ubuntu)
Run the pipeline to produce the prioritized CSV and both report types:

```
python3 src/generate_reports.py \
  --findings sample_data/scans/scan_findings.csv \
  --assets sample_data/assets.csv \
  --known-exploited sample_data/known_exploited_cves.txt \
  --outdir outputs \
  --reportdir reports
```

---

## 5) Publish to GitHub (Ubuntu → Git over SSH)
Commit and push changes from Ubuntu:

```
git add -A
git commit -m "Update scan + findings + reports"
git push origin main
```
---

## Architecture diagram
Paste this directly into your README.md. GitHub renders Mermaid automatically **as long as it’s in a** ```mermaid 
**block**.

```
flowchart LR
  K["Kali VM (Scanner)"] -->|"Nmap scan"| X["scan.xml"]
  K -->|"SCP over SSH"| U["Ubuntu VM (Workstation)"]
  U -->|"Parse XML → CSV"| F["sample_data/scans/scan_findings.csv"]
  U -->|"Prioritize findings"| P["outputs/prioritized_findings.csv"]
  U -->|"Generate reports"| R["reports/*.md"]
  U -->|"Git push (SSH)"| G["GitHub Repo"]
```
--- 

## Project structure

- sample_data/ — sample assets + scan inputs (sanitized/demo)
- src/ — parsing, scoring, SLA assignment, report generation
- outputs/ — prioritized CSV outputs
- reports/ — executive and technical markdown reports
- docs/ — triage workflow, false-positive handling, verification notes (optional/future)

---

## Run it Locally (Optional)
If you already have Python 3 installed:

```
python3 src/generate_reports.py \
  --findings sample_data/scans/scan_findings.csv \
  --assets sample_data/assets.csv \
  --known-exploited sample_data/known_exploited_cves.txt \
  --outdir outputs \
  --reportdir reports
```
---

## Version control approach (hybrid)
To keep the repo recruiter-friendly and still provide proof:
- **Commit**: key outputs and reports (easy to read directly in GitHub)
- **Artifacts (Actions):** optionally publish full run artifacts for each CI run

---

##  Safety / ethics
All scanning and testing should be performed only on systems you own or are authorized to assess.

---

## Roadmap (future labs)
This repo can be extended with additional security operations workflows, for example:
- Windows target VM scanning + normalization
- GRC evidence capture (controls → evidence mapping)
- IAM review checks (accounts, permissions, drift)
- Patch verification + compliance reporting
- Ticket automation (prioritized findings → remediation tasks)
