import argparse
import csv
from datetime import date, timedelta
from pathlib import Path

from parse_scan import load_findings
from risk_score import load_known_exploited, calculate_risk_score
from sla_assign import assign_sla_days, severity_label

def load_assets(assets_csv_path: str) -> dict[str, dict]:
    assets = {}
    with open(assets_csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key = (row.get("hostname") or "").strip()
            if key:
                assets[key] = row
    return assets

def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", required=True)
    ap.add_argument("--assets", required=True)
    ap.add_argument("--known-exploited", default="sample_data/known_exploited_cves.txt")
    ap.add_argument("--outdir", default="outputs")
    ap.add_argument("--reportdir", default="reports")
    args = ap.parse_args()

    findings = load_findings(args.findings)
    assets = load_assets(args.assets)
    known_exploited = load_known_exploited(args.known_exploited)

    enriched = []
    today = date.today()

    for f in findings:
        hostname = (f.get("hostname") or "").strip()
        asset = assets.get(hostname)
        risk = calculate_risk_score(f, asset, known_exploited)
        sla_days = assign_sla_days(risk)
        due_date = today + timedelta(days=sla_days)

        enriched.append({
            "severity": severity_label(risk),
            "risk_score": risk,
            "sla_days": sla_days,
            "due_date": due_date.isoformat(),
            "hostname": hostname,
            "ip": f.get("ip"),
            "port": f.get("port"),
            "protocol": f.get("protocol"),
            "cve": f.get("cve"),
            "cvss": f.get("cvss"),
            "title": f.get("title"),
            "business_unit": asset.get("business_unit") if asset else "",
            "environment": asset.get("environment") if asset else "",
            "internet_facing": asset.get("internet_facing") if asset else "",
            "data_sensitivity": asset.get("data_sensitivity") if asset else "",
            "criticality": asset.get("criticality") if asset else "",
        })

    # Sort: highest risk first
    enriched.sort(key=lambda x: float(x["risk_score"]), reverse=True)

    outdir = Path(args.outdir)
    reportdir = Path(args.reportdir)

    prioritized_path = outdir / "prioritized_findings.csv"
    fieldnames = list(enriched[0].keys()) if enriched else []
    if enriched:
        write_csv(prioritized_path, enriched, fieldnames)

    # Executive summary
    total = len(enriched)
    crit = sum(1 for x in enriched if x["severity"] == "Critical")
    high = sum(1 for x in enriched if x["severity"] == "High")
    med = sum(1 for x in enriched if x["severity"] == "Medium")
    low = sum(1 for x in enriched if x["severity"] == "Low")

    top5 = enriched[:5]

    exec_md = f"""# Executive Summary — Vulnerability Triage (v1)

**Date:** {today.isoformat()}  
**Total Findings:** {total}  
**Severity Breakdown:** Critical {crit} | High {high} | Medium {med} | Low {low}

## Top Priorities (Top 5)
| Severity | Risk Score | Host | CVE | Title | Due Date |
|---|---:|---|---|---|---|
""" + "\n".join(
        f"| {x['severity']} | {x['risk_score']} | {x['hostname']} | {x['cve']} | {x['title']} | {x['due_date']} |"
        for x in top5
    ) + "\n"

    write_text(reportdir / "executive-summary.md", exec_md)

    tech_md = f"""# Technical Remediation Report (v1)

**Date:** {today.isoformat()}  

## Remediation Guidance (How to use this)
1. Validate exposure (service reachable? version confirmed? false positive?)
2. Patch or mitigate (vendor fix / config change / compensating control)
3. Verify remediation (re-scan or targeted validation)
4. Document exceptions (risk acceptance + expiration date)

## Findings (Prioritized)
| Severity | Risk | Host | IP | Port | CVE | Title | SLA Days | Due |
|---|---:|---|---|---:|---|---|---:|---|
""" + "\n".join(
        f"| {x['severity']} | {x['risk_score']} | {x['hostname']} | {x['ip']} | {x['port']} | {x['cve']} | {x['title']} | {x['sla_days']} | {x['due_date']} |"
        for x in enriched
    ) + "\n"

    write_text(reportdir / "technical-remediation.md", tech_md)

    print(f"✅ Wrote: {prioritized_path}")
    print(f"✅ Wrote: {reportdir / 'executive-summary.md'}")
    print(f"✅ Wrote: {reportdir / 'technical-remediation.md'}")

if __name__ == "__main__":
    main()
