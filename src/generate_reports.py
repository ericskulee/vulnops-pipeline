import argparse
import csv
from datetime import date, timedelta
from pathlib import Path

from parse_scan import load_findings
from risk_score import load_known_exploited, calculate_risk_score
from sla_assign import assign_sla_days, severity_label


def load_assets(assets_csv_path: str) -> dict[str, dict]:
    assets: dict[str, dict] = {}
    with open(assets_csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            hostname = (row.get("hostname") or "").strip()
            if hostname:
                assets[hostname] = row
    return assets


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main() -> None:
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

    enriched: list[dict] = []
    today = date.today()

    for fnd in findings:
        hostname = (fnd.get("hostname") or "").strip()
        asset = assets.get(hostname)

        risk = calculate_risk_score(fnd, asset, known_exploited)
        sla_days = assign_sla_days(risk)
        due_date = (today + timedelta(days=sla_days)).isoformat()

        row = {
            "severity": severity_label(risk),
            "risk_score": risk,
            "sla_days": sla_days,
            "due_date": due_date,
            "hostname": hostname,
            "ip": fnd.get("ip"),
            "port": fnd.get("port"),
            "protocol": fnd.get("protocol"),
            "cve": fnd.get("cve"),
            "cvss": fnd.get("cvss"),
            "title": fnd.get("title"),
            "business_unit": asset.get("business_unit") if asset else "",
            "environment": asset.get("environment") if asset else "",
            "internet_facing": asset.get("internet_facing") if asset else "",
            "data_sensitivity": asset.get("data_sensitivity") if asset else "",
            "criticality": asset.get("criticality") if asset else "",
        }
        enriched.append(row)

    enriched.sort(key=lambda x: float(x["risk_score"]), reverse=True)

    outdir = Path(args.outdir)
    reportdir = Path(args.reportdir)

    # Outputs
    write_csv(outdir / "prioritized_findings.csv", enriched)

    # Executive summary
    total = len(enriched)
    crit = sum(1 for x in enriched if x["severity"] == "Critical")
    high = sum(1 for x in enriched if x["severity"] == "High")
    med = sum(1 for x in enriched if x["severity"] == "Medium")
    low = sum(1 for x in enriched if x["severity"] == "Low")

    top5 = enriched[:5]
    lines = []
    lines.append("# Executive Summary — Vulnerability Triage (v1)\n")
    lines.append(f"**Date:** {today.isoformat()}  \n")
    lines.append(f"**Total Findings:** {total}  \n")
    lines.append(f"**Severity Breakdown:** Critical {crit} | High {high} | Medium {med} | Low {low}\n")
    lines.append("\n## Top Priorities (Top 5)\n")
    lines.append("| Severity | Risk Score | Host | CVE | Title | Due Date |\n")
    lines.append("|---|---:|---|---|---|---|\n")
    for x in top5:
        lines.append(f"| {x['severity']} | {x['risk_score']} | {x['hostname']} | {x['cve']} | {x['title']} | {x['due_date']} |\n")

    write_text(reportdir / "executive-summary.md", "".join(lines))

    # Technical report
    lines = []
    lines.append("# Technical Remediation Report (v1)\n\n")
    lines.append(f"**Date:** {today.isoformat()}  \n\n")
    lines.append("## Findings (Prioritized)\n")
    lines.append("| Severity | Risk | Host | IP | Port | CVE | Title | SLA Days | Due |\n")
    lines.append("|---|---:|---|---|---:|---|---|---:|---|\n")
    for x in enriched:
        lines.append(
            f"| {x['severity']} | {x['risk_score']} | {x['hostname']} | {x['ip']} | {x['port']} | {x['cve']} | {x['title']} | {x['sla_days']} | {x['due_date']} |\n"
        )

    write_text(reportdir / "technical-remediation.md", "".join(lines))

    print("Done. Generated outputs/ and reports/.")


if __name__ == "__main__":
    main()
