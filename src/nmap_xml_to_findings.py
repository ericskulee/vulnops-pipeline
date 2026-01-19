import argparse
import csv
import re
import xml.etree.ElementTree as ET
from pathlib import Path

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
# CVSS is 0.0–10.0; keep it strict so we don't accidentally grab port numbers.
CVSS_RE = re.compile(r"\b(?:10(?:\.0)?|[0-9](?:\.\d)?)\b")

FIELDS = ["hostname","ip","port","protocol","cve","cvss","title","description"]

def text_of(elem: ET.Element) -> str:
    parts = []
    if elem is None:
        return ""
    if elem.text:
        parts.append(elem.text)
    for e in elem:
        parts.append(text_of(e))
        if e.tail:
            parts.append(e.tail)
    return " ".join(p.strip() for p in parts if p and p.strip())

def extract_cvss_for_cve(blob: str, cve: str) -> str:
    # Try to find a CVSS score on the same line as the CVE
    for line in blob.splitlines():
        if cve in line:
            m = CVSS_RE.search(line)
            if m:
                return m.group(0)
    return ""

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--xml", required=True, help="Path to nmap XML (scan.xml)")
    ap.add_argument("--out", required=True, help="Path to output CSV (scan_findings.csv)")
    args = ap.parse_args()

    xml_path = Path(args.xml)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    tree = ET.parse(xml_path)
    root = tree.getroot()

    rows = []

    for host in root.findall("host"):
        # IP address
        addr = host.find("address[@addrtype='ipv4']")
        ip = addr.get("addr") if addr is not None else ""

        # Hostname (fallback to IP)
        hn = host.find("hostnames/hostname")
        hostname = hn.get("name") if hn is not None else ip

        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            protocol = port.get("protocol","")
            portid = port.get("portid","")

            svc = port.find("service")
            svc_name = svc.get("name","") if svc is not None else ""
            product = svc.get("product","") if svc is not None else ""
            version = svc.get("version","") if svc is not None else ""
            extrainfo = svc.get("extrainfo","") if svc is not None else ""

            title = " ".join(x for x in [svc_name, product, version] if x).strip() or f"{protocol}/{portid}"
            desc_parts = []
            if extrainfo:
                desc_parts.append(extrainfo)

            # Pull script outputs (where CVEs might appear)
            script_blobs = []
            for s in port.findall("script"):
                out = s.get("output","")
                if out:
                    script_blobs.append(out)
                # Sometimes details are nested
                script_blobs.append(text_of(s))

            blob = "\n".join([b for b in script_blobs if b and b.strip()]).strip()
            if blob:
                desc_parts.append(blob)

            description = "\n\n".join(desc_parts).strip()

            cves = sorted(set(CVE_RE.findall(description)))

            # If no CVEs were discovered, still create a row for the open port
            if not cves:
                rows.append({
                    "hostname": hostname,
                    "ip": ip,
                    "port": portid,
                    "protocol": protocol,
                    "cve": "",
                    "cvss": "",
                    "title": title,
                    "description": description,
                })
            else:
                # Make one row per CVE (better for triage)
                for cve in cves:
                    cvss = extract_cvss_for_cve(description, cve)
                    rows.append({
                        "hostname": hostname,
                        "ip": ip,
                        "port": portid,
                        "protocol": protocol,
                        "cve": cve,
                        "cvss": cvss,
                        "title": title,
                        "description": description,
                    })

    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)

    print(f"✅ Wrote {out_path} ({len(rows)} rows)")

if __name__ == "__main__":
    main()
