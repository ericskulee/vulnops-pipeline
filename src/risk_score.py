from pathlib import Path

def load_known_exploited(path: str) -> set[str]:
    p = Path(path)
    if not p.exists():
        return set()
    return {line.strip() for line in p.read_text(encoding="utf-8").splitlines() if line.strip()}

def to_float(value: str, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default

def calculate_risk_score(finding: dict, asset: dict | None, known_exploited: set[str]) -> float:
    """
    Risk score v1 (0–10):
      - Base = CVSS
      - +1.5 if internet-facing
      - +1.0 if criticality >= 4
      - +1.0 if data sensitivity = High
      - +1.5 if CVE is known exploited (simple proxy)
      - clamp to 10
    """
    cvss = to_float(finding.get("cvss", "0"), 0.0)
    score = cvss

    if asset:
        if asset.get("internet_facing", "").upper() == "Y":
            score += 1.5
        if to_float(asset.get("criticality", "0"), 0.0) >= 4:
            score += 1.0
        if asset.get("data_sensitivity", "").strip().lower() == "high":
            score += 1.0

    cve = (finding.get("cve") or "").strip()
    if cve and cve in known_exploited:
        score += 1.5

    return min(10.0, round(score, 1))
