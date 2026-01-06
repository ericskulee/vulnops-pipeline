from datetime import timedelta

def assign_sla_days(risk_score: float) -> int:
    # Simple SLA policy for v1
    if risk_score >= 9.0:
        return 7      # Critical
    if risk_score >= 7.5:
        return 14     # High
    if risk_score >= 5.0:
        return 30     # Medium
    return 60         # Low

def severity_label(risk_score: float) -> str:
    if risk_score >= 9.0:
        return "Critical"
    if risk_score >= 7.5:
        return "High"
    if risk_score >= 5.0:
        return "Medium"
    return "Low"
