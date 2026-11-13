"""Basic audit-result statistics."""

from collections import Counter


def summarize(events, findings) -> dict[str, int | float | dict[str, int]]:
    findings = list(findings)
    risks = Counter(str(getattr(f.severity, "value", f.severity)) for f in findings)
    affected = {event_id for finding in findings for event_id in finding.source_event_ids}
    total = len(events)
    return {"total_events": total, "total_findings": len(findings), "events_with_findings": len(affected),
            "event_pass_rate": round(100 * (total - len(affected)) / total, 2) if total else 100.0,
            "risk_distribution": dict(risks)}
