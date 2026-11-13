"""Human-readable Markdown report exporter."""

from pathlib import Path

from agent_security_audit.models import AuditReport


def export_markdown(report: AuditReport, destination: str | Path | None = None) -> str:
    meta = report.meta
    lines = [f"# Agent Security Audit: {meta.audit_id}", "", f"- **Date:** {meta.audit_date}",
             f"- **Scope:** {meta.scope}", f"- **Owner:** {meta.owner}",
             f"- **Policy version:** {meta.policy_version}", f"- **Events reviewed:** {report.total_events}",
             f"- **Findings:** {len(report.findings)}", "", "## Findings", ""]
    if not report.findings:
        lines.append("No findings.")
    for finding in report.findings:
        lines.extend([f"### {finding.severity.value if hasattr(finding.severity, 'value') else finding.severity}: {finding.title}",
                      "", f"- **Code:** `{finding.code}`", f"- **Domain:** `{finding.domain.value if hasattr(finding.domain, 'value') else finding.domain}`",
                      f"- **Description:** {finding.description}", f"- **Recommendation:** {finding.recommendation}"])
        if finding.source_event_ids:
            lines.append(f"- **Source events:** {', '.join(finding.source_event_ids)}")
        lines.append("")
    text = "\n".join(lines).rstrip() + "\n"
    if destination is not None:
        Path(destination).write_text(text, encoding="utf-8")
    return text
