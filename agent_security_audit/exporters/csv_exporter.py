"""CSV finding exporter."""

import csv
import io
from pathlib import Path

from agent_security_audit.models import AuditReport

_FIELDS = ["finding_id", "code", "title", "severity", "domain", "description", "recommendation",
           "affected_agent", "affected_resource", "source_event_ids"]


def export_csv(report: AuditReport, destination: str | Path | None = None) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=_FIELDS)
    writer.writeheader()
    for finding in report.findings:
        row = finding.model_dump(mode="json")
        row["source_event_ids"] = ",".join(row["source_event_ids"])
        row.pop("evidence", None)
        writer.writerow({field: row.get(field, "") for field in _FIELDS})
    text = output.getvalue()
    if destination is not None:
        Path(destination).write_text(text, encoding="utf-8", newline="")
    return text
