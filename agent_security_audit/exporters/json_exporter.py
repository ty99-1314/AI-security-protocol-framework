"""JSON report exporter."""

import json
from pathlib import Path
from typing import Any

from agent_security_audit.models import AuditReport


def export_json(report: AuditReport, destination: str | Path | None = None, *, indent: int = 2) -> str:
    text = json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=indent)
    if destination is not None:
        Path(destination).write_text(text + "\n", encoding="utf-8")
    return text
