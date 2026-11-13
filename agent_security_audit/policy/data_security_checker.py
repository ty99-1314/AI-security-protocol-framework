"""Data export and sensitive-data exposure checks."""

import re
from typing import Any, Iterable, Mapping

from agent_security_audit.constants import AuditDomain, FindingCode, RiskLevel
from agent_security_audit.models import Finding, PolicyConfig
from .base_checker import BaseChecker


class DataSecurityChecker(BaseChecker):
    domain = AuditDomain.DATA_SECURITY

    def run(self, events: Iterable[Mapping[str, Any]]) -> list[Finding]:
        findings = []
        patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.policy.sensitive_data_patterns]
        for event in events:
            action = str(event.get("action", "")).lower()
            destination = str(event.get("destination", "")).lower()
            if action == "export" and destination and destination not in {x.lower() for x in self.policy.export_allowlist}:
                findings.append(self.make_finding(code=FindingCode.UNSAFE_EXPORT.value,
                    title="Export destination is not allowlisted", severity=RiskLevel.HIGH,
                    description=f"Export destination {destination!r} is not in the configured allowlist.",
                    event=event, recommendation="Restrict exports to approved destinations and validate recipient identity."))
            content = event.get("content", event.get("payload_preview", ""))
            if isinstance(content, str) and any(pattern.search(content) for pattern in patterns):
                findings.append(self.make_finding(code=FindingCode.DATA_EXPOSURE.value,
                    title="Sensitive data detected in event content", severity=RiskLevel.HIGH,
                    description="Configured sensitive-data pattern matched event content.", event=event,
                    recommendation="Minimize sensitive data handling and redact it before logging or exporting."))
        return findings
