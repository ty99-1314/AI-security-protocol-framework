"""Audit-log completeness and traceability checks."""

from typing import Any, Iterable, Mapping

from agent_security_audit.constants import AuditDomain, FindingCode, RiskLevel
from agent_security_audit.models import Finding, PolicyConfig
from .base_checker import BaseChecker


class LogAuditChecker(BaseChecker):
    domain = AuditDomain.LOG_AUDIT

    def run(self, events: Iterable[Mapping[str, Any]]) -> list[Finding]:
        findings = []
        for event in events:
            if self.policy.require_logging and event.get("logged") is False:
                findings.append(self.make_finding(code=FindingCode.LOG_MISSING.value,
                    title="Event was not logged", severity=RiskLevel.HIGH,
                    description="The event explicitly reports that audit logging did not occur.", event=event,
                    recommendation="Emit tamper-resistant audit records for all security-relevant operations."))
            if self.policy.require_traceability and not (event.get("trace_id") or event.get("request_id")):
                findings.append(self.make_finding(code=FindingCode.TRACE_MISSING.value,
                    title="Trace identifier missing", severity=RiskLevel.MEDIUM,
                    description="Event cannot be correlated to a request or distributed trace.", event=event,
                    recommendation="Attach a stable request_id or trace_id to every event."))
            required = ("timestamp", "event_type")
            missing = [key for key in required if not event.get(key)]
            if missing:
                findings.append(self.make_finding(code=FindingCode.INCOMPLETE_AUDIT_RECORD.value,
                    title="Audit record is incomplete", severity=RiskLevel.MEDIUM,
                    description=f"Missing required audit fields: {', '.join(missing)}.", event=event,
                    recommendation="Validate normalized event records before they enter the audit pipeline."))
        return findings
