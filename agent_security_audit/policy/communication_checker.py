"""Communication confidentiality and integrity checks."""

from typing import Any, Iterable, Mapping

from agent_security_audit.constants import AuditDomain, FindingCode, RiskLevel
from agent_security_audit.models import Finding, PolicyConfig
from .base_checker import BaseChecker


class CommunicationChecker(BaseChecker):
    domain = AuditDomain.COMMUNICATION_SECURITY

    def run(self, events: Iterable[Mapping[str, Any]]) -> list[Finding]:
        findings = []
        for event in events:
            if str(event.get("event_type", "")) not in {"network", "communication", "message"}:
                continue
            if event.get("encrypted") is False:
                findings.append(self.make_finding(code=FindingCode.COMMUNICATION_UNENCRYPTED.value,
                    title="Communication is not encrypted", severity=RiskLevel.HIGH,
                    description="Communication event explicitly reports encryption disabled.", event=event,
                    recommendation="Protect inter-agent and agent-to-service traffic with authenticated TLS."))
            if event.get("integrity_valid") is False:
                findings.append(self.make_finding(code=FindingCode.INTEGRITY_FAIL.value,
                    title="Communication integrity check failed", severity=RiskLevel.CRITICAL,
                    description="Message integrity verification failed.", event=event,
                    recommendation="Reject the message and investigate the signing or transport boundary."))
            if event.get("authenticated") is False:
                findings.append(self.make_finding(code=FindingCode.AUTH_HEADER_MISSING.value,
                    title="Communication sender is not authenticated", severity=RiskLevel.HIGH,
                    description="Communication event has no verified sender authentication.", event=event,
                    recommendation="Authenticate peers before accepting messages."))
        return findings
