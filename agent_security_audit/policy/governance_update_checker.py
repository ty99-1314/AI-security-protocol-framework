"""Policy-change approval and update-governance checks."""

from typing import Any, Iterable, Mapping

from agent_security_audit.constants import AuditDomain, FindingCode, RiskLevel
from agent_security_audit.models import Finding, PolicyConfig
from .base_checker import BaseChecker


class GovernanceUpdateChecker(BaseChecker):
    domain = AuditDomain.GOVERNANCE_UPDATE

    def run(self, events: Iterable[Mapping[str, Any]]) -> list[Finding]:
        findings = []
        for event in events:
            if str(event.get("event_type", "")) != "policy_change":
                continue
            if event.get("approved") is not True:
                findings.append(self.make_finding(code=FindingCode.POLICY_CHANGE_NO_APPROVAL.value,
                    title="Policy change lacks approval", severity=RiskLevel.CRITICAL,
                    description="Policy-change event does not record explicit approval.", event=event,
                    recommendation="Require independent review and approval, and retain an immutable change record."))
            if event.get("patch_current") is False:
                findings.append(self.make_finding(code=FindingCode.OUTDATED_PATCH.value,
                    title="Security update is outdated", severity=RiskLevel.HIGH,
                    description="Update event reports that the applied patch level is not current.", event=event,
                    recommendation="Track supported versions and apply security updates through a reviewed release process."))
            if not event.get("change_id"):
                findings.append(self.make_finding(code=FindingCode.GOVERNANCE_MISSING.value,
                    title="Change record is missing", severity=RiskLevel.MEDIUM,
                    description="Policy change has no change_id for traceability.", event=event,
                    recommendation="Assign a change identifier and link approval, version, and deployment evidence."))
        return findings
