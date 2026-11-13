"""Identity presence, authentication, and authorization checks."""

from typing import Any, Iterable, Mapping

from agent_security_audit.constants import AuditDomain, FindingCode, RiskLevel
from agent_security_audit.models import Finding, PolicyConfig
from .base_checker import BaseChecker


class IdentityAuthChecker(BaseChecker):
    domain = AuditDomain.IDENTITY_AUTHORIZATION

    def run(self, events: Iterable[Mapping[str, Any]]) -> list[Finding]:
        findings = []
        for event in events:
            kind = str(event.get("event_type", "tool_call"))
            if kind not in {"auth", "authz", "tool_call"}:
                continue
            if kind == "auth" and event.get("authenticated") is False:
                code, title = FindingCode.IDENTITY_MISSING.value, "Authentication failed"
                findings.append(self.make_finding(code=code, title=title, severity=RiskLevel.HIGH,
                    description="Authentication event records an unauthenticated or failed identity.",
                    event=event, recommendation="Verify agent identity at the trusted execution boundary."))
            elif kind == "tool_call":
                if not event.get("agent_id"):
                    findings.append(self.make_finding(code=FindingCode.IDENTITY_MISSING.value,
                        title="Agent identity missing", severity=RiskLevel.HIGH,
                        description="Tool-call event does not identify the acting agent.", event=event,
                        recommendation="Record a verified agent identity for every tool call."))
                role, action, resource = event.get("role"), event.get("action"), event.get("resource")
                if role and action and resource:
                    rule = next((r for r in self.policy.allowed_actions
                                 if (r.role, r.action, r.resource) == (role, action, resource)), None)
                    if rule is None or not rule.allowed:
                        findings.append(self.make_finding(code=FindingCode.UNAUTHORIZED_ACTION.value,
                            title="Action is not authorized", severity=RiskLevel.HIGH,
                            description=f"No allowing policy rule for role={role!r}, action={action!r}, resource={resource!r}.",
                            event=event, recommendation="Apply default-deny authorization and review the role policy."))
        return findings
