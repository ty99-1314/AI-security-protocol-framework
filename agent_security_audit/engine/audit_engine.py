"""Run all configured audit-domain checkers and aggregate a report."""

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping
from uuid import uuid4

from agent_security_audit.models import AuditMeta, AuditReport, PolicyConfig
from agent_security_audit.policy.base_checker import as_mapping
from agent_security_audit.policy.behavior_constraint_checker import BehaviorConstraintChecker
from agent_security_audit.policy.communication_checker import CommunicationChecker
from agent_security_audit.policy.data_security_checker import DataSecurityChecker
from agent_security_audit.policy.governance_update_checker import GovernanceUpdateChecker
from agent_security_audit.policy.identity_auth_checker import IdentityAuthChecker
from agent_security_audit.policy.log_audit_checker import LogAuditChecker
from .evidence_tracker import EvidenceTracker


class AuditEngine:
    def __init__(self, policy: PolicyConfig):
        self.policy = policy
        self.checkers = [IdentityAuthChecker(policy), CommunicationChecker(policy),
                         BehaviorConstraintChecker(policy), DataSecurityChecker(policy),
                         LogAuditChecker(policy), GovernanceUpdateChecker(policy)]
        self.evidence_tracker = EvidenceTracker()

    def run(self, events: Iterable[Any], *, meta: AuditMeta | None = None) -> AuditReport:
        normalized = [dict(as_mapping(event)) for event in events]
        findings = []
        for checker in self.checkers:
            findings.extend(checker.run(normalized))
        # Deduplicate repeated findings emitted by compatible checks without collapsing distinct evidence.
        unique = {}
        for finding in findings:
            key = (finding.code, finding.domain, tuple(finding.source_event_ids), finding.description)
            unique.setdefault(key, finding)
        findings = list(unique.values())
        self.evidence_tracker.track(normalized, findings)
        if meta is None:
            meta = AuditMeta(audit_id=str(uuid4()), audit_date=datetime.now(timezone.utc).date(),
                             scope="all supplied events", owner="unspecified", policy_version=self.policy.version)
        return AuditReport(meta=meta, findings=findings, total_events=len(normalized),
                           sampled_events=len(normalized), generated_at=datetime.now(timezone.utc),
                           statistics=_statistics(findings, len(normalized)))


def _statistics(findings, total_events: int) -> dict[str, int | float]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[f"risk_{finding.severity.value if hasattr(finding.severity, 'value') else finding.severity}"] = counts.get(
            f"risk_{finding.severity.value if hasattr(finding.severity, 'value') else finding.severity}", 0) + 1
    counts["events"] = total_events
    counts["findings"] = len(findings)
    counts["events_with_findings"] = len({event_id for finding in findings for event_id in finding.source_event_ids})
    return counts
