"""Structured, evidence-linked audit finding."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agent_security_audit.constants import AuditDomain, RiskLevel


class Finding(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    finding_id: str = Field(min_length=1)
    code: str = Field(min_length=1)
    title: str = Field(min_length=1)
    severity: RiskLevel = RiskLevel.MEDIUM
    domain: AuditDomain
    description: str = ""
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    recommendation: str = ""
    affected_agent: str | None = None
    affected_resource: str | None = None
    source_event_ids: list[str] = Field(default_factory=list)
