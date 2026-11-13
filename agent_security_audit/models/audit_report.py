"""Aggregated audit report model."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from .audit_meta import AuditMeta
from .finding import Finding


class AuditReport(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    meta: AuditMeta
    findings: list[Finding] = Field(default_factory=list)
    total_events: int = Field(default=0, ge=0)
    sampled_events: int = Field(default=0, ge=0)
    generated_at: datetime
    statistics: dict[str, int | float] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)
