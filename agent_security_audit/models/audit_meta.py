"""Metadata identifying an audit run."""

from datetime import date

from pydantic import BaseModel, ConfigDict, Field


class AuditMeta(BaseModel):
    model_config = ConfigDict(extra="forbid")

    audit_id: str = Field(min_length=1)
    audit_date: date
    scope: str = Field(min_length=1)
    owner: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)
    reviewer: str | None = None
