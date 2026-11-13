"""Policy configuration models."""

from pydantic import BaseModel, ConfigDict, Field, model_validator


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: str = Field(min_length=1)
    allowed: bool = True


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = "default"
    version: str = "0.1.0"
    allowed_actions: list[PolicyRule] = Field(default_factory=list)
    sensitive_actions: list[str] = Field(default_factory=lambda: ["delete", "export", "send_payment"])
    external_destinations: list[str] = Field(default_factory=lambda: ["external", "public", "unknown"])
    export_allowlist: list[str] = Field(default_factory=list)
    require_approval_for: list[str] = Field(default_factory=lambda: ["delete", "export", "send_payment"])
    denied_burst_limit: int = Field(default=3, ge=1)
    denied_burst_window_seconds: int = Field(default=60, ge=1)
    require_logging: bool = True
    require_traceability: bool = True
    sensitive_data_patterns: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_policy(self):
        rule_keys = [(r.role, r.action, r.resource) for r in self.allowed_actions]
        if len(rule_keys) != len(set(rule_keys)):
            raise ValueError("allowed_actions contains duplicate role/action/resource rules")
        return self
