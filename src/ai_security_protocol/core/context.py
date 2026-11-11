from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet


@dataclass(frozen=True)
class ApprovalGrant:
    """Trusted approval evidence bound to one principal and operation scope."""

    approval_ref: str
    principal_id: str
    tool_name: str
    action: str
    resource: str
    arguments_sha256: str | None = None


@dataclass(frozen=True)
class SecurityContext:
    """Identity and approval context supplied by trusted host middleware.

    Do not construct this object from model-generated content or untrusted
    request fields. The host integration is responsible for authentication.
    """

    principal_id: str
    role: str
    trusted: bool = False
    request_id: str | None = None
    session_id: str | None = None
    policy_version: str | None = None
    approvals: FrozenSet[ApprovalGrant] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.principal_id.strip():
            raise ValueError("principal_id must not be empty")
        if not self.role.strip():
            raise ValueError("role must not be empty")
