"""Security domains covered by the first-version audit framework."""

from enum import Enum


class AuditDomain(str, Enum):
    IDENTITY_AUTHORIZATION = "identity_authorization"
    COMMUNICATION_SECURITY = "communication_security"
    BEHAVIOR_CONSTRAINTS = "behavior_constraints"
    DATA_SECURITY = "data_security"
    LOG_AUDIT = "log_audit"
    GOVERNANCE_UPDATE = "governance_update"
    GENERAL = "general"
