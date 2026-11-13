"""Finding risk levels."""

from enum import Enum


class RiskLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NOT_VERIFIED = "NotVerified"
    NOT_APPLICABLE = "NotApplicable"
