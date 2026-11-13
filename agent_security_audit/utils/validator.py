"""Input validation and conservative data-redaction helpers."""

import re
from collections.abc import Mapping
from urllib.parse import urlparse


def validate_event_fields(event: Mapping, required: tuple[str, ...] = ("timestamp", "event_type")) -> list[str]:
    return [field for field in required if event.get(field) in (None, "")]


def redact_text(value: str, patterns: list[str], replacement: str = "[REDACTED]") -> str:
    for pattern in patterns:
        value = re.sub(pattern, replacement, value, flags=re.IGNORECASE)
    return value


def destination_allowed(destination: str, allowlist: list[str]) -> bool:
    """Compare URL hosts (or exact opaque destination names) against an allowlist."""
    candidate = urlparse(destination).hostname or destination
    approved = set()
    for item in allowlist:
        approved.add((urlparse(item).hostname or item).lower())
    return candidate.lower() in approved
