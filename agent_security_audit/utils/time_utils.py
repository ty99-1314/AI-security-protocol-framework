"""Timezone-safe timestamp parsing and range helpers."""

from datetime import datetime, timezone


def parse_aware_datetime(value: str | datetime) -> datetime:
    result = value if isinstance(value, datetime) else datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return result.astimezone(timezone.utc)


def in_time_window(value: str | datetime, start: str | datetime, end: str | datetime) -> bool:
    timestamp = parse_aware_datetime(value)
    return parse_aware_datetime(start) <= timestamp <= parse_aware_datetime(end)
