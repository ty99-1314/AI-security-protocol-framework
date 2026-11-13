"""Deterministic event sampling helpers."""

from typing import Any, Iterable, Mapping


class EventSampler:
    """Select events by request id and/or inclusive time range."""

    def sample(self, events: Iterable[Mapping[str, Any]], *, request_ids: set[str] | None = None,
               start: str | None = None, end: str | None = None, limit: int | None = None) -> list[Mapping[str, Any]]:
        selected = []
        for event in events:
            if request_ids is not None and str(event.get("request_id", "")) not in request_ids:
                continue
            timestamp = str(event.get("timestamp", ""))
            if start is not None and timestamp < start:
                continue
            if end is not None and timestamp > end:
                continue
            selected.append(event)
        selected.sort(key=lambda event: (str(event.get("timestamp", "")), str(event.get("event_id", ""))))
        return selected if limit is None else selected[:max(0, limit)]
