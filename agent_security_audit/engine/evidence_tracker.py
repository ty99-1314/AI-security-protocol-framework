"""Bind findings to source events and reproducible evidence digests."""

import hashlib
import json
from typing import Any, Iterable, Mapping


class EvidenceTracker:
    def __init__(self):
        self._event_hashes: dict[str, str] = {}

    def track(self, events: Iterable[Mapping[str, Any]], findings=()) -> dict[str, str]:
        for index, event in enumerate(events):
            event_id = str(event.get("event_id") or f"event-{index + 1}")
            canonical = json.dumps(event, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":"))
            self._event_hashes[event_id] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        for finding in findings:
            for event_id in finding.source_event_ids:
                digest = self._event_hashes.get(event_id)
                if digest:
                    for evidence in finding.evidence:
                        if evidence.get("event_id") == event_id:
                            evidence["sha256"] = digest
        return dict(self._event_hashes)

    def hashes(self) -> dict[str, str]:
        return dict(self._event_hashes)
