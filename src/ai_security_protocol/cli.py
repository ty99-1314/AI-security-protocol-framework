from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import AuditPolicy, audit_events, read_events


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit AI-agent tool events from a JSONL file.")
    parser.add_argument("events", type=Path, help="JSONL action-event file")
    parser.add_argument("--burst-limit", type=int, default=3)
    parser.add_argument("--burst-window-seconds", type=int, default=60)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.burst_limit < 1:
        parser.error("--burst-limit must be at least 1")
    if args.burst_window_seconds < 1:
        parser.error("--burst-window-seconds must be at least 1")
    try:
        events = read_events(args.events)
        findings = audit_events(
            events,
            policy=AuditPolicy(
                burst_limit=args.burst_limit,
                burst_window_seconds=args.burst_window_seconds,
            ),
        )
    except (OSError, ValueError) as error:
        print(f"audit input error: {error}", file=sys.stderr)
        return 2

    print(json.dumps({
        "events_reviewed": len(events),
        "findings_count": len(findings),
        "findings": findings,
    }, ensure_ascii=False, indent=2))
    return 1 if findings else 0
