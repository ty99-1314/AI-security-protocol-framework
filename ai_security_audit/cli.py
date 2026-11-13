"""Command-line interface for the AI security audit package."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .audit import DEFAULT_POLICY, audit_events, read_jsonl


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-security-audit",
        description="Audit AI-agent action events against an explicit policy.",
    )
    parser.add_argument("events", type=Path, help="JSONL file containing one event per line")
    parser.add_argument(
        "--burst-limit", type=int, default=3,
        help="denied attempts within the time window that trigger an alert (default: 3)",
    )
    parser.add_argument(
        "--window-seconds", type=int, default=60,
        help="rolling window in seconds for denied-action burst detection (default: 60)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the audit CLI; return 0 clean, 1 findings, or 2 input/config error."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.burst_limit < 1:
        parser.error("--burst-limit must be at least 1")
    if args.window_seconds < 1:
        parser.error("--window-seconds must be at least 1")

    try:
        events = read_jsonl(args.events)
        findings = audit_events(
            events,
            policy=DEFAULT_POLICY,
            burst_limit=args.burst_limit,
            window_seconds=args.window_seconds,
        )
    except (OSError, ValueError, TypeError) as error:
        print(f"audit input error: {error}", file=sys.stderr)
        return 2

    print(json.dumps({
        "events_reviewed": len(events),
        "findings_count": len(findings),
        "findings": findings,
    }, ensure_ascii=False, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
