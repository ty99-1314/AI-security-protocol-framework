"""Package command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from agent_security_audit.engine.audit_engine import AuditEngine
from agent_security_audit.exporters.csv_exporter import export_csv
from agent_security_audit.exporters.json_exporter import export_json
from agent_security_audit.exporters.markdown_exporter import export_markdown
from agent_security_audit.models import PolicyConfig


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit AI-agent security events from JSONL.")
    parser.add_argument("events", type=Path, help="JSONL input events")
    parser.add_argument("--policy", type=Path, required=True, help="YAML policy configuration")
    parser.add_argument("--format", choices=("json", "csv", "markdown"), default="json")
    parser.add_argument("--output", type=Path, help="Output path; defaults to stdout")
    args = parser.parse_args(argv)
    try:
        policy_data = yaml.safe_load(args.policy.read_text(encoding="utf-8")) or {}
        policy = PolicyConfig.model_validate(policy_data)
        events = []
        with args.events.open(encoding="utf-8") as source:
            for line_number, line in enumerate(source, 1):
                if line.strip():
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise ValueError(f"line {line_number}: expected JSON object")
                    events.append(value)
        report = AuditEngine(policy).run(events)
        exporters = {"json": export_json, "csv": export_csv, "markdown": export_markdown}
        text = exporters[args.format](report, args.output)
        if args.output is None:
            print(text, end="" if text.endswith("\n") else "\n")
        return 1 if report.findings else 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        print(f"audit error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
