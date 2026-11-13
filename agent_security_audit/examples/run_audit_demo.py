"""Run the bundled audit example from the repository root."""

from pathlib import Path

from agent_security_audit.engine import AuditEngine
from agent_security_audit.exporters.markdown_exporter import export_markdown
from agent_security_audit.models import PolicyConfig

ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    import json
    import yaml

    policy = PolicyConfig.model_validate(yaml.safe_load((ROOT / "agent_security_audit/examples/sample_policy.yaml").read_text()))
    events = [json.loads(line) for line in (ROOT / "agent_security_audit/examples/sample_events.jsonl").read_text().splitlines() if line.strip()]
    report = AuditEngine(policy).run(events)
    print(export_markdown(report))


if __name__ == "__main__":
    main()
