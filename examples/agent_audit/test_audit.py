import unittest
from datetime import datetime, timezone

from audit import audit


def event(line, *, role="support", action="read", resource="ticket", **extra):
    return {
        "_line": line,
        "_time": datetime(2026, 11, 7, 10, 0, line, tzinfo=timezone.utc),
        "timestamp": "2026-11-07T10:00:00Z",
        "agent_id": "agent-1",
        "role": role,
        "action": action,
        "resource": resource,
        **extra,
    }


class AuditTests(unittest.TestCase):
    def test_allowed_action_has_no_finding(self):
        self.assertEqual(audit([event(1)]), [])

    def test_unauthorized_action_is_reported(self):
        findings = audit([event(1, action="delete")])
        self.assertIn("UNAUTHORIZED_ACTION", {f["code"] for f in findings})

    def test_external_export_and_missing_approval_are_reported(self):
        findings = audit([event(1, action="export", resource="invoice",
                                destination="external", approved=False)])
        codes = {f["code"] for f in findings}
        self.assertIn("EXTERNAL_DATA_EXPORT", codes)
        self.assertIn("APPROVAL_REQUIRED", codes)

    def test_denied_burst_triggers_on_limit(self):
        events = [event(i, action="delete", outcome="denied") for i in range(1, 4)]
        findings = audit(events, burst_limit=3)
        self.assertEqual(sum(f["code"] == "DENIED_ACTION_BURST" for f in findings), 1)


if __name__ == "__main__":
    unittest.main()
