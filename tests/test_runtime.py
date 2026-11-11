import unittest

from ai_security_protocol import (
    ApprovalGrant,
    DecisionAction,
    PolicyEngine,
    SecurityContext,
    SecurityDenied,
    SecurityPolicy,
    SecurityRuntime,
    ToolCall,
    ToolPermission,
    arguments_fingerprint,
)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.permission = ToolPermission("support", "read_ticket", "read", "ticket:T-1")
        self.policy = SecurityPolicy(
            policy_id="test",
            version="v1",
            permissions=frozenset({self.permission}),
            approval_required_actions=frozenset({"delete"}),
        )
        self.runtime = SecurityRuntime(PolicyEngine(self.policy))
        self.context = SecurityContext("agent-1", "support", trusted=True, request_id="req-1")

    def call(self, **overrides):
        values = {
            "tool_name": "read_ticket",
            "action": "read",
            "resource": "ticket:T-1",
            "arguments": {"ticket_id": "T-1"},
        }
        values.update(overrides)
        return ToolCall(**values)

    def test_allowed_tool_executes(self):
        self.assertEqual(self.runtime.execute_tool(self.call(), self.context, lambda **kw: "ok"), "ok")

    def test_untrusted_context_denied_without_side_effect(self):
        calls = []
        context = SecurityContext("agent-1", "support", trusted=False)
        with self.assertRaises(SecurityDenied):
            self.runtime.execute_tool(self.call(), context, lambda **kw: calls.append(kw))
        self.assertEqual(calls, [])

    def test_unlisted_tool_denied_without_side_effect(self):
        calls = []
        call = self.call(tool_name="delete_ticket", action="delete")
        with self.assertRaises(SecurityDenied):
            self.runtime.execute_tool(call, self.context, lambda **kw: calls.append(kw))
        self.assertEqual(calls, [])

    def test_sensitive_call_requires_bound_approval(self):
        call = self.call(tool_name="delete_ticket", action="delete")
        decision = self.runtime.before_tool_call(call, self.context)
        self.assertEqual(decision.action, DecisionAction.DENY)  # Permission is not allowed.

        permission = ToolPermission("support", "delete_ticket", "delete", "ticket:T-1")
        engine = PolicyEngine(SecurityPolicy(
            permissions=frozenset({permission}),
            approval_required_actions=frozenset({"delete"}),
        ))
        runtime = SecurityRuntime(engine)
        self.assertEqual(runtime.before_tool_call(call, self.context).action, DecisionAction.REQUIRE_APPROVAL)
        grant = ApprovalGrant(
            approval_ref="approval-1",
            principal_id="agent-1",
            tool_name="delete_ticket",
            action="delete",
            resource="ticket:T-1",
            arguments_sha256=arguments_fingerprint(call.arguments),
        )
        approved_context = SecurityContext(
            "agent-1", "support", trusted=True, approvals=frozenset({grant})
        )
        self.assertEqual(runtime.before_tool_call(call, approved_context).action, DecisionAction.ALLOW)

    def test_approval_for_different_arguments_does_not_match(self):
        call = self.call(tool_name="delete_ticket", action="delete")
        permission = ToolPermission("support", "delete_ticket", "delete", "ticket:T-1")
        runtime = SecurityRuntime(PolicyEngine(SecurityPolicy(
            permissions=frozenset({permission}),
            approval_required_actions=frozenset({"delete"}),
        )))
        grant = ApprovalGrant("approval-1", "agent-1", "delete_ticket", "delete", "ticket:T-1", "wrong-digest")
        context = SecurityContext("agent-1", "support", trusted=True, approvals=frozenset({grant}))
        self.assertEqual(runtime.before_tool_call(call, context).action, DecisionAction.REQUIRE_APPROVAL)

    def test_event_sink_records_decision_and_execution(self):
        events = []
        runtime = SecurityRuntime(PolicyEngine(self.policy), event_sink=events.append)
        runtime.execute_tool(self.call(), self.context, lambda **kw: "ok")
        self.assertEqual([event.event_type for event in events], [
            "tool.call.decided", "tool.execution.started", "tool.execution.completed"
        ])
        self.assertEqual(events[-1].execution_status, "completed")


if __name__ == "__main__":
    unittest.main()
