"""Unit tests for the governed Hermes tool-selection middleware."""

from __future__ import annotations

import importlib.util
import os
import unittest
from pathlib import Path
from unittest.mock import patch

PLUGIN_PATH = Path(__file__).with_name("__init__.py")
SPEC = importlib.util.spec_from_file_location("aip_governed_tool_policy", PLUGIN_PATH)
assert SPEC is not None and SPEC.loader is not None
PLUGIN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PLUGIN)


def provider_request(*tools: str, messages: list[dict] | None = None) -> dict:
    return {
        "model": "test-model",
        "messages": messages or [{"role": "user", "content": "book a table"}],
        "tools": [
            {"type": "function", "function": {"name": name, "parameters": {}}}
            for name in tools
        ],
    }


class GovernedToolPolicyTests(unittest.TestCase):
    def invoke(self, role: str, request: dict, api_call_count: int = 1):
        with patch.dict(
            os.environ, {PLUGIN.ROLE_ENVIRONMENT_VARIABLE: role}, clear=False
        ):
            return PLUGIN.enforce_governed_tool_policy(
                platform="api_server",
                request=request,
                api_call_count=api_call_count,
            )

    def test_concierge_forces_namespaced_booking_tool_on_first_call(self):
        result = self.invoke(
            "concierge",
            provider_request(
                "mcp__booking__restaurant_booking_request",
                "mcp__booking__restaurant_booking_status",
            ),
        )
        self.assertEqual(
            result["request"]["tool_choice"]["function"]["name"],
            "mcp__booking__restaurant_booking_request",
        )
        self.assertFalse(result["request"]["parallel_tool_calls"])

    def test_concierge_does_not_force_tool_loop_follow_up(self):
        result = self.invoke(
            "concierge",
            provider_request("mcp__booking__restaurant_booking_request"),
            api_call_count=2,
        )
        self.assertEqual(result["request"]["tool_choice"], "none")

    def test_concierge_forces_status_while_workflow_is_processing(self):
        request_tool = "mcp__booking__restaurant_booking_request"
        status_tool = "mcp__booking__restaurant_booking_status"
        messages = [
            {"role": "user", "content": "book a table"},
            {
                "role": "assistant",
                "tool_calls": [{"id": "one", "function": {"name": request_tool}}],
            },
            {
                "role": "tool",
                "tool_call_id": "one",
                "content": '<untrusted>{"structuredContent":{"status":"processing"}}</untrusted>',
            },
        ]
        result = self.invoke(
            "concierge",
            provider_request(request_tool, status_tool, messages=messages),
            api_call_count=2,
        )
        self.assertEqual(
            result["request"]["tool_choice"]["function"]["name"], status_tool
        )

    def test_concierge_disables_tools_after_clarification(self):
        request_tool = "mcp__booking__restaurant_booking_request"
        messages = [
            {"role": "user", "content": "my name is Alex"},
            {
                "role": "assistant",
                "tool_calls": [{"id": "one", "function": {"name": request_tool}}],
            },
            {
                "role": "tool",
                "tool_call_id": "one",
                "content": (
                    '<untrusted>{"structuredContent":'
                    '{"status":"clarification_required"}}</untrusted>'
                ),
            },
        ]
        result = self.invoke(
            "concierge",
            provider_request(request_tool, messages=messages),
            api_call_count=2,
        )
        self.assertEqual(result["request"]["tool_choice"], "none")

    def test_manager_forces_aip_call(self):
        result = self.invoke("manager", provider_request("mcp__aip__aip_call"))
        self.assertEqual(
            result["request"]["tool_choice"]["function"]["name"],
            "mcp__aip__aip_call",
        )

    def test_supervisor_forces_complete_approval_evidence_sequence(self):
        tools = (
            "mcp__aip__aip_action_result",
            "mcp__aip__aip_approval_get",
            "mcp__aip__aip_approval_decide",
        )
        messages = [
            {
                "role": "user",
                "content": "Act as the independent booking supervisor for approval review.",
            }
        ]
        first = self.invoke("supervisor", provider_request(*tools, messages=messages))
        self.assertEqual(first["request"]["tool_choice"]["function"]["name"], tools[0])

        messages.extend(
            [
                {
                    "role": "assistant",
                    "tool_calls": [{"id": "one", "function": {"name": tools[0]}}],
                },
                {
                    "role": "tool",
                    "tool_call_id": "one",
                    "content": '{"status":"completed"}',
                },
            ]
        )
        second = self.invoke(
            "supervisor", provider_request(*tools, messages=messages), api_call_count=2
        )
        self.assertEqual(second["request"]["tool_choice"]["function"]["name"], tools[1])

        messages.extend(
            [
                {
                    "role": "assistant",
                    "tool_calls": [{"id": "two", "function": {"name": tools[1]}}],
                },
                {
                    "role": "tool",
                    "tool_call_id": "two",
                    "content": '{"status":"pending"}',
                },
                {
                    "role": "assistant",
                    "tool_calls": [{"id": "three", "function": {"name": tools[2]}}],
                },
                {
                    "role": "tool",
                    "tool_call_id": "three",
                    "content": '{"status":"approved"}',
                },
            ]
        )
        complete = self.invoke(
            "supervisor", provider_request(*tools, messages=messages), api_call_count=4
        )
        self.assertEqual(complete["request"]["tool_choice"], "none")

    def test_failed_tool_result_does_not_advance_sequence(self):
        tool = "mcp__aip__aip_action_result"
        messages = [
            {
                "role": "user",
                "content": "Act as the independent booking supervisor for approval review.",
            },
            {
                "role": "assistant",
                "tool_calls": [{"id": "one", "function": {"name": tool}}],
            },
            {
                "role": "tool",
                "tool_call_id": "one",
                "content": '{"status":"failed","error_code":"not_found"}',
            },
        ]
        result = self.invoke(
            "supervisor",
            provider_request(
                tool,
                "mcp__aip__aip_approval_get",
                "mcp__aip__aip_approval_decide",
                messages=messages,
            ),
            api_call_count=2,
        )
        self.assertEqual(result["request"]["tool_choice"]["function"]["name"], tool)

    def test_missing_role_is_fail_closed(self):
        result = self.invoke("", provider_request("unrelated"))
        self.assertEqual(
            result["request"]["tool_choice"]["function"]["name"],
            "__aip_role_configuration_invalid__",
        )


if __name__ == "__main__":
    unittest.main()
