"""Enforce deployment-owned MCP tool sequencing for governed Hermes roles.

The plugin changes only provider tool selection. AIP remains the authority for
identity, authorization, approvals, transactions, receipts, and action results.
Hermes still supplies tool arguments and the supervisor decision, but a model
cannot skip the evidence-gathering calls required by this deployment.
"""

from __future__ import annotations

import json
import os
from typing import Any

ROLE_ENVIRONMENT_VARIABLE = "AIP_RESTAURANT_HERMES_ROLE"
PLUGIN_SOURCE = "aip-governed-tool-policy"
_KNOWN_ROLES = frozenset({"concierge", "manager", "supervisor"})
_SUPERVISOR_APPROVAL_SEQUENCE = (
    "aip_action_result",
    "aip_approval_get",
    "aip_approval_decide",
)
_FAILED_RESULT_MARKERS = (
    '"iserror":true',
    '"is_error":true',
    '"status":"failed"',
    '"status":"error"',
    '"error_code":',
    "tool execution failed",
    "tool returned error",
)


def register(context: Any) -> None:
    """Register the provider-request policy with Hermes middleware."""

    context.register_middleware("llm_request", enforce_governed_tool_policy)


def enforce_governed_tool_policy(**context: Any) -> dict[str, Any] | None:
    """Force the next deployment-required MCP tool, when one is pending."""

    if context.get("platform") != "api_server":
        return None

    request = context.get("request")
    if not isinstance(request, dict):
        return None

    role = os.getenv(ROLE_ENVIRONMENT_VARIABLE, "").strip().casefold()
    messages = _messages(request)
    required = _required_logical_tool(
        role=role,
        messages=messages,
        api_call_count=_positive_integer(context.get("api_call_count")),
    )
    updated = dict(request)
    if required is None:
        # Governed roles have closed workflows. Once the required call sequence
        # is complete, the provider must produce customer/operator text rather
        # than inventing another side-effecting call in the same user turn.
        updated["tool_choice"] = "none"
        reason = "governed_sequence_complete"
    else:
        selected = _resolve_provider_tool_name(request, required)
        updated["tool_choice"] = {
            "type": "function",
            "function": {"name": selected},
        }
        reason = f"required_tool:{required}"
    updated["parallel_tool_calls"] = False
    return {
        "request": updated,
        "source": PLUGIN_SOURCE,
        "reason": reason,
    }


def _required_logical_tool(
    *, role: str, messages: list[dict[str, Any]], api_call_count: int
) -> str | None:
    if role == "concierge":
        if api_call_count == 1:
            return "restaurant_booking_request"
        tool_name, status = _latest_successful_tool_status(messages)
        if (
            tool_name in {"restaurant_booking_request", "restaurant_booking_status"}
            and status == "processing"
        ):
            return "restaurant_booking_status"
        return None
    if role == "manager":
        return "aip_call" if api_call_count == 1 else None
    if role != "supervisor":
        return "__aip_role_configuration_invalid__" if api_call_count == 1 else None

    user_text = _latest_user_text(messages).casefold()
    if "aip_delegation" in user_text:
        return "aip_call" if api_call_count == 1 else None
    if "independent booking supervisor" in user_text and "approval" in user_text:
        completed = _successful_logical_tools(messages)
        completed_index = 0
        for tool_name in completed:
            if (
                completed_index < len(_SUPERVISOR_APPROVAL_SEQUENCE)
                and tool_name == _SUPERVISOR_APPROVAL_SEQUENCE[completed_index]
            ):
                completed_index += 1
        if completed_index < len(_SUPERVISOR_APPROVAL_SEQUENCE):
            return _SUPERVISOR_APPROVAL_SEQUENCE[completed_index]
        return None
    return "__aip_supervisor_workflow_unrecognized__" if api_call_count == 1 else None


def _messages(request: dict[str, Any]) -> list[dict[str, Any]]:
    value = request.get("messages")
    if not isinstance(value, list):
        value = request.get("input")
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _latest_user_text(messages: list[dict[str, Any]]) -> str:
    for message in reversed(messages):
        if message.get("role") == "user":
            return _content_text(message.get("content"))
    return ""


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(
            str(part.get("text", ""))
            for part in content
            if isinstance(part, dict) and part.get("type") in {"text", "input_text"}
        )
    return ""


def _available_tool_names(request: dict[str, Any]) -> tuple[str, ...]:
    tools = request.get("tools")
    if not isinstance(tools, list):
        return ()
    names: list[str] = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        function = tool.get("function")
        name = function.get("name") if isinstance(function, dict) else tool.get("name")
        if isinstance(name, str) and name:
            names.append(name)
    return tuple(names)


def _resolve_provider_tool_name(request: dict[str, Any], logical_name: str) -> str:
    names = _available_tool_names(request)
    exact = [name for name in names if name == logical_name]
    if len(exact) == 1:
        return exact[0]
    namespaced = [name for name in names if name.endswith(f"__{logical_name}")]
    if len(namespaced) == 1:
        return namespaced[0]

    # Selecting a non-advertised name makes the provider reject the request.
    # This is deliberate fail-closed behavior if discovery or configuration is
    # inconsistent with the deployment policy.
    return logical_name


def _successful_logical_tools(messages: list[dict[str, Any]]) -> list[str]:
    calls: dict[str, str] = {}
    successful: list[str] = []
    for message in messages:
        if message.get("role") == "assistant":
            tool_calls = message.get("tool_calls")
            if not isinstance(tool_calls, list):
                continue
            for call in tool_calls:
                if not isinstance(call, dict):
                    continue
                function = call.get("function")
                call_id = call.get("id")
                name = function.get("name") if isinstance(function, dict) else None
                if isinstance(call_id, str) and isinstance(name, str):
                    calls[call_id] = _logical_tool_name(name)
        elif message.get("role") == "tool":
            call_id = message.get("tool_call_id")
            explicit_name = message.get("name")
            logical_name = (
                _logical_tool_name(explicit_name)
                if isinstance(explicit_name, str)
                else calls.get(call_id)
                if isinstance(call_id, str)
                else None
            )
            if logical_name and not _tool_result_failed(message.get("content")):
                successful.append(logical_name)
    return successful


def _latest_successful_tool_status(
    messages: list[dict[str, Any]],
) -> tuple[str | None, str | None]:
    """Return the latest successful logical tool and its structured status.

    Hermes wraps MCP results in an untrusted-data envelope. The envelope keeps
    the MCP ``structuredContent`` JSON, so matching a bounded status vocabulary
    avoids parsing provider-generated prose while remaining transport agnostic.
    """

    calls: dict[str, str] = {}
    latest: tuple[str | None, str | None] = (None, None)
    statuses = (
        "processing",
        "confirmed",
        "failed",
        "clarification_required",
        "not_found",
    )
    for message in messages:
        if message.get("role") == "assistant":
            tool_calls = message.get("tool_calls")
            if not isinstance(tool_calls, list):
                continue
            for call in tool_calls:
                if not isinstance(call, dict):
                    continue
                function = call.get("function")
                call_id = call.get("id")
                name = function.get("name") if isinstance(function, dict) else None
                if isinstance(call_id, str) and isinstance(name, str):
                    calls[call_id] = _logical_tool_name(name)
            continue
        if message.get("role") != "tool":
            continue
        call_id = message.get("tool_call_id")
        explicit_name = message.get("name")
        logical_name = (
            _logical_tool_name(explicit_name)
            if isinstance(explicit_name, str)
            else calls.get(call_id)
            if isinstance(call_id, str)
            else None
        )
        content = message.get("content")
        if logical_name is None or _tool_result_failed(content):
            continue
        normalized = "".join(str(content or "").casefold().split())
        status = next(
            (
                candidate
                for candidate in statuses
                if f'"status":"{candidate}"' in normalized
            ),
            None,
        )
        latest = (logical_name, status)
    return latest


def _tool_result_failed(content: Any) -> bool:
    if isinstance(content, (dict, list)):
        serialized = json.dumps(content, ensure_ascii=True, separators=(",", ":"))
    else:
        serialized = str(content or "")
    normalized = "".join(serialized.casefold().split())
    return any(marker in normalized for marker in _FAILED_RESULT_MARKERS)


def _logical_tool_name(name: str) -> str:
    return name.rsplit("__", 1)[-1]


def _positive_integer(value: Any) -> int:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value > 0
        else 0
    )
