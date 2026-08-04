#!/usr/bin/env python3
"""Run and attest the live three-Hermes restaurant booking scenario."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, time, timedelta
from pathlib import Path
from typing import Any, AsyncIterator
from zoneinfo import ZoneInfo

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from psycopg import AsyncConnection
from psycopg.rows import dict_row

INITIAL_REQUEST = "Забронируй мне столик на вечер."
NAME_ONLY_REQUEST = "Меня зовут Алекс. Забронируйте."
BANNED_PUBLIC_TERMS = (
    "aip",
    "mcp",
    "hermes",
    "cap:",
    "approval",
    "supervisor",
    "manager agent",
    "внутренний агент",
    "супервайзер",
    "asia/dubai",
    "rfc3339",
    "timezone",
)
PROVIDER_FAILURE_MARKERS = (
    "api call failed",
    "rate limit exceeded",
    "insufficient credits",
    "provider request failed",
)
MANAGER_PRINCIPAL = "agent:hermes_operator:manager"
SUPERVISOR_PRINCIPAL = "agent:hermes_operator:supervisor"
CAL_SLOT_LIST = "cap:cal_diy:slot.list"
CAL_BOOKING_CREATE = "cap:cal_diy:booking.create"


def required_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or "\r" in value or "\n" in value:
        raise RuntimeError(f"{name} is missing or invalid")
    return value


def read_secret(path_value: str) -> str:
    path = Path(path_value)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & (
        stat.S_IRWXG | stat.S_IRWXO
    ):
        raise RuntimeError(f"secret permissions are invalid: {path}")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError(f"secret is empty: {path}")
    return value


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def stable_id(prefix: str, *parts: str) -> str:
    return prefix + uuid.uuid5(uuid.NAMESPACE_URL, ":".join(parts)).hex


def structured(payload: dict[str, Any]) -> dict[str, Any]:
    value = payload.get("structuredContent", payload.get("structured_content"))
    if not isinstance(value, dict):
        raise AssertionError("MCP result omitted structured content")
    return value


def find_mapping(value: Any, required: set[str]) -> dict[str, Any] | None:
    if isinstance(value, dict):
        if required.issubset(value):
            return value
        for child in value.values():
            found = find_mapping(child, required)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_mapping(child, required)
            if found is not None:
                return found
    return None


def find_key(value: Any, key: str) -> Any:
    if isinstance(value, dict):
        if key in value:
            return value[key]
        for child in value.values():
            found = find_key(child, key)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_key(child, key)
            if found is not None:
                return found
    return None


def parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def slot_capacity(output: Any, requested: datetime) -> int | None:
    if isinstance(output, dict):
        candidate = output.get("start", output.get("time"))
        remaining = output.get("seatsRemaining")
        if isinstance(candidate, str) and isinstance(remaining, int):
            try:
                if parse_datetime(candidate).astimezone(
                    ZoneInfo("UTC")
                ) == requested.astimezone(ZoneInfo("UTC")):
                    return remaining
            except ValueError:
                pass
        for child in output.values():
            capacity = slot_capacity(child, requested)
            if capacity is not None:
                return capacity
    elif isinstance(output, list):
        for child in output:
            capacity = slot_capacity(child, requested)
            if capacity is not None:
                return capacity
    return None


@asynccontextmanager
async def mcp_session(url: str, token: str) -> AsyncIterator[ClientSession]:
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=httpx.Timeout(300.0),
        follow_redirects=False,
        trust_env=False,
    ) as client:
        async with streamable_http_client(url, http_client=client) as streams:
            read_stream, write_stream, _ = streams
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                yield session


async def call_tool(
    session: ClientSession,
    name: str,
    arguments: dict[str, Any],
    *,
    allow_error: bool = False,
) -> dict[str, Any]:
    result = await session.call_tool(
        name, arguments, read_timeout_seconds=timedelta(seconds=300)
    )
    payload = result.model_dump(mode="json", by_alias=True, exclude_none=True)
    is_error = bool(payload.get("isError", payload.get("is_error", False)))
    if is_error and not allow_error:
        raise AssertionError(f"MCP tool {name} returned isError=true")
    return payload


async def reservation_count(connection: AsyncConnection[Any]) -> int:
    """Count customer reservations represented by Cal.diy booking seats."""

    cursor = await connection.execute('SELECT count(*) AS count FROM "BookingSeat"')
    row = await cursor.fetchone()
    return int(row["count"])


async def workflow_rows(connection: AsyncConnection[Any]) -> list[dict[str, Any]]:
    cursor = await connection.execute(
        "SELECT * FROM restaurant_booking.workflows ORDER BY created_at"
    )
    return list(await cursor.fetchall())


async def workflow_row(
    connection: AsyncConnection[Any], request_id: str
) -> dict[str, Any] | None:
    cursor = await connection.execute(
        "SELECT * FROM restaurant_booking.workflows WHERE request_id = %s",
        (request_id,),
    )
    return await cursor.fetchone()


async def wait_for_workflow_state(
    connection: AsyncConnection[Any],
    request_id: str,
    expected_state: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while asyncio.get_running_loop().time() < deadline:
        row = await workflow_row(connection, request_id)
        if row is not None and row["state"] == expected_state:
            return row
        if row is not None and row["state"] == "completed":
            raise AssertionError(
                f"workflow completed before `{expected_state}` was observed"
            )
        if row is not None and row.get("last_error") is not None:
            raise AssertionError(
                f"workflow failed before `{expected_state}`: {row['last_error']}"
            )
        await asyncio.sleep(0.1)
    raise AssertionError(f"workflow did not reach `{expected_state}` before timeout")


def scenario_rows(
    rows: list[dict[str, Any]], baseline_ids: set[str]
) -> list[dict[str, Any]]:
    return [row for row in rows if str(row["request_id"]) not in baseline_ids]


async def hermes_chat(
    client: httpx.AsyncClient,
    api_key: str,
    messages: list[dict[str, str]],
    session_id: str | None,
    session_key: str,
) -> tuple[str, str]:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "X-Hermes-Session-Key": session_key,
    }
    if session_id:
        headers["X-Hermes-Session-Id"] = session_id
    response = await client.post(
        "http://hermes-concierge:8642/v1/chat/completions",
        headers=headers,
        json={
            "model": "hermes-agent",
            "messages": messages,
            "temperature": 0,
            "stream": False,
        },
    )
    response.raise_for_status()
    payload = response.json()
    content = payload.get("choices", [{}])[0].get("message", {}).get("content")
    assert_true(isinstance(content, str) and content.strip(), "Hermes returned no text")
    lowered_content = content.casefold()
    for marker in PROVIDER_FAILURE_MARKERS:
        assert_true(marker not in lowered_content, f"Hermes provider failed: {marker}")
    resolved_session = response.headers.get("X-Hermes-Session-Id") or session_id
    assert_true(bool(resolved_session), "Hermes did not return a session id")
    return content.strip(), str(resolved_session)


def assert_public_text(text: str) -> None:
    lowered = text.casefold().replace("aip bistro", "")
    for term in BANNED_PUBLIC_TERMS:
        assert_true(term.casefold() not in lowered, f"public response leaked `{term}`")


async def main() -> None:
    central_token = read_secret(required_environment("CENTRAL_COORDINATOR_TOKEN_FILE"))
    auditor_token = read_secret(required_environment("CENTRAL_AUDITOR_TOKEN_FILE"))
    edge_token = read_secret(required_environment("EDGE_CONCIERGE_TOKEN_FILE"))
    concierge_api_key = read_secret(required_environment("CONCIERGE_API_KEY_FILE"))
    evidence_path = Path(required_environment("EVIDENCE_FILE"))
    evidence_path.parent.mkdir(parents=True, exist_ok=True)

    dubai = ZoneInfo("Asia/Dubai")
    requested_start: datetime | None = None
    preflight_capacity: int | None = None
    scenario_id = uuid.uuid4().hex
    request_id: str | None = None
    booking_uid: str | None = None
    seat_uid: str | None = None
    first_response = ""
    name_response = ""
    final_response = ""
    pending_approval_observed = False
    transaction_receipt_types: list[str] = []
    approval_receipt_types: list[str] = []
    commit_event_kinds: list[str] = []
    transaction_id: str | None = None
    baseline_workflow_count = 0
    reservation_count_before = 0

    async with (
        await AsyncConnection.connect(
            required_environment("WORKFLOW_DATABASE_URL"), row_factory=dict_row
        ) as workflow_db,
        await AsyncConnection.connect(
            required_environment("CAL_DATABASE_URL"), row_factory=dict_row
        ) as cal_db,
        httpx.AsyncClient(
            timeout=httpx.Timeout(300.0), follow_redirects=False, trust_env=False
        ) as http,
    ):
        baseline_rows = await workflow_rows(workflow_db)
        baseline_ids = {str(row["request_id"]) for row in baseline_rows}
        baseline_workflow_count = len(baseline_rows)
        reservation_count_before = await reservation_count(cal_db)

        async with mcp_session(
            "http://restaurant-coordinator:8081/mcp", edge_token
        ) as edge:
            tools = await edge.list_tools()
            edge_names = sorted(tool.name for tool in tools.tools)
            assert_true(
                edge_names
                == ["restaurant_booking_request", "restaurant_booking_status"],
                f"concierge MCP surface is not narrow: {edge_names}",
            )

        async with mcp_session("http://getaip-server:8080/mcp", central_token) as central:
            capability_result = await call_tool(
                central,
                "aip_capabilities",
                {"query": "cal_diy", "limit": 200, "include_schemas": False},
            )
            capability_ids = {
                item.get("id")
                for item in structured(capability_result).get("capabilities", [])
                if isinstance(item, dict)
            }
            assert_true(
                CAL_SLOT_LIST in capability_ids, "Cal.diy slot capability is absent"
            )
            assert_true(
                CAL_BOOKING_CREATE in capability_ids,
                "Cal.diy booking capability is absent",
            )
            first_candidate = datetime.now(dubai).date() + timedelta(days=1)
            for day_offset in range(14):
                candidate_date = first_candidate + timedelta(days=day_offset)
                candidate_start = datetime.combine(
                    candidate_date, time(19, 0), tzinfo=dubai
                )
                slot_result = await call_tool(
                    central,
                    "aip_call",
                    {
                        "capability_id": CAL_SLOT_LIST,
                        "idempotency_key": (
                            f"restaurant:preflight:{scenario_id}:{candidate_date}"
                        ),
                        "input": {
                            "start": candidate_start.isoformat(),
                            "end": (candidate_start + timedelta(hours=2)).isoformat(),
                            "eventTypeId": 70001,
                            "timeZone": "Asia/Dubai",
                            "format": "time",
                        },
                    },
                )
                capacity = slot_capacity(structured(slot_result), candidate_start)
                if capacity is not None and capacity >= 4:
                    requested_start = candidate_start
                    preflight_capacity = capacity
                    break
            assert_true(
                requested_start is not None,
                "Cal.diy has no evening slot with capacity for four guests",
            )

        session_key = f"restaurant-e2e-{scenario_id}"
        # Hermes derives an implicit transcript id from the first user message.
        # This scenario intentionally reuses the same natural-language opening,
        # so supply a unique authenticated id from the first turn to prevent a
        # previous production run from contaminating the conversation.
        session_id = f"restaurant-concierge-{scenario_id}"
        first_response, session_id = await hermes_chat(
            http,
            concierge_api_key,
            [{"role": "user", "content": INITIAL_REQUEST}],
            session_id,
            session_key,
        )
        assert_public_text(first_response)
        rows = scenario_rows(await workflow_rows(workflow_db), baseline_ids)
        assert_true(len(rows) == 1, "vague request did not create exactly one workflow")
        assert_true(rows[0]["state"] == "collecting", "vague request started execution")
        assert_true(
            rows[0]["request"].get("restaurant") == "AIP Bistro"
            and rows[0]["request"].get("customer_time_zone") == "Asia/Dubai",
            "deployment-owned booking context was not applied",
        )
        missing = {
            field
            for field in (
                "restaurant",
                "start",
                "party_size",
                "customer_name",
                "customer_email",
                "customer_time_zone",
            )
            if rows[0]["request"].get(field) in (None, "")
        }
        assert_true(
            len(missing) >= 4, "vague request was populated with invented facts"
        )
        assert_true(
            await reservation_count(cal_db) == reservation_count_before,
            "vague request created a Cal.diy booking",
        )
        request_id = str(rows[0]["request_id"])

        name_response, _ = await hermes_chat(
            http,
            concierge_api_key,
            [{"role": "user", "content": NAME_ONLY_REQUEST}],
            session_id,
            session_key,
        )
        assert_public_text(name_response)
        assert_true(
            name_response.count("?") <= 2,
            "name-only response asked more than two questions",
        )
        lowered_name_response = name_response.casefold()
        for forbidden_prompt in ("email", "почт", "как вас зовут", "your name"):
            assert_true(
                forbidden_prompt not in lowered_name_response,
                f"name-only response prematurely requested `{forbidden_prompt}`",
            )
        rows = scenario_rows(await workflow_rows(workflow_db), baseline_ids)
        assert_true(len(rows) == 1, "name-only turn forked the workflow")
        name_row = rows[0]
        assert_true(
            name_row["state"] == "collecting", "name-only turn started execution"
        )
        assert_true(
            name_row["request"].get("customer_name") == "Алекс",
            "explicit customer name was not persisted",
        )
        assert_true(
            name_row["request"].get("raw_request") == INITIAL_REQUEST,
            "name-only turn overwrote the original request",
        )
        assert_true(
            name_row["request"].get("conversation")
            == [INITIAL_REQUEST, NAME_ONLY_REQUEST],
            "name-only conversation history is incomplete or duplicated",
        )
        assert_true(
            all(
                name_row[field] is None
                for field in (
                    "manager_result",
                    "manager_delegation_id",
                    "plan_result",
                    "plan_id",
                    "commit_action_id",
                    "approval_id",
                    "supervisor_result",
                    "supervisor_delegation_id",
                    "approval_record",
                    "commit_result",
                    "booking_uid",
                    "booking_seat_uid",
                )
            ),
            "name-only turn created a governed execution side effect",
        )
        assert_true(
            await reservation_count(cal_db) == reservation_count_before,
            "name-only turn created a Cal.diy booking",
        )

        assert requested_start is not None
        details = (
            f"{requested_start.date().isoformat()}, в 19:00 по дубайскому времени, "
            "4 гостя. Подтверждение отправьте на "
            f"alex.morgan+{scenario_id}@example.com. Телефон не нужен."
        )
        commit_action = stable_id("act_", request_id, "booking", "commit")
        final_call = asyncio.create_task(
            hermes_chat(
                http,
                concierge_api_key,
                [{"role": "user", "content": details}],
                session_id,
                session_key,
            )
        )
        try:
            pending_row = await wait_for_workflow_state(
                workflow_db, request_id, "approval_pending", 240.0
            )
            pending_approval_observed = True
            assert_true(
                pending_row["commit_action_id"] == commit_action,
                "pending workflow references the wrong commit action",
            )
            assert_true(
                isinstance(pending_row["approval_id"], str)
                and pending_row["approval_id"],
                "pending workflow omitted the approval id",
            )
            async with mcp_session("http://getaip-server:8080/mcp", auditor_token) as auditor:
                pending_status_result = await call_tool(
                    auditor,
                    "aip_action_status",
                    {
                        "action_id": commit_action,
                        "include_result": True,
                        "include_receipts": True,
                    },
                )
                pending_status = find_mapping(
                    structured(pending_status_result), {"action_id", "state"}
                )
                assert_true(
                    pending_status is not None
                    and pending_status.get("state") == "pending_approval",
                    "commit action was not blocked on approval",
                )
                pending_approval_result = await call_tool(
                    auditor,
                    "aip_approval_get",
                    {
                        "approval_id": pending_row["approval_id"],
                        "include_action_status": True,
                        "include_receipts": True,
                    },
                )
                pending_approval = find_mapping(
                    structured(pending_approval_result),
                    {"request", "status"},
                )
                assert_true(
                    pending_approval is not None
                    and pending_approval.get("status") == "pending"
                    and pending_approval.get("decision") is None,
                    "approval was not durably pending before supervisor review",
                )
            final_response, _ = await final_call
        except Exception:
            if not final_call.done():
                final_call.cancel()
            try:
                await final_call
            except asyncio.CancelledError:
                pass
            raise
        assert_public_text(final_response)
        rows = scenario_rows(await workflow_rows(workflow_db), baseline_ids)
        assert_true(len(rows) == 1, "completed conversation forked the workflow")
        row = rows[0]
        assert_true(row["state"] == "completed", "booking workflow did not complete")
        booking_uid = row["booking_uid"]
        seat_uid = row["booking_seat_uid"]
        assert_true(
            isinstance(booking_uid, str) and booking_uid, "booking uid is absent"
        )
        assert_true(
            isinstance(seat_uid, str) and seat_uid,
            "booking seat uid is absent",
        )
        assert_true(
            booking_uid in final_response,
            "customer response does not contain the verified booking uid",
        )

        cursor = await cal_db.execute(
            'SELECT uid, status, "startTime", "endTime" FROM "Booking" WHERE uid = %s',
            (booking_uid,),
        )
        booking = await cursor.fetchone()
        assert_true(booking is not None, "booking uid does not exist in Cal.diy")
        booking_start = booking["startTime"]
        if booking_start.tzinfo is None:
            booking_start = booking_start.replace(tzinfo=ZoneInfo("UTC"))
        assert_true(
            booking_start.astimezone(ZoneInfo("UTC"))
            == requested_start.astimezone(ZoneInfo("UTC")),
            "Cal.diy booking start does not match the requested instant",
        )
        assert_true(
            await reservation_count(cal_db) == reservation_count_before + 1,
            "Cal.diy reservation count is wrong",
        )
        seat_cursor = await cal_db.execute(
            """
            SELECT "referenceUid", data, metadata
            FROM "BookingSeat"
            WHERE metadata ->> 'aip_action_id' = %s
            """,
            (commit_action,),
        )
        seats = list(await seat_cursor.fetchall())
        assert_true(
            len(seats) == 1,
            "commit action is not bound to exactly one Cal.diy booking seat",
        )
        assert_true(
            seats[0]["referenceUid"] == seat_uid,
            "Cal.diy booking seat uid does not match durable workflow state",
        )
        assert_true(
            find_key(seats[0]["data"], "party_size") == 4
            and find_key(seats[0]["data"], "restaurant") == "AIP Bistro"
            and find_key(seats[0]["metadata"], "aip_request_id") == request_id,
            "Cal.diy booking seat facts are not bound to the workflow",
        )

        manager_action = stable_id("act_", request_id, "manager", "slot")
        supervisor_action = stable_id("act_", request_id, "supervisor", "slot")
        async with mcp_session("http://getaip-server:8080/mcp", auditor_token) as auditor:
            for principal, action_id in (
                (MANAGER_PRINCIPAL, manager_action),
                (SUPERVISOR_PRINCIPAL, supervisor_action),
            ):
                listed = await call_tool(
                    auditor,
                    "aip_action_list",
                    {
                        "principal_id": principal,
                        "capability_id": CAL_SLOT_LIST,
                        "include_results": True,
                        "include_receipts": True,
                        "limit": 100,
                    },
                )
                actions = find_key(structured(listed), "actions")
                assert_true(isinstance(actions, list), "AIP action list is absent")
                matching_actions = [
                    action
                    for action in actions
                    if isinstance(action, dict) and action.get("action_id") == action_id
                ]
                assert_true(
                    len(matching_actions) == 1,
                    f"authenticated child action is absent for {principal}",
                )
                assert_true(
                    matching_actions[0].get("state") == "completed",
                    f"authenticated child action is not completed for {principal}",
                )
            commit_status_result = await call_tool(
                auditor,
                "aip_action_status",
                {
                    "action_id": commit_action,
                    "include_result": True,
                    "include_receipts": True,
                },
            )
            commit_status = find_mapping(
                structured(commit_status_result), {"action_id", "state", "result"}
            )
            assert_true(
                commit_status is not None and commit_status.get("state") == "completed",
                "AIP commit action is not completed",
            )
            assert_true(
                commit_status.get("receipt_chain") is not None,
                "AIP commit receipt chain is absent",
            )
            receipts = find_key(commit_status["receipt_chain"], "receipts")
            assert_true(isinstance(receipts, list), "AIP commit receipts are absent")
            transaction_receipt_types = sorted(
                {
                    receipt.get("receipt_type")
                    for receipt in receipts
                    if isinstance(receipt, dict)
                    and isinstance(receipt.get("receipt_type"), str)
                }
            )
            assert_true(
                {
                    "transaction_planned",
                    "transaction_commit_started",
                    "transaction_committed",
                }.issubset(transaction_receipt_types),
                f"AIP transaction receipt chain is incomplete: {transaction_receipt_types}",
            )
            approval_result = await call_tool(
                auditor,
                "aip_approval_get",
                {
                    "approval_id": row["approval_id"],
                    "include_action_status": True,
                    "include_receipts": True,
                },
            )
            approval = find_mapping(structured(approval_result), {"request", "status"})
            assert_true(
                approval is not None and approval.get("status") == "approved",
                "AIP approval is not approved",
            )
            decision = approval.get("decision")
            assert_true(
                isinstance(decision, dict)
                and find_key(decision, "approver") is not None
                and SUPERVISOR_PRINCIPAL
                in json.dumps(decision.get("approver"), sort_keys=True),
                "approval decision is not bound to the supervisor principal",
            )
            approval_receipts = find_key(approval.get("receipt_chain"), "receipts")
            assert_true(
                isinstance(approval_receipts, list),
                "AIP approval receipts are absent",
            )
            approval_receipt_types = sorted(
                {
                    receipt.get("receipt_type")
                    for receipt in approval_receipts
                    if isinstance(receipt, dict)
                    and isinstance(receipt.get("receipt_type"), str)
                }
            )
            assert_true(
                {
                    "policy_decision",
                    "approval_requested",
                    "approval_granted",
                }.issubset(approval_receipt_types),
                f"AIP approval receipt chain is incomplete: {approval_receipt_types}",
            )
            assert_true(
                find_key(approval.get("request"), "action_id") == commit_action,
                "approval request is not bound to the commit action",
            )
            transaction_result = await call_tool(
                auditor,
                "aip_transaction_get",
                {
                    "action_id": commit_action,
                    "include_result": True,
                    "include_receipts": True,
                },
            )
            transaction = find_mapping(
                structured(transaction_result),
                {"transaction_id", "action_id", "status"},
            )
            assert_true(
                transaction is not None
                and transaction.get("action_id") == commit_action
                and transaction.get("status") == "committed",
                "AIP transaction is not durably committed",
            )
            transaction_id = str(transaction["transaction_id"])
            action_events_result = await call_tool(
                auditor,
                "aip_action_events",
                {"action_id": commit_action, "limit": 1000},
            )
            action_events = find_key(structured(action_events_result), "events")
            assert_true(
                isinstance(action_events, list), "commit action events are absent"
            )
            commit_event_kinds = [
                event["kind"]
                for event in action_events
                if isinstance(event, dict) and isinstance(event.get("kind"), str)
            ]
            for required_kind in (
                "aip.approval.requested",
                "aip.approval.granted",
                "aip.action.resumed_result",
            ):
                assert_true(
                    required_kind in commit_event_kinds,
                    f"commit event `{required_kind}` is absent",
                )
            assert_true(
                commit_event_kinds.index("aip.approval.requested")
                < commit_event_kinds.index("aip.approval.granted")
                < commit_event_kinds.index("aip.action.resumed_result"),
                "approval and commit events are out of order",
            )
            audit_result = await call_tool(
                auditor,
                "aip_audit_events",
                {
                    "action_id": commit_action,
                    "limit": 1000,
                    "include_receipts": True,
                },
            )
            audit_events = find_key(structured(audit_result), "events")
            assert_true(
                isinstance(audit_events, list) and audit_events,
                "commit audit events are absent",
            )

        async with mcp_session(
            "http://restaurant-coordinator:8081/mcp", edge_token
        ) as edge:
            replay = await call_tool(
                edge,
                "restaurant_booking_request",
                {
                    "request_id": request_id,
                    "raw_request": details,
                    "restaurant": row["request"].get("restaurant"),
                    "start": row["request"].get("start"),
                    "party_size": row["request"].get("party_size"),
                    "customer_name": row["request"].get("customer_name"),
                    "customer_email": row["request"].get("customer_email"),
                    "customer_phone": row["request"].get("customer_phone"),
                    "customer_time_zone": row["request"].get("customer_time_zone"),
                },
            )
            replay_content = structured(replay)
            assert_true(
                replay_content.get("status") == "confirmed", "replay did not confirm"
            )
            assert_true(
                replay_content.get("booking_uid") == booking_uid, "replay uid changed"
            )
            assert_true(
                replay_content.get("booking_seat_uid") == seat_uid,
                "replay seat uid changed",
            )
        assert_true(
            await reservation_count(cal_db) == reservation_count_before + 1,
            "replay created a duplicate Cal.diy booking",
        )

    assert request_id is not None and booking_uid is not None and seat_uid is not None
    evidence = {
        "scenario": "three-hermes-restaurant-booking",
        "status": "passed",
        "request_id": request_id,
        "booking_uid": booking_uid,
        "seat_uid": seat_uid,
        "manager_action_id": stable_id("act_", request_id, "manager", "slot"),
        "supervisor_action_id": stable_id("act_", request_id, "supervisor", "slot"),
        "commit_action_id": stable_id("act_", request_id, "booking", "commit"),
        "transaction_id": transaction_id,
        "requested_start": requested_start.isoformat(),
        "preflight_capacity": preflight_capacity,
        "baseline_workflow_count": baseline_workflow_count,
        "reservation_count_before": reservation_count_before,
        "reservation_count_after": reservation_count_before + 1,
        "transaction_receipt_types": transaction_receipt_types,
        "approval_receipt_types": approval_receipt_types,
        "commit_event_kinds": commit_event_kinds,
        "initial_request_sha256": hashlib.sha256(INITIAL_REQUEST.encode()).hexdigest(),
        "first_response_sha256": hashlib.sha256(first_response.encode()).hexdigest(),
        "name_only_request_sha256": hashlib.sha256(
            NAME_ONLY_REQUEST.encode()
        ).hexdigest(),
        "name_response_sha256": hashlib.sha256(name_response.encode()).hexdigest(),
        "final_response_sha256": hashlib.sha256(final_response.encode()).hexdigest(),
        "assertions": {
            "concierge_mcp_tools": 2,
            "vague_request_no_booking": True,
            "name_only_fact_persisted_without_execution": True,
            "commit_observed_pending_approval": pending_approval_observed,
            "manager_authenticated_child_action": True,
            "supervisor_authenticated_child_action": True,
            "supervisor_authenticated_approval": True,
            "cal_booking_verified": True,
            "receipt_chain_present": True,
            "transaction_committed": True,
            "audit_events_present": True,
            "idempotent_replay": True,
            "public_response_redacted": True,
        },
    }
    temporary = evidence_path.with_suffix(".tmp")
    temporary.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    temporary.chmod(stat.S_IRUSR | stat.S_IWUSR)
    temporary.replace(evidence_path)
    print(json.dumps(evidence, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())
