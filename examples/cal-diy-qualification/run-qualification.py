#!/usr/bin/env python3
"""Execute and attest the isolated Cal.diy connector qualification."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import stat
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncIterator
from zoneinfo import ZoneInfo

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from psycopg import AsyncConnection
from psycopg.rows import dict_row

EVENT_TYPE_ID = 70001
TENANT_ID = "tenant-cal-qualified"
REQUESTER = "service:cal-qualified-client"
APPROVER = "human:cal-qualified-approver"
CAL_PROFILE_GET = "cap:cal_diy:profile.get"
CAL_SLOT_LIST = "cap:cal_diy:slot.list"
CAL_BOOKING_CREATE = "cap:cal_diy:booking.create"
WEBHOOK_KIND = "cal_diy.booking.created"


def required_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or "\r" in value or "\n" in value:
        raise RuntimeError(f"{name} is missing or invalid")
    return value


def read_secret(environment_name: str) -> str:
    path = Path(required_environment(environment_name))
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


def collect_mappings(value: Any, required: set[str]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if required.issubset(value):
            found.append(value)
        for child in value.values():
            found.extend(collect_mappings(child, required))
    elif isinstance(value, list):
        for child in value:
            found.extend(collect_mappings(child, required))
    return found


def slot_capacity(output: Any, requested: datetime) -> int | None:
    if isinstance(output, dict):
        candidate = output.get("start", output.get("time"))
        remaining = output.get("seatsRemaining")
        if isinstance(candidate, str) and isinstance(remaining, int):
            try:
                parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
                if parsed.astimezone(timezone.utc) == requested.astimezone(
                    timezone.utc
                ):
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
async def mcp_session(token: str) -> AsyncIterator[ClientSession]:
    async with httpx.AsyncClient(
        headers={"Authorization": f"Bearer {token}"},
        timeout=httpx.Timeout(180.0),
        follow_redirects=False,
        trust_env=False,
    ) as client:
        async with streamable_http_client(
            required_environment("AIP_MCP_URL"), http_client=client
        ) as streams:
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
        name, arguments, read_timeout_seconds=timedelta(seconds=180)
    )
    payload = result.model_dump(mode="json", by_alias=True, exclude_none=True)
    is_error = bool(payload.get("isError", payload.get("is_error", False)))
    if is_error and not allow_error:
        raise AssertionError(f"MCP tool {name} returned isError=true: {payload}")
    return payload


async def booking_count(connection: AsyncConnection[Any]) -> int:
    cursor = await connection.execute('SELECT count(*) AS count FROM "Booking"')
    row = await cursor.fetchone()
    return int(row["count"])


async def booking_for_action(
    connection: AsyncConnection[Any], action_id: str
) -> dict[str, Any] | None:
    cursor = await connection.execute(
        """
        SELECT b.uid, b.status, b."startTime", s."referenceUid" AS seat_uid,
               s.metadata AS seat_metadata
        FROM "BookingSeat" s
        JOIN "Booking" b ON b.id = s."bookingId"
        WHERE s.metadata ->> 'aip_action_id' = %s
        """,
        (action_id,),
    )
    return await cursor.fetchone()


async def native_profile_get(native_token: str, run_id: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    action_id = stable_id("act_", run_id, "native", "profile")
    envelope = {
        "aip_version": "1.0",
        "message_type": "aip.core.v1.action",
        "message_id": stable_id("msg_", run_id, "native", "profile"),
        "correlation_id": stable_id("corr_", run_id, "native", "profile"),
        "sent_at": now,
        "from": {"id": REQUESTER, "kind": "service"},
        "body": {
            "action": {
                "id": action_id,
                "capability_id": CAL_PROFILE_GET,
                "input": {},
                "mode": "sync",
            }
        },
    }
    async with httpx.AsyncClient(timeout=60.0, trust_env=False) as client:
        response = await client.post(
            required_environment("AIP_NATIVE_URL"),
            headers={"Authorization": f"Bearer {native_token}"},
            json=envelope,
        )
    assert_true(response.status_code == 200, f"native AIP call failed: {response.text}")
    payload = response.json()
    result = find_key(payload, "action_result")
    assert_true(
        isinstance(result, dict) and result.get("status") == "completed",
        "native Cal.diy profile action did not complete",
    )
    return {"action_id": action_id, "message_type": payload.get("message_type")}


def webhook_payload(marker: str, created_at: str) -> bytes:
    return json.dumps(
        {
            "triggerEvent": "BOOKING_CREATED",
            "createdAt": created_at,
            "payload": {"qualificationMarker": marker},
        },
        separators=(",", ":"),
    ).encode("utf-8")


async def deliver_webhook(
    secret: str, body: bytes, signature: str | None = None
) -> int:
    supplied = signature or hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    async with httpx.AsyncClient(timeout=30.0, trust_env=False) as client:
        response = await client.post(
            "http://getaip-server:8080/connectors/cal-diy/webhooks/cal-live",
            content=body,
            headers={
                "content-type": "application/json",
                "x-cal-signature-256": supplied,
                "x-cal-webhook-version": "2021-10-20",
            },
        )
    return response.status_code


async def webhook_event_count(session: ClientSession, marker: str) -> int:
    result = await call_tool(
        session, "aip_events", {"kinds": [WEBHOOK_KIND], "limit": 1000}
    )
    events = collect_mappings(structured(result), {"kind", "data"})
    return sum(
        1
        for event in events
        if event.get("kind") == WEBHOOK_KIND
        and find_key(event.get("data"), "qualificationMarker") == marker
    )


async def wait_for_completed_action(
    session: ClientSession, action_id: str, timeout_seconds: float = 120.0
) -> dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    last: dict[str, Any] = {}
    while asyncio.get_running_loop().time() < deadline:
        payload = await call_tool(
            session,
            "aip_action_status",
            {
                "action_id": action_id,
                "include_result": True,
                "include_receipts": True,
                "wait_ms": 1000,
            },
        )
        last = structured(payload)
        action_views = [
            view
            for view in collect_mappings(last, {"action_id", "state"})
            if view.get("action_id") == action_id
        ]
        assert_true(
            bool(action_views), "action status response omitted its lifecycle view"
        )
        state = action_views[0].get("state")
        if state == "completed":
            return last
        if state in {"failed", "cancelled", "expired", "dead_lettered"}:
            raise AssertionError(
                f"commit action reached terminal state {state}: {last}"
            )
        await asyncio.sleep(0.25)
    raise AssertionError(f"commit action did not complete: {last}")


def source_attestation() -> dict[str, str]:
    names = (
        "AIP_BASE_COMMIT",
        "AIP_SOURCE_DIGEST",
        "AIP_HARNESS_DIGEST",
        "AIP_IMAGE_ID",
        "AIP_BUILDER_IMAGE_ID",
        "AIP_RUNTIME_BASE_IMAGE_ID",
        "CAL_COMMIT",
        "CAL_IMAGE_ID",
        "CAL_SOURCE_DIGEST",
        "QUALIFICATION_RUNNER_IMAGE_ID",
    )
    return {name.lower(): required_environment(name) for name in names}


async def run_qualification() -> None:
    requester_token = read_secret("REQUESTER_TOKEN_FILE")
    approver_token = read_secret("APPROVER_TOKEN_FILE")
    native_token = read_secret("NATIVE_TOKEN_FILE")
    webhook_secret = read_secret("WEBHOOK_SECRET_FILE")
    evidence_path = Path(required_environment("EVIDENCE_FILE"))
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex
    dubai = ZoneInfo("Asia/Dubai")
    start: datetime | None = None
    capacity: int | None = None
    plan_action_id = stable_id("act_", run_id, "booking", "plan")
    commit_action_id = stable_id("act_", run_id, "booking", "commit")
    commit_key = f"cal-qualification:{run_id}:booking:commit"
    booking_input: dict[str, Any]

    async with await AsyncConnection.connect(
        required_environment("CAL_DATABASE_URL"), row_factory=dict_row
    ) as database:
        before = await booking_count(database)
        native = await native_profile_get(native_token, run_id)
        async with mcp_session(requester_token) as requester:
            listed = await requester.list_tools()
            tool_names = {tool.name for tool in listed.tools}
            required_tools = {
                "aip_capabilities",
                "aip_call",
                "aip_action_status",
                "aip_approval_get",
                "aip_approval_decide",
                "aip_transaction_get",
                "aip_events",
            }
            assert_true(
                required_tools.issubset(tool_names), "stable MCP facade is incomplete"
            )
            capabilities_result = await call_tool(
                requester,
                "aip_capabilities",
                {
                    "query": "cal_diy",
                    "limit": 200,
                    "include_schemas": True,
                    "include_contracts": True,
                },
            )
            capabilities = structured(capabilities_result).get("capabilities", [])
            assert_true(
                len(capabilities) == 81,
                f"expected 81 Cal.diy capabilities: {len(capabilities)}",
            )
            capability_ids = {
                item.get("id") for item in capabilities if isinstance(item, dict)
            }
            assert_true(
                {CAL_PROFILE_GET, CAL_SLOT_LIST, CAL_BOOKING_CREATE}.issubset(
                    capability_ids
                ),
                "required Cal.diy capabilities are absent",
            )
            credential_policies = [
                find_key(item.get("contract"), "credentials")
                for item in capabilities
                if isinstance(item, dict)
            ]
            assert_true(
                len(credential_policies) == 81
                and all(
                    isinstance(policy, dict) and policy.get("required") is True
                    for policy in credential_policies
                ),
                "tenant-routed capabilities do not require opaque credentials",
            )
            profile = await call_tool(
                requester,
                "aip_call",
                {"capability_id": CAL_PROFILE_GET, "input": {}},
            )
            assert_true(
                find_key(structured(profile), "status") in {"completed", "success"},
                "MCP Cal.diy profile call did not complete",
            )
            first_day = datetime.now(dubai).date() + timedelta(days=1)
            for offset in range(14):
                candidate = datetime.combine(
                    first_day + timedelta(days=offset), time(19, 0), tzinfo=dubai
                )
                slots = await call_tool(
                    requester,
                    "aip_call",
                    {
                        "capability_id": CAL_SLOT_LIST,
                        "input": {
                            "start": candidate.isoformat(),
                            "end": (candidate + timedelta(hours=2)).isoformat(),
                            "eventTypeId": EVENT_TYPE_ID,
                            "timeZone": "Asia/Dubai",
                            "format": "time",
                        },
                    },
                )
                candidate_capacity = slot_capacity(structured(slots), candidate)
                if candidate_capacity is not None and candidate_capacity >= 2:
                    start = candidate
                    capacity = candidate_capacity
                    break
            assert_true(start is not None, "no real Cal.diy evening slot was available")
            booking_input = {
                "start": start.isoformat(),
                "eventTypeId": EVENT_TYPE_ID,
                "attendee": {
                    "name": "Cal Qualification",
                    "email": f"cal-qualification+{run_id}@example.com",
                    "timeZone": "Asia/Dubai",
                    "language": "en",
                },
                "bookingFieldsResponses": {
                    "party_size": 2,
                    "qualification_run": run_id,
                },
                "metadata": {"qualification_run": run_id},
            }
            plan = await call_tool(
                requester,
                "aip_call",
                {
                    "action_id": plan_action_id,
                    "capability_id": CAL_BOOKING_CREATE,
                    "idempotency_key": f"cal-qualification:{run_id}:booking:plan",
                    "transaction": {"mode": "plan"},
                    "input": booking_input,
                },
            )
            plan_content = structured(plan)
            plan_id = find_key(plan_content, "plan_id")
            assert_true(isinstance(plan_id, str) and plan_id, "AIP plan id is absent")
            assert_true(
                isinstance(find_key(plan_content, "connector_validation"), dict),
                "Cal.diy downstream plan validation evidence is absent",
            )
            assert_true(
                await booking_count(database) == before, "plan created a booking"
            )
            pending = await call_tool(
                requester,
                "aip_call",
                {
                    "action_id": commit_action_id,
                    "capability_id": CAL_BOOKING_CREATE,
                    "idempotency_key": commit_key,
                    "transaction": {"mode": "commit", "plan_id": plan_id},
                    "input": booking_input,
                },
                allow_error=True,
            )
            pending_content = structured(pending)
            approval_id = find_key(pending_content, "approval_id")
            assert_true(
                find_key(pending_content, "requires_human_approval") is True
                and isinstance(approval_id, str)
                and approval_id,
                "commit was not durably blocked on approval",
            )
            assert_true(
                await booking_count(database) == before,
                "blocked commit created a booking",
            )

        async with mcp_session(approver_token) as approver:
            approval_payload = await call_tool(
                approver,
                "aip_approval_get",
                {
                    "approval_id": approval_id,
                    "include_action_status": True,
                    "include_receipts": True,
                    "include_evidence_payload": True,
                },
            )
            approval = structured(approval_payload)
            approval_records = collect_mappings(approval, {"request", "status"})
            assert_true(
                any(record.get("status") == "pending" for record in approval_records),
                "approval is not pending",
            )
            policy_hash = find_key(approval, "policy_hash")
            assert_true(
                isinstance(policy_hash, str) and policy_hash, "policy hash is absent"
            )
            decision = await call_tool(
                approver,
                "aip_approval_decide",
                {
                    "approval_id": approval_id,
                    "decision": "approved",
                    "approver_principal": APPROVER,
                    "decision_id": f"decision:cal-qualification:{run_id}",
                    "reason": "Verified the immutable Cal.diy booking plan and slot evidence.",
                    "policy_hash": policy_hash,
                    "evidence": [
                        {
                            "id": f"evidence:cal-qualification:{run_id}",
                            "kind": "qualification_review",
                            "hash": f"sha256:{hashlib.sha256(run_id.encode()).hexdigest()}",
                            "redacted": True,
                        }
                    ],
                },
            )
            decision_events = collect_mappings(structured(decision), {"id", "kind"})
            assert_true(
                any(
                    event.get("kind") == "aip.approval.granted"
                    for event in decision_events
                ),
                "approval command did not emit the granted lifecycle event",
            )
            approved_payload = await call_tool(
                approver,
                "aip_approval_get",
                {
                    "approval_id": approval_id,
                    "include_action_status": True,
                    "include_receipts": True,
                },
            )
            approved_records = collect_mappings(
                structured(approved_payload), {"request", "status", "decision"}
            )
            assert_true(
                any(
                    record.get("status") == "approved"
                    and find_key(record.get("decision"), "id") == APPROVER
                    for record in approved_records
                ),
                "durable approval record is not bound to the authenticated approver",
            )

        async with mcp_session(requester_token) as requester:
            completed = await wait_for_completed_action(requester, commit_action_id)
            transaction_payload = await call_tool(
                requester,
                "aip_transaction_get",
                {
                    "action_id": commit_action_id,
                    "include_result": True,
                    "include_receipts": True,
                },
            )
            transaction = structured(transaction_payload)
            transaction_views = collect_mappings(
                transaction, {"transaction_id", "action_id", "status"}
            )
            transaction_view = next(
                (
                    view
                    for view in transaction_views
                    if view.get("action_id") == commit_action_id
                ),
                None,
            )
            transaction_id = (
                transaction_view.get("transaction_id")
                if isinstance(transaction_view, dict)
                else None
            )
            assert_true(
                isinstance(transaction_view, dict)
                and transaction_view.get("status") == "committed"
                and isinstance(transaction_id, str),
                "AIP transaction is not durably committed",
            )
            replay = await call_tool(
                requester,
                "aip_call",
                {
                    "action_id": commit_action_id,
                    "capability_id": CAL_BOOKING_CREATE,
                    "idempotency_key": commit_key,
                    "transaction": {"mode": "commit", "plan_id": plan_id},
                    "input": booking_input,
                },
                allow_error=True,
            )
            replay_content = structured(replay)
            replay_booking_uid = find_key(replay_content, "uid")
            assert_true(
                not replay.get("isError", replay.get("is_error", False))
                and find_key(replay_content, "status") == "success"
                and isinstance(replay_booking_uid, str)
                and replay_booking_uid,
                "exact action replay did not return the successful durable provider output",
            )
            webhook_created_at = (
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            )
            body = webhook_payload(run_id, webhook_created_at)
            assert_true(
                await deliver_webhook(webhook_secret, body) == 204,
                "signed webhook failed",
            )
            assert_true(
                await deliver_webhook(webhook_secret, body) == 204,
                "webhook replay was not idempotent",
            )
            assert_true(
                await deliver_webhook(webhook_secret, body, "0" * 64) == 401,
                "invalid webhook HMAC was not rejected",
            )
            stale = webhook_payload(f"{run_id}-stale", "2020-01-01T00:00:00Z")
            assert_true(
                await deliver_webhook(webhook_secret, stale) == 400,
                "stale webhook was not rejected",
            )
            assert_true(
                await webhook_event_count(requester, run_id) == 1,
                "webhook replay produced duplicate AIP events",
            )

        after = await booking_count(database)
        booking = await booking_for_action(database, commit_action_id)
        assert_true(
            after == before + 1, "commit did not create exactly one Cal.diy booking"
        )
        assert_true(
            booking is not None, "Cal.diy booking is not correlated to the AIP action"
        )
        assert_true(
            replay_booking_uid == booking["uid"],
            "exact action replay did not return the original Cal.diy booking",
        )
        assert_true(
            find_key(booking["seat_metadata"], "aip_transaction_id") == transaction_id,
            "Cal.diy booking is not correlated to the AIP transaction",
        )

    evidence = {
        "schema": "aip.cal-diy.qualification.v1",
        "status": "passed",
        "qualified_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": source_attestation(),
        "isolation": {
            "docker_project": "aip-cal-diy-qualification",
            "agent_services": [],
            "external_network_access": False,
        },
        "mcp": {
            "transport": "streamable_http",
            "stable_tools_verified": True,
            "cal_capabilities": 81,
        },
        "native": native,
        "identity": {
            "tenant_id": TENANT_ID,
            "requester": REQUESTER,
            "approver": APPROVER,
            "credential_material_in_protocol": False,
        },
        "workflow": {
            "run_id": run_id,
            "plan_action_id": plan_action_id,
            "commit_action_id": commit_action_id,
            "approval_id": approval_id,
            "transaction_id": transaction_id,
            "booking_uid": booking["uid"],
            "booking_seat_uid": booking["seat_uid"],
            "available_capacity": capacity,
            "booking_count_before": before,
            "booking_count_after": after,
            "pending_approval_observed": True,
            "authenticated_decision_observed": True,
            "idempotent_replay_observed": True,
            "completed_state": find_key(completed, "state"),
        },
        "webhook": {
            "subscription_id": "cal-live",
            "marker": run_id,
            "created_at": webhook_created_at,
            "valid_delivery": 204,
            "duplicate_delivery": 204,
            "invalid_hmac": 401,
            "stale_timestamp": 400,
            "event_count": 1,
        },
        "restart_verified": False,
    }
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"status": "passed", "commit_action_id": commit_action_id}))


async def verify_restart() -> None:
    evidence_path = Path(required_environment("EVIDENCE_FILE"))
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert_true(
        evidence.get("status") == "passed", "initial qualification did not pass"
    )
    requester_token = read_secret("REQUESTER_TOKEN_FILE")
    webhook_secret = read_secret("WEBHOOK_SECRET_FILE")
    workflow = evidence["workflow"]
    webhook = evidence["webhook"]
    async with mcp_session(requester_token) as requester:
        status = await call_tool(
            requester,
            "aip_action_status",
            {
                "action_id": workflow["commit_action_id"],
                "include_result": True,
                "include_receipts": True,
            },
        )
        action_views = [
            view
            for view in collect_mappings(structured(status), {"action_id", "state"})
            if view.get("action_id") == workflow["commit_action_id"]
        ]
        assert_true(
            any(view.get("state") == "completed" for view in action_views),
            "action was not recovered",
        )
        transaction = await call_tool(
            requester,
            "aip_transaction_get",
            {
                "transaction_id": workflow["transaction_id"],
                "include_result": True,
                "include_receipts": True,
            },
        )
        transaction_views = collect_mappings(
            structured(transaction), {"transaction_id", "action_id", "status"}
        )
        assert_true(
            any(
                view.get("transaction_id") == workflow["transaction_id"]
                and view.get("status") == "committed"
                for view in transaction_views
            ),
            "transaction was not recovered",
        )
        body = webhook_payload(webhook["marker"], webhook["created_at"])
        assert_true(
            await deliver_webhook(webhook_secret, body) == 204,
            "durable webhook replay failed after restart",
        )
        assert_true(
            await webhook_event_count(requester, webhook["marker"]) == 1,
            "webhook replay duplicated an event after restart",
        )
    async with await AsyncConnection.connect(
        required_environment("CAL_DATABASE_URL"), row_factory=dict_row
    ) as database:
        booking = await booking_for_action(database, workflow["commit_action_id"])
        assert_true(
            booking is not None and booking["uid"] == workflow["booking_uid"],
            "provider fact was not retained after AIP restart",
        )
        assert_true(
            await booking_count(database) == workflow["booking_count_after"],
            "restart or replay produced an additional provider mutation",
        )
    evidence["restart_verified"] = True
    evidence["restart_verified_at"] = (
        datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"status": "passed", "restart_verified": True}))


async def main() -> None:
    mode = required_environment("QUALIFICATION_MODE")
    if mode == "run":
        await run_qualification()
    elif mode == "verify-restart":
        await verify_restart()
    else:
        raise RuntimeError(f"unsupported QUALIFICATION_MODE: {mode}")


if __name__ == "__main__":
    asyncio.run(main())
