"""Fail-closed MCP edge and durable coordinator for the restaurant E2E.

This process is an application-level AIP consumer. It does not implement a new
protocol profile or connector. All agent, calendar, approval, transaction, and
audit operations cross the central AIP MCP resource.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import stat
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool
from starlette.requests import Request
from starlette.responses import JSONResponse

LOGGER = logging.getLogger("restaurant_booking")
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

CAL_SLOT_LIST = "cap:cal_diy:slot.list"
CAL_BOOKING_CREATE = "cap:cal_diy:booking.create"
CAL_BOOKING_GET = "cap:cal_diy:booking.get"
SUPERVISOR_CHAT = "cap:hermes_agent:supervisor:chat"
MANAGER_PRINCIPAL = "agent:hermes_operator:manager"
SUPERVISOR_PRINCIPAL = "agent:hermes_operator:supervisor"
TERMINAL_STATE = "completed"
LEASE_TTL_SECONDS = 180
LEASE_RENEW_SECONDS = 30
PUBLIC_WAIT_SECONDS = 45
MAX_SECRET_BYTES = 16 * 1024
MAX_REQUEST_TEXT_BYTES = 8 * 1024
MAX_CONVERSATION_MESSAGES = 64
MAX_CUSTOMER_NAME_BYTES = 256

_NAME_TOKEN = r"[^\W\d_](?:[^\W\d_]|[-'’]){0,63}"
_EXPLICIT_NAME_PATTERNS = (
    re.compile(
        rf"\b(?:меня\s+зовут|мо[её]\s+имя)\s*(?:[-:]\s*)?"
        rf"(?P<name>{_NAME_TOKEN}(?:\s+{_NAME_TOKEN}){{0,3}})"
        r"(?=\s*(?:[,.!?;]|$))",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\bmy\s+name\s+is\s*(?:[-:]\s*)?"
        rf"(?P<name>{_NAME_TOKEN}(?:\s+{_NAME_TOKEN}){{0,3}})"
        r"(?=\s*(?:[,.!?;]|$))",
        re.IGNORECASE,
    ),
)
_NON_NAME_WORDS = frozenset(
    {
        "book",
        "booking",
        "please",
        "reserve",
        "reservation",
        "бронь",
        "забронировать",
        "забронируйте",
        "пожалуйста",
    }
)

JSON_FIELDS = {
    "manager_result",
    "plan_result",
    "supervisor_result",
    "approval_record",
    "commit_result",
    "booking_snapshot",
    "last_error",
}
TEXT_FIELDS = {
    "manager_delegation_id",
    "plan_id",
    "commit_action_id",
    "approval_id",
    "supervisor_delegation_id",
    "booking_uid",
    "booking_seat_uid",
}


class WorkflowFailure(RuntimeError):
    """Redacted workflow failure safe for internal state and public error codes."""

    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


def required_environment(name: str) -> str:
    """Read one bounded, newline-free required environment value."""
    value = os.environ.get(name, "")
    if not value or "\r" in value or "\n" in value or len(value) > 4096:
        raise RuntimeError(f"{name} is missing or invalid")
    return value


def read_secret(path_value: str) -> str:
    """Read a regular owner-only secret file without logging its content."""
    path = Path(path_value)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError(f"secret path is not a regular file: {path}")
    if metadata.st_size <= 0 or metadata.st_size > MAX_SECRET_BYTES:
        raise RuntimeError(f"secret file has an invalid size: {path}")
    if metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise RuntimeError(f"secret file grants group or world access: {path}")
    value = path.read_text(encoding="utf-8").strip()
    if not value or "\r" in value or "\n" in value:
        raise RuntimeError(f"secret file is empty or invalid: {path}")
    return value


@dataclass(frozen=True)
class Config:
    """Validated deployment configuration."""

    database_url: str
    aip_mcp_url: str
    aip_mcp_token: str
    introspection_url: str
    introspection_issuer: str
    introspection_audience: str
    introspection_client_id: str
    introspection_client_secret: str
    allowed_subject: str
    restaurant_name: str
    default_customer_time_zone: str
    event_type_id: int
    listen_host: str
    listen_port: int
    public_resource_url: str
    request_timeout_seconds: int

    @classmethod
    def from_environment(cls) -> "Config":
        event_type_id = int(required_environment("CAL_EVENT_TYPE_ID"))
        if event_type_id <= 0:
            raise RuntimeError("CAL_EVENT_TYPE_ID must be positive")
        default_customer_time_zone = required_environment("DEFAULT_CUSTOMER_TIME_ZONE")
        try:
            ZoneInfo(default_customer_time_zone)
        except ZoneInfoNotFoundError as error:
            raise RuntimeError(
                "DEFAULT_CUSTOMER_TIME_ZONE must be an IANA time zone"
            ) from error
        listen_port = int(os.environ.get("LISTEN_PORT", "8081"))
        timeout = int(os.environ.get("AIP_REQUEST_TIMEOUT_SECONDS", "300"))
        if not 1 <= listen_port <= 65535 or not 30 <= timeout <= 900:
            raise RuntimeError(
                "listen port or AIP timeout is outside the supported bounds"
            )
        return cls(
            database_url=required_environment("DATABASE_URL"),
            aip_mcp_url=required_environment("AIP_MCP_URL"),
            aip_mcp_token=read_secret(required_environment("AIP_MCP_TOKEN_FILE")),
            introspection_url=required_environment("INTROSPECTION_URL"),
            introspection_issuer=required_environment("INTROSPECTION_ISSUER"),
            introspection_audience=required_environment("INTROSPECTION_AUDIENCE"),
            introspection_client_id=required_environment("INTROSPECTION_CLIENT_ID"),
            introspection_client_secret=read_secret(
                required_environment("INTROSPECTION_CLIENT_SECRET_FILE")
            ),
            allowed_subject=required_environment("MCP_ALLOWED_SUBJECT"),
            restaurant_name=required_environment("RESTAURANT_NAME"),
            default_customer_time_zone=default_customer_time_zone,
            event_type_id=event_type_id,
            listen_host=os.environ.get("LISTEN_HOST", "0.0.0.0"),
            listen_port=listen_port,
            public_resource_url=required_environment("MCP_RESOURCE_URL"),
            request_timeout_seconds=timeout,
        )


class IntrospectionVerifier(TokenVerifier):
    """RFC 7662 verifier with issuer, audience, expiry, scope, and subject checks."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(5.0), follow_redirects=False, trust_env=False
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token or len(token) > MAX_SECRET_BYTES:
            return None
        try:
            response = await self._client.post(
                self._config.introspection_url,
                data={"token": token, "token_type_hint": "access_token"},
                auth=(
                    self._config.introspection_client_id,
                    self._config.introspection_client_secret,
                ),
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError):
            LOGGER.warning("MCP token introspection failed closed")
            return None
        if payload.get("active") is not True:
            return None
        subject = payload.get("sub")
        issuer = payload.get("iss")
        audience = payload.get("aud")
        scopes = payload.get("scope", "").split()
        expires_at = payload.get("exp")
        audiences = {audience} if isinstance(audience, str) else set(audience or [])
        if (
            subject != self._config.allowed_subject
            or issuer != self._config.introspection_issuer
            or self._config.introspection_audience not in audiences
            or "mcp:connect" not in scopes
            or not isinstance(expires_at, int)
            or expires_at <= int(time.time())
        ):
            return None
        return AccessToken(
            token=token,
            client_id=subject,
            scopes=scopes,
            expires_at=expires_at,
            resource=self._config.introspection_audience,
        )


class WorkflowStore:
    """PostgreSQL workflow state with expiring fenced leases."""

    def __init__(self, database_url: str, schema_path: Path) -> None:
        self._pool = AsyncConnectionPool(
            database_url,
            min_size=1,
            max_size=10,
            open=False,
            kwargs={"row_factory": dict_row},
        )
        self._schema_path = schema_path

    async def open(self) -> None:
        await self._pool.open(wait=True, timeout=30)
        schema = self._schema_path.read_text(encoding="utf-8")
        async with self._pool.connection() as connection:
            await connection.execute(schema)
            await connection.commit()

    async def close(self) -> None:
        await self._pool.close()

    async def ping(self) -> None:
        """Verify that the workflow database is reachable."""
        async with self._pool.connection() as connection:
            await connection.execute("SELECT 1")

    async def get(self, request_id: str) -> dict[str, Any] | None:
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                "SELECT * FROM restaurant_booking.workflows WHERE request_id = %s",
                (request_id,),
            )
            return await cursor.fetchone()

    async def nonterminal(self) -> list[dict[str, Any]]:
        """Return workflows eligible for crash-recovery scheduling."""

        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                """
                SELECT *
                FROM restaurant_booking.workflows
                WHERE state <> 'completed'
                  AND last_error IS NULL
                  AND (lease_expires_at IS NULL OR lease_expires_at <= clock_timestamp())
                ORDER BY created_at
                """
            )
            return list(await cursor.fetchall())

    async def merge_request(
        self, request_id: str, update: Mapping[str, Any]
    ) -> dict[str, Any]:
        async with self._pool.connection() as connection:
            async with connection.transaction():
                cursor = await connection.execute(
                    "SELECT * FROM restaurant_booking.workflows WHERE request_id = %s FOR UPDATE",
                    (request_id,),
                )
                row = await cursor.fetchone()
                if row is None:
                    merged = {
                        key: value for key, value in update.items() if value is not None
                    }
                    append_user_message(merged, update.get("raw_request"))
                    cursor = await connection.execute(
                        """
                        INSERT INTO restaurant_booking.workflows (request_id, state, request)
                        VALUES (%s, 'collecting', %s)
                        RETURNING *
                        """,
                        (request_id, Jsonb(merged)),
                    )
                    created = await cursor.fetchone()
                    if created is None:
                        raise WorkflowFailure(
                            "workflow.store", "workflow insert returned no row"
                        )
                    return created
                current = dict(row["request"])
                candidate = dict(current)
                for key, value in update.items():
                    if value is not None and value != "":
                        if key == "raw_request":
                            append_user_message(candidate, value)
                            continue
                        candidate[key] = (
                            value.strip() if isinstance(value, str) else value
                        )
                if row["state"] != "collecting" and candidate != current:
                    raise WorkflowFailure(
                        "workflow.request_immutable",
                        "a booking request cannot change after execution starts",
                    )
                cursor = await connection.execute(
                    """
                    UPDATE restaurant_booking.workflows
                    SET request = %s, version = version + 1,
                        updated_at = clock_timestamp()
                    WHERE request_id = %s
                    RETURNING *
                    """,
                    (Jsonb(candidate), request_id),
                )
                updated = await cursor.fetchone()
                if updated is None:
                    raise WorkflowFailure(
                        "workflow.store", "workflow update returned no row"
                    )
                return updated

    async def acquire(self, request_id: str, owner: str) -> int | None:
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                """
                UPDATE restaurant_booking.workflows
                SET lease_owner = %s,
                    lease_expires_at = clock_timestamp() + make_interval(secs => %s),
                    fencing_token = fencing_token + 1,
                    version = version + 1,
                    updated_at = clock_timestamp()
                WHERE request_id = %s
                  AND state <> 'completed'
                  AND (lease_expires_at IS NULL OR lease_expires_at <= clock_timestamp())
                RETURNING fencing_token
                """,
                (owner, LEASE_TTL_SECONDS, request_id),
            )
            row = await cursor.fetchone()
            await connection.commit()
            return int(row["fencing_token"]) if row else None

    async def renew(self, request_id: str, owner: str, token: int) -> bool:
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                """
                UPDATE restaurant_booking.workflows
                SET lease_expires_at = clock_timestamp() + make_interval(secs => %s),
                    updated_at = clock_timestamp()
                WHERE request_id = %s AND lease_owner = %s AND fencing_token = %s
                  AND lease_expires_at > clock_timestamp()
                """,
                (LEASE_TTL_SECONDS, request_id, owner, token),
            )
            await connection.commit()
            return cursor.rowcount == 1

    async def release(self, request_id: str, owner: str, token: int) -> bool:
        async with self._pool.connection() as connection:
            cursor = await connection.execute(
                """
                UPDATE restaurant_booking.workflows
                SET lease_owner = NULL, lease_expires_at = NULL,
                    version = version + 1, updated_at = clock_timestamp()
                WHERE request_id = %s AND lease_owner = %s AND fencing_token = %s
                """,
                (request_id, owner, token),
            )
            await connection.commit()
            return cursor.rowcount == 1

    async def update(
        self,
        request_id: str,
        owner: str,
        token: int,
        expected_state: str,
        next_state: str,
        **fields: Any,
    ) -> dict[str, Any]:
        unknown = set(fields) - JSON_FIELDS - TEXT_FIELDS
        if unknown:
            raise WorkflowFailure("workflow.store", "unsupported workflow field")
        assignments: list[sql.Composable] = [sql.SQL("state = %s")]
        values: list[Any] = [next_state]
        for name, value in fields.items():
            assignments.append(sql.SQL("{} = %s").format(sql.Identifier(name)))
            values.append(
                Jsonb(value) if name in JSON_FIELDS and value is not None else value
            )
        assignments.extend(
            [
                sql.SQL("version = version + 1"),
                sql.SQL("updated_at = clock_timestamp()"),
            ]
        )
        statement = sql.SQL(
            "UPDATE restaurant_booking.workflows SET {} "
            "WHERE request_id = %s AND state = %s AND lease_owner = %s "
            "AND fencing_token = %s AND lease_expires_at > clock_timestamp() RETURNING *"
        ).format(sql.SQL(", ").join(assignments))
        values.extend([request_id, expected_state, owner, token])
        async with self._pool.connection() as connection:
            cursor = await connection.execute(statement, values)
            row = await cursor.fetchone()
            await connection.commit()
            if row is None:
                raise WorkflowFailure(
                    "workflow.lease_lost", "workflow lease or state was lost"
                )
            return row

    async def set_error(
        self, request_id: str, owner: str, token: int, error: WorkflowFailure
    ) -> None:
        async with self._pool.connection() as connection:
            await connection.execute(
                """
                UPDATE restaurant_booking.workflows
                SET last_error = %s, version = version + 1,
                    updated_at = clock_timestamp()
                WHERE request_id = %s AND lease_owner = %s AND fencing_token = %s
                """,
                (
                    Jsonb({"code": error.code, "retryable": error.retryable}),
                    request_id,
                    owner,
                    token,
                ),
            )
            await connection.commit()


class AipMcpClient:
    """Short-lived authenticated MCP sessions against the central AIP edge."""

    def __init__(self, config: Config) -> None:
        self._url = config.aip_mcp_url
        self._token = config.aip_mcp_token
        self._timeout = config.request_timeout_seconds

    async def call(
        self, name: str, arguments: dict[str, Any], *, allow_error: bool = False
    ) -> dict[str, Any]:
        timeout = httpx.Timeout(float(self._timeout))
        async with httpx.AsyncClient(
            headers={"Authorization": f"Bearer {self._token}"},
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            async with streamable_http_client(self._url, http_client=client) as streams:
                read_stream, write_stream, _ = streams
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    result = await session.call_tool(
                        name,
                        arguments,
                        read_timeout_seconds=timedelta(seconds=self._timeout),
                    )
        payload = result.model_dump(mode="json", by_alias=True, exclude_none=True)
        is_error = bool(payload.get("isError", payload.get("is_error", False)))
        if is_error and not allow_error:
            code = nested_text(payload, "code") or "aip.remote_error"
            raise WorkflowFailure(code, "central AIP call failed", retryable=False)
        return payload


class BookingCoordinator:
    """Crash-resumable business coordinator over existing AIP capabilities."""

    def __init__(self, config: Config, store: WorkflowStore, aip: AipMcpClient) -> None:
        self._config = config
        self._store = store
        self._aip = aip
        self._instance_id = str(uuid.uuid4())
        self._tasks: dict[str, asyncio.Task[dict[str, Any]]] = {}
        self._task_lock = asyncio.Lock()

    async def submit(
        self, request_id: str, update: Mapping[str, Any]
    ) -> dict[str, Any]:
        try:
            normalized_update = normalize_booking_update(update)
            raw_message = normalized_update.get("raw_request")
            if normalized_update.get("customer_name") in (None, "") and isinstance(
                raw_message, str
            ):
                explicit_name = extract_explicit_customer_name(raw_message)
                if explicit_name is not None:
                    normalized_update["customer_name"] = explicit_name
            if normalized_update.get("restaurant") in (None, ""):
                normalized_update["restaurant"] = self._config.restaurant_name
            if normalized_update.get("customer_time_zone") in (None, ""):
                normalized_update["customer_time_zone"] = (
                    self._config.default_customer_time_zone
                )
            row = await self._store.merge_request(request_id, normalized_update)
            if row["request"].get("restaurant") != self._config.restaurant_name:
                raise WorkflowFailure(
                    "booking.restaurant_unknown",
                    f"this endpoint serves only {self._config.restaurant_name}",
                )
            missing = missing_fields(row["request"])
            if missing:
                return clarification_response(request_id, row["request"])
            validate_request(row["request"], self._config)
        except WorkflowFailure as error:
            return public_failure(request_id, error)
        if row["state"] == TERMINAL_STATE:
            return public_completed(row)
        if isinstance(row.get("last_error"), dict):
            return public_stored_failure(request_id, row["last_error"])
        task = await self._ensure_execution(request_id)
        return await self._wait_for_execution(request_id, task)

    async def recover(self) -> None:
        """Schedule complete, nonterminal workflows after process restart."""

        for row in await self._store.nonterminal():
            request = row["request"]
            if missing_fields(request):
                continue
            try:
                validate_request(request, self._config)
            except WorkflowFailure:
                continue
            await self._ensure_execution(str(row["request_id"]))

    async def close(self) -> None:
        """Cancel local workers while leaving durable state recoverable."""

        tasks = list(self._tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _ensure_execution(self, request_id: str) -> asyncio.Task[dict[str, Any]]:
        async with self._task_lock:
            existing = self._tasks.get(request_id)
            if existing is not None and not existing.done():
                return existing
            task = asyncio.create_task(
                self._run_workflow(request_id),
                name=f"restaurant-booking:{request_id}",
            )
            self._tasks[request_id] = task
            task.add_done_callback(
                lambda completed, key=request_id: self._execution_done(key, completed)
            )
            return task

    def _execution_done(
        self, request_id: str, task: asyncio.Task[dict[str, Any]]
    ) -> None:
        if self._tasks.get(request_id) is task:
            self._tasks.pop(request_id, None)
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            LOGGER.error(
                "background workflow terminated request_id=%s error_type=%s",
                request_id,
                type(error).__name__,
            )

    async def _wait_for_execution(
        self, request_id: str, task: asyncio.Task[dict[str, Any]]
    ) -> dict[str, Any]:
        try:
            return await asyncio.wait_for(
                asyncio.shield(task), timeout=PUBLIC_WAIT_SECONDS
            )
        except TimeoutError:
            return processing_response(request_id)

    async def _run_workflow(self, request_id: str) -> dict[str, Any]:
        owner = str(uuid.uuid4())
        token = await self._store.acquire(request_id, owner)
        if token is None:
            row = await self._store.get(request_id)
            if row is not None and row["state"] == TERMINAL_STATE:
                return public_completed(row)
            return processing_response(request_id)
        stop = asyncio.Event()
        heartbeat = asyncio.create_task(
            self._renew_lease(request_id, owner, token, stop)
        )
        execution = asyncio.create_task(self._execute(request_id, owner, token))
        try:
            done, _ = await asyncio.wait(
                {execution, heartbeat}, return_when=asyncio.FIRST_COMPLETED
            )
            if heartbeat in done and not stop.is_set():
                execution.cancel()
                try:
                    await execution
                except asyncio.CancelledError:
                    pass
                await heartbeat
                raise WorkflowFailure("workflow.lease_lost", "workflow lease was lost")
            completed = await execution
            stop.set()
            await heartbeat
            return public_completed(completed)
        except asyncio.CancelledError:
            execution.cancel()
            try:
                await execution
            except asyncio.CancelledError:
                pass
            raise
        except WorkflowFailure as error:
            try:
                await self._store.set_error(request_id, owner, token, error)
            except Exception:
                LOGGER.exception(
                    "failed to persist workflow error request_id=%s", request_id
                )
            LOGGER.error(
                "workflow failed request_id=%s code=%s", request_id, error.code
            )
            return public_failure(request_id, error)
        except Exception:
            LOGGER.exception("workflow crashed request_id=%s", request_id)
            error = WorkflowFailure("workflow.internal_error", "workflow crashed")
            try:
                await self._store.set_error(request_id, owner, token, error)
            except Exception:
                LOGGER.exception(
                    "failed to persist workflow crash request_id=%s", request_id
                )
            return public_failure(request_id, error)
        finally:
            stop.set()
            if not heartbeat.done():
                await heartbeat
            if not await self._store.release(request_id, owner, token):
                LOGGER.error("workflow lease release failed request_id=%s", request_id)

    async def status(self, request_id: str) -> dict[str, Any]:
        row = await self._store.get(request_id)
        if row is None:
            return {"status": "not_found", "request_id": request_id}
        if row["state"] == TERMINAL_STATE:
            return public_completed(row)
        if isinstance(row.get("last_error"), dict):
            return public_stored_failure(request_id, row["last_error"])
        if row["state"] == "collecting" and missing_fields(row["request"]):
            return clarification_response(request_id, row["request"])
        task = await self._ensure_execution(request_id)
        return await self._wait_for_execution(request_id, task)

    async def _renew_lease(
        self, request_id: str, owner: str, token: int, stop: asyncio.Event
    ) -> None:
        while True:
            try:
                await asyncio.wait_for(stop.wait(), timeout=LEASE_RENEW_SECONDS)
                return
            except TimeoutError:
                if not await self._store.renew(request_id, owner, token):
                    raise WorkflowFailure(
                        "workflow.lease_lost", "workflow lease was lost"
                    )

    async def _execute(self, request_id: str, owner: str, token: int) -> dict[str, Any]:
        while True:
            row = await self._store.get(request_id)
            if row is None:
                raise WorkflowFailure("workflow.not_found", "workflow disappeared")
            state = row["state"]
            if state == "collecting":
                result = await self._delegate_slot_check(
                    row, "manager", MANAGER_PRINCIPAL
                )
                row = await self._store.update(
                    request_id,
                    owner,
                    token,
                    "collecting",
                    "manager_checked",
                    manager_result=result,
                    manager_delegation_id=result["delegation_id"],
                )
            elif state == "manager_checked":
                row = await self._plan(row, owner, token)
            elif state == "planned":
                row = await self._start_commit(row, owner, token)
            elif state == "approval_pending":
                result = await self._delegate_slot_check(
                    row, "supervisor", SUPERVISOR_PRINCIPAL
                )
                row = await self._store.update(
                    request_id,
                    owner,
                    token,
                    "approval_pending",
                    "supervisor_checked",
                    supervisor_result=result,
                    supervisor_delegation_id=result["delegation_id"],
                )
            elif state == "supervisor_checked":
                row = await self._approve(row, owner, token)
            elif state == "approved":
                row = await self._finish_commit(row, owner, token)
            elif state == "committed":
                row = await self._verify_booking(row, owner, token)
            elif state == TERMINAL_STATE:
                return row
            else:
                raise WorkflowFailure(
                    "workflow.invalid_state", f"unsupported workflow state {state}"
                )

    async def _delegate_slot_check(
        self, row: Mapping[str, Any], role: str, principal: str
    ) -> dict[str, Any]:
        request_id = str(row["request_id"])
        slot_input = slot_query(row["request"], self._config.event_type_id)
        result = await self._aip.call(
            "aip_delegate",
            {
                "delegation_id": stable_id("dlg_", request_id, role, "delegation"),
                "parent_action_id": stable_id("act_", request_id, role, "parent"),
                "action_id": stable_id("act_", request_id, role, "slot"),
                "delegate_id": principal,
                "scope": "cal_diy.slot.read",
                "capability_id": CAL_SLOT_LIST,
                "input": slot_input,
                "idempotency_key": f"restaurant:{request_id}:{role}:slot",
                "timeout_ms": self._config.request_timeout_seconds * 1000,
                "metadata": {"workflow": "restaurant_booking", "role": role},
            },
        )
        delegation = find_mapping(
            structured_content(result), {"delegation_id", "child_action_id", "status"}
        )
        if delegation is None or delegation.get("status") != "completed":
            raise WorkflowFailure(
                f"workflow.{role}_delegation_failed",
                f"{role} delegation did not complete",
            )
        child_result = delegation.get("result")
        if (
            not isinstance(child_result, dict)
            or child_result.get("status") != "completed"
        ):
            raise WorkflowFailure(
                f"workflow.{role}_slot_failed", f"{role} slot action did not complete"
            )
        output = child_result.get("output")
        if not slot_is_available(output, row["request"]["start"]):
            raise WorkflowFailure(
                "booking.slot_unavailable", "requested Cal.diy slot is unavailable"
            )
        return dict(delegation)

    async def _plan(
        self, row: Mapping[str, Any], owner: str, token: int
    ) -> dict[str, Any]:
        request_id = str(row["request_id"])
        result = await self._aip.call(
            "aip_call",
            {
                "action_id": stable_id("act_", request_id, "booking", "plan"),
                "capability_id": CAL_BOOKING_CREATE,
                "idempotency_key": f"restaurant:{request_id}:booking:plan",
                "transaction": {"mode": "plan"},
                "input": booking_input(
                    row["request"], self._config.event_type_id, request_id
                ),
            },
        )
        content = structured_content(result)
        plan_id = nested_text(content, "plan_id")
        if not plan_id:
            raise WorkflowFailure("booking.plan_missing", "AIP plan id is missing")
        connector_validation = find_key(content, "connector_validation")
        if not isinstance(connector_validation, dict):
            raise WorkflowFailure(
                "booking.plan_not_validated",
                "Cal.diy downstream plan evidence is missing",
            )
        return await self._store.update(
            request_id,
            owner,
            token,
            "manager_checked",
            "planned",
            plan_result=content,
            plan_id=plan_id,
        )

    async def _start_commit(
        self, row: Mapping[str, Any], owner: str, token: int
    ) -> dict[str, Any]:
        request_id = str(row["request_id"])
        action_id = stable_id("act_", request_id, "booking", "commit")
        result = await self._aip.call(
            "aip_call",
            {
                "action_id": action_id,
                "capability_id": CAL_BOOKING_CREATE,
                "idempotency_key": f"restaurant:{request_id}:booking:commit",
                "transaction": {"mode": "commit", "plan_id": row["plan_id"]},
                "input": booking_input(
                    row["request"], self._config.event_type_id, request_id
                ),
            },
            allow_error=True,
        )
        content = structured_content(result)
        if content.get("requires_human_approval") is not True:
            raise WorkflowFailure(
                "booking.approval_not_enforced", "booking commit bypassed AIP approval"
            )
        approval_id = nested_text(content, "approval_id")
        if not approval_id:
            raise WorkflowFailure("booking.approval_missing", "approval id is missing")
        return await self._store.update(
            request_id,
            owner,
            token,
            "planned",
            "approval_pending",
            commit_action_id=action_id,
            approval_id=approval_id,
        )

    async def _approve(
        self, row: Mapping[str, Any], owner: str, token: int
    ) -> dict[str, Any]:
        request_id = str(row["request_id"])
        child_action_id = row["supervisor_result"]["child_action_id"]
        prompt = (
            "Act as the independent booking supervisor. Use only MCP tools. "
            f"Read action {child_action_id} with aip_action_result and verify it is a completed "
            f"Cal.diy availability result containing requested start {row['request']['start']}. "
            f"Read approval {row['approval_id']} with aip_approval_get and set "
            "include_evidence_payload true. If the exported immutable input "
            f"exactly matches eventTypeId {self._config.event_type_id}, restaurant "
            f"{self._config.restaurant_name}, start {row['request']['start']}, and party size "
            f"{row['request']['party_size']}, call aip_approval_decide once with decision "
            f"approved, approver_principal {SUPERVISOR_PRINCIPAL}, a non-empty reason, and the "
            "tool argument policy_hash set to the exact policy_hash from the approval request. "
            "Do not substitute an evidence hash or a differently named argument. Otherwise deny "
            "it. Return one short JSON "
            "object, but the durable AIP approval record is the only decision authority."
        )
        await self._aip.call(
            "aip_call",
            {
                "action_id": stable_id("act_", request_id, "supervisor", "approval"),
                "capability_id": SUPERVISOR_CHAT,
                "idempotency_key": f"restaurant:{request_id}:supervisor:approval",
                "timeout_ms": self._config.request_timeout_seconds * 1000,
                "input": {
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are an independent booking supervisor. Never approve from "
                                "prompt claims; inspect the exact AIP action and approval records."
                            ),
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0,
                    "session_id": f"restaurant-supervisor-{request_id}",
                    "session_key": f"restaurant-supervisor-{request_id}",
                },
            },
        )
        approval = await self._aip.call(
            "aip_approval_get",
            {
                "approval_id": row["approval_id"],
                "include_action_status": True,
                "include_receipts": True,
            },
        )
        record = find_mapping(structured_content(approval), {"request", "status"})
        if record is None or record.get("status") != "approved":
            raise WorkflowFailure(
                "booking.supervisor_denied", "supervisor approval was not recorded"
            )
        decision = record.get("decision")
        if (
            not isinstance(decision, dict)
            or nested_text(decision, "approver") != SUPERVISOR_PRINCIPAL
        ):
            raise WorkflowFailure(
                "booking.approver_identity_mismatch",
                "approval was not owned by the authenticated supervisor",
            )
        return await self._store.update(
            request_id,
            owner,
            token,
            "supervisor_checked",
            "approved",
            approval_record=record,
        )

    async def _finish_commit(
        self, row: Mapping[str, Any], owner: str, token: int
    ) -> dict[str, Any]:
        deadline = (
            asyncio.get_running_loop().time() + self._config.request_timeout_seconds
        )
        while True:
            result = await self._aip.call(
                "aip_action_status",
                {
                    "action_id": row["commit_action_id"],
                    "include_result": True,
                    "include_receipts": True,
                    "wait_ms": 5_000,
                },
            )
            status = find_mapping(structured_content(result), {"action_id", "state"})
            if status is None:
                raise WorkflowFailure(
                    "booking.commit_status_missing", "commit status is missing"
                )
            if status.get("state") == "completed":
                action_result = status.get("result")
                if (
                    not isinstance(action_result, dict)
                    or action_result.get("status") != "completed"
                ):
                    raise WorkflowFailure(
                        "booking.commit_result_invalid",
                        "commit result is not completed",
                    )
                booking_uid, booking_seat_uid = reservation_identifiers(
                    action_result.get("output"), str(row["commit_action_id"])
                )
                if not booking_uid or not booking_seat_uid:
                    raise WorkflowFailure(
                        "booking.identifier_missing",
                        "Cal.diy booking or seat uid is missing",
                    )
                return await self._store.update(
                    str(row["request_id"]),
                    owner,
                    token,
                    "approved",
                    "committed",
                    commit_result=status,
                    booking_uid=booking_uid,
                    booking_seat_uid=booking_seat_uid,
                )
            if status.get("state") in {
                "failed",
                "cancelled",
                "expired",
                "dead_lettered",
            }:
                raise WorkflowFailure(
                    "booking.commit_failed", "AIP booking commit failed"
                )
            if asyncio.get_running_loop().time() >= deadline:
                raise WorkflowFailure(
                    "booking.commit_timeout",
                    "AIP booking commit timed out",
                    retryable=True,
                )
            await asyncio.sleep(0.5)

    async def _verify_booking(
        self, row: Mapping[str, Any], owner: str, token: int
    ) -> dict[str, Any]:
        request_id = str(row["request_id"])
        result = await self._aip.call(
            "aip_call",
            {
                "action_id": stable_id("act_", request_id, "booking", "verify"),
                "capability_id": CAL_BOOKING_GET,
                "idempotency_key": f"restaurant:{request_id}:booking:verify",
                "input": {"booking_uid": row["booking_uid"]},
            },
        )
        snapshot = structured_content(result)
        if nested_text(snapshot, "uid") != row[
            "booking_uid"
        ] or not contains_mapping_value(snapshot, "seatUid", row["booking_seat_uid"]):
            raise WorkflowFailure(
                "booking.verification_mismatch",
                "Cal.diy returned another booking or seat uid",
            )
        return await self._store.update(
            request_id,
            owner,
            token,
            "committed",
            "completed",
            booking_snapshot=snapshot,
            last_error=None,
        )


def stable_id(prefix: str, *parts: str) -> str:
    value = uuid.uuid5(uuid.NAMESPACE_URL, ":".join(parts)).hex
    return f"{prefix}{value}"


def append_user_message(request: dict[str, Any], message: Any) -> None:
    """Append one bounded user message without overwriting the initial request."""
    if not isinstance(message, str):
        raise WorkflowFailure("booking.request_invalid", "user message must be text")
    normalized = message.strip()
    if not normalized or len(normalized.encode("utf-8")) > MAX_REQUEST_TEXT_BYTES:
        raise WorkflowFailure(
            "booking.request_too_large", "user message is empty or too large"
        )
    initial = request.get("raw_request")
    if not isinstance(initial, str) or not initial.strip():
        request["raw_request"] = normalized
        initial = normalized
    conversation = request.get("conversation")
    if conversation is None:
        conversation = [initial.strip()]
    if not isinstance(conversation, list) or not all(
        isinstance(item, str) for item in conversation
    ):
        raise WorkflowFailure(
            "workflow.conversation_invalid", "conversation history is invalid"
        )
    if not conversation or conversation[-1] != normalized:
        if len(conversation) >= MAX_CONVERSATION_MESSAGES:
            raise WorkflowFailure(
                "booking.conversation_too_long", "conversation limit exceeded"
            )
        conversation.append(normalized)
    request["conversation"] = conversation
    request["latest_user_message"] = normalized


def extract_explicit_customer_name(message: str) -> str | None:
    """Extract a bounded name only from an unambiguous self-identification phrase."""
    if len(message.encode("utf-8")) > MAX_REQUEST_TEXT_BYTES:
        return None
    for pattern in _EXPLICIT_NAME_PATTERNS:
        match = pattern.search(message)
        if match is None:
            continue
        candidate = " ".join(match.group("name").split())
        words = candidate.casefold().split()
        if (
            candidate
            and len(candidate.encode("utf-8")) <= MAX_CUSTOMER_NAME_BYTES
            and not any(word in _NON_NAME_WORDS for word in words)
        ):
            return candidate
    return None


def normalize_booking_update(update: Mapping[str, Any]) -> dict[str, Any]:
    """Discard provider placeholders before they enter durable workflow state.

    Tool-capable models may serialize unknown nullable arguments as empty strings
    or zero. Those values are not customer facts and must not become immutable
    workflow input. Invalid non-empty values remain subject to the normal
    validation path, except for party size where every out-of-range integer is
    treated as an unanswered slot so the customer can correct it conversationally.
    """

    normalized = dict(update)
    for field in (
        "restaurant",
        "start",
        "customer_name",
        "customer_email",
        "customer_phone",
        "customer_time_zone",
    ):
        value = normalized.get(field)
        if isinstance(value, str):
            value = value.strip()
            normalized[field] = value or None

    party_size = normalized.get("party_size")
    if party_size is not None and (
        not isinstance(party_size, int)
        or isinstance(party_size, bool)
        or not 1 <= party_size <= 8
    ):
        normalized["party_size"] = None
    return normalized


def field_is_present(request: Mapping[str, Any], field: str) -> bool:
    """Return whether a collected field contains a usable customer fact."""

    value = request.get(field)
    if field == "party_size":
        return (
            isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 8
        )
    if isinstance(value, str):
        return bool(value.strip())
    return value is not None


def missing_fields(request: Mapping[str, Any]) -> list[str]:
    fields = [
        "restaurant",
        "start",
        "party_size",
        "customer_name",
        "customer_email",
        "customer_time_zone",
    ]
    return [field for field in fields if not field_is_present(request, field)]


def clarification_fields(request: Mapping[str, Any]) -> list[str]:
    """Return only the next conversational slot-filling stage."""
    missing = set(missing_fields(request))
    for stage in (
        ("start", "party_size"),
        ("customer_name", "customer_email"),
        ("restaurant", "customer_time_zone"),
    ):
        requested = [field for field in stage if field in missing]
        if requested:
            return requested
    return []


def clarification_response(
    request_id: str, request: Mapping[str, Any]
) -> dict[str, Any]:
    requested = clarification_fields(request)
    questions = {
        "restaurant": "Which restaurant would you like to book?",
        "start": "For which day and at approximately what time should I look?",
        "party_size": "How many guests should the table seat?",
        "customer_name": "What name should the reservation use?",
        "customer_email": "What email should receive the confirmation?",
        "customer_time_zone": "Which time zone should I use for the requested time?",
    }
    requirements = {
        "start": (
            "Accept a natural-language answer from the customer and convert it to "
            "RFC3339 with an explicit UTC offset only when invoking this tool."
        ),
        "party_size": "Integer from 1 through 8.",
        "customer_email": "A deliverable confirmation address.",
    }
    return {
        "status": "clarification_required",
        "request_id": request_id,
        "requested_fields": requested,
        "questions": [questions[field] for field in requested],
        "input_requirements": {
            field: requirements[field] for field in requested if field in requirements
        },
        "captured_fields": [
            field
            for field in (
                "restaurant",
                "start",
                "party_size",
                "customer_name",
                "customer_email",
                "customer_phone",
                "customer_time_zone",
            )
            if field_is_present(request, field)
        ],
        "known_context": {
            "restaurant_configured": field_is_present(request, "restaurant"),
            "customer_time_zone_configured": field_is_present(
                request, "customer_time_zone"
            ),
        },
    }


def validate_request(request: Mapping[str, Any], config: Config) -> None:
    if request.get("restaurant") != config.restaurant_name:
        raise WorkflowFailure(
            "booking.restaurant_unknown",
            f"this endpoint serves only {config.restaurant_name}",
        )
    party_size = request.get("party_size")
    if (
        not isinstance(party_size, int)
        or isinstance(party_size, bool)
        or not 1 <= party_size <= 8
    ):
        raise WorkflowFailure(
            "booking.party_size_invalid", "party size must be 1 through 8"
        )
    start = parse_datetime(request.get("start"))
    if start <= datetime.now(timezone.utc) + timedelta(minutes=30):
        raise WorkflowFailure("booking.start_invalid", "start must be in the future")
    customer_time_zone = request.get("customer_time_zone")
    if not isinstance(customer_time_zone, str):
        raise WorkflowFailure(
            "booking.time_zone_invalid", "customer time zone is invalid"
        )
    try:
        ZoneInfo(customer_time_zone)
    except ZoneInfoNotFoundError as error:
        raise WorkflowFailure(
            "booking.time_zone_invalid", "customer time zone is invalid"
        ) from error
    email = request.get("customer_email")
    if not isinstance(email, str) or "@" not in email or len(email) > 320:
        raise WorkflowFailure("booking.email_invalid", "customer email is invalid")
    customer_name = request.get("customer_name")
    if (
        not isinstance(customer_name, str)
        or not customer_name.strip()
        or len(customer_name.encode("utf-8")) > MAX_CUSTOMER_NAME_BYTES
        or any(character in customer_name for character in ("\r", "\n", "\x00"))
        or not any(character.isalpha() for character in customer_name)
    ):
        raise WorkflowFailure(
            "booking.customer_name_invalid", "customer name is invalid"
        )
    raw_request = request.get("raw_request", "")
    if (
        not isinstance(raw_request, str)
        or len(raw_request.encode("utf-8")) > MAX_REQUEST_TEXT_BYTES
    ):
        raise WorkflowFailure("booking.request_too_large", "raw request is too large")


def parse_datetime(value: Any) -> datetime:
    if not isinstance(value, str):
        raise WorkflowFailure(
            "booking.start_invalid", "start must be an RFC3339 string"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise WorkflowFailure(
            "booking.start_invalid", "start is not RFC3339"
        ) from error
    if parsed.tzinfo is None:
        raise WorkflowFailure(
            "booking.start_invalid", "start must include a UTC offset"
        )
    return parsed.astimezone(timezone.utc)


def slot_query(request: Mapping[str, Any], event_type_id: int) -> dict[str, Any]:
    start = parse_datetime(request["start"])
    end = start + timedelta(hours=2)
    return {
        "start": start.isoformat().replace("+00:00", "Z"),
        "end": end.isoformat().replace("+00:00", "Z"),
        "eventTypeId": event_type_id,
        "timeZone": request["customer_time_zone"],
        "format": "time",
    }


def booking_input(
    request: Mapping[str, Any], event_type_id: int, request_id: str
) -> dict[str, Any]:
    return {
        "start": request["start"],
        "eventTypeId": event_type_id,
        "attendee": {
            "name": request["customer_name"],
            "email": request["customer_email"],
            "timeZone": request["customer_time_zone"],
            "language": "en",
        },
        "bookingFieldsResponses": {
            "party_size": request["party_size"],
            "restaurant": request["restaurant"],
        },
        "metadata": {
            "aip_request_id": request_id,
            "party_size": str(request["party_size"]),
            "restaurant": request["restaurant"],
        },
    }


def structured_content(payload: Mapping[str, Any]) -> dict[str, Any]:
    content = payload.get("structuredContent", payload.get("structured_content"))
    if not isinstance(content, dict):
        raise WorkflowFailure(
            "aip.structured_content_missing", "MCP structured content is missing"
        )
    return content


def find_mapping(value: Any, required_keys: set[str]) -> dict[str, Any] | None:
    if isinstance(value, dict):
        if required_keys.issubset(value):
            return value
        for child in value.values():
            found = find_mapping(child, required_keys)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = find_mapping(child, required_keys)
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


def contains_mapping_value(value: Any, key: str, expected: Any) -> bool:
    """Return whether a nested mapping contains one exact field value."""

    if isinstance(value, dict):
        if value.get(key) == expected:
            return True
        return any(
            contains_mapping_value(child, key, expected) for child in value.values()
        )
    if isinstance(value, list):
        return any(contains_mapping_value(child, key, expected) for child in value)
    return False


def nested_text(value: Any, key: str) -> str | None:
    found = find_key(value, key)
    if isinstance(found, str) and found:
        return found
    if isinstance(found, dict):
        candidate = found.get("id")
        return candidate if isinstance(candidate, str) and candidate else None
    return None


def reservation_identifiers(
    output: Any, action_id: str
) -> tuple[str | None, str | None]:
    """Resolve the parent booking and action-bound seated reservation ids."""

    booking_uid = nested_text(output, "uid")
    seat_uids: set[str] = set()

    def collect(value: Any) -> None:
        if isinstance(value, dict):
            metadata = value.get("metadata")
            seat_uid = value.get("seatUid")
            if (
                isinstance(metadata, dict)
                and metadata.get("aip_action_id") == action_id
                and isinstance(seat_uid, str)
                and seat_uid
            ):
                seat_uids.add(seat_uid)
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    collect(output)
    booking_seat_uid = next(iter(seat_uids)) if len(seat_uids) == 1 else None
    return booking_uid, booking_seat_uid


def slot_is_available(output: Any, requested_start: str) -> bool:
    expected = parse_datetime(requested_start)
    candidates: list[str] = []

    def collect(value: Any, parent_key: str | None = None) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                collect(child, key)
        elif isinstance(value, list):
            for child in value:
                collect(child, parent_key)
        elif isinstance(value, str) and parent_key in {"start", "time"}:
            candidates.append(value)

    collect(output)
    for candidate in candidates:
        try:
            if parse_datetime(candidate) == expected:
                return True
        except WorkflowFailure:
            continue
    return False


def public_completed(row: Mapping[str, Any]) -> dict[str, Any]:
    request = row["request"]
    return {
        "status": "confirmed",
        "request_id": str(row["request_id"]),
        "booking_uid": row["booking_uid"],
        "booking_seat_uid": row["booking_seat_uid"],
        "restaurant": request["restaurant"],
        "start": request["start"],
        "party_size": request["party_size"],
        "message": "The reservation is confirmed.",
    }


def public_failure(request_id: str, error: WorkflowFailure) -> dict[str, Any]:
    return {
        "status": "failed",
        "request_id": request_id,
        "error_code": error.code,
        "retryable": error.retryable,
        "message": "The booking could not be completed safely.",
    }


def public_stored_failure(
    request_id: str, stored_error: Mapping[str, Any]
) -> dict[str, Any]:
    """Project a durable internal failure without disclosing its message."""

    code = stored_error.get("code")
    retryable = stored_error.get("retryable")
    return public_failure(
        request_id,
        WorkflowFailure(
            code if isinstance(code, str) and code else "workflow.failed",
            "durable workflow failure",
            retryable=retryable if isinstance(retryable, bool) else False,
        ),
    )


def processing_response(request_id: str) -> dict[str, Any]:
    """Return the stable public representation of an active workflow."""

    return {
        "status": "processing",
        "request_id": request_id,
        "message": "The booking is being verified.",
    }


CONFIG = Config.from_environment()
STORE = WorkflowStore(CONFIG.database_url, Path(__file__).with_name("schema.sql"))
AIP = AipMcpClient(CONFIG)
COORDINATOR = BookingCoordinator(CONFIG, STORE, AIP)
VERIFIER = IntrospectionVerifier(CONFIG)


SERVER = FastMCP(
    "restaurant-booking",
    instructions=(
        "Book and inspect restaurant reservations through progressive slot filling. "
        "For clarification_required, ask only the returned questions and reuse the "
        "same request id on the next customer turn. For processing, call the status "
        "tool with the same request id until the workflow is terminal."
    ),
    host=CONFIG.listen_host,
    port=CONFIG.listen_port,
    streamable_http_path="/mcp",
    json_response=True,
    stateless_http=False,
    token_verifier=VERIFIER,
    auth=AuthSettings(
        issuer_url=CONFIG.introspection_issuer,
        resource_server_url=CONFIG.public_resource_url,
        required_scopes=["mcp:connect"],
    ),
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[
            f"restaurant-coordinator:{CONFIG.listen_port}",
            f"127.0.0.1:{CONFIG.listen_port}",
            "127.0.0.1:18181",
            "localhost:18181",
        ],
        allowed_origins=[],
    ),
)


@SERVER.custom_route("/health", methods=["GET"], include_in_schema=False)
async def health(_: Request) -> JSONResponse:
    try:
        await STORE.ping()
        return JSONResponse({"status": "ok"})
    except Exception:
        return JSONResponse({"status": "unavailable"}, status_code=503)


@SERVER.tool()
async def restaurant_booking_request(
    raw_request: str,
    request_id: str | None = None,
    restaurant: str | None = None,
    start: str | None = None,
    party_size: int | None = None,
    customer_name: str | None = None,
    customer_email: str | None = None,
    customer_phone: str | None = None,
    customer_time_zone: str | None = None,
) -> dict[str, Any]:
    """Create or continue one governed restaurant reservation.

    Incomplete calls return a stable request id and no more than two questions
    for the next conversational stage. Reuse that request id after obtaining
    the customer's answer. Restaurant and time-zone defaults are owned by the
    deployment and do not need to be requested from the customer.

    Args:
        raw_request: The customer's current booking message. Always map every explicit
            fact in this message to its corresponding argument, even when that fact is
            not part of the current clarification stage.
        request_id: UUID returned by the first incomplete call; never replace it.
        restaurant: Explicit restaurant only when it differs from known context.
        start: RFC3339 date-time with an explicit UTC offset.
        party_size: Integer number of guests from one through eight.
        customer_name: Reservation holder's name. Set this whenever the current
            message states the customer's name, including phrases such as "my name is"
            or "меня зовут"; never defer it to a later clarification stage.
        customer_email: Address that receives the booking confirmation.
        customer_phone: Optional E.164 phone number.
        customer_time_zone: Explicit IANA zone only when known context is wrong.
    """
    resolved_id = request_id or str(uuid.uuid4())
    try:
        uuid.UUID(resolved_id)
    except ValueError as error:
        raise WorkflowFailure(
            "booking.request_id_invalid", "request_id must be a UUID"
        ) from error
    return await COORDINATOR.submit(
        resolved_id,
        {
            "raw_request": raw_request,
            "restaurant": restaurant,
            "start": start,
            "party_size": party_size,
            "customer_name": customer_name,
            "customer_email": customer_email,
            "customer_phone": customer_phone,
            "customer_time_zone": customer_time_zone,
        },
    )


@SERVER.tool()
async def restaurant_booking_status(request_id: str) -> dict[str, Any]:
    """Long-poll the redacted public state of one restaurant reservation."""
    try:
        uuid.UUID(request_id)
    except ValueError as error:
        raise WorkflowFailure(
            "booking.request_id_invalid", "request_id must be a UUID"
        ) from error
    return await COORDINATOR.status(request_id)


APP = SERVER.streamable_http_app()
MCP_LIFESPAN = APP.router.lifespan_context


@asynccontextmanager
async def application_lifespan(app: Any) -> AsyncIterator[None]:
    """Open durable dependencies before publishing application readiness."""
    await STORE.open()
    await COORDINATOR.recover()
    try:
        async with MCP_LIFESPAN(app):
            yield
    finally:
        await COORDINATOR.close()
        await VERIFIER.close()
        await STORE.close()


APP.router.lifespan_context = application_lifespan


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(APP, host=CONFIG.listen_host, port=CONFIG.listen_port)
