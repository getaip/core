"""FastAPI execution boundary for real CrewAI crews."""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import stat
import tempfile
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from .registry import CrewFactory, RegistryError, load_registry


LOGGER = logging.getLogger("aip_crewai_sidecar")
DEFAULT_TIMEOUT_MS = 600_000
MAX_TIMEOUT_MS = 3_600_000
MAX_INPUT_BYTES = 1_048_576
MAX_OUTPUT_BYTES = 4_194_304
DEFAULT_MAX_RETAINED_RUNS = 2_000
DEFAULT_MAX_EVENTS_PER_RUN = 1_000
DEFAULT_MAX_EVENT_BYTES = 262_144
DEFAULT_MAX_STATE_BYTES = 268_435_456
DEFAULT_STREAM_CHECKPOINT_EVENTS = 128
MAX_STREAM_CHECKPOINT_EVENTS = 10_000
MAX_BEARER_TOKEN_BYTES = 16_384


class RunStatus(str, Enum):
    """Terminal and non-terminal sidecar run states."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CrewOperation(str, Enum):
    """Frozen CrewAI operation names shared with the Rust connector."""

    RUN = "run"
    STATUS = "status"
    EVENTS = "events"
    CANCEL = "cancel"
    BATCH_RUN = "batch_run"
    REPLAY = "replay"
    TRAIN = "train"
    TEST = "test"
    KNOWLEDGE_QUERY = "knowledge_query"
    MEMORY_RESET = "memory_reset"


CONTROL_OPERATIONS = frozenset(
    {CrewOperation.STATUS, CrewOperation.EVENTS, CrewOperation.CANCEL}
)
STARTABLE_OPERATIONS = frozenset(CrewOperation) - CONTROL_OPERATIONS
DEFAULT_ALLOWED_OPERATIONS = frozenset({CrewOperation.RUN})
CANCELLABLE_OPERATIONS = frozenset({CrewOperation.RUN, CrewOperation.BATCH_RUN})
READ_ONLY_STARTABLE_OPERATIONS = frozenset({CrewOperation.KNOWLEDGE_QUERY})


class CrewRunRequest(BaseModel):
    """AIP-owned CrewAI invocation request."""

    model_config = ConfigDict(extra="forbid")

    crew_id: str = Field(min_length=1, max_length=256)
    action_id: str = Field(min_length=1, max_length=256)
    operation: CrewOperation = CrewOperation.RUN
    input: dict[str, Any] = Field(default_factory=dict)
    timeout_ms: int | None = Field(default=None, ge=1, le=MAX_TIMEOUT_MS)


class CrewCancelRequest(BaseModel):
    """AIP-owned cancellation request."""

    model_config = ConfigDict(extra="forbid")

    crew_id: str = Field(min_length=1, max_length=256)
    action_id: str = Field(min_length=1, max_length=256)
    reason: str | None = Field(default=None, max_length=2_048)


@dataclass(slots=True)
class RunRecord:
    """Process-local execution record and replay buffer."""

    action_id: str
    crew_id: str
    operation: CrewOperation
    input_hash: str
    status: RunStatus = RunStatus.RUNNING
    events: list[dict[str, Any]] = field(default_factory=list)
    output: dict[str, Any] | None = None
    task: asyncio.Task[None] | None = None
    streaming_output: Any = None
    condition: asyncio.Condition = field(default_factory=asyncio.Condition)
    persisted_event_count: int = 0

    async def append(self, event: str, data: Mapping[str, Any]) -> None:
        """Append one monotonically ordered event and wake subscribers."""

        async with self.condition:
            self.events.append(
                {
                    "event": event,
                    "sequence": len(self.events),
                    "data": dict(data),
                }
            )
            self.condition.notify_all()

    def snapshot(self) -> dict[str, Any]:
        """Return credential-free coordinator state plus governed run data."""

        return {
            "action_id": self.action_id,
            "crew_id": self.crew_id,
            "operation": self.operation,
            "input_hash": self.input_hash,
            "status": self.status,
            "events": self.events,
            "output": self.output,
        }

    @classmethod
    def restore(cls, value: Mapping[str, Any]) -> RunRecord:
        """Restore a journal entry and fence interrupted execution."""

        events = list(value.get("events", []))
        record = cls(
            action_id=str(value["action_id"]),
            crew_id=str(value["crew_id"]),
            operation=CrewOperation(
                str(value.get("operation", CrewOperation.RUN.value))
            ),
            input_hash=str(value["input_hash"]),
            status=RunStatus(str(value["status"])),
            events=events,
            output=value.get("output"),
            persisted_event_count=len(events),
        )
        if record.status is RunStatus.RUNNING:
            record.status = RunStatus.FAILED
            record.events.append(
                {
                    "event": "failed",
                    "sequence": len(record.events),
                    "data": {
                        "status": RunStatus.FAILED,
                        "uncertain_outcome": True,
                        "message": "sidecar restarted before CrewAI produced a terminal result",
                    },
                }
            )
        return record


class SidecarRuntime:
    """Bounded CrewAI execution and idempotency coordinator."""

    def __init__(
        self,
        registry: Mapping[str, CrewFactory],
        *,
        max_concurrency: int,
        state_path: Path | None = None,
        max_retained_runs: int = DEFAULT_MAX_RETAINED_RUNS,
        max_events_per_run: int = DEFAULT_MAX_EVENTS_PER_RUN,
        max_event_bytes: int = DEFAULT_MAX_EVENT_BYTES,
        max_state_bytes: int = DEFAULT_MAX_STATE_BYTES,
        stream_checkpoint_events: int = DEFAULT_STREAM_CHECKPOINT_EVENTS,
        allowed_operations: frozenset[CrewOperation] = DEFAULT_ALLOWED_OPERATIONS,
        training_directory: Path | None = None,
    ) -> None:
        if max_concurrency < 1 or max_concurrency > 1_024:
            raise RegistryError("max concurrency must be between 1 and 1024")
        if max_retained_runs < max_concurrency or max_retained_runs > 100_000:
            raise RegistryError(
                "max retained runs must be between max concurrency and 100000"
            )
        if max_events_per_run < 2 or max_events_per_run > 100_000:
            raise RegistryError("max events per run must be between 2 and 100000")
        if max_event_bytes < 1_024 or max_event_bytes > 4_194_304:
            raise RegistryError("max event bytes must be between 1024 and 4194304")
        if max_state_bytes < 1_048_576 or max_state_bytes > 4_294_967_296:
            raise RegistryError(
                "max state bytes must be between 1048576 and 4294967296"
            )
        if (
            stream_checkpoint_events < 1
            or stream_checkpoint_events > MAX_STREAM_CHECKPOINT_EVENTS
        ):
            raise RegistryError("stream checkpoint events must be between 1 and 10000")
        if not allowed_operations or not allowed_operations <= STARTABLE_OPERATIONS:
            raise RegistryError(
                "allowed operations must be a non-empty startable subset"
            )
        self.registry = dict(registry)
        self.state_path = state_path
        self.max_retained_runs = max_retained_runs
        self.max_events_per_run = max_events_per_run
        self.max_event_bytes = max_event_bytes
        self.max_state_bytes = max_state_bytes
        self.stream_checkpoint_events = stream_checkpoint_events
        self.allowed_operations = allowed_operations
        self.training_directory = training_directory
        if CrewOperation.TRAIN in allowed_operations:
            self.training_directory = _prepare_training_directory(training_directory)
        self._state_lock_fd: int | None = None
        try:
            self._state_lock_fd = self._acquire_state_lock()
            self.runs = self._restore_runs()
        except Exception:
            self._release_state_lock()
            raise
        self._runs_lock = asyncio.Lock()
        self._state_lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(max_concurrency)

    def _acquire_state_lock(self) -> int | None:
        """Fence a durable journal to one active sidecar process."""

        if self.state_path is None:
            return None
        self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = self.state_path.parent.lstat()
        if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
            raise RegistryError("CrewAI state parent must be a non-symlink directory")
        if parent.st_mode & 0o022:
            raise RegistryError(
                "CrewAI state parent must not be group- or world-writable"
            )
        lock_path = self.state_path.with_suffix(self.state_path.suffix + ".lock")
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(lock_path, flags, 0o600)
        try:
            lock_stat = os.fstat(descriptor)
            if not stat.S_ISREG(lock_stat.st_mode):
                raise RegistryError("CrewAI state lock must be a regular file")
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(descriptor)
            raise RegistryError(
                "CrewAI state journal is already owned by another active sidecar"
            ) from error
        except Exception:
            os.close(descriptor)
            raise
        return descriptor

    def _release_state_lock(self) -> None:
        """Release the journal fence without awaiting application state."""

        if self._state_lock_fd is not None:
            with suppress(OSError):
                fcntl.flock(self._state_lock_fd, fcntl.LOCK_UN)
            with suppress(OSError):
                os.close(self._state_lock_fd)
            self._state_lock_fd = None

    async def close(self) -> None:
        """Persist state and release the single-active-replica fence."""

        try:
            await self._persist()
        finally:
            self._release_state_lock()

    async def start(
        self, request: CrewRunRequest, idempotency_key: str | None
    ) -> RunRecord:
        """Start once or return the byte-identical idempotent action record."""

        if request.operation not in self.allowed_operations:
            raise HTTPException(
                status_code=403, detail="CrewAI operation is not enabled"
            )
        if idempotency_key is None or not idempotency_key.strip():
            raise HTTPException(
                status_code=428, detail="Idempotency-Key is required for CrewAI jobs"
            )
        if len(idempotency_key.encode()) > 512 or any(
            ord(character) < 32 for character in idempotency_key
        ):
            raise HTTPException(status_code=400, detail="Idempotency-Key is invalid")
        _validate_operation_input(request)
        factory = self.registry.get(request.crew_id)
        if factory is None:
            raise HTTPException(status_code=404, detail="configured crew was not found")
        request_hash = _request_hash(request, idempotency_key)
        async with self._runs_lock:
            existing = self.runs.get(request.action_id)
            if existing is not None:
                if existing.input_hash != request_hash:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="action id was reused with different input",
                    )
                return existing
            if len(self.runs) >= self.max_retained_runs:
                raise HTTPException(
                    status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
                    detail=(
                        "CrewAI durable idempotency journal reached its retained-run "
                        "limit; archive only after the AIP replay-retention window"
                    ),
                )
            record = RunRecord(
                action_id=request.action_id,
                crew_id=request.crew_id,
                operation=request.operation,
                input_hash=request_hash,
            )
            self.runs[request.action_id] = record
            try:
                # Persist the idempotency fence before scheduling any provider
                # work. A crash can therefore produce an uncertain result, but
                # can never make the action id disappear after an external effect.
                await self._persist()
            except Exception as error:
                self.runs.pop(request.action_id, None)
                raise HTTPException(
                    status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
                    detail="CrewAI durable idempotency journal could not accept the run",
                ) from error
            record.task = asyncio.create_task(
                self._execute(record, request, factory),
                name=f"aip-crewai:{request.action_id}",
            )
            LOGGER.info(
                "CrewAI job admitted",
                extra={
                    "action_id": record.action_id,
                    "crew_id": record.crew_id,
                    "operation": record.operation,
                },
            )
            return record

    async def cancel(self, request: CrewCancelRequest) -> RunRecord:
        """Cancel a cooperatively cancellable CrewAI job.

        CrewAI exposes native async execution for ``run`` and ``batch_run`` in
        the pinned revision. Replay, training and evaluation are synchronous
        provider calls executed in worker threads; cancelling their asyncio
        waiter would not stop the provider work. Those operations therefore
        fail closed instead of publishing a false terminal cancellation.
        """

        record = self.runs.get(request.action_id)
        if record is None or record.crew_id != request.crew_id:
            raise HTTPException(status_code=404, detail="run was not found")
        if record.status is not RunStatus.RUNNING:
            return record
        if record.operation not in CANCELLABLE_OPERATIONS:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"CrewAI operation {record.operation.value} cannot be cancelled "
                    "after provider execution starts"
                ),
            )
        streaming_output = record.streaming_output
        if streaming_output is not None and hasattr(streaming_output, "aclose"):
            with suppress(Exception):
                await streaming_output.aclose()
        if record.task is not None:
            record.task.cancel()
            with suppress(asyncio.CancelledError):
                await record.task
        await self._persist()
        return record

    async def archive(self, action_id: str) -> None:
        """Remove one terminal record after explicit operator confirmation."""

        async with self._runs_lock:
            record = self.runs.get(action_id)
            if record is None:
                raise HTTPException(status_code=404, detail="run was not found")
            if record.status is RunStatus.RUNNING:
                raise HTTPException(
                    status_code=409, detail="running jobs cannot be archived"
                )
            removed = self.runs.pop(action_id)
            try:
                await self._persist()
            except Exception:
                self.runs[action_id] = removed
                raise
        LOGGER.info(
            "CrewAI job archived",
            extra={
                "action_id": record.action_id,
                "crew_id": record.crew_id,
                "operation": record.operation,
            },
        )

    async def _execute(
        self,
        record: RunRecord,
        request: CrewRunRequest,
        factory: CrewFactory,
    ) -> None:
        try:
            async with self._semaphore:
                crew = factory()
                if not hasattr(crew, "kickoff") and not hasattr(crew, "kickoff_async"):
                    raise RegistryError("registry factory did not return a CrewAI Crew")
                crew.tracing = os.environ.get(
                    "CREWAI_TRACING_ENABLED", "false"
                ).lower() in {"true", "1"}
                await self._append(
                    record,
                    "started",
                    {
                        "status": RunStatus.RUNNING,
                        "operation": request.operation,
                    },
                )
                LOGGER.info(
                    "CrewAI job started",
                    extra={
                        "action_id": record.action_id,
                        "crew_id": record.crew_id,
                        "operation": record.operation,
                    },
                )
                timeout_seconds = (request.timeout_ms or DEFAULT_TIMEOUT_MS) / 1_000
                await asyncio.wait_for(
                    self._execute_operation(record, request, crew),
                    timeout=timeout_seconds,
                )
        except asyncio.CancelledError:
            record.status = RunStatus.CANCELLED
            await self._append(
                record,
                "cancelled",
                {"status": RunStatus.CANCELLED},
                terminal=True,
            )
            LOGGER.info(
                "CrewAI job cancelled",
                extra={
                    "action_id": record.action_id,
                    "crew_id": record.crew_id,
                    "operation": record.operation,
                },
            )
            raise
        except TimeoutError as error:
            await self._record_failure(
                record,
                request,
                error,
                "CrewAI execution exceeded its bounded timeout; inspect sidecar logs by action id",
            )
        except Exception as error:  # noqa: BLE001 - provider boundary
            await self._record_failure(
                record,
                request,
                error,
                "CrewAI execution failed; inspect sidecar logs by action id",
            )
        finally:
            record.streaming_output = None

    async def _record_failure(
        self,
        record: RunRecord,
        request: CrewRunRequest,
        error: Exception,
        message: str,
    ) -> None:
        """Persist a terminal failure without claiming remote-effect certainty."""

        uncertain_outcome = request.operation not in READ_ONLY_STARTABLE_OPERATIONS
        record.status = RunStatus.FAILED
        # Provider exceptions can embed prompts, tool inputs, URLs, or
        # credentials in their string representation and traceback. Persist
        # only the exception class and correlate detailed provider logs by the
        # AIP action id instead of copying exception material into this log.
        LOGGER.error(
            "CrewAI job failed",
            extra={
                "action_id": record.action_id,
                "crew_id": record.crew_id,
                "operation": record.operation,
                "uncertain_outcome": uncertain_outcome,
                "error_type": type(error).__name__,
            },
        )
        await self._append(
            record,
            "failed",
            {
                "status": RunStatus.FAILED,
                "error_type": type(error).__name__,
                "message": message,
                "uncertain_outcome": uncertain_outcome,
            },
            terminal=True,
        )

    async def _execute_operation(
        self, record: RunRecord, request: CrewRunRequest, crew: Any
    ) -> None:
        operation = request.operation
        if operation is CrewOperation.RUN:
            output = await self._consume_run(record, request, crew)
        elif operation is CrewOperation.BATCH_RUN:
            crew.stream = False
            inputs = request.input["inputs"]
            if not hasattr(crew, "akickoff_for_each"):
                raise RegistryError(
                    "pinned CrewAI revision does not expose native async batch execution"
                )
            values = await crew.akickoff_for_each(inputs=inputs)
            output = {
                "results": [_serialize_output(value) for value in values],
                "count": len(values),
            }
        elif operation is CrewOperation.REPLAY:
            crew.stream = False
            output = _serialize_output(
                await asyncio.to_thread(
                    crew.replay,
                    request.input["task_id"],
                    request.input.get("inputs"),
                )
            )
        elif operation is CrewOperation.TRAIN:
            crew.stream = False
            assert self.training_directory is not None
            artifact = self.training_directory / request.input["artifact_name"]
            await asyncio.to_thread(
                crew.train,
                request.input["n_iterations"],
                str(artifact),
                request.input.get("inputs"),
            )
            output = {
                "status": "completed",
                "artifact_name": artifact.name,
                "n_iterations": request.input["n_iterations"],
            }
        elif operation is CrewOperation.TEST:
            crew.stream = False
            await asyncio.to_thread(
                crew.test,
                request.input["n_iterations"],
                request.input["eval_llm"],
                request.input.get("inputs"),
            )
            output = {
                "status": "completed",
                "n_iterations": request.input["n_iterations"],
                "eval_llm": request.input["eval_llm"],
            }
        elif operation is CrewOperation.KNOWLEDGE_QUERY:
            if hasattr(crew, "aquery_knowledge"):
                results = await crew.aquery_knowledge(
                    request.input["query"],
                    results_limit=request.input.get("results_limit", 3),
                    score_threshold=request.input.get("score_threshold", 0.35),
                )
            else:
                results = await asyncio.to_thread(
                    crew.query_knowledge,
                    request.input["query"],
                    request.input.get("results_limit", 3),
                    request.input.get("score_threshold", 0.35),
                )
            output = {"results": _serialize_json_value(results or [])}
        elif operation is CrewOperation.MEMORY_RESET:
            await asyncio.to_thread(crew.reset_memories, request.input["command_type"])
            output = {
                "status": "completed",
                "command_type": request.input["command_type"],
            }
        else:
            raise RegistryError("control operations cannot start CrewAI jobs")
        _validate_json_size(output, MAX_OUTPUT_BYTES, "CrewAI output")
        record.output = output
        record.status = RunStatus.COMPLETED
        try:
            await self._append(record, "completed", output, terminal=True)
        except Exception:
            record.output = None
            raise
        LOGGER.info(
            "CrewAI job completed",
            extra={
                "action_id": record.action_id,
                "crew_id": record.crew_id,
                "operation": record.operation,
            },
        )

    async def _consume_run(
        self, record: RunRecord, request: CrewRunRequest, crew: Any
    ) -> dict[str, Any]:
        crew.stream = True
        if hasattr(crew, "akickoff"):
            streaming_output = await crew.akickoff(inputs=request.input)
        else:
            streaming_output = await crew.kickoff_async(inputs=request.input)
        record.streaming_output = streaming_output
        if hasattr(streaming_output, "__aiter__"):
            async for chunk in streaming_output:
                await self._append(
                    record,
                    "chunk",
                    _serialize_chunk(chunk),
                    stream_chunk=True,
                )
            output = streaming_output.result
        else:
            output = streaming_output
        return _serialize_output(output)

    async def _append(
        self,
        record: RunRecord,
        event: str,
        data: Mapping[str, Any],
        *,
        terminal: bool = False,
        stream_chunk: bool = False,
    ) -> None:
        _validate_json_size(data, self.max_event_bytes, "CrewAI stream event")
        event_limit = (
            self.max_events_per_run if terminal else self.max_events_per_run - 1
        )
        if len(record.events) >= event_limit:
            raise RegistryError(
                "CrewAI run reached its bounded event journal before completion"
            )
        await record.append(event, data)
        if (
            stream_chunk
            and len(record.events) - record.persisted_event_count
            < self.stream_checkpoint_events
        ):
            return
        try:
            await self._persist()
        except Exception:
            async with record.condition:
                if record.events and record.events[-1]["event"] == event:
                    record.events.pop()
                    record.condition.notify_all()
            raise

    def _restore_runs(self) -> dict[str, RunRecord]:
        if self.state_path is None or not self.state_path.exists():
            return {}
        try:
            state_lstat = self.state_path.lstat()
            if stat.S_ISLNK(state_lstat.st_mode) or not stat.S_ISREG(
                state_lstat.st_mode
            ):
                raise RegistryError("CrewAI state journal must be a regular file")
            if state_lstat.st_mode & 0o077:
                raise RegistryError("CrewAI state journal must have mode 0600")
            if state_lstat.st_size > self.max_state_bytes:
                raise RegistryError("CrewAI state journal exceeds its configured bound")
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self.state_path, flags)
            try:
                opened = os.fstat(descriptor)
                if (opened.st_dev, opened.st_ino) != (
                    state_lstat.st_dev,
                    state_lstat.st_ino,
                ):
                    raise RegistryError("CrewAI state journal changed while opening")
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    encoded = stream.read(self.max_state_bytes + 1)
            finally:
                os.close(descriptor)
            if len(encoded) > self.max_state_bytes:
                raise RegistryError("CrewAI state journal exceeds its configured bound")
            values = json.loads(encoded.decode("utf-8"))
            if not isinstance(values, list) or len(values) > self.max_retained_runs:
                raise RegistryError("CrewAI state journal contains too many runs")
            records = [RunRecord.restore(value) for value in values]
            if len({record.action_id for record in records}) != len(records):
                raise RegistryError(
                    "CrewAI state journal contains duplicate action ids"
                )
            for record in records:
                if len(record.events) > self.max_events_per_run:
                    raise RegistryError(
                        "CrewAI state journal contains too many run events"
                    )
                for event in record.events:
                    _validate_json_size(
                        event, self.max_event_bytes, "CrewAI restored stream event"
                    )
        except (OSError, UnicodeError, ValueError, KeyError, TypeError) as error:
            raise RegistryError(
                f"cannot restore CrewAI sidecar state: {error}"
            ) from error
        return {record.action_id: record for record in records}

    async def _persist(self) -> None:
        if self.state_path is None:
            return
        async with self._state_lock:
            snapshots = [record.snapshot() for record in self.runs.values()]
            persisted_event_counts = {
                record.action_id: len(record.events) for record in self.runs.values()
            }
            encoded = json.dumps(snapshots, separators=(",", ":"), sort_keys=True)
            if len(encoded.encode("utf-8")) > self.max_state_bytes:
                raise RegistryError(
                    "CrewAI state journal reached its configured byte bound"
                )
            path = self.state_path

            def replace() -> None:
                path.parent.mkdir(parents=True, exist_ok=True)
                descriptor, temporary_name = tempfile.mkstemp(
                    prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
                )
                try:
                    os.fchmod(descriptor, 0o600)
                    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                        descriptor = -1
                        stream.write(encoded)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temporary_name, path)
                    os.chmod(path, 0o600, follow_symlinks=False)
                    directory = os.open(path.parent, os.O_RDONLY)
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
                    with suppress(FileNotFoundError):
                        os.unlink(temporary_name)

            await asyncio.to_thread(replace)
            for action_id, event_count in persisted_event_counts.items():
                record = self.runs.get(action_id)
                if record is not None:
                    record.persisted_event_count = max(
                        record.persisted_event_count, event_count
                    )


def create_app(
    registry: Mapping[str, CrewFactory] | None = None,
    *,
    bearer_token: str | None = None,
    max_concurrency: int | None = None,
    allowed_operations: frozenset[CrewOperation] | None = None,
) -> FastAPI:
    """Create a sidecar app from an explicit registry or environment config."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
        os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
        os.environ.setdefault("OTEL_SDK_DISABLED", "true")
        resolved = registry
        if resolved is None:
            reference = os.environ.get("AIP_CREWAI_REGISTRY", "")
            if not reference:
                raise RegistryError("AIP_CREWAI_REGISTRY is required")
            resolved = load_registry(reference)
        concurrency = max_concurrency or int(
            os.environ.get("AIP_CREWAI_MAX_CONCURRENCY", "4")
        )
        if concurrency < 1 or concurrency > 1_024:
            raise RegistryError("AIP_CREWAI_MAX_CONCURRENCY must be between 1 and 1024")
        state_file = os.environ.get("AIP_CREWAI_STATE_FILE")
        if not state_file and not _explicit_ephemeral_loopback():
            raise RegistryError(
                "AIP_CREWAI_STATE_FILE is required outside explicit loopback development"
            )
        operations = allowed_operations or _configured_allowed_operations()
        training_directory_value = os.environ.get("AIP_CREWAI_TRAINING_DIR")
        app.state.runtime = SidecarRuntime(
            resolved,
            max_concurrency=concurrency,
            state_path=Path(state_file) if state_file else None,
            max_retained_runs=int(
                os.environ.get(
                    "AIP_CREWAI_MAX_RETAINED_RUNS", str(DEFAULT_MAX_RETAINED_RUNS)
                )
            ),
            max_events_per_run=int(
                os.environ.get(
                    "AIP_CREWAI_MAX_EVENTS_PER_RUN", str(DEFAULT_MAX_EVENTS_PER_RUN)
                )
            ),
            max_event_bytes=int(
                os.environ.get(
                    "AIP_CREWAI_MAX_EVENT_BYTES", str(DEFAULT_MAX_EVENT_BYTES)
                )
            ),
            max_state_bytes=int(
                os.environ.get(
                    "AIP_CREWAI_MAX_STATE_BYTES", str(DEFAULT_MAX_STATE_BYTES)
                )
            ),
            stream_checkpoint_events=int(
                os.environ.get(
                    "AIP_CREWAI_STREAM_CHECKPOINT_EVENTS",
                    str(DEFAULT_STREAM_CHECKPOINT_EVENTS),
                )
            ),
            allowed_operations=operations,
            training_directory=(
                Path(training_directory_value) if training_directory_value else None
            ),
        )
        await app.state.runtime._persist()
        yield
        pending_tasks = []
        for record in app.state.runtime.runs.values():
            if record.task is not None and not record.task.done():
                record.task.cancel()
                pending_tasks.append(record.task)
        if pending_tasks:
            await asyncio.gather(*pending_tasks, return_exceptions=True)
        await app.state.runtime.close()

    app = FastAPI(title="AIP CrewAI Sidecar", version="1.0.0", lifespan=lifespan)
    configured_token = _configured_bearer_token(bearer_token)
    if configured_token is None and not _explicit_unauthenticated_loopback():
        raise RegistryError(
            "CrewAI sidecar bearer authentication is required outside explicit loopback development"
        )

    async def authorize(authorization: str | None = Header(default=None)) -> None:
        if configured_token is None:
            return
        expected = f"Bearer {configured_token}"
        if authorization is None or not hmac.compare_digest(authorization, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid sidecar credential",
                headers={"WWW-Authenticate": "Bearer"},
            )

    @app.get("/health", dependencies=[Depends(authorize)])
    async def health(request: Request) -> dict[str, Any]:
        runtime: SidecarRuntime = request.app.state.runtime
        return {
            "status": "ready",
            "crews": sorted(runtime.registry),
            "active_runs": sum(
                record.status is RunStatus.RUNNING for record in runtime.runs.values()
            ),
            "retained_runs": len(runtime.runs),
            "max_retained_runs": runtime.max_retained_runs,
            "durable_journal": runtime.state_path is not None,
            "stream_checkpoint_events": runtime.stream_checkpoint_events,
            "operations": sorted(
                operation.value
                for operation in runtime.allowed_operations | CONTROL_OPERATIONS
            ),
            "training_directory": runtime.training_directory is not None,
        }

    @app.post("/jobs", dependencies=[Depends(authorize)])
    @app.post("/runs", dependencies=[Depends(authorize)])
    async def run_blocking(
        request: Request,
        body: CrewRunRequest,
        idempotency_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _validate_input_size(body)
        if request.url.path == "/runs" and body.operation is not CrewOperation.RUN:
            raise HTTPException(
                status_code=400, detail="legacy run route only accepts run"
            )
        runtime: SidecarRuntime = request.app.state.runtime
        record = await runtime.start(body, idempotency_key)
        timeout_seconds = (body.timeout_ms or DEFAULT_TIMEOUT_MS) / 1_000
        if record.task is not None and not record.task.done():
            try:
                await asyncio.wait_for(asyncio.shield(record.task), timeout_seconds)
            except TimeoutError as error:
                raise HTTPException(
                    status_code=504, detail="CrewAI run timed out"
                ) from error
        return _terminal_response(record)

    @app.post("/jobs/stream", dependencies=[Depends(authorize)])
    @app.post("/runs/stream", dependencies=[Depends(authorize)])
    async def run_stream(
        request: Request,
        body: CrewRunRequest,
        idempotency_key: str | None = Header(default=None),
    ) -> StreamingResponse:
        _validate_input_size(body)
        if (
            request.url.path == "/runs/stream"
            and body.operation is not CrewOperation.RUN
        ):
            raise HTTPException(
                status_code=400, detail="legacy run route only accepts run"
            )
        runtime: SidecarRuntime = request.app.state.runtime
        record = await runtime.start(body, idempotency_key)
        return StreamingResponse(
            _event_stream(record),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/jobs/{action_id}", dependencies=[Depends(authorize)])
    @app.get("/runs/{action_id}", dependencies=[Depends(authorize)])
    async def run_status(request: Request, action_id: str) -> dict[str, Any]:
        runtime: SidecarRuntime = request.app.state.runtime
        record = runtime.runs.get(action_id)
        if record is None:
            raise HTTPException(status_code=404, detail="run was not found")
        return _record_view(record)

    @app.get("/jobs/{action_id}/events", dependencies=[Depends(authorize)])
    async def run_events(
        request: Request,
        action_id: str,
        cursor: int = 0,
        accept: str | None = Header(default=None),
    ) -> Any:
        runtime: SidecarRuntime = request.app.state.runtime
        record = runtime.runs.get(action_id)
        if record is None:
            raise HTTPException(status_code=404, detail="run was not found")
        if cursor < 0 or cursor > len(record.events):
            raise HTTPException(
                status_code=416, detail="event cursor is outside the journal"
            )
        if accept is not None and "text/event-stream" in accept.lower():
            return StreamingResponse(
                _event_stream(record, cursor),
                media_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
            )
        return {
            "action_id": action_id,
            "cursor": cursor,
            "next_cursor": len(record.events),
            "status": record.status,
            "events": record.events[cursor:],
        }

    @app.post("/jobs/{action_id}/cancel", dependencies=[Depends(authorize)])
    @app.post("/runs/{action_id}/cancel", dependencies=[Depends(authorize)])
    async def cancel_run(
        request: Request,
        action_id: str,
        body: CrewCancelRequest,
    ) -> dict[str, Any]:
        if action_id != body.action_id:
            raise HTTPException(
                status_code=400, detail="path and payload action ids differ"
            )
        runtime: SidecarRuntime = request.app.state.runtime
        return _record_view(await runtime.cancel(body))

    @app.delete("/jobs/{action_id}", dependencies=[Depends(authorize)])
    async def archive_run(
        request: Request,
        action_id: str,
        archive_confirmation: str | None = Header(
            default=None, alias="X-AIP-Archive-Confirmation"
        ),
    ) -> dict[str, Any]:
        if archive_confirmation != action_id:
            raise HTTPException(
                status_code=428, detail="archive confirmation is required"
            )
        runtime: SidecarRuntime = request.app.state.runtime
        await runtime.archive(action_id)
        return {"archived": True, "action_id": action_id}

    return app


async def _event_stream(record: RunRecord, cursor: int = 0) -> AsyncIterator[str]:
    while True:
        async with record.condition:
            await record.condition.wait_for(
                lambda: cursor < len(record.events)
                or record.status is not RunStatus.RUNNING
            )
            available = record.events[cursor:]
        for event in available:
            cursor += 1
            yield f"event: {event['event']}\ndata: {json.dumps(event, separators=(',', ':'))}\n\n"
        if record.status is not RunStatus.RUNNING and cursor >= len(record.events):
            return


def _request_hash(request: CrewRunRequest, idempotency_key: str | None) -> str:
    payload = {
        "crew_id": request.crew_id,
        "action_id": request.action_id,
        "operation": request.operation,
        "input": request.input,
        "timeout_ms": request.timeout_ms,
        "idempotency_key": idempotency_key,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _validate_input_size(request: CrewRunRequest) -> None:
    try:
        _validate_json_size(request.input, MAX_INPUT_BYTES, "CrewAI input")
    except RegistryError as error:
        raise HTTPException(status_code=413, detail=str(error)) from error


def _validate_operation_input(request: CrewRunRequest) -> None:
    """Validate the complete, operation-specific provider call contract."""

    value = request.input
    operation = request.operation
    if operation is CrewOperation.RUN:
        return
    if operation is CrewOperation.BATCH_RUN:
        _require_exact_fields(value, {"inputs"}, {"inputs"})
        inputs = value["inputs"]
        if (
            not isinstance(inputs, list)
            or not 1 <= len(inputs) <= 100
            or any(not isinstance(item, dict) for item in inputs)
        ):
            _invalid_operation_input("inputs must contain 1 to 100 objects")
        return
    if operation is CrewOperation.REPLAY:
        _require_exact_fields(value, {"task_id"}, {"task_id", "inputs"})
        _bounded_string(value["task_id"], "task_id", 256)
        if "inputs" in value and not isinstance(value["inputs"], dict):
            _invalid_operation_input("inputs must be an object")
        return
    if operation is CrewOperation.TRAIN:
        _require_exact_fields(
            value,
            {"n_iterations", "artifact_name"},
            {"n_iterations", "artifact_name", "inputs"},
        )
        _bounded_iterations(value["n_iterations"])
        artifact_name = value["artifact_name"]
        if not isinstance(artifact_name, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", artifact_name
        ):
            _invalid_operation_input("artifact_name must be a safe basename")
        if "inputs" in value and not isinstance(value["inputs"], dict):
            _invalid_operation_input("inputs must be an object")
        return
    if operation is CrewOperation.TEST:
        _require_exact_fields(
            value,
            {"n_iterations", "eval_llm"},
            {"n_iterations", "eval_llm", "inputs"},
        )
        _bounded_iterations(value["n_iterations"])
        _bounded_string(value["eval_llm"], "eval_llm", 256)
        if "inputs" in value and not isinstance(value["inputs"], dict):
            _invalid_operation_input("inputs must be an object")
        return
    if operation is CrewOperation.KNOWLEDGE_QUERY:
        _require_exact_fields(
            value,
            {"query"},
            {"query", "results_limit", "score_threshold"},
        )
        query = value["query"]
        if (
            not isinstance(query, list)
            or not 1 <= len(query) <= 100
            or any(
                not isinstance(item, str)
                or not item
                or len(item.encode()) > 4_096
                or any(ord(character) < 32 for character in item)
                for item in query
            )
        ):
            _invalid_operation_input("query must contain 1 to 100 bounded strings")
        results_limit = value.get("results_limit", 3)
        if (
            not isinstance(results_limit, int)
            or isinstance(results_limit, bool)
            or not 1 <= results_limit <= 100
        ):
            _invalid_operation_input("results_limit must be between 1 and 100")
        score_threshold = value.get("score_threshold", 0.35)
        if (
            not isinstance(score_threshold, (int, float))
            or isinstance(score_threshold, bool)
            or not 0 <= score_threshold <= 1
        ):
            _invalid_operation_input("score_threshold must be between 0 and 1")
        return
    if operation is CrewOperation.MEMORY_RESET:
        _require_exact_fields(value, {"command_type"}, {"command_type"})
        if value["command_type"] not in {
            "memory",
            "knowledge",
            "agent_knowledge",
            "kickoff_outputs",
            "all",
        }:
            _invalid_operation_input("command_type is not supported")
        return
    _invalid_operation_input("control operations cannot start a job")


def _require_exact_fields(
    value: dict[str, Any], required: set[str], allowed: set[str]
) -> None:
    missing = required - value.keys()
    unknown = value.keys() - allowed
    if missing:
        _invalid_operation_input(f"missing fields: {', '.join(sorted(missing))}")
    if unknown:
        _invalid_operation_input(f"unknown fields: {', '.join(sorted(unknown))}")


def _bounded_iterations(value: Any) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 100:
        _invalid_operation_input("n_iterations must be between 1 and 100")


def _bounded_string(value: Any, name: str, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode()) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        _invalid_operation_input(f"{name} must be a bounded non-control string")


def _invalid_operation_input(message: str) -> None:
    raise HTTPException(status_code=422, detail=message)


def _validate_json_size(value: Any, maximum: int, label: str) -> None:
    """Reject non-JSON or oversized values before they enter durable state."""

    try:
        encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    except (TypeError, ValueError) as error:
        raise RegistryError(f"{label} is not JSON serializable") from error
    if len(encoded) > maximum:
        raise RegistryError(f"{label} exceeds its {maximum}-byte bound")


def _configured_allowed_operations() -> frozenset[CrewOperation]:
    raw = os.environ.get("AIP_CREWAI_ALLOWED_OPERATIONS", CrewOperation.RUN.value)
    names = [name.strip() for name in raw.split(",") if name.strip()]
    try:
        operations = frozenset(CrewOperation(name) for name in names)
    except ValueError as error:
        raise RegistryError(
            "AIP_CREWAI_ALLOWED_OPERATIONS contains an unknown operation"
        ) from error
    if not operations or not operations <= STARTABLE_OPERATIONS:
        raise RegistryError(
            "AIP_CREWAI_ALLOWED_OPERATIONS must contain startable job operations"
        )
    return operations


def _prepare_training_directory(path: Path | None) -> Path:
    if path is None:
        raise RegistryError("AIP_CREWAI_TRAINING_DIR is required when train is enabled")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RegistryError("CrewAI training path must be a non-symlink directory")
    if metadata.st_mode & 0o022:
        raise RegistryError(
            "CrewAI training directory must not be group- or world-writable"
        )
    return path


def _loopback_host() -> bool:
    host = os.environ.get("AIP_CREWAI_HOST", "0.0.0.0")
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _enabled(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true"}


def _explicit_ephemeral_loopback() -> bool:
    return _loopback_host() and _enabled("AIP_CREWAI_ALLOW_EPHEMERAL")


def _explicit_unauthenticated_loopback() -> bool:
    return _loopback_host() and _enabled("AIP_CREWAI_ALLOW_UNAUTHENTICATED")


def _configured_bearer_token(explicit: str | None) -> str | None:
    inline = (
        explicit if explicit is not None else os.environ.get("AIP_CREWAI_BEARER_TOKEN")
    )
    file_name = os.environ.get("AIP_CREWAI_BEARER_TOKEN_FILE")
    if inline and file_name:
        raise RegistryError(
            "AIP_CREWAI_BEARER_TOKEN and AIP_CREWAI_BEARER_TOKEN_FILE are mutually exclusive"
        )
    if inline is not None:
        token = inline.strip()
        if not token or len(token.encode()) > MAX_BEARER_TOKEN_BYTES:
            raise RegistryError("CrewAI sidecar bearer token has an invalid length")
        return token
    if not file_name:
        return None
    path = Path(file_name)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RegistryError("CrewAI bearer-token path must be a regular file")
    if metadata.st_mode & 0o077:
        raise RegistryError("CrewAI bearer-token file must have mode 0600")
    if metadata.st_size < 1 or metadata.st_size > MAX_BEARER_TOKEN_BYTES:
        raise RegistryError("CrewAI bearer-token file has an invalid size")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise RegistryError("CrewAI bearer-token file changed while opening")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_BEARER_TOKEN_BYTES + 1)
    finally:
        os.close(descriptor)
    try:
        token = raw.decode("utf-8").strip()
    except UnicodeError as error:
        raise RegistryError("CrewAI bearer-token file must contain UTF-8") from error
    if not token or len(raw) > MAX_BEARER_TOKEN_BYTES:
        raise RegistryError("CrewAI bearer-token file has an invalid length")
    return token


def _serialize_chunk(chunk: Any) -> dict[str, Any]:
    if hasattr(chunk, "model_dump"):
        payload = chunk.model_dump(mode="json")
    elif isinstance(chunk, Mapping):
        payload = dict(chunk)
    else:
        payload = {"content": str(chunk)}
    content = getattr(chunk, "content", None)
    if isinstance(content, str) and "content" not in payload:
        payload["content"] = content
    return payload


def _serialize_output(output: Any) -> dict[str, Any]:
    if hasattr(output, "model_dump"):
        payload = output.model_dump(mode="json")
    elif isinstance(output, Mapping):
        payload = dict(output)
    else:
        payload = {"raw": str(output), "token_usage": {}}
    payload.setdefault("raw", str(output))
    payload.setdefault("token_usage", getattr(output, "usage_metrics", {}))
    payload.setdefault("tasks_output", [])
    return payload


def _serialize_json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return {str(key): _serialize_json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_serialize_json_value(item) for item in value]
    return str(value)


def _record_view(record: RunRecord) -> dict[str, Any]:
    return {
        "action_id": record.action_id,
        "crew_id": record.crew_id,
        "operation": record.operation,
        "status": record.status,
        "event_count": len(record.events),
        "output": record.output,
    }


def _terminal_response(record: RunRecord) -> dict[str, Any]:
    if record.status is RunStatus.COMPLETED and record.output is not None:
        return record.output
    if record.status is RunStatus.CANCELLED:
        raise HTTPException(status_code=409, detail="CrewAI run was cancelled")
    raise HTTPException(status_code=502, detail="CrewAI run failed")
