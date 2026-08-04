"""Deterministic tests for CrewAI sidecar lifecycle semantics."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

import httpx
import pytest
from fastapi import HTTPException

from aip_crewai_sidecar.app import (
    CrewCancelRequest,
    CrewOperation,
    CrewRunRequest,
    RunStatus,
    SidecarRuntime,
    create_app,
)
from aip_crewai_sidecar.registry import RegistryError


@dataclass
class FakeChunk:
    content: str

    def model_dump(self, *, mode: str) -> dict[str, str]:
        assert mode == "json"
        return {"content": self.content, "channel": "llm"}


class FakeOutput:
    def model_dump(self, *, mode: str) -> dict[str, object]:
        assert mode == "json"
        return {
            "raw": "complete",
            "json_dict": None,
            "pydantic": None,
            "tasks_output": [],
            "token_usage": {"total_tokens": 2},
        }


class FakeStreamingOutput:
    def __init__(self, gate: asyncio.Event | None = None) -> None:
        self.result = FakeOutput()
        self.gate = gate
        self.closed = False

    def __aiter__(self):
        return self._chunks()

    async def _chunks(self):
        yield FakeChunk("hello")
        if self.gate is not None:
            await self.gate.wait()
        yield FakeChunk(" world")

    async def aclose(self) -> None:
        self.closed = True


class FakeCrew:
    def __init__(self, gate: asyncio.Event | None = None) -> None:
        self.stream = False
        self.gate = gate

    async def kickoff_async(self, *, inputs):
        assert inputs["case_id"] == "case-1"
        return FakeStreamingOutput(self.gate)


class FakeFullCrew(FakeCrew):
    async def akickoff(self, *, inputs):
        assert inputs["case_id"] == "case-1"
        return FakeStreamingOutput()

    async def akickoff_for_each(self, *, inputs):
        assert inputs == [{"case_id": "case-1"}, {"case_id": "case-2"}]
        return [FakeOutput(), FakeOutput()]

    def replay(self, task_id, inputs):
        assert task_id == "task-1"
        assert inputs == {"case_id": "case-1"}
        return FakeOutput()

    def train(self, n_iterations, filename, inputs):
        assert n_iterations == 2
        assert inputs == {"case_id": "case-1"}
        with open(filename, "w", encoding="utf-8") as stream:
            stream.write("trained")

    def test(self, n_iterations, eval_llm, inputs):
        assert n_iterations == 2
        assert eval_llm == "openrouter/test-model"
        assert inputs == {"case_id": "case-1"}

    async def aquery_knowledge(self, query, *, results_limit, score_threshold):
        assert query == ["contract policy"]
        assert results_limit == 5
        assert score_threshold == 0.4
        return [{"content": "policy", "score": 0.9}]

    def reset_memories(self, command_type):
        assert command_type == "kickoff_outputs"


@pytest.mark.asyncio
async def test_streaming_run_is_idempotent_and_ordered() -> None:
    runtime = SidecarRuntime({"support": FakeCrew}, max_concurrency=1)
    request = CrewRunRequest(
        crew_id="support",
        action_id="action-1",
        input={"case_id": "case-1"},
    )
    record = await runtime.start(request, "key-1")
    assert record.task is not None
    await record.task
    assert record.status is RunStatus.COMPLETED
    assert [event["sequence"] for event in record.events] == [0, 1, 2, 3]
    assert [event["event"] for event in record.events] == [
        "started",
        "chunk",
        "chunk",
        "completed",
    ]

    duplicate = await runtime.start(request, "key-1")
    assert duplicate is record
    with pytest.raises(HTTPException) as conflict:
        await runtime.start(
            request.model_copy(update={"input": {"case_id": "other"}}), "key-1"
        )
    assert conflict.value.status_code == 409


@pytest.mark.asyncio
async def test_stream_chunks_use_bounded_durable_checkpoints(tmp_path) -> None:
    state_path = tmp_path / "runs.json"
    runtime = SidecarRuntime(
        {"support": FakeCrew},
        max_concurrency=1,
        state_path=state_path,
        stream_checkpoint_events=2,
    )
    original_persist = runtime._persist
    persisted_event_counts: list[int] = []

    async def counted_persist() -> None:
        record = runtime.runs.get("action-checkpointed")
        persisted_event_counts.append(len(record.events) if record else 0)
        await original_persist()

    runtime._persist = counted_persist  # type: ignore[method-assign]
    request = CrewRunRequest(
        crew_id="support",
        action_id="action-checkpointed",
        input={"case_id": "case-1"},
    )
    record = await runtime.start(request, "key-checkpointed")
    assert record.task is not None
    await record.task

    # The admission fence and lifecycle transitions are immediately durable.
    # Token-sized chunks are checkpointed as a bounded group, then the complete
    # stream is atomically persisted with the terminal result.
    assert persisted_event_counts == [0, 1, 3, 4]
    assert record.persisted_event_count == 4
    restored = json.loads(state_path.read_text(encoding="utf-8"))
    assert [event["event"] for event in restored[0]["events"]] == [
        "started",
        "chunk",
        "chunk",
        "completed",
    ]
    await runtime.close()


@pytest.mark.asyncio
async def test_every_product_operation_uses_the_durable_job_boundary(tmp_path) -> None:
    operations = frozenset(
        {
            CrewOperation.RUN,
            CrewOperation.BATCH_RUN,
            CrewOperation.REPLAY,
            CrewOperation.TRAIN,
            CrewOperation.TEST,
            CrewOperation.KNOWLEDGE_QUERY,
            CrewOperation.MEMORY_RESET,
        }
    )
    training_directory = tmp_path / "training"
    runtime = SidecarRuntime(
        {"support": FakeFullCrew},
        max_concurrency=2,
        allowed_operations=operations,
        training_directory=training_directory,
    )
    inputs = {
        CrewOperation.RUN: {"case_id": "case-1"},
        CrewOperation.BATCH_RUN: {
            "inputs": [{"case_id": "case-1"}, {"case_id": "case-2"}]
        },
        CrewOperation.REPLAY: {
            "task_id": "task-1",
            "inputs": {"case_id": "case-1"},
        },
        CrewOperation.TRAIN: {
            "n_iterations": 2,
            "artifact_name": "support-training.json",
            "inputs": {"case_id": "case-1"},
        },
        CrewOperation.TEST: {
            "n_iterations": 2,
            "eval_llm": "openrouter/test-model",
            "inputs": {"case_id": "case-1"},
        },
        CrewOperation.KNOWLEDGE_QUERY: {
            "query": ["contract policy"],
            "results_limit": 5,
            "score_threshold": 0.4,
        },
        CrewOperation.MEMORY_RESET: {"command_type": "kickoff_outputs"},
    }
    for index, operation in enumerate(operations):
        request = CrewRunRequest(
            crew_id="support",
            action_id=f"operation-{index}",
            operation=operation,
            input=inputs[operation],
        )
        record = await runtime.start(request, f"operation-key-{index}")
        assert record.task is not None
        await record.task
        assert record.status is RunStatus.COMPLETED
        assert record.operation is operation
        assert record.events[0]["event"] == "started"
        assert record.events[-1]["event"] == "completed"
        assert record.output is not None
    assert (training_directory / "support-training.json").read_text(
        encoding="utf-8"
    ) == "trained"


@pytest.mark.asyncio
async def test_jobs_require_idempotency_before_provider_admission() -> None:
    provider_started = False

    def factory():
        nonlocal provider_started
        provider_started = True
        return FakeCrew()

    runtime = SidecarRuntime({"support": factory}, max_concurrency=1)
    request = CrewRunRequest(
        crew_id="support",
        action_id="missing-idempotency",
        input={"case_id": "case-1"},
    )
    with pytest.raises(HTTPException) as missing:
        await runtime.start(request, None)
    assert missing.value.status_code == 428
    assert not provider_started


@pytest.mark.asyncio
async def test_cancel_closes_streaming_output_and_records_terminal_event() -> None:
    gate = asyncio.Event()
    runtime = SidecarRuntime({"support": lambda: FakeCrew(gate)}, max_concurrency=1)
    request = CrewRunRequest(
        crew_id="support",
        action_id="action-2",
        input={"case_id": "case-1"},
    )
    record = await runtime.start(request, "key-2")
    for _ in range(100):
        if record.streaming_output is not None:
            break
        await asyncio.sleep(0.001)
    streaming_output = record.streaming_output
    assert streaming_output is not None
    cancelled = await runtime.cancel(
        CrewCancelRequest(
            crew_id="support",
            action_id="action-2",
            reason="operator request",
        )
    )
    assert cancelled.status is RunStatus.CANCELLED
    assert streaming_output.closed
    assert cancelled.events[-1]["event"] == "cancelled"


@pytest.mark.asyncio
async def test_cancel_rejects_synchronous_provider_operations() -> None:
    gate = asyncio.Event()

    class SlowReplayCrew(FakeFullCrew):
        def replay(self, task_id, inputs):
            del task_id, inputs
            gate.set()
            import time

            time.sleep(0.1)
            return FakeOutput()

    runtime = SidecarRuntime(
        {"support": SlowReplayCrew},
        max_concurrency=1,
        allowed_operations=frozenset({CrewOperation.REPLAY}),
    )
    request = CrewRunRequest(
        crew_id="support",
        action_id="action-replay-not-cancellable",
        operation=CrewOperation.REPLAY,
        input={"task_id": "task-1", "inputs": {"case_id": "case-1"}},
    )
    record = await runtime.start(request, "key-replay-not-cancellable")
    await gate.wait()
    with pytest.raises(HTTPException) as conflict:
        await runtime.cancel(
            CrewCancelRequest(
                crew_id="support",
                action_id=request.action_id,
                reason="operator request",
            )
        )
    assert conflict.value.status_code == 409
    assert record.status is RunStatus.RUNNING
    assert record.task is not None
    await record.task
    assert record.status is RunStatus.COMPLETED


@pytest.mark.asyncio
async def test_provider_failures_preserve_effect_uncertainty_by_operation() -> None:
    class FailingRunCrew(FakeFullCrew):
        async def akickoff(self, *, inputs):
            del inputs
            raise RuntimeError("provider failed after dispatch")

    mutation_runtime = SidecarRuntime(
        {"support": FailingRunCrew},
        max_concurrency=1,
        allowed_operations=frozenset({CrewOperation.RUN}),
    )
    mutation = await mutation_runtime.start(
        CrewRunRequest(
            crew_id="support",
            action_id="action-failed-mutation",
            operation=CrewOperation.RUN,
            input={"case_id": "case-1"},
        ),
        "key-failed-mutation",
    )
    assert mutation.task is not None
    await mutation.task
    assert mutation.status is RunStatus.FAILED
    assert mutation.events[-1]["data"]["uncertain_outcome"] is True

    class FailingKnowledgeCrew(FakeFullCrew):
        async def aquery_knowledge(self, query, *, results_limit, score_threshold):
            del query, results_limit, score_threshold
            raise RuntimeError("knowledge backend unavailable")

    read_runtime = SidecarRuntime(
        {"support": FailingKnowledgeCrew},
        max_concurrency=1,
        allowed_operations=frozenset({CrewOperation.KNOWLEDGE_QUERY}),
    )
    read = await read_runtime.start(
        CrewRunRequest(
            crew_id="support",
            action_id="action-failed-read",
            operation=CrewOperation.KNOWLEDGE_QUERY,
            input={"query": ["contract policy"]},
        ),
        "key-failed-read",
    )
    assert read.task is not None
    await read.task
    assert read.status is RunStatus.FAILED
    assert read.events[-1]["data"]["uncertain_outcome"] is False


@pytest.mark.asyncio
async def test_synchronous_provider_timeout_is_terminal_but_uncertain() -> None:
    class SlowReplayCrew(FakeFullCrew):
        def replay(self, task_id, inputs):
            del task_id, inputs
            import time

            time.sleep(0.05)
            return FakeOutput()

    runtime = SidecarRuntime(
        {"support": SlowReplayCrew},
        max_concurrency=1,
        allowed_operations=frozenset({CrewOperation.REPLAY}),
    )
    record = await runtime.start(
        CrewRunRequest(
            crew_id="support",
            action_id="action-replay-timeout",
            operation=CrewOperation.REPLAY,
            input={"task_id": "task-1", "inputs": {"case_id": "case-1"}},
            timeout_ms=1,
        ),
        "key-replay-timeout",
    )
    assert record.task is not None
    await record.task
    assert record.status is RunStatus.FAILED
    assert record.events[-1]["data"]["error_type"] == "TimeoutError"
    assert record.events[-1]["data"]["uncertain_outcome"] is True
    await asyncio.sleep(0.06)
    assert record.status is RunStatus.FAILED


@pytest.mark.asyncio
async def test_durable_journal_replays_terminal_and_fences_interrupted_run(
    tmp_path,
) -> None:
    state_path = tmp_path / "runs.json"
    runtime = SidecarRuntime(
        {"support": FakeCrew},
        max_concurrency=1,
        state_path=state_path,
    )
    request = CrewRunRequest(
        crew_id="support",
        action_id="action-3",
        input={"case_id": "case-1"},
    )
    completed = await runtime.start(request, "key-3")
    assert completed.task is not None
    await completed.task
    await runtime.close()
    assert state_path.stat().st_mode & 0o777 == 0o600

    restarted = SidecarRuntime(
        {"support": FakeCrew},
        max_concurrency=1,
        state_path=state_path,
    )
    replay = await restarted.start(request, "key-3")
    assert replay.status is RunStatus.COMPLETED
    assert replay.task is None
    assert replay.output is not None

    interrupted = replay.snapshot()
    await restarted.close()
    interrupted["action_id"] = "action-4"
    interrupted["status"] = RunStatus.RUNNING
    interrupted["input_hash"] = "interrupted-hash"
    state_path.write_text(json.dumps([interrupted]), encoding="utf-8")
    after_crash = SidecarRuntime(
        {"support": FakeCrew},
        max_concurrency=1,
        state_path=state_path,
    )
    assert after_crash.runs["action-4"].status is RunStatus.FAILED
    assert after_crash.runs["action-4"].events[-1]["data"]["uncertain_outcome"] is True
    await after_crash.close()


@pytest.mark.asyncio
async def test_durable_journal_rejects_a_second_active_process(tmp_path) -> None:
    state_path = tmp_path / "runs.json"
    runtime = SidecarRuntime(
        {"support": FakeCrew},
        max_concurrency=1,
        state_path=state_path,
    )
    with pytest.raises(RegistryError, match="already owned"):
        SidecarRuntime(
            {"support": FakeCrew},
            max_concurrency=1,
            state_path=state_path,
        )
    await runtime.close()


@pytest.mark.asyncio
async def test_run_fence_is_durable_before_provider_task_is_scheduled() -> None:
    provider_started = asyncio.Event()
    persist_started = asyncio.Event()
    allow_persist = asyncio.Event()

    def factory():
        provider_started.set()
        return FakeCrew()

    runtime = SidecarRuntime({"support": factory}, max_concurrency=1)

    async def delayed_persist() -> None:
        persist_started.set()
        await allow_persist.wait()

    runtime._persist = delayed_persist  # type: ignore[method-assign]
    request = CrewRunRequest(
        crew_id="support",
        action_id="action-fenced-before-effect",
        input={"case_id": "case-1"},
    )
    start_task = asyncio.create_task(runtime.start(request, "key-fenced"))
    await persist_started.wait()
    await asyncio.sleep(0)
    assert not provider_started.is_set()
    allow_persist.set()
    record = await start_task
    assert record.task is not None
    await record.task
    assert provider_started.is_set()


@pytest.mark.asyncio
async def test_retained_run_and_event_bounds_fail_closed() -> None:
    runtime = SidecarRuntime(
        {"support": FakeCrew},
        max_concurrency=1,
        max_retained_runs=1,
        max_events_per_run=2,
    )
    first = CrewRunRequest(
        crew_id="support",
        action_id="action-bounded-1",
        input={"case_id": "case-1"},
    )
    record = await runtime.start(first, "key-bounded-1")
    assert record.task is not None
    await record.task
    assert record.status is RunStatus.FAILED
    assert [event["event"] for event in record.events] == ["started", "failed"]

    with pytest.raises(HTTPException) as full:
        await runtime.start(
            first.model_copy(update={"action_id": "action-bounded-2"}),
            "key-bounded-2",
        )
    assert full.value.status_code == 507


@pytest.mark.asyncio
async def test_http_boundary_requires_authentication_and_durable_state(
    tmp_path, monkeypatch
) -> None:
    state_path = tmp_path / "runs.json"
    monkeypatch.setenv("AIP_CREWAI_HOST", "0.0.0.0")
    monkeypatch.setenv("AIP_CREWAI_STATE_FILE", str(state_path))
    app = create_app(
        {"support": FakeCrew},
        bearer_token="qualification-sidecar-token",
        max_concurrency=1,
    )

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://sidecar.test"
        ) as client:
            denied = await client.get("/health")
            assert denied.status_code == 401
            assert denied.headers["www-authenticate"] == "Bearer"

            authorized = {"Authorization": "Bearer qualification-sidecar-token"}
            health = await client.get("/health", headers=authorized)
            assert health.status_code == 200
            assert health.json() == {
                "status": "ready",
                "crews": ["support"],
                "active_runs": 0,
                "retained_runs": 0,
                "max_retained_runs": 2_000,
                "durable_journal": True,
                "stream_checkpoint_events": 128,
                "operations": ["cancel", "events", "run", "status"],
                "training_directory": False,
            }

            started = await client.post(
                "/runs",
                headers={**authorized, "Idempotency-Key": "http-key-1"},
                json={
                    "crew_id": "support",
                    "action_id": "action-http-1",
                    "input": {"case_id": "case-1"},
                },
            )
            assert started.status_code == 200
            assert started.json()["raw"] == "complete"

            status_response = await client.get(
                "/runs/action-http-1", headers=authorized
            )
            assert status_response.status_code == 200
            assert status_response.json()["status"] == "completed"
            assert status_response.json()["operation"] == "run"

            event_response = await client.get(
                "/jobs/action-http-1/events?cursor=1", headers=authorized
            )
            assert event_response.status_code == 200
            assert event_response.json()["cursor"] == 1
            assert event_response.json()["next_cursor"] == 4
            assert event_response.json()["events"][-1]["event"] == "completed"

            stream_response = await client.get(
                "/jobs/action-http-1/events?cursor=2",
                headers={**authorized, "Accept": "text/event-stream"},
            )
            assert stream_response.status_code == 200
            assert "event: completed" in stream_response.text

            replayed = await client.post(
                "/runs",
                headers={**authorized, "Idempotency-Key": "http-key-1"},
                json={
                    "crew_id": "support",
                    "action_id": "action-http-1",
                    "input": {"case_id": "case-1"},
                },
            )
            assert replayed.status_code == 200
            assert replayed.json() == started.json()

            denied_archive = await client.delete(
                "/jobs/action-http-1", headers=authorized
            )
            assert denied_archive.status_code == 428
            archived = await client.delete(
                "/jobs/action-http-1",
                headers={
                    **authorized,
                    "X-AIP-Archive-Confirmation": "action-http-1",
                },
            )
            assert archived.status_code == 200
            missing = await client.get("/jobs/action-http-1", headers=authorized)
            assert missing.status_code == 404

    assert state_path.is_file()
    assert state_path.stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
async def test_non_loopback_app_rejects_ephemeral_or_unauthenticated_startup(
    monkeypatch,
) -> None:
    monkeypatch.setenv("AIP_CREWAI_HOST", "0.0.0.0")
    monkeypatch.delenv("AIP_CREWAI_STATE_FILE", raising=False)
    monkeypatch.delenv("AIP_CREWAI_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("AIP_CREWAI_BEARER_TOKEN_FILE", raising=False)

    with pytest.raises(RegistryError, match="bearer authentication is required"):
        create_app({"support": FakeCrew}, max_concurrency=1)

    authenticated = create_app(
        {"support": FakeCrew},
        bearer_token="qualification-sidecar-token",
        max_concurrency=1,
    )
    with pytest.raises(RegistryError, match="STATE_FILE is required"):
        async with authenticated.router.lifespan_context(authenticated):
            pass
