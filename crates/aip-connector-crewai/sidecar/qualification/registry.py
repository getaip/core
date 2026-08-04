"""Deterministic real-CrewAI registry used by connector qualification."""

from __future__ import annotations

from typing import Any

from crewai import Agent, Crew, Process, Task
from crewai.events.event_bus import crewai_event_bus
from crewai.events.types.llm_events import LLMStreamChunkEvent
from crewai.llms.base_llm import BaseLLM


class QualificationLLM(BaseLLM):
    """Network-free LLM that emits real CrewAI streaming events."""

    def call(self, messages: Any, *args: Any, **kwargs: Any) -> str:
        del messages, args, kwargs
        self._track_token_usage_internal(
            {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5}
        )
        for sequence, chunk in enumerate(("case ", "triaged")):
            crewai_event_bus.emit(
                self,
                LLMStreamChunkEvent(
                    type="llm_stream_chunk",
                    chunk=chunk,
                    call_id=f"qualification-{sequence}",
                ),
            )
        return "Final Answer: case triaged"

    def supports_function_calling(self) -> bool:
        return False

    def supports_stop_words(self) -> bool:
        return False

    def get_context_window_size(self) -> int:
        return 8_192


def support_crew() -> Crew:
    """Build an isolated real CrewAI crew for one sidecar run."""

    agent = Agent(
        role="Support triage specialist",
        goal="Classify case {case_id} using the supplied facts",
        backstory="A deterministic connector qualification agent.",
        llm=QualificationLLM(model="aip-qualification"),
        verbose=False,
    )
    task = Task(
        description="Triage support case {case_id}.",
        expected_output="A concise triage decision.",
        agent=agent,
    )
    return Crew(
        agents=[agent],
        tasks=[task],
        process=Process.sequential,
        stream=True,
        tracing=False,
        verbose=False,
    )


def crews():
    """Return the stable registry consumed by the sidecar loader."""

    return {"support-qualification": support_crew}
