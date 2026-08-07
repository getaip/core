"""Explicit CrewAI registry loading for the AIP sidecar."""

from __future__ import annotations

import importlib
import inspect
from collections.abc import Callable, Mapping
from typing import Any


CrewFactory = Callable[[], Any]


class RegistryError(RuntimeError):
    """Raised when the configured CrewAI registry is invalid."""


def load_registry(reference: str) -> dict[str, CrewFactory]:
    """Load `module:attribute` and normalize it to per-run crew factories.

    The referenced attribute must be a mapping or a zero-argument callable
    returning a mapping. Mapping values may be Crew instances or zero-argument
    factories. Instances are cloned for every run to prevent cross-request
    mutation of CrewAI state.
    """

    module_name, separator, attribute_name = reference.partition(":")
    if not separator or not module_name or not attribute_name:
        raise RegistryError("AIP_CREWAI_REGISTRY must use module:attribute syntax")
    module = importlib.import_module(module_name)
    try:
        registry: Any = getattr(module, attribute_name)
    except AttributeError as error:
        raise RegistryError(
            f"registry attribute {reference!r} does not exist"
        ) from error
    if callable(registry) and not isinstance(registry, Mapping):
        registry = registry()
    if not isinstance(registry, Mapping) or not registry:
        raise RegistryError("CrewAI registry must be a non-empty mapping")

    normalized: dict[str, CrewFactory] = {}
    for crew_id, configured in registry.items():
        if not isinstance(crew_id, str) or not crew_id.strip():
            raise RegistryError("CrewAI registry ids must be non-empty strings")
        normalized[crew_id] = _factory(configured)
    return normalized


def _factory(configured: Any) -> CrewFactory:
    if (
        inspect.isclass(configured)
        or inspect.isfunction(configured)
        or inspect.ismethod(configured)
    ):
        return configured

    def clone() -> Any:
        if hasattr(configured, "model_copy"):
            return configured.model_copy(deep=True)
        if hasattr(configured, "copy"):
            return configured.copy()
        raise RegistryError(
            "registry values must be crew factories or cloneable Crew instances"
        )

    return clone
