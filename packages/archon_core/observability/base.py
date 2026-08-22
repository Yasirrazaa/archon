"""Minimal observability contracts.

Tracer is a protocol-style ABC so the pipeline has zero hard dependency on
OpenTelemetry. A production OTel exporter lives in integrations/otel; the
in-memory LocalTracer used for tests and local runs lives here.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Span:
    """A lightweight, OpenTelemetry-shaped span record."""

    name: str
    attributes: dict[str, Any] = field(default_factory=dict)
    events: list[tuple[str, dict[str, Any]]] = field(default_factory=list)


class Tracer(ABC):
    """Sink for pipeline spans."""

    @abstractmethod
    def start_span(self, name: str, attributes: dict[str, Any] | None = None) -> Span: ...

    @abstractmethod
    def end_span(self, span: Span, attributes: dict[str, Any] | None = None) -> None: ...


class NullTracer(Tracer):
    """Default no-op tracer."""

    def start_span(self, name: str, attributes=None) -> Span:
        return Span(name=name, attributes=attributes or {})

    def end_span(self, span: Span, attributes=None) -> None:
        return None
