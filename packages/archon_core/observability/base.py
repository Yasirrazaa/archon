"""Minimal observability contracts.

Tracer is a protocol-style ABC so the pipeline has zero hard dependency on
OpenTelemetry. LocalTracer provides in-memory span recording (OTel-shaped
JSON export) for tests, local runs, and as the reference implementation for
production exporters in integrations/.
"""

from __future__ import annotations

import contextvars
import json
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Span:
    """A lightweight, OpenTelemetry-shaped span record."""

    name: str
    span_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    parent_id: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)
    duration_ms: float | None = None


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


class LocalTracer(Tracer):
    """In-memory tracer with async-safe parent/child nesting.

    Nesting is tracked per asyncio task (contextvars), so concurrent requests
    each get their own span tree. Completed spans are appended to a shared,
    thread-safe list.
    """

    def __init__(self) -> None:
        self._stack: contextvars.ContextVar[tuple[Span, ...]] = contextvars.ContextVar(
            f"archon_span_stack_{id(self)}", default=()
        )
        self._completed: list[Span] = []
        self._lock = threading.Lock()

    def start_span(self, name: str, attributes=None) -> Span:
        stack = self._stack.get()
        parent = stack[-1] if stack else None
        span = Span(
            name=name,
            parent_id=parent.span_id if parent else None,
            attributes=dict(attributes or {}),
        )
        self._stack.set(stack + (span,))
        return span

    def end_span(self, span: Span, attributes=None) -> None:
        stack = self._stack.get()
        if stack and stack[-1].span_id == span.span_id:
            self._stack.set(stack[:-1])
        span.duration_ms = round((time.time() - span.started_at) * 1000.0, 3)
        if attributes:
            span.attributes.update(attributes)
        with self._lock:
            self._completed.append(span)

    @property
    def spans(self) -> list[Span]:
        with self._lock:
            return list(self._completed)

    def to_json(self) -> str:
        with self._lock:
            records = [
                {
                    "name": s.name,
                    "span_id": s.span_id,
                    "parent_span_id": s.parent_id,
                    "duration_ms": s.duration_ms,
                    "attributes": dict(s.attributes),
                    "started_at_unix": s.started_at,
                }
                for s in self._completed
            ]
        return json.dumps(records)


__all__ = ["LocalTracer", "NullTracer", "Span", "Tracer"]

