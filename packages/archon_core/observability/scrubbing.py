"""PII/secret scrubbing for span attributes and structured logs."""

from __future__ import annotations

import re
from typing import Any

from .base import Tracer

_REDACTED = "[REDACTED]"


class AttributeScrubber:
    """Recursively removes PII/secrets from attribute dicts.

    Patterns cover the highest-risk classes: SSNs, emails, phone numbers,
    bearer/API tokens, and payment card numbers. Values are replaced with a
    stable marker so downstream tooling can count redactions.
    """

    PATTERNS = [
        re.compile(r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b"),                       # SSN
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),     # email
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+"),                          # bearer token
        re.compile(r"\bsk-[A-Za-z0-9\-_]{8,}"),                                  # api key style
        re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), # phone
        re.compile(r"\b(?:\d[ -]?){13,16}\b"),                                   # card number
    ]

    def scrub_value(self, value: Any) -> Any:
        if isinstance(value, str):
            for pattern in self.PATTERNS:
                value = pattern.sub(_REDACTED, value)
            return value
        if isinstance(value, dict):
            return {k: self.scrub_value(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.scrub_value(v) for v in value]
        return value

    def scrub(self, attrs: dict | None) -> dict:
        return self.scrub_value(dict(attrs or {}))


class ScrubbingTracer(Tracer):
    """Decorator over any Tracer that scrubs attributes before they land."""

    def __init__(self, inner: Tracer, scrubber: AttributeScrubber | None = None):
        self._inner = inner
        self._scrubber = scrubber or AttributeScrubber()

    def start_span(self, name: str, attributes=None) -> Any:
        span = self._inner.start_span(name, self._scrubber.scrub(attributes))
        return span

    def end_span(self, span: Any, attributes=None) -> None:
        self._inner.end_span(span, self._scrubber.scrub(attributes))
