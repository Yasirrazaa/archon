"""Streaming JSONL span export — OTLP-JSON-shaped records, one per line.

Output is directly ingestible by log pipelines (Fluent Bit, Vector, OTel
collector filelog) and by Cloud Logging sinks; each record carries name,
span/parent ids, duration, and scrubbed attributes.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from .base import LocalTracer


class JsonlTracer(LocalTracer):
    """LocalTracer that streams every completed span to a JSONL file."""

    def __init__(self, path: str | Path):
        super().__init__()
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.Lock()

    def end_span(self, span, attributes=None) -> None:
        super().end_span(span, attributes)
        record = {
            "name": span.name,
            "span_id": span.span_id,
            "parent_span_id": span.parent_id,
            "duration_ms": span.duration_ms,
            "attributes": dict(span.attributes),
            "started_at_unix": span.started_at,
        }
        line = json.dumps(record, separators=(",", ":")) + "\n"
        with self._write_lock:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
