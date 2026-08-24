"""Sprint 87 — Streaming rolling-buffer rail primitives.

NeMo ``buffer.py``-style design, forward-compatible with SSE transport.
Today the upstream transport is non-streaming, but these primitives ship
the enforcement side first so that adding streaming later cannot bypass
output rails: a rolling buffer holds back the last ``context_size``
characters so a safety predicate can inspect text spanning chunk
boundaries *before* it is ever emitted downstream, and once blocked the
scanner stays silent.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass


class RollingBuffer:
    """Emits SAFE chunks while holding back the last ``context_size`` chars.

    Invariant: for any sequence of pushes, the concatenation of all
    emitted chunks plus :meth:`flush` reproduces the pushed text exactly.
    """

    def __init__(self, context_size: int = 80, chunk_size: int = 40) -> None:
        if context_size < 0:
            raise ValueError("context_size must be >= 0")
        if chunk_size <= 0:
            raise ValueError("chunk_size must be > 0")
        self.context_size = context_size
        self.chunk_size = chunk_size
        self._pending = ""

    def push(self, text: str) -> list[str]:
        """Append ``text`` and return the chunks now safe to emit."""
        self._pending += text
        emitted: list[str] = []
        while len(self._pending) - self.chunk_size >= self.context_size:
            emitted.append(self._pending[: self.chunk_size])
            self._pending = self._pending[self.chunk_size :]
        return emitted

    def flush(self) -> str:
        """Return (and clear) the held-back remainder."""
        tail, self._pending = self._pending, ""
        return tail


@dataclass(frozen=True)
class ScanVerdict:
    """Outcome of scanning one streamed chunk."""

    emit: str | None
    blocked: bool
    reason: str | None = None


class StreamBlocked(Exception):
    """Raised/flagged when a stream safety predicate fires mid-stream."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class StreamScanner:
    """Wraps a sync predicate over the rolling window of a chunked stream.

    The predicate is evaluated against the last ``context_size`` chars of
    raw input plus the new chunk, so a marker spanning two adjacent chunks
    is caught before either part is released. Once blocked, every further
    feed returns a blocked verdict with no emit.
    """

    def __init__(
        self,
        predicate: Callable[[str], bool],
        context_size: int = 80,
        chunk_size: int = 40,
    ) -> None:
        self._predicate = predicate
        self._buffer = RollingBuffer(context_size=context_size, chunk_size=chunk_size)
        self._window_tail_len = max(context_size - 1, 0)
        self._recent = ""
        self._blocked = False
        self._reason: str | None = None

    def feed(self, chunk: str) -> ScanVerdict:
        """Scan one upstream chunk; returns what is safe to emit now."""
        if self._blocked:
            return ScanVerdict(emit=None, blocked=True, reason=self._reason)
        window = self._recent + chunk
        if self._predicate(window):
            self._blocked = True
            self._reason = "stream safety predicate matched in rolling window"
            return ScanVerdict(emit=None, blocked=True, reason=self._reason)
        self._recent = window[-self._window_tail_len :] if self._window_tail_len else ""
        safe = "".join(self._buffer.push(chunk))
        return ScanVerdict(emit=safe or None, blocked=False)

    def flush(self) -> str:
        """Release the held-back tail once the stream ends cleanly."""
        return self._buffer.flush()


async def stream_guard(
    upstream_stream_aiter: AsyncIterator[str],
    scanner: StreamScanner,
) -> AsyncIterator[str | StreamBlocked]:
    """Yield safe text from an upstream async stream, flagging on block.

    Yields only predicate-cleared text; on detection it stops consuming
    the upstream iterator and yields a single :class:`StreamBlocked`
    instance as its final item (returned, not raised, for testability).
    On clean close, the held-back tail is flushed through.
    """
    async for chunk in upstream_stream_aiter:
        verdict = scanner.feed(chunk)
        if verdict.blocked:
            yield StreamBlocked(verdict.reason or "stream blocked")
            return
        if verdict.emit:
            yield verdict.emit
    tail = scanner.flush()
    if tail:
        yield tail
