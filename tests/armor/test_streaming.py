"""Sprint 87 — Streaming rolling-buffer rail primitives.

NeMo buffer.py-style design: hold back a context window so a safety
predicate can inspect text spanning chunk boundaries before it is ever
emitted downstream. Forward-compatible with SSE transport: today upstream
is non-streaming, but these primitives guarantee an output rail even if
streaming is added later.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from archon_armor.streaming import (
    RollingBuffer,
    ScanVerdict,
    StreamBlocked,
    StreamScanner,
    stream_guard,
)


def _marker_predicate(chunk: str) -> bool:
    return "jailbreak-marker" in chunk


class TestRollingBuffer:
    @pytest.mark.parametrize(
        ("context_size", "chunk_size", "feed_sizes"),
        [
            (80, 40, [30, 30, 30, 30, 30]),
            (40, 20, [7, 13, 41, 2, 100]),
            (10, 5, [1] * 25),
            (3, 7, [50]),
            (80, 13, [11, 97, 5, 23, 64]),
        ],
        ids=["even", "ragged", "char-by-char", "single-big-chunk", "mixed"],
    )
    def test_exact_reassembly_invariant(
        self, context_size: int, chunk_size: int, feed_sizes: list[int]
    ) -> None:
        source = "abcdefghij" * 20
        buf = RollingBuffer(context_size=context_size, chunk_size=chunk_size)
        emitted: list[str] = []
        pushed: list[str] = []
        pos = 0
        for size in feed_sizes:
            piece = source[pos : pos + size]
            pushed.append(piece)
            emitted.extend(buf.push(piece))
            pos += size
        expected = "".join(pushed)
        assert "".join(emitted) + buf.flush() == expected

    def test_holdback_emitted_text_lags(self) -> None:
        buf = RollingBuffer(context_size=80, chunk_size=40)
        text = "x" * 200
        emitted = buf.push(text)
        # Everything except (at least) the last context_size chars stays held.
        assert len("".join(emitted)) <= len(text) - 80
        assert buf.flush() == text[len("".join(emitted)) :]

    def test_flush_returns_tail_and_empties(self) -> None:
        buf = RollingBuffer(context_size=80, chunk_size=40)
        buf.push("short")
        tail = buf.flush()
        assert tail == "short"
        assert buf.flush() == ""

    def test_push_empty_yields_nothing(self) -> None:
        buf = RollingBuffer()
        assert buf.push("") == []
        assert buf.flush() == ""


class TestStreamScanner:
    def test_verdict_fields_on_clean_feed(self) -> None:
        scanner = StreamScanner(_marker_predicate)
        verdict = scanner.feed("hello world, nothing to see here" * 4)
        assert isinstance(verdict, ScanVerdict)
        assert verdict.blocked is False
        assert verdict.reason is None
        assert isinstance(verdict.emit, str)

    def test_blocks_marker_spanning_two_chunks(self) -> None:
        scanner = StreamScanner(_marker_predicate)
        first = scanner.feed("safe prefix ... jailbreak-")
        assert first.blocked is False
        second = scanner.feed("marker and more unsafe content")
        assert second.blocked is True
        assert second.emit is None
        assert second.reason

    def test_post_block_silence(self) -> None:
        scanner = StreamScanner(_marker_predicate)
        scanner.feed("a" * 100)
        blocked = scanner.feed("jailbreak-marker")
        assert blocked.blocked is True
        for _ in range(5):
            later = scanner.feed("more text after detection")
            assert later.emit is None
            assert later.blocked is True

    def test_clean_stream_passes_everything(self) -> None:
        chunks = ["benign text one ", "benign text two ", "benign text three"]
        scanner = StreamScanner(_marker_predicate, context_size=20, chunk_size=10)
        out: list[str | None] = []
        for chunk in chunks:
            out.append(scanner.feed(chunk).emit)
        reassembled = "".join(e or "" for e in out) + scanner.flush()
        assert reassembled == "".join(chunks)

    def test_emit_is_none_until_holdback_satisfied(self) -> None:
        scanner = StreamScanner(_marker_predicate, context_size=50, chunk_size=10)
        assert scanner.feed("tiny").emit is None


class TestStreamGuard:
    async def _collect(self, chunks: list[str]) -> list[object]:
        async def upstream() -> AsyncIterator[str]:
            for chunk in chunks:
                yield chunk

        results: list[object] = []
        guard = stream_guard(upstream(), StreamScanner(_marker_predicate))
        async for item in guard:
            results.append(item)
        return results

    async def test_clean_stream_passes_end_to_end(self) -> None:
        results = await self._collect(["good ", "clean ", "stream"])
        joined = "".join(r for r in results if isinstance(r, str))
        assert joined == "good clean stream"
        assert not any(isinstance(r, StreamBlocked) for r in results)

    async def test_guard_flags_blocked_object_not_raise(self) -> None:
        results = await self._collect(["innocent ", "jailbreak-", "marker payload"])
        assert any(isinstance(r, StreamBlocked) for r in results)
        blocked_items = [r for r in results if isinstance(r, StreamBlocked)]
        assert blocked_items[-1].reason

    async def test_guard_yields_only_safe_text_before_block(self) -> None:
        results = await self._collect(["safe text here ", "bad jailbreak-", "marker"])
        joined = "".join(r for r in results if isinstance(r, str))
        assert "jailbreak-" not in joined and "marker" not in joined

    async def test_guard_stops_consuming_upstream_after_block(self) -> None:
        consumed: list[str] = []

        async def upstream() -> AsyncIterator[str]:
            for chunk in ["ok ", "jailbreak-", "marker"]:
                consumed.append(chunk)
                yield chunk

        results: list[object] = []
        async for item in stream_guard(upstream(), StreamScanner(_marker_predicate)):
            results.append(item)
        assert isinstance(results[-1], StreamBlocked)
        assert consumed == ["ok ", "jailbreak-", "marker"]

    async def test_guard_flushes_tail_on_clean_close(self) -> None:
        results = await self._collect(["only a little"])
        assert "".join(r for r in results if isinstance(r, str)) == "only a little"
