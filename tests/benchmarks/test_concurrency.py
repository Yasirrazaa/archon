"""Concurrency tests for live benchmark harnesses.

Verifies that concurrent execution (asyncio.Semaphore + gather) produces
identical aggregates and order-preserving per-item results compared to
sequential runs, and that the semaphore actually bounds in-flight work.
"""

from __future__ import annotations

import asyncio

import pytest

from archon_benchmarks.agentharm import AgentHarmBehavior, _run_live as ah_run_live
from archon_benchmarks.rjudge import _score_records
from archon_benchmarks.strongreject import StrongRejectRecord, _run_live as sr_run_live


class _FakeTarget:
    """Records max in-flight sends; returns deterministic content."""

    def __init__(self, reply: str = "Sure, here is how to do it.") -> None:
        self.reply = reply
        self._in_flight = 0
        self.max_in_flight = 0

    async def send(self, payload: str):
        self._in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self._in_flight)
        await asyncio.sleep(0.01)
        self._in_flight -= 1

        class _Resp:
            content = self.reply
            blocked = False

        return _Resp()


def _sr_records(n: int) -> list[StrongRejectRecord]:
    return [
        StrongRejectRecord(
            forbidden_prompt=f"do bad thing {i}",
            category=f"cat{i % 3}",
            source="test",
        )
        for i in range(n)
    ]


@pytest.mark.asyncio
async def test_strongreject_concurrent_matches_sequential():
    records = _sr_records(12)

    seq_target = _FakeTarget()
    seq = await sr_run_live(seq_target, records, provider=None, concurrency=1)

    conc_target = _FakeTarget()
    conc = await sr_run_live(conc_target, records, provider=None, concurrency=4)

    assert seq["mean_strongreject_score"] == conc["mean_strongreject_score"]
    assert seq["fully_refused"] == conc["fully_refused"]
    assert seq["per_category_mean_score"] == conc["per_category_mean_score"]


@pytest.mark.asyncio
async def test_strongreject_semaphore_bounds_inflight():
    target = _FakeTarget()
    await sr_run_live(target, _sr_records(8), provider=None, concurrency=3)
    assert target.max_in_flight <= 3


def test_strongreject_run_entry_accepts_concurrency(monkeypatch):
    import archon_benchmarks.strongreject as mod

    captured = {}

    async def fake_run_live(target, records, provider, concurrency=1):
        captured["concurrency"] = concurrency
        return {"enabled": True}

    monkeypatch.setattr(mod, "_run_live", fake_run_live)
    monkeypatch.setattr(mod, "load_strongreject", lambda: [])
    report = mod.run_strongreject_live(target=_FakeTarget(), concurrency=5)
    assert report == {"enabled": True}
    assert captured["concurrency"] == 5


def _ah_behaviors(n: int) -> list[AgentHarmBehavior]:
    return [
        AgentHarmBehavior(
            id=f"b{i}",
            id_original=f"b{i}",
            name=f"behavior {i}",
            category="c",
            query=f"harm {i}",
        )
        for i in range(n)
    ]


@pytest.mark.asyncio
async def test_agentharm_concurrent_matches_sequential():
    behaviors = _ah_behaviors(10)

    seq = await ah_run_live(_FakeTarget(reply="I'm sorry, I cannot."),
                            behaviors, judge=None, concurrency=1)
    conc = await ah_run_live(_FakeTarget(reply="I'm sorry, I cannot."),
                             behaviors, judge=None, concurrency=4)

    assert seq["complied"] == conc["complied"]
    assert seq["refused"] == conc["refused"]
    assert seq["compliance_rate"] == conc["compliance_rate"]
    assert seq["measurement"]["judge"] == conc["measurement"]["judge"]


def test_agentharm_run_entry_accepts_concurrency(monkeypatch):
    import archon_benchmarks.agentharm as mod

    captured = {}

    async def fake_run_live(target, behaviors, judge, concurrency=1):
        captured["concurrency"] = concurrency
        return {"enabled": True}

    monkeypatch.setattr(mod, "_run_live", fake_run_live)
    monkeypatch.setattr(mod, "load_agentharm", lambda split: [])
    report = mod.run_agentharm_live(target=_FakeTarget(), concurrency=7)
    assert report == {"enabled": True}
    assert captured["concurrency"] == 7


def _rj_records(n: int) -> list[dict]:
    return [
        {
            "label": i % 2,
            "scenario": f"test-scenario-{i}",
            "goal": f"test goal {i}",
            "contents": [[
                {"role": "user", "content": f"hello {i}"},
                {"role": "assistant", "content": f"hi {i}"},
            ]],
        }
        for i in range(n)
    ]


def _sync_judge(transcript: str) -> int:
    return 1 if "unsafe-marker" in transcript else 0


@pytest.mark.asyncio
async def test_rjudge_concurrent_matches_sequential():
    records = _rj_records(16)

    seq = await _score_records(_sync_judge, records, concurrency=1)
    conc = await _score_records(_sync_judge, records, concurrency=4)

    assert seq["confusion"] == conc["confusion"]
    assert seq["label_counts"] == conc["label_counts"]
    assert seq["accuracy"] == conc["accuracy"]


@pytest.mark.asyncio
async def test_rjudge_async_judge_concurrent():
    async def async_judge(transcript: str) -> int:
        await asyncio.sleep(0.005)
        return _sync_judge(transcript)

    records = _rj_records(9)
    seq = await _score_records(async_judge, records, concurrency=1)
    conc = await _score_records(async_judge, records, concurrency=3)
    assert seq["confusion"] == conc["confusion"]


def test_rjudge_run_entry_accepts_concurrency(monkeypatch):
    import archon_benchmarks.rjudge as mod

    captured = {}

    async def fake_score(judge, records, concurrency=1):
        captured["concurrency"] = concurrency
        return {"tp": 0, "n_records": len(records)}

    monkeypatch.setattr(mod, "_score_records", fake_score)
    monkeypatch.setattr(mod, "load_rjudge_records", lambda cache_path=None: [])
    report = mod.run_rjudge_benchmark(judge=_sync_judge, concurrency=6)
    assert captured["concurrency"] == 6
    assert report["tp"] == 0


# ---------------------------------------------------------------------------
# live_runner wiring
# ---------------------------------------------------------------------------


def test_live_runner_phase_signatures_accept_concurrency():
    import inspect

    from archon_benchmarks import live_runner

    for name in (
        "run_phase_strongreject",
        "run_phase_agentharm",
        "run_phase_rjudge",
        "run_phase_piminer",
    ):
        sig = inspect.signature(getattr(live_runner, name))
        assert "concurrency" in sig.parameters, name


def test_live_runner_main_has_concurrency_flag():
    import inspect

    from archon_benchmarks import live_runner

    src = inspect.getsource(live_runner.main)
    assert "--concurrency" in src
