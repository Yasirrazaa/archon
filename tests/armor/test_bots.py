"""Sprint IMP-2: autonomous red-bot tests.

Covers the continuous-probe loop in archon_core.bots:
config defaults, round-robin probe scheduling, blocked/unblocked finding
recording, stop-file and max-rounds loop termination, injected sleepers
(no real sleeping), payload-excerpt truncation, run summarization, and the
nightly fuzz workflow file (parses as YAML with schedule + dispatch).
"""

from __future__ import annotations

import asyncio
import pathlib
import time
from dataclasses import dataclass

import yaml
from archon_core.bots import BotFinding, RedBot, RedBotConfig, summarize_bot_run

WORKFLOW = pathlib.Path(".github/workflows/fuzz.yml")


# ---------------------------------------------------------------------------
# Fakes / helpers
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FakeProbe:
    """Probe-like object mirroring archon_armor.probes.Probe."""

    name: str
    payload: str
    category: str


FAKE_PACKS: dict[str, list[FakeProbe]] = {
    "alpha": [FakeProbe("a1", "probe-a1", "LLM01"), FakeProbe("a2", "probe-a2", "LLM01")],
    "beta": [FakeProbe("b1", "probe-b1", "LLM02")],
}


def fake_probe_source(pack: str) -> list[FakeProbe]:
    return list(FAKE_PACKS[pack])


class ScriptedTarget:
    """Duck-typed TargetAdapter popping canned verdicts in call order."""

    def __init__(self, blocked_flags: list[bool]):
        self.blocked_flags = list(blocked_flags)

    async def send(self, payload: str):
        return {"content": "ok", "blocked": self.blocked_flags.pop(0)}


async def instant_sleeper(_seconds: float) -> None:
    """Injectable sleeper: records intent, never actually sleeps."""


def run(coro):
    return asyncio.run(coro)


def make_bot(blocked_flags, packs=("alpha",), max_rounds=3) -> tuple[RedBot, list[float]]:
    sleeps: list[float] = []

    async def sleeper(seconds: float) -> None:
        sleeps.append(seconds)

    config = RedBotConfig(interval_seconds=0.25, packs=tuple(packs), max_rounds=max_rounds)
    bot = RedBot(
        send=ScriptedTarget(blocked_flags).send,
        probe_source=fake_probe_source,
        config=config,
        sleeper=sleeper,
    )
    return bot, sleeps


# ---------------------------------------------------------------------------
# Config + loop mechanics
# ---------------------------------------------------------------------------

def test_config_defaults():
    cfg = RedBotConfig()
    assert cfg.interval_seconds == 300
    assert cfg.packs == ("core",)
    assert cfg.max_rounds is None
    assert cfg.target_url is None
    assert cfg.stop_file is None


def test_round_robin_ordering_across_seeds():
    """Two packs flatten into one sequence; the cycle repeats after exhaustion."""
    bot, _ = make_bot([False] * 6, packs=("alpha", "beta"), max_rounds=3)
    findings = run(bot.run())
    names = [f.payload_excerpt for f in findings]
    # flattened order is a1, a2, b1 (alpha first, then beta)
    assert names == ["probe-a1", "probe-a2", "probe-b1"]


def test_blocked_and_unblocked_recorded_correctly():
    bot, _ = make_bot([True, False, True], max_rounds=3)
    findings = run(bot.run())
    assert [f.blocked for f in findings] == [True, False, True]


def test_stop_file_stops_loop(tmp_path):
    stop_file = tmp_path / "STOP"
    stop_file.write_text("halt")
    sleeps: list[float] = []

    async def sleeper(seconds: float) -> None:
        sleeps.append(seconds)

    config = RedBotConfig(
        interval_seconds=0.25,
        packs=("alpha",),
        max_rounds=None,
        stop_file=str(stop_file),
    )
    bot = RedBot(
        send=ScriptedTarget([False]).send,
        probe_source=fake_probe_source,
        config=config,
        sleeper=sleeper,
    )
    findings = run(bot.run())
    assert findings == []  # stop checked before first round
    assert sleeps == []


def test_max_rounds_bounds_loop():
    bot, _ = make_bot([False] * 10, packs=("alpha",), max_rounds=5)
    findings = run(bot.run())
    assert len(findings) == 5


def test_sleeper_injection_avoids_real_sleep():
    bot, sleeps = make_bot([False] * 3, packs=("alpha",))
    start = time.perf_counter()
    run(bot.run())
    elapsed = time.perf_counter() - start
    assert sleeps == [0.25, 0.25]  # no sleep after the final round
    assert elapsed < 0.2


def test_builtin_seed_fallback_when_no_probe_source():
    seen: list[str] = []

    class Recorder:
        async def send(self, payload: str):
            seen.append(payload)
            return {"content": "", "blocked": False}

    config = RedBotConfig(max_rounds=2)
    bot = RedBot(send=Recorder().send, probe_source=None, config=config, sleeper=instant_sleeper)
    findings = run(bot.run())
    assert len(findings) == 2
    assert seen == [f.payload_excerpt for f in findings]
    assert all(seen)  # non-empty built-in seeds were used


# ---------------------------------------------------------------------------
# Finding shape + summary math
# ---------------------------------------------------------------------------

def test_excerpt_truncation_le_200():
    long_probe = FakeProbe("big", "x" * 5000, "benign")

    def source(_pack: str) -> list[FakeProbe]:
        return [long_probe]

    class Echo:
        async def send(self, payload: str):
            return {"content": "y", "blocked": True}

    config = RedBotConfig(max_rounds=1)
    bot = RedBot(send=Echo().send, probe_source=source, config=config, sleeper=instant_sleeper)
    (finding,) = run(bot.run())
    assert len(finding.payload_excerpt) == 200
    assert finding.payload_excerpt == "x" * 200


def test_summarize_math_correct():
    def mk(round_: int, blocked: bool) -> BotFinding:
        return BotFinding(
            round=round_, payload_excerpt="p", blocked=blocked,
            latency_ms=1.0, summary="s",
        )

    findings = [mk(1, True), mk(2, False), mk(3, True)]
    summary = summarize_bot_run(findings)
    assert summary["rounds"] == 3
    assert summary["probes_sent"] == 3
    assert summary["blocked"] == 2
    assert abs(summary["block_rate"] - (2 / 3)) < 1e-9
    assert len(summary["findings_sample"]) == min(3, len(findings))


def test_summarize_empty_findings():
    summary = summarize_bot_run([])
    assert summary["rounds"] == 0
    assert summary["probes_sent"] == 0
    assert summary["blocked"] == 0
    assert summary["block_rate"] == 0.0
    assert summary["findings_sample"] == []


def test_latency_recorded_non_negative():
    bot, _ = make_bot([False], packs=("alpha",), max_rounds=1)
    (finding,) = run(bot.run())
    assert finding.latency_ms >= 0.0
    assert finding.round == 1


# ---------------------------------------------------------------------------
# Nightly fuzz workflow
# ---------------------------------------------------------------------------

def test_fuzz_workflow_exists_and_parses_with_schedule_and_dispatch():
    assert WORKFLOW.is_file(), "missing .github/workflows/fuzz.yml"
    doc = yaml.safe_load(WORKFLOW.read_text())
    # YAML 1.1 parses bare `on:` as boolean True — that IS the trigger key.
    triggers = doc.get(True, doc.get("on"))
    assert isinstance(triggers, dict), f"expected trigger map, got {triggers!r}"
    assert "schedule" in triggers, "workflow must have a cron schedule"
    crons = [item.get("cron") for item in triggers["schedule"]]
    assert any(crons), "schedule entries must define cron expressions"
    assert "workflow_dispatch" in triggers, "workflow must allow manual dispatch"


def test_fuzz_workflow_runs_pytest_and_uploads_artifacts():
    text = WORKFLOW.read_text()
    assert "pytest" in text, "nightly job must invoke pytest on fuzz suites"
    assert "upload-artifact" in text, "failures must upload artifacts"
    assert "test_fuzz_parsers.py" in text, "must target the existing fuzz suite"
