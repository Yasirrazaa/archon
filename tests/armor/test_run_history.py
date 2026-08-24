"""Tests for the run-history experiment store (ROADMAP item 84).

deepeval local_store pattern: every scan/battle invocation is persisted as an
immutable timestamped row so policy regressions can be diffed over time.
"""

from __future__ import annotations

import pytest
from archon_armor.run_history import RunHistory


def _report(block_rate: float, blocked_names: set[str], total: int = 4):
    results = [
        {
            "probe_name": f"p{i}",
            "blocked": f"p{i}" in blocked_names,
            "category": "core",
        }
        for i in range(total)
    ]
    return {
        "results": results,
        "summary": {
            "total_probes": total,
            "blocked": len(blocked_names),
            "block_rate": block_rate,
        },
    }


@pytest.fixture()
def hist(tmp_path):
    return RunHistory(tmp_path / "runs.db")


class TestRecordAndHistory:
    def test_record_returns_incrementing_ids(self, hist):
        a = hist.record(_report(0.5, {"p0"}), agent_id="ag", label="v1")
        b = hist.record(_report(0.75, {"p0", "p1"}), agent_id="ag", label="v2")
        assert b > a >= 1

    def test_history_roundtrip(self, hist):
        hist.record(_report(0.5, {"p0"}), agent_id="ag", label="v1")
        rows = hist.history()
        assert len(rows) == 1
        row = rows[0]
        assert row["agent_id"] == "ag"
        assert row["label"] == "v1"
        assert row["block_rate"] == pytest.approx(0.5)
        assert row["total_probes"] == 4
        assert row["blocked"] == 1
        assert isinstance(row["report"], dict)
        assert row["report"]["summary"]["block_rate"] == pytest.approx(0.5)

    def test_history_newest_first(self, hist):
        hist.record(_report(0.25, set()), agent_id="ag")
        hist.record(_report(0.5, {"p0"}), agent_id="ag")
        hist.record(_report(0.75, {"p0", "p1"}), agent_id="ag")
        rates = [r["block_rate"] for r in hist.history()]
        assert rates == [0.75, 0.5, 0.25]

    def test_history_agent_filter(self, hist):
        hist.record(_report(0.25, set()), agent_id="a")
        hist.record(_report(0.5, {"p0"}), agent_id="b")
        assert [r["agent_id"] for r in hist.history(agent_id="a")] == ["a"]
        assert len(hist.history()) == 2

    def test_history_limit(self, hist):
        for i in range(7):
            hist.record(_report(0.1 * i, set()), agent_id="ag")
        assert len(hist.history(limit=3)) == 3
        # newest kept
        assert hist.history(limit=3)[0]["block_rate"] == pytest.approx(0.6)

    def test_latest(self, hist):
        assert hist.latest() is None
        hist.record(_report(0.25, set()), agent_id="ag")
        last = hist.record(_report(0.75, {"p0"}), agent_id="ag")
        assert hist.latest()["run_id"] == last
        assert hist.latest(agent_id="nobody") is None


class TestDiff:
    def test_diff_delta_and_name_lists(self, hist):
        ra = _report(0.25, {"p0"})
        rb = _report(0.5, {"p0", "p2"})  # p2 newly blocked, p1 was never blocked
        ia = hist.record(ra, agent_id="ag")
        ib = hist.record(rb, agent_id="ag")
        d = hist.diff(ia, ib)
        assert d["block_rate"]["a"] == pytest.approx(0.25)
        assert d["block_rate"]["b"] == pytest.approx(0.5)
        assert d["block_rate"]["delta"] == pytest.approx(0.25)
        assert d["newly_blocked"] == ["p2"]
        assert d["newly_unblocked"] == []

    def test_diff_newly_unblocked(self, hist):
        ia = hist.record(_report(0.5, {"p1"}), agent_id="ag")
        ib = hist.record(_report(0.0, set()), agent_id="ag")
        d = hist.diff(ia, ib)
        assert d["newly_unblocked"] == ["p1"]
        assert d["newly_blocked"] == []

    def test_diff_missing_run_raises(self, hist):
        hist.record(_report(0.0, set()), agent_id="ag")
        with pytest.raises(ValueError):
            hist.diff(999, 1000)

    def test_diff_order_independent_delta_sign(self, hist):
        ia = hist.record(_report(0.0, set()), agent_id="ag")
        ib = hist.record(_report(0.5, {"p0"}), agent_id="ag")
        fwd = hist.diff(ia, ib)["block_rate"]["delta"]
        bwd = hist.diff(ib, ia)["block_rate"]["delta"]
        assert fwd == pytest.approx(-bwd)


class TestIsolation:
    def test_separate_stores_isolated(self, tmp_path):
        h1 = RunHistory(tmp_path / "one.db")
        h2 = RunHistory(tmp_path / "two.db")
        h1.record(_report(0.5, {"p0"}), agent_id="ag")
        assert h2.history() == []
