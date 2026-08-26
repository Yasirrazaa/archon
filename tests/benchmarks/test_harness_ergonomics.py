"""Sprint W14-86: benchmark harness ergonomics.

Covers:
- on_progress callbacks on strongreject/_run_live, rjudge scoring,
  agentharm/_run_live (done, total) after each record; silent by default;
- incremental partial saves in the __main__ layers (--out DIR);
- response sampling ('samples') in strongreject + agentharm live reports.
"""

import asyncio
import json

import pytest
from archon_benchmarks import agentharm as ah
from archon_benchmarks import rjudge as rj
from archon_benchmarks import strongreject as sr
from archon_core.targets.base import TargetAdapter, TargetResponse


class _FakeTarget(TargetAdapter):
    def __init__(self, content: str = "Sure, here are step-by-step details.",
                 model: str = "fake-model"):
        self.content = content
        self.model = model
        self.payloads: list[str] = []

    async def send(self, payload: str) -> TargetResponse:
        self.payloads.append(payload)
        return TargetResponse(content=self.content, blocked=False)


def _rj_record(i: int) -> dict:
    return {
        "record_id": f"t{i}",
        "scenario": "Application/chatbot",
        "profile": "",
        "goal": f"goal {i}",
        "contents": [[{"role": "user", "content": f"hello {i}"}]],
        "label": 0,
        "risk_description": "",
        "attack_type": "",
        "source_file": "test",
    }


class TestOnProgress:
    def test_strongreject_live_calls_on_progress_per_record(self):
        calls: list[tuple[int, int]] = []
        records = sr.load_strongreject_fixture()[:3]
        report = sr.run_strongreject_live(
            _FakeTarget(), records=records, on_progress=lambda d, t: calls.append((d, t))
        )
        assert report["enabled"] is True
        assert calls == [(1, 3), (2, 3), (3, 3)]

    def test_agentharm_live_calls_on_progress_per_record(self):
        calls: list[tuple[int, int]] = []
        behaviors = ah.load_agentharm_fixture()[:4]
        report = ah.run_agentharm_live(
            _FakeTarget("I'm sorry, I cannot help with that."),
            behaviors=behaviors,
            on_progress=lambda d, t: calls.append((d, t)),
        )
        assert report["enabled"] is True
        assert calls == [(1, 4), (2, 4), (3, 4), (4, 4)]

    def test_rjudge_scoring_calls_on_progress_per_record(self):
        calls: list[tuple[int, int]] = []
        records = [_rj_record(i) for i in range(5)]
        report = asyncio.run(
            rj._score_records(rj.heuristic_judge, records, 1,
                              on_progress=lambda d, t: calls.append((d, t)))
        )
        assert report["n_records"] == 5
        assert calls == [(1, 5), (2, 5), (3, 5), (4, 5), (5, 5)]

    def test_default_is_silent(self, capsys, tmp_path):
        records = sr.load_strongreject_fixture()[:2]
        rep = sr.run_strongreject_live(_FakeTarget(), records=records)
        assert rep["enabled"] is True
        assert capsys.readouterr().out == ""
        rep2 = rj.run_rjudge_benchmark(
            judge=rj.heuristic_judge, records=[_rj_record(i) for i in range(2)])
        assert rep2["enabled"] is True
        assert capsys.readouterr().out == ""
        # incremental runner without out_dir writes no files
        rj._run_heuristic_incremental([_rj_record(i) for i in range(3)], out_dir=None)
        assert list(tmp_path.iterdir()) == []


class TestPrinterAndIncrementalSaves:
    def test_printer_format(self, capsys):
        cb = sr._progress_printer("strongreject")
        cb(7, 36)
        out = capsys.readouterr().out
        assert "[strongreject] 7/36" in out
        assert out.endswith("\n")

    def test_partial_file_written_mid_run(self, tmp_path):
        seen: dict[int, int] = {}

        def observer(done: int, total: int) -> None:
            path = tmp_path / "rjudge_partial.json"
            if path.exists():
                seen[done] = json.loads(path.read_text())["n_records"]

        records = [_rj_record(i) for i in range(5)]
        report = rj._run_heuristic_incremental(
            records, out_dir=tmp_path, interval=2, on_progress=observer
        )
        # partial existed BEFORE later records were processed
        assert seen.get(2) == 2
        assert seen.get(4) == 4
        assert report["n_records"] == 5

    def test_rjudge_main_writes_partial_and_final(self, tmp_path, capsys):
        rc = rj._main(["--limit", "4", "--out", str(tmp_path)])
        assert rc == 0
        assert "[rjudge] 4/4" in capsys.readouterr().out
        final = json.loads((tmp_path / "rjudge_report.json").read_text())
        assert final["n_records"] == 4
        assert final["benchmark"] == "rjudge_safety_agreement"
        partial = json.loads((tmp_path / "rjudge_partial.json").read_text())
        assert partial["n_records"] == 4

    def test_strongreject_main_incremental_chunks_and_files(self, tmp_path, capsys):
        fixture = sr.load_strongreject_fixture()
        assert len(fixture) > 25  # guarantees at least two chunks
        rc = sr._main(["--out", str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert f"[strongreject] 25/{len(fixture)}" in out
        assert f"[strongreject] {len(fixture)}/{len(fixture)}" in out
        final = json.loads((tmp_path / "strongreject_report.json").read_text())
        assert final["total_cases"] == len(fixture)
        partial = json.loads((tmp_path / "strongreject_partial.json").read_text())
        assert partial["total_cases"] == len(fixture)

    def test_agentharm_main_prints_progress(self, capsys):
        fixture = ah.load_agentharm_fixture()
        rc = ah._main([])
        assert rc == 0
        assert f"[agentharm] {len(fixture)}/{len(fixture)}" in capsys.readouterr().out


class TestResponseSampling:
    def test_strongreject_samples_present_truncated_capped(self):
        long_prompt = "p" * 120
        records = [
            sr.StrongRejectRecord(forbidden_prompt=f"{long_prompt}-{i}",
                                  category="Violence", source="DAN")
            for i in range(45)
        ]
        target = _FakeTarget("r" * 300)
        report = sr.run_strongreject_live(target, records=records)
        samples = report["samples"]
        assert len(samples) == 40  # capped at 40 entries
        first = samples[0]
        assert set(first) == {"prompt_excerpt", "reply_excerpt", "score"}
        assert len(first["prompt_excerpt"]) == 80  # truncated from 120+
        assert len(first["reply_excerpt"]) == 200  # truncated from 300
        assert isinstance(first["score"], float)

    def test_agentharm_samples_present_with_compliant_flag(self):
        behaviors = [
            ah.AgentHarmBehavior(id=str(i), id_original=str(i), name=f"b{i}",
                                 category="Drugs", query="q" * 100 + str(i))
            for i in range(42)
        ]
        report = ah.run_agentharm_live(
            _FakeTarget("Of course, here is how." * 20), behaviors=behaviors)
        samples = report["samples"]
        assert len(samples) == 40
        entry = samples[0]
        assert set(entry) == {"prompt_excerpt", "reply_excerpt", "compliant"}
        assert len(entry["prompt_excerpt"]) <= 80
        assert len(entry["reply_excerpt"]) <= 200
        assert isinstance(entry["compliant"], bool)

    def test_samples_reflect_first_40_records_in_order(self):
        records = [
            sr.StrongRejectRecord(forbidden_prompt=f"prompt-{i}", category="Violence",
                                  source="DAN")
            for i in range(41)
        ]
        report = sr.run_strongreject_live(_FakeTarget(), records=records)
        assert [s["prompt_excerpt"] for s in report["samples"]][0] == "prompt-0"
        assert [s["prompt_excerpt"] for s in report["samples"]][-1] == "prompt-39"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
