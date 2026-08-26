"""Sprint 92: buff layer in benchmark series — offline deterministic tests."""

import pytest
from archon_armor.probes import get_pack
from archon_benchmarks.buffed_series import (
    BENCHMARK_NAME,
    render_buffed_md,
    run_buffed_series,
)

BUFFS = ("base64", "rot13", "leetspeak")


class TestFanOut:
    def test_probes_out_is_multiplicative(self):
        report = run_buffed_series(pack_name="core", buff_names=BUFFS)
        assert report["pack"] == "core"
        assert list(report["buffs"]) == list(BUFFS)
        assert report["probes_in"] == len(get_pack("core"))
        assert (
            report["probes_out"]
            == len(get_pack("core")) * len(BUFFS)
            == report["blocked"] * 0 + report["probes_out"]
        )

    def test_derived_names_carry_buff_suffix(self):
        from archon_core.attacks.buffs import Base64Buff, LeetspeakBuff, Rot13Buff

        probes = get_pack("core")[:2]
        buffs = [Base64Buff(), Rot13Buff(), LeetspeakBuff()]
        from archon_core.attacks.buffs import apply_buffs

        out = apply_buffs(probes, buffs)
        assert len(out) == 6
        assert {p.name for p in out} >= {
            f"{probe.name}__{b.name}" for probe in probes for b in buffs
        }


class TestMetrics:
    def test_block_rate_bounds(self):
        report = run_buffed_series()
        assert 0 <= report["blocked"] <= report["probes_out"]
        assert 0.0 <= report["block_rate"] <= 1.0
        for rate in report["per_buff_block_rate"].values():
            assert 0.0 <= rate <= 1.0

    def test_per_buff_keys_match_buffs(self):
        report = run_buffed_series(buff_names=BUFFS)
        assert set(report["per_buff_block_rate"]) == set(BUFFS)


class TestDeterminism:
    def test_same_seed_twice_equal(self):
        a = run_buffed_series(seed=1234)
        b = run_buffed_series(seed=1234)
        assert a == b


class TestMethodologyAndRender:
    def test_measurement_block(self):
        m = run_buffed_series(budget=5)["measurement"]
        assert m["attempt_budget"] == 5
        assert m["adaptivity"] == "static"
        assert m["judge"] == "deterministic-rules"
        assert m["upstream_model"] is None
        assert BENCHMARK_NAME == "buffed_series"

    def test_render_writes_file(self, tmp_path):
        report = run_buffed_series()
        out = tmp_path / "BUFFED.md"
        render_buffed_md(report, out)
        text = out.read_text()
        assert "buff" in text.lower()
        assert "block" in text.lower()

    def test_unknown_pack_raises(self):
        from archon_armor.probes import UnknownPackError

        with pytest.raises(UnknownPackError):
            run_buffed_series(pack_name="no_such_pack")
