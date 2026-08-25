"""Tests for the reproducible live-LLM benchmark runner (repo-resident).

Offline only: every external call goes through httpx.MockTransport or fakes.
The real network phases are exercised by running the module's ``__main__``
with an API key — documented in RESULTS.md.
"""

from __future__ import annotations

import json

import httpx
import pytest
from archon_benchmarks import live_runner as lr


class TestCompleteShim:
    def test_returns_content_on_200(self):
        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content.decode())
            assert body["messages"][0]["content"] == "ping"
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": "pong"}}]},
            )

        shim = lr.CompleteShim(
            base_url="https://x.test/v1",
            api_key="k",
            model="m",
            transport=httpx.MockTransport(handler),
        )
        assert shim.complete("ping") == "pong"

    def test_retries_on_429_then_succeeds(self):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] < 3:
                return httpx.Response(429, json={"error": "rate limited"})
            return httpx.Response(
                200, json={"choices": [{"message": {"content": "ok"}}]}
            )

        shim = lr.CompleteShim(
            base_url="https://x.test/v1",
            api_key="k",
            model="m",
            transport=httpx.MockTransport(handler),
            backoff_seconds=0.0,
        )
        assert shim.complete("q") == "ok"
        assert calls["n"] == 3

    def test_raises_after_exhausting_retries(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, json={"error": "boom"})

        shim = lr.CompleteShim(
            base_url="https://x.test/v1",
            api_key="k",
            model="m",
            transport=httpx.MockTransport(handler),
            max_retries=2,
            backoff_seconds=0.0,
        )
        with pytest.raises(RuntimeError):
            shim.complete("q")

    def test_never_retries_4xx_client_errors(self):
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(401, json={"error": "bad key"})

        shim = lr.CompleteShim(
            base_url="https://x.test/v1",
            api_key="bad",
            model="m",
            transport=httpx.MockTransport(handler),
            backoff_seconds=0.0,
        )
        with pytest.raises(RuntimeError):
            shim.complete("q")
        assert calls["n"] == 1


class TestEnvConfig:
    def test_resolves_key_from_openrouter_env(self, monkeypatch):
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
        monkeypatch.delenv("ARCHON_ATTACK_PROVIDER_API_KEY", raising=False)
        cfg = lr.resolve_config()
        assert cfg["api_key"] == "sk-or-test"
        assert cfg["base_url"] == "https://openrouter.ai/api/v1"
        assert cfg["model"]  # non-empty default

    def test_explicit_args_override_env(self, monkeypatch):
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
        cfg = lr.resolve_config(
            base_url="https://other.test/v1", model="custom-model"
        )
        assert cfg["base_url"] == "https://other.test/v1"
        assert cfg["model"] == "custom-model"

    def test_missing_key_raises(self, monkeypatch):
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        monkeypatch.delenv("ARCHON_ATTACK_PROVIDER_API_KEY", raising=False)
        with pytest.raises(RuntimeError, match="API key"):
            lr.resolve_config(env_file=None)


class TestPhaseRegistry:
    def test_all_four_phases_registered(self):
        assert set(lr.PHASES) == {"strongreject", "agentharm", "rjudge", "piminer"}

    def test_phase_fns_are_callable(self):
        for fn in lr.PHASES.values():
            assert callable(fn)


class TestResumeAndSave:
    def test_save_report_writes_json(self, tmp_path):
        path = lr.save_report(tmp_path, "strongreject", {"block_rate": 0.5})
        assert path.exists()
        assert json.loads(path.read_text())["block_rate"] == 0.5

    def test_piminer_resume_skips_completed_tasks(self, tmp_path):
        partial = {
            "completed": ["task_1", "task_2"],
            "results": [
                {"goal": "g1", "success": True},
                {"goal": "g2", "success": False},
            ],
        }
        (tmp_path / "piminer_vs_shield_partial.json").write_text(
            json.dumps(partial)
        )
        state = lr.load_piminer_state(tmp_path)
        assert state is not None
        assert state["completed"] == ["task_1", "task_2"]
        assert len(state["results"]) == 2

    def test_piminer_resume_missing_file_returns_none(self, tmp_path):
        assert lr.load_piminer_state(tmp_path) is None

    def test_partial_state_saved_after_each_task(self, tmp_path):
        lr.save_piminer_partial(tmp_path, ["t1"], [{"goal": "g"}])
        loaded = json.loads(
            (tmp_path / "piminer_vs_shield_partial.json").read_text()
        )
        assert loaded["completed"] == ["t1"]
