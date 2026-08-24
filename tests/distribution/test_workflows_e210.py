"""E2.10 Augustus-derived hardening contract tests (ROADMAP items 62, 63, 65).

Pins the three CI-hygiene workflows (AI code review, secrets scan,
verify-pins) and the /metrics endpoint wiring in archon-armor.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"


def _load(name: str) -> dict:
    path = WORKFLOWS / name
    assert path.exists(), f"missing workflow: {name}"
    data = yaml.safe_load(path.read_text())
    assert isinstance(data, dict), f"{name} is not a mapping"
    return data


class TestAiReviewWorkflow:
    def test_exists_and_triggers_on_pr(self) -> None:
        wf = _load("ai-review.yml")
        triggers = wf.get(True) or wf.get("on") or {}
        assert "pull_request" in triggers

    def test_posts_comment_and_uses_diff(self) -> None:
        blob = (WORKFLOWS / "ai-review.yml").read_text()
        assert "createComment" in blob or "issue.createComment" in blob
        assert "git diff" in blob
        assert "pull-requests: write" in blob


class TestSecretsScanWorkflow:
    def test_exists_and_runs_on_push(self) -> None:
        wf = _load("secrets-scan.yml")
        triggers = wf.get(True) or wf.get("on") or {}
        assert "push" in triggers
        assert "pull_request" in triggers

    def test_scans_high_signal_patterns(self) -> None:
        blob = (WORKFLOWS / "secrets-scan.yml").read_text()
        for marker in ("sk-ant-", "AIza", "BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY"):
            assert marker in blob, f"missing pattern {marker}"
        assert "sys.exit(1)" in blob, "scan must fail the job on findings"


class TestVerifyPinsWorkflow:
    def test_exists_and_triggers_on_manifests(self) -> None:
        wf = _load("verify-pins.yml")
        triggers = wf.get(True) or wf.get("on") or {}
        push_paths = triggers["push"]["paths"]
        assert "pyproject.toml" in push_paths and "uv.lock" in push_paths

    def test_enforces_exact_pins_and_lockfile(self) -> None:
        blob = (WORKFLOWS / "verify-pins.yml").read_text()
        assert "==" in blob
        assert "uv.lock missing" in blob


class TestMetricsEndpointWiring:
    def _client(self):
        from archon_armor.app import create_app
        from archon_core.registry.base import AgentCard, SecurityPolicy
        from archon_core.registry.memory import InMemoryRegistry
        from archon_core.security.authn import AllowAllVerifier
        from fastapi.testclient import TestClient

        registry = InMemoryRegistry()
        registry.register(
            AgentCard(
                "metrics-agent",
                "Metrics Agent",
                "1.0.0",
                policy=SecurityPolicy(upstream_base_url="https://u.test/v1"),
            )
        )
        app = create_app(registry, upstream=None, identity=AllowAllVerifier())
        return TestClient(app)

    def test_metrics_route_served(self) -> None:
        client = self._client()
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]

    def test_metrics_render_contains_archon_counters(self) -> None:
        client = self._client()
        body = client.get("/metrics").text
        # Empty collector still exposes metric families via HELP/TYPE lines.
        assert "# TYPE archon_requests_total counter" in body
        assert "# TYPE archon_request_latency_ms histogram" in body

    def test_observe_request_reflected_in_endpoint(self) -> None:
        from archon_armor.metrics import ArmorMetrics

        m = ArmorMetrics()
        m.observe_request(agent_id="a1", blocked=True, latency_ms=12.0)
        rendered = m.render()
        assert 'agent_id="a1"' in rendered
        assert "archon_requests_blocked_total" in rendered
