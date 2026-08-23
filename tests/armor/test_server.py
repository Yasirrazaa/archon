"""TDD Phase 10: server factory wiring (container entry point)."""

import pytest
from archon_armor.server import build_app
from fastapi.testclient import TestClient


def test_build_app_wires_full_production_stack(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCHON_REGISTRY_PATH", str(tmp_path / "registry.db"))
    monkeypatch.setenv("ARCHON_AUDIT_PATH", str(tmp_path / "audit.db"))
    monkeypatch.setenv("ARCHON_SPANS_JSONL", str(tmp_path / "spans.jsonl"))

    app = build_app()
    client = TestClient(app)

    # healthz works without identity
    assert client.get("/healthz").status_code == 200

    # signed-identity mode is enforced: unsigned request -> 401
    resp = client.post("/v1/chat/completions", json={
        "model": "m", "messages": [{"role": "user", "content": "hi"}]
    }, headers={"X-Agent-ID": "anyone"})
    assert resp.status_code == 401

    # infrastructure files get created
    assert (tmp_path / "registry.db").exists()


# ------------------------------------------------------------ fail fast ---


def test_initialize_app_fails_fast_on_broken_paths(monkeypatch):
    """A misconfigured container must crash at startup, not serve 500s.

    Cloud Run rejects revisions whose process exits before the startup probe
    passes; a silent ``app = None`` zombie instead accepts traffic and fails
    every request with an opaque ASGI error.
    """
    from archon_armor import server

    monkeypatch.setenv("ARCHON_SERVER_AUTOSTART", "1")
    monkeypatch.setenv("ARCHON_REGISTRY_PATH", "/nonexistent-dir-zz/reg.db")
    monkeypatch.setenv("ARCHON_AUDIT_PATH", "/nonexistent-dir-zz/audit.db")
    with pytest.raises(Exception):
        server.initialize_app()


def test_initialize_app_respects_autostart_off(monkeypatch):
    from archon_armor import server

    monkeypatch.setenv("ARCHON_SERVER_AUTOSTART", "0")
    server.initialize_app()  # must not raise; app stays untouched
