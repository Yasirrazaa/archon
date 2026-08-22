"""TDD Phase 10: server factory wiring (container entry point)."""

from fastapi.testclient import TestClient

from archon_armor.server import build_app


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
