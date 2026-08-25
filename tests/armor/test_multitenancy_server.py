"""Server-level wiring tests: SCIM mount + tenant enforcement middleware."""
import time

from archon_armor.app import create_app
from archon_core.registry.base import AgentCard, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry
from archon_core.security.authn import sign_request
from archon_core.security.scim import ScimUserStore
from archon_core.security.tenancy import TenantStore
from fastapi.testclient import TestClient


class _FakeUpstream:
    async def complete(self, payload, base_url):
        return {"choices": [{"message": {"content": "upstream-ok"}}]}


def _register(registry, agent_id="agent-x", secret="s3cret"):
    card = AgentCard(
        agent_id, "Agent X", "1.0.0",
        policy=SecurityPolicy(upstream_base_url="https://u.test/v1"),
        api_secret=secret,
    )
    registry.register(card)
    return secret


def _headers(secret, body, path="/v1/chat/completions"):
    ts = str(int(time.time()))
    return {
        "X-Agent-ID": "agent-x",
        "X-Timestamp": ts,
        "X-Signature": sign_request(secret, "POST", path, body, int(ts)),
        "Content-Type": "application/json",
    }


def _app(tenant_store=None, scim_store=None):
    registry = InMemoryRegistry()
    secret = _register(registry)
    app = create_app(
        registry, _FakeUpstream(), tenant_store=tenant_store, scim_store=scim_store,
    )
    return app, secret


def test_scim_router_mounted_and_lists_users(tmp_path):
    store = ScimUserStore(str(tmp_path / "scim.db"))
    store.create(user_name="a@x.test", display_name="A")
    app, _ = _app(scim_store=store)
    c = TestClient(app, raise_server_exceptions=False)
    r = c.get("/scim/v2/Users")
    assert r.status_code == 200
    assert r.json()["totalResults"] == 1


def test_tenant_middleware_allows_enrolled(tmp_path):
    ts_store = TenantStore(str(tmp_path / "t.db"))
    ts_store.create_tenant("acme", "Acme")
    ts_store.enroll_agent("agent-x", "acme")
    app, secret = _app(tenant_store=ts_store)
    c = TestClient(app, raise_server_exceptions=False)
    body = b'{"messages":[{"role":"user","content":"hi"}]}'
    h = _headers(secret, body)
    h["X-Tenant-ID"] = "acme"
    r = c.post("/v1/chat/completions", content=body, headers=h)
    assert r.status_code == 200


def test_tenant_middleware_blocks_cross_tenant(tmp_path):
    ts_store = TenantStore(str(tmp_path / "t.db"))
    ts_store.create_tenant("acme", "Acme")
    # agent-x NOT enrolled in acme
    app, secret = _app(tenant_store=ts_store)
    c = TestClient(app, raise_server_exceptions=False)
    body = b'{"messages":[{"role":"user","content":"hi"}]}'
    h = _headers(secret, body)
    h["X-Tenant-ID"] = "acme"
    r = c.post("/v1/chat/completions", content=body, headers=h)
    assert r.status_code == 403
    assert "not enrolled" in r.text


def test_no_tenant_header_keeps_single_tenant_behavior(tmp_path):
    ts_store = TenantStore(str(tmp_path / "t.db"))
    app, secret = _app(tenant_store=ts_store)
    c = TestClient(app, raise_server_exceptions=False)
    body = b'{"messages":[{"role":"user","content":"hi"}]}'
    r = c.post("/v1/chat/completions", content=body, headers=_headers(secret, body))
    assert r.status_code == 200
