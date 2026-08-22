"""P1 backlog — Postgres registry backend (psycopg3).

Unit tests run against a fake DBAPI connection that records SQL and can raise
the real psycopg exceptions, so CRUD + error mapping are fully exercised
offline. A real-Postgres integration test runs when ARCHON_TEST_DATABASE_URL
is set (CI/`docker run postgres`).
"""

from __future__ import annotations

import json

import pytest

from archon_core.registry.base import (
    AgentCard,
    AgentNotFoundError,
    DuplicateAgentError,
    SecurityPolicy,
)


class FakeCursor:
    """psycopg3-shaped cursor: records SQL, serves canned rows/exceptions."""

    def __init__(self, rows=None, rowcount=None, errors=None):
        self.rows = list(rows or [])
        self._rowcount = rowcount if rowcount is not None else len(self.rows)
        self.errors = errors or {}
        self.executed: list[tuple[str, tuple | None]] = []

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        for fragment, exc in self.errors.items():
            if sql and fragment in sql:
                raise exc
        return self

    def fetchone(self):
        return self.rows.pop(0) if self.rows else None

    def fetchall(self):
        rows = self.rows
        self.rows = []
        return rows

    @property
    def rowcount(self) -> int:
        return self._rowcount

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeConn:
    def __init__(self, cursor=None):
        self._cursor = cursor or FakeCursor()
        self.closed = False

    def cursor(self):
        return self._cursor

    def close(self):
        self.closed = True


def _card(aid="a1", **over):
    return AgentCard(
        agent_id=aid, name="svc", version="2", policy=SecurityPolicy(
            block_categories=("jailbreak",), min_confidence=0.6,
        ),
        **over,
    )


def _reg(cursor):
    """PostgresRegistry wired to a fake connection (connector seam)."""
    from archon_core.registry.postgres import PostgresRegistry

    return PostgresRegistry(dsn="postgresql://test", connector=lambda: FakeConn(cursor))


def test_schema_bootstrapped_on_init():
    cursor = FakeCursor()
    _reg(cursor)
    ddls = [sql for sql, _ in cursor.executed if "CREATE TABLE" in sql]
    assert any("agents" in d for d in ddls)
    assert any("agent_id" in d for d in ddls)


def test_register_inserts_all_columns_with_json_policy():
    cursor = FakeCursor()
    reg = _reg(cursor)
    reg.register(_card(api_secret="sk-secret"))
    sql, params = cursor.executed[-1]
    assert "INSERT INTO agents" in sql
    assert isinstance(params, (tuple, list))
    loaded = json.loads(params[4])  # policy column
    assert loaded["block_categories"] == ["jailbreak"]
    assert loaded["min_confidence"] == 0.6
    assert params[6] == "sk-secret"  # api_secret


def test_register_duplicate_raises_duplicate_error():
    from psycopg.errors import UniqueViolation
    from archon_core.registry.postgres import PostgresRegistry

    cursor = FakeCursor(errors={"INSERT INTO agents": UniqueViolation("dup")})
    reg = _reg(cursor)
    with pytest.raises(DuplicateAgentError):
        reg.register(_card())


def test_get_returns_card_roundtrip():
    row = ("a-1", "svc", "2", '["http"]',
           json.dumps({"block_categories": ["jailbreak"], "min_confidence": 0.6,
                       "output_guardrails": True, "max_llm_budget": 4,
                       "upstream_base_url": "", "extra": {}}),
           "2026-08-22T00:00:00+00:00", "sk-secret")
    cursor = FakeCursor(rows=[row])
    card = _reg(cursor).get("a-1")
    assert card.agent_id == "a-1"
    assert card.policy.block_categories == ("jailbreak",)
    assert card.policy.min_confidence == 0.6
    assert card.api_secret == "sk-secret"


def test_get_missing_raises_not_found():
    with pytest.raises(AgentNotFoundError):
        _reg(FakeCursor(rows=[])).get("nope")


def test_update_policy_runs_update_and_maps_no_row():
    from archon_core.registry.postgres import PostgresRegistry

    cursor = FakeCursor(rowcount=0)
    with pytest.raises(AgentNotFoundError):
        _reg(cursor).update_policy("ghost", SecurityPolicy())

    cursor2 = FakeCursor(rowcount=1)
    _reg(cursor2).update_policy("a-1", SecurityPolicy(min_confidence=0.9))
    sql, params = cursor2.executed[-1]
    assert "UPDATE agents SET policy" in sql
    assert json.loads(params[0])["min_confidence"] == 0.9


def test_list_agents_returns_all():
    cards = _reg(FakeCursor(rows=[_row_tuple("a1"), _row_tuple("a2")])).list_agents()
    assert [c.agent_id for c in cards] == ["a1", "a2"]


def test_delete_reports_affinity():
    from archon_core.registry.postgres import PostgresRegistry

    assert _reg(FakeCursor(rowcount=1)).delete("a1") is True
    assert _reg(FakeCursor(rowcount=0)).delete("nope") is False


def _row_tuple(aid):
    return (aid, "svc", "1", '["a"]', "{}", "2026-01-01+00:00", None)

def test_real_postgres_integration_skips_without_env():
    """Run against a live Postgres when ARCHON_TEST_DATABASE_URL is set."""
    import os

    url = os.environ.get("ARCHON_TEST_DATABASE_URL")
    if not url:
        pytest.skip("set ARCHON_TEST_DATABASE_URL to run against live Postgres")
    from archon_core.registry.postgres import PostgresRegistry

    reg = PostgresRegistry(dsn=url)
    reg.delete("it-agent")
    reg.register(_card("it-agent"))
    got = reg.get("it-agent")
    assert got.policy.min_confidence == 0.6
    assert reg.delete("it-agent") is True


# ------------------------------------------------------------- server wire ---


def test_server_uses_postgres_when_database_url_set(monkeypatch, tmp_path):
    monkeypatch.setenv("ARCHON_DATABASE_URL", "postgresql://armor:pass@pg:5432/armor")
    monkeypatch.setenv("ARCHON_AUDIT_PATH", str(tmp_path / "a.db"))
    monkeypatch.setenv("ARCHON_SPANS_JSONL", str(tmp_path / "s.jsonl"))
    monkeypatch.setenv("ARCHON_SERVER_AUTOSTART", "0")

    import archon_armor.server as server
    from archon_core.registry import postgres as pg_mod

    seen = {}

    class FakePg:
        def __init__(self, dsn, **kw):
            seen["dsn"] = dsn
            self.dsn = dsn
            from archon_core.registry.memory import InMemoryRegistry

            self._fake = InMemoryRegistry()

        def register(self, card):
            self._fake.register(card)

        def get(self, agent_id):
            return self._fake.get(agent_id)

    monkeypatch.setattr(pg_mod, "PostgresRegistry", FakePg)
    app = server.build_app()
    assert seen["dsn"] == "postgresql://armor:pass@pg:5432/armor"
