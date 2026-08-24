"""Tests for persistence hardening (Sprint E0.4).

Covers the schema-migration framework (`archon_core.registry.migrations`),
the durable battle-results store (`archon_armor.results_store`), and the
`archon results` CLI surface.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3

import pytest
from archon_armor.results_store import ResultsStore
from archon_core.registry.migrations import MIGRATIONS, Migration, SchemaMigrator

# ---------------------------------------------------------------------------
# Schema migrations
# ---------------------------------------------------------------------------


class TestMigrationFramework:
    def test_migrations_list_has_at_least_three(self):
        assert len(MIGRATIONS) >= 3

    def test_migration_dataclass_fields(self):
        m = Migration(version=99, name="x", statements=["SELECT 1"])
        assert m.version == 99
        assert m.name == "x"
        assert m.statements == ["SELECT 1"]

    def test_apply_all_applies_in_order(self, tmp_path):
        mig = SchemaMigrator(str(tmp_path / "m.db"))
        applied = mig.apply_all()
        assert applied == sorted(applied)
        assert applied == [m.version for m in MIGRATIONS]

    def test_apply_all_is_idempotent(self, tmp_path):
        path = str(tmp_path / "m.db")
        first = SchemaMigrator(path).apply_all()
        second = SchemaMigrator(path).apply_all()
        assert first  # sanity: something was applied initially
        assert second == []
        # State unchanged: no duplicate rows in schema_migrations.
        conn = sqlite3.connect(path)
        versions = [r[0] for r in conn.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()]
        assert versions == first

    def test_migrations_create_expected_tables_and_columns(self, tmp_path):
        path = str(tmp_path / "m.db")
        SchemaMigrator(path).apply_all()
        conn = sqlite3.connect(path)

        agents_cols = {r[1] for r in conn.execute("PRAGMA table_info(agents)").fetchall()}
        assert {"agent_id", "name", "version", "policy_json"} <= agents_cols
        pk = [r[1] for r in conn.execute("PRAGMA table_info(agents)").fetchall() if r[5]]
        assert pk == ["agent_id"]

        battles_cols = {
            r[1]: r for r in conn.execute("PRAGMA table_info(battles)").fetchall()
        }
        assert {"battle_id", "agent_id", "status", "summary_json", "created_at"} <= set(battles_cols)

        indexes = {
            r[1]
            for r in conn.execute("PRAGMA index_list(battles)").fetchall()
        }
        assert any("agent" in idx.lower() for idx in indexes), indexes

    def test_accepts_existing_connection(self, tmp_path):
        conn = sqlite3.connect(str(tmp_path / "m.db"))
        migrator = SchemaMigrator(conn)
        assert migrator.apply_all() == [m.version for m in MIGRATIONS]
        assert migrator.applied_versions() == {m.version for m in MIGRATIONS}

    def test_migration_v4_adds_tenant_column_on_fresh_db(self, tmp_path):
        path = str(tmp_path / "m.db")
        SchemaMigrator(path).apply_all()
        conn = sqlite3.connect(path)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(battles)").fetchall()}
        assert "tenant_id" in cols

    def test_upgrade_from_v3_adds_tenant_without_data_loss(self, tmp_path):
        path = str(tmp_path / "m.db")
        # Construct a genuine v3-era database by applying only v1-v3 SQL.
        conn = sqlite3.connect(path)
        from archon_core.registry.migrations import _MIGRATIONS_TABLE_SQL

        conn.execute(_MIGRATIONS_TABLE_SQL)
        for m in MIGRATIONS:
            if m.version > 3:
                continue
            for stmt in m.statements:
                conn.execute(stmt)
            conn.execute(
                "INSERT INTO schema_migrations (version, name, applied_at)"
                " VALUES (?, ?, ?)",
                (m.version, m.name, "2020-01-01T00:00:00+00:00"),
            )
        conn.execute(
            "INSERT INTO battles (battle_id, agent_id, status, summary_json)"
            " VALUES ('b-legacy', 'agent-a', 'done', '{}')"
        )
        conn.commit()
        conn.close()

        # Re-open and migrate: v4 applies, legacy row survives.
        newly = SchemaMigrator(path).apply_all()
        assert 4 in newly
        conn = sqlite3.connect(path)
        rows = conn.execute(
            "SELECT battle_id, agent_id FROM battles"
        ).fetchall()
        assert rows == [("b-legacy", "agent-a")]
        cols = {r[1]: r for r in conn.execute("PRAGMA table_info(battles)").fetchall()}
        assert "tenant_id" in cols
        # Legacy rows read back as '' (constant default).
        tenants = [r[0] for r in conn.execute(
            "SELECT tenant_id FROM battles WHERE battle_id = 'b-legacy'"
        ).fetchall()]
        assert tenants == [""]

    def test_migration_v4_is_idempotent(self, tmp_path):
        path = str(tmp_path / "m.db")
        SchemaMigrator(path).apply_all()
        second = SchemaMigrator(path).apply_all()
        assert 4 not in second


# ---------------------------------------------------------------------------
# ResultsStore
# ---------------------------------------------------------------------------


class TestResultsStore:
    def test_save_and_get_roundtrip(self, tmp_path):
        store = ResultsStore(str(tmp_path / "results.db"))
        summary = {"total_probes": 4, "blocked": 3, "block_rate": 0.75}
        store.save_battle("b-1", "agent-a", summary)
        got = store.get_battle("b-1")
        assert got is not None
        assert got["battle_id"] == "b-1"
        assert got["agent_id"] == "agent-a"
        assert got["summary"]["block_rate"] == pytest.approx(0.75)

    def test_get_unknown_battle_returns_none(self, tmp_path):
        store = ResultsStore(str(tmp_path / "results.db"))
        assert store.get_battle("nope") is None

    def test_upsert_overwrites_summary(self, tmp_path):
        store = ResultsStore(str(tmp_path / "results.db"))
        store.save_battle("b-1", "agent-a", {"blocked": 0})
        store.save_battle("b-1", "agent-a", {"blocked": 9})
        got = store.get_battle("b-1")
        assert got["summary"] == {"blocked": 9}
        store2 = ResultsStore(str(tmp_path / "results.db"))
        assert len(store2.list_battles()) == 1

    def test_list_filters_by_agent_and_orders_newest_first(self, tmp_path):
        import time

        store = ResultsStore(str(tmp_path / "results.db"))
        for i, (bid, aid) in enumerate([
            ("b-old", "agent-a"),
            ("b-mid", "agent-b"),
            ("b-new", "agent-a"),
        ]):
            if i:
                time.sleep(0.01)
            store.save_battle(bid, aid, {"seq": i})

        all_rows = store.list_battles(limit=10)
        assert [r["battle_id"] for r in all_rows] == ["b-new", "b-mid", "b-old"]

        only_a = store.list_battles(agent_id="agent-a")
        assert [r["battle_id"] for r in only_a] == ["b-new", "b-old"]

        limited = store.list_battles(limit=2)
        assert [r["battle_id"] for r in limited] == ["b-new", "b-mid"]

    def test_share_token_is_deterministic_16_hex(self, tmp_path):
        t1 = ResultsStore(str(tmp_path / "a.db")).share_token("b-42")
        t2 = ResultsStore(str(tmp_path / "b.db")).share_token("b-42")
        assert t1 == t2
        assert len(t1) == 16
        int(t1, 16)  # hex-parseable
        expected = hashlib.sha256(b"b-42").hexdigest()[:16]
        assert t1 == expected

    def test_share_resolve_roundtrip(self, tmp_path):
        store = ResultsStore(str(tmp_path / "results.db"))
        store.save_battle("b-7", "agent-z", {"blocked": 1})
        token = store.share_token("b-7")
        resolved = store.resolve_share(token)
        assert resolved is not None
        assert resolved["battle_id"] == "b-7"

    def test_resolve_unknown_token_returns_none(self, tmp_path):
        store = ResultsStore(str(tmp_path / "results.db"))
        assert store.resolve_share("deadbeefdeadbeef") is None


# ---------------------------------------------------------------------------
# Tenant scoping (Sprint E2.7 item 43)
# ---------------------------------------------------------------------------


class TestTenantScoping:
    def test_save_with_tenant_id_is_stored(self, tmp_path):
        store = ResultsStore(str(tmp_path / "results.db"))
        store.save_battle("b-1", "agent-a", {"blocked": 1}, tenant_id="acme")
        got = store.get_battle("b-1")
        assert got is not None
        assert got["tenant_id"] == "acme"

    def test_save_without_tenant_defaults_to_default(self, tmp_path):
        store = ResultsStore(str(tmp_path / "results.db"))
        store.save_battle("b-1", "agent-a", {})
        assert store.get_battle("b-1")["tenant_id"] == "default"

    def test_list_filter_by_tenant_isolates_tenants(self, tmp_path):
        store = ResultsStore(str(tmp_path / "results.db"))
        store.save_battle("b-a1", "agent-a", {}, tenant_id="tenant-a")
        store.save_battle("b-b1", "agent-b", {}, tenant_id="tenant-b")
        store.save_battle("b-a2", "agent-c", {}, tenant_id="tenant-a")

        only_a = store.list_battles(tenant_id="tenant-a")
        assert {r["battle_id"] for r in only_a} == {"b-a1", "b-a2"}
        only_b = store.list_battles(tenant_id="tenant-b")
        assert [r["battle_id"] for r in only_b] == ["b-b1"]
        # Tenant + agent filters compose.
        both = store.list_battles(agent_id="agent-a", tenant_id="tenant-a")
        assert [r["battle_id"] for r in both] == ["b-a1"]

    def test_list_without_tenant_filter_sees_all(self, tmp_path):
        store = ResultsStore(str(tmp_path / "results.db"))
        store.save_battle("b-a", "agent-a", {}, tenant_id="tenant-a")
        store.save_battle("b-b", "agent-b", {}, tenant_id="tenant-b")
        store.save_battle("b-d", "agent-d", {})  # default tenant
        rows = store.list_battles()
        assert {r["battle_id"] for r in rows} == {"b-a", "b-b", "b-d"}

    def test_get_battle_includes_tenant_id_key(self, tmp_path):
        store = ResultsStore(str(tmp_path / "results.db"))
        store.save_battle("b-1", "agent-a", {}, tenant_id="acme")
        record = store.get_battle("b-1")
        assert "tenant_id" in record

    def test_upsert_updates_tenant_id(self, tmp_path):
        store = ResultsStore(str(tmp_path / "results.db"))
        store.save_battle("b-1", "agent-a", {}, tenant_id="tenant-old")
        store.save_battle("b-1", "agent-a", {"v": 2}, tenant_id="tenant-new")
        got = store.get_battle("b-1")
        assert got["tenant_id"] == "tenant-new"
        assert len(store.list_battles()) == 1
        # Reassignment is visible from the new tenant's filter, not the old.
        assert len(store.list_battles(tenant_id="tenant-new")) == 1
        assert store.list_battles(tenant_id="tenant-old") == []

    def test_legacy_store_rows_read_back_with_legacy_tenant(self, tmp_path):
        """A pre-v4 battle_results db upgrades transparently and keeps data."""
        import sqlite3 as _sq

        db = tmp_path / "legacy.db"
        conn = _sq.connect(str(db))
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS battle_results (
                battle_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                share_token TEXT NOT NULL UNIQUE
            )
            """
        )
        conn.execute(
            "INSERT INTO battle_results (battle_id, agent_id, summary_json,"
            " created_at, share_token) VALUES ('b-legacy', 'ag', '{}', 't0', 'tok')"
        )
        conn.commit()
        conn.close()

        store = ResultsStore(str(db))
        got = store.get_battle("b-legacy")
        assert got is not None
        assert got["battle_id"] == "b-legacy"
        assert got["tenant_id"] == ""
        # Legacy '' matches only explicit '' in filters (exact-match semantics).
        assert len(store.list_battles()) == 1
        assert store.list_battles(tenant_id="default") == []
        assert len(store.list_battles(tenant_id="")) == 1


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def _args(**kwargs) -> argparse.Namespace:
    ns = argparse.Namespace(
        db=str(kwargs.pop("db")),
        agent_id=kwargs.pop("agent_id", None),
        limit=kwargs.pop("limit", 50),
        share=kwargs.pop("share", ""),
        json=True,
    )
    assert not kwargs, kwargs
    return ns


class TestCliResultsCommand:
    def test_parser_accepts_flags(self):
        from archon_cli.main import build_parser

        parser = build_parser()
        args = parser.parse_args([
            "results", "--db", "/tmp/x.db",
            "--agent-id", "ag", "--limit", "7", "--share", "b-1",
        ])
        assert args.command == "results"
        assert args.db == "/tmp/x.db"
        assert args.agent_id == "ag"
        assert args.limit == 7
        assert args.share == "b-1"

    def test_cmd_results_lists_stored_battles(self, tmp_path, capsys):
        from archon_cli.main import _cmd_results

        db = tmp_path / "r.db"
        ResultsStore(str(db)).save_battle("b-1", "agent-a", {"blocked": 1})
        rc = _cmd_results(_args(db=db))
        out = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert out[0]["battle_id"] == "b-1"

    def test_cmd_results_share_prints_url_fragment(self, tmp_path, capsys):
        from archon_cli.main import _cmd_results

        db = tmp_path / "r.db"
        ResultsStore(str(db)).save_battle("b-share", "agent-a", {})
        rc = _cmd_results(_args(db=db, share="b-share"))
        captured = capsys.readouterr().out
        assert rc == 0
        token = ResultsStore(str(db)).share_token("b-share")
        assert f"?share={token}" in captured

    def test_cmd_results_empty_db(self, tmp_path, capsys):
        from archon_cli.main import _cmd_results

        rc = _cmd_results(_args(db=tmp_path / "empty.db"))
        out = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert out == []
