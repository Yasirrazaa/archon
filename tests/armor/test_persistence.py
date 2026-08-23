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
