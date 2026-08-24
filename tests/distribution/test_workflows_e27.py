"""E2.7 CI-workflow sprint contract tests (sprints 36 and 42).

Sprint 36 pins a monthly kill-switch drill workflow that exercises
``archon_core.security.killswitch.KillSwitch`` end-to-end in CI.
Sprint 42 pins a docs workflow publishing MkDocs Material to GitHub Pages.
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


class TestKillSwitchDrillWorkflow:
    def test_workflow_exists(self) -> None:
        _load("killswitch_drill.yml")

    def test_triggers_monthly_cron_and_manual_dispatch(self) -> None:
        wf = _load("killswitch_drill.yml")
        triggers = wf.get(True) or wf.get("on") or {}
        assert isinstance(triggers, dict)
        assert "workflow_dispatch" in triggers, "drill must be manually runnable"
        schedule = triggers.get("schedule")
        assert schedule, "drill must run on a schedule"
        crons = [entry.get("cron", "") for entry in schedule if isinstance(entry, dict)]
        monthly = any(
            len(parts) == 5 and parts[2] == "1" and parts[4] == "*"
            for parts in (c.split() for c in crons)
        )
        assert monthly, f"expected a monthly cron (day-of-month 1), got {crons}"

    def test_drill_exercises_killswitch_revocation_and_restore(self) -> None:
        wf = _load("killswitch_drill.yml")
        blob = str(wf["jobs"])
        assert "KillSwitch" in blob, "drill must exercise KillSwitch"
        assert "archon_core.security.killswitch" in blob, (
            "drill must import the real kill-switch module"
        )
        assert "mttc" in blob, "drill must assert on MTTC latency"
        assert "1000" in blob, "MTTC assertion must enforce sub-second revocation"
        assert "restore" in blob.lower(), "drill must restore after revocation"

    def test_drill_installs_uv_environment(self) -> None:
        wf = _load("killswitch_drill.yml")
        blob = str(wf["jobs"])
        assert "astral-sh/setup-uv" in blob, "drill needs uv setup"
        assert "uv sync" in blob, "drill must sync the project environment"


class TestDocsWorkflow:
    def test_workflow_exists(self) -> None:
        _load("docs.yml")

    def test_triggers_on_push_to_docs_paths_and_dispatch(self) -> None:
        wf = _load("docs.yml")
        triggers = wf.get(True) or wf.get("on") or {}
        assert isinstance(triggers, dict)
        assert "push" in triggers, "docs must deploy on push"
        push_blob = str(triggers["push"])
        assert "mkdocs.yml" in push_blob or "docs-site" in push_blob, (
            "push trigger should scope to mkdocs.yml / docs-site changes"
        )
        assert "workflow_dispatch" in triggers

    def test_deploys_mkdocs_to_github_pages(self) -> None:
        wf = _load("docs.yml")
        blob = str(wf["jobs"])
        assert "mkdocs" in blob.lower(), "docs workflow must use mkdocs"
        assert "mkdocs-material" in blob.lower() or "material" in blob.lower(), (
            "docs must use the Material theme"
        )
        pages_mechanism = "gh-deploy" in blob or "deploy-pages" in blob
        assert pages_mechanism, "docs must deploy to GitHub Pages"

    def test_pages_write_permission(self) -> None:
        wf = _load("docs.yml")
        perms = wf.get("permissions") or {}
        assert perms.get("pages") == "write", "Pages deployment requires pages: write"
