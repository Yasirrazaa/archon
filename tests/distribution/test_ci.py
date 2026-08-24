"""CI pipeline contract tests (ROADMAP E0.1).

The repo's credibility depends on CI actually enforcing what developers run
locally. These tests pin the GitHub Actions workflows to a minimum contract so
the pipeline cannot silently rot: test matrix, lint, coverage gate, and a
release flow that produces tagged, SBOM-backed artifacts.
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


class TestCiWorkflow:
    def test_ci_workflow_exists_with_triggers(self) -> None:
        ci = _load("ci.yml")
        triggers = ci.get(True) or ci.get("on") or {}
        assert isinstance(triggers, dict)
        assert "push" in triggers, "CI must run on push"
        assert "pull_request" in triggers, "CI must run on PRs"

    def test_test_matrix_covers_supported_pythons(self) -> None:
        ci = _load("ci.yml")
        jobs = ci["jobs"]
        test_jobs = [
            job for job in jobs.values() if isinstance(job, dict) and "matrix" in str(job)
        ]
        assert test_jobs, "expected at least one matrix job"
        blob = str(test_jobs[0])
        for version in ("3.11", "3.12", "3.13"):
            assert version in blob, f"python {version} missing from test matrix"

    def test_lint_job_runs_ruff(self) -> None:
        ci = _load("ci.yml")
        blob = str(ci["jobs"])
        assert "ruff" in blob, "lint job must run ruff"

    def test_coverage_gate_enforces_minimum(self) -> None:
        ci = _load("ci.yml")
        blob = str(ci["jobs"])
        assert "--cov-fail-under" in blob or "cov-fail-under" in blob, (
            "coverage gate must fail the build below the threshold"
        )
        assert "85" in blob, "coverage threshold must be at least 85"

    def test_coverage_gate_runs_full_suite(self) -> None:
        ci = _load("ci.yml")
        blob = str(ci["jobs"])
        assert "pytest" in blob and "--cov" in blob


class TestReleaseWorkflow:
    def test_release_workflow_exists_and_tags(self) -> None:
        rel = _load("release.yml")
        triggers = rel.get(True) or rel.get("on") or {}
        assert isinstance(triggers, dict)
        assert "push" in triggers and "tags" in str(triggers["push"]), (
            "release workflow must trigger on version tags"
        )

    def test_release_builds_distribution_and_sbom(self) -> None:
        rel = _load("release.yml")
        blob = str(rel["jobs"])
        assert "build" in blob, "release must build distributions"
        assert "sbom" in blob.lower(), "release must produce an SBOM"

    def test_release_signs_artifacts_with_cosign(self) -> None:
        text = (WORKFLOWS / "release.yml").read_text()
        assert "cosign" in text.lower(), "release must sign artifacts with cosign"
        assert "cosign-installer" in text or "sign-blob" in text, (
            "release must install cosign and/or sign-blob the dist artifacts"
        )
        assert "sigstore/cosign-installer" in text, (
            "cosign must be installed via sigstore/cosign-installer action"
        )

    def test_release_signing_keeps_existing_steps(self) -> None:
        rel = _load("release.yml")
        jobs = str(rel["jobs"]).lower()
        assert "uv build" in jobs, "signing must not remove the build step"
        assert "sbom" in jobs, "signing must not remove the SBOM step"
        assert "softprops/action-gh-release" in jobs, (
            "signing must not remove the release-attachment step"
        )
        signature_assets = str(rel["jobs"])
        assert ".sig" in signature_assets and ".cert" in signature_assets, (
            "signature and certificate files must be produced/uploaded"
        )


class TestLocalToolingConfig:
    def test_ruff_configured_in_pyproject(self) -> None:
        text = (REPO_ROOT / "pyproject.toml").read_text()
        assert "[tool.ruff]" in text

    def test_coverage_configured_in_pyproject(self) -> None:
        text = (REPO_ROOT / "pyproject.toml").read_text()
        assert "[tool.coverage.run]" in text

    def test_pytest_cov_plugin_registered(self) -> None:
        text = (REPO_ROOT / "pyproject.toml").read_text()
        assert "pytest-cov" in text or "pytest_cov" in text
