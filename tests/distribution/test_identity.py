"""Sprint E0.2: project identity and packaging split checks."""

import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

COMPETITION_ONLY_DEPS = ["a2a-sdk", "google-adk", "google-genai", "openai"]


class TestLicenseIdentity:
    def test_license_exists(self):
        assert (REPO_ROOT / "LICENSE").is_file()

    def test_license_is_mit_attributed_to_archon(self):
        text = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")
        assert "MIT License" in text
        assert "Archon" in text
        assert "AgentBeats" not in text


class TestChangelog:
    def test_changelog_exists(self):
        assert (REPO_ROOT / "CHANGELOG.md").is_file()

    def test_changelog_has_100_section_with_platform_summary(self):
        text = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        assert "## [1.0.0]" in text
        for topic in (
            "defense pipeline",
            "armor proxy",
            "probe packs",
            "AgentDojo",
            "CI pipeline",
        ):
            assert topic.lower() in text.lower(), f"missing changelog topic: {topic}"


class TestPyprojectMetadata:
    @staticmethod
    def _load() -> dict:
        with open(REPO_ROOT / "pyproject.toml", "rb") as fh:
            return tomllib.load(fh)

    def test_version_is_100(self):
        data = self._load()
        assert data["project"]["version"] == "1.0.1"

    def test_license_is_mit(self):
        data = self._load()
        license_field = str(data["project"]["license"])
        assert "MIT" in license_field

    def test_competition_deps_are_optional_not_required(self):
        data = self._load()
        required = [dep.split(">")[0].split("<")[0].split("=")[0].strip().lower()
                    for dep in data["project"]["dependencies"]]
        extras = data["project"]["optional-dependencies"]
        assert "competition" in extras, (
            "competition-only deps must live under [project.optional-dependencies].competition"
        )
        competition_deps = [d.split(">")[0].split("<")[0].split("=")[0].strip().lower()
                            for d in extras["competition"]]
        for name in COMPETITION_ONLY_DEPS:
            assert name not in required, (
                f"{name} must not be a hard dependency of the root install"
            )
            assert name in competition_deps, f"{name} must be listed in the competition extra"
