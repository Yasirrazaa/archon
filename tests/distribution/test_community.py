"""Community scaffolding guards: CONTRIBUTING.md, CODE_OF_CONDUCT.md, issue template.

These tests keep the community docs honest as commands and processes move:
a doc that references a removed command or a missing enforcement contact
fails CI here instead of misleading a contributor.
"""

from __future__ import annotations

import os
import re

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
CONTRIBUTING = os.path.join(REPO_ROOT, "CONTRIBUTING.md")
COC = os.path.join(REPO_ROOT, "CODE_OF_CONDUCT.md")
FEATURE_TEMPLATE = os.path.join(REPO_ROOT, ".github", "ISSUE_TEMPLATE", "feature_request.md")
README = os.path.join(REPO_ROOT, "README.md")


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


class TestContributingGuide:
    def test_exists_nontrivial(self):
        assert os.path.isfile(CONTRIBUTING), "CONTRIBUTING.md missing at repo root"
        assert len(_read(CONTRIBUTING)) > 1000, "CONTRIBUTING.md suspiciously short"

    def test_documents_uv_workflow(self):
        text = _read(CONTRIBUTING)
        assert "uv sync" in text, "dev setup must mention `uv sync`"
        assert "uv run pytest" in text, "must document running tests via `uv run pytest`"

    def test_documents_ruff_style(self):
        text = _read(CONTRIBUTING)
        assert "ruff" in text
        assert "100" in text, "ruff line-length (100) must be stated"

    def test_documents_tdd_expectation(self):
        assert re.search(r"TDD|test[- ]first|tests first", _read(CONTRIBUTING), re.IGNORECASE)

    def test_links_contrib_pack_rules(self):
        text = _read(CONTRIBUTING)
        assert "contrib/README.md" in text, "must link contrib pack contribution rules"
        assert os.path.isfile(os.path.join(REPO_ROOT, "contrib", "README.md"))

    def test_documents_attack_target_convention(self):
        text = _read(CONTRIBUTING)
        assert "TargetAdapter" in text, "must explain the TargetAdapter seam"
        assert "attack_success" in text, "must explain raw['attack_success'] ground truth"

    def test_routes_security_issues_to_security_md(self):
        text = _read(CONTRIBUTING).lower()
        assert "security.md" in text, "security reports must route to SECURITY.md process"

    def test_states_mit_license(self):
        text = _read(CONTRIBUTING)
        assert "MIT" in text, "licensing note required"


class TestCodeOfConduct:
    def test_exists_nontrivial(self):
        assert os.path.isfile(COC), "CODE_OF_CONDUCT.md missing at repo root"
        assert len(_read(COC)) > 2000, "COC suspiciously short for Contributor Covenant"

    def test_is_contributor_covenant(self):
        assert "Contributor Covenant" in _read(COC)

    def test_has_enforcement_contact(self):
        text = _read(COC)
        match = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", text)
        assert match, "COC must include an enforcement contact email"
        assert "@" in match.group(0)

    def test_mentions_enforcement(self):
        assert "enforcement@archon.dev" in _read(COC)


class TestFeatureRequestTemplate:
    def test_exists(self):
        assert os.path.isfile(FEATURE_TEMPLATE)

    def test_front_matter_matches_security_template_pattern(self):
        security = _read(
            os.path.join(REPO_ROOT, ".github", "ISSUE_TEMPLATE", "security_advisory.md")
        )
        feature = _read(FEATURE_TEMPLATE)
        for key in ("name:", "about:", "labels:"):
            assert key in feature, f"front-matter `{key}` missing"
            assert key in security, f"reference template lost `{key}` — update this guard"
        # front-matter delimiters present
        stripped = feature.strip()
        assert stripped.startswith("---") and "---" in stripped[3:]

    def test_covers_required_sections(self):
        text = _read(FEATURE_TEMPLATE).lower()
        for section in ("problem", "proposed solution", "alternatives", "additional context"):
            assert section in text, f"template section `{section}` missing"

    def test_does_not_collide_with_security_label(self):
        text = _read(FEATURE_TEMPLATE)
        labels_line = next(line for line in text.splitlines() if line.startswith("labels:"))
        assert "security" not in labels_line.lower(), (
            "feature requests must not use the reserved `security` label"
        )


class TestReferencedCommandsExist:
    def test_spot_check_archon_plugins_ci_in_readme(self):
        """If CONTRIBUTING references a README-documented command, it must still exist."""
        contributing = _read(CONTRIBUTING)
        readme = _read(README)
        if "archon plugins --ci" in contributing or "archon scan" in contributing:
            assert "archon plugins --ci" in readme or "archon scan" in readme, (
                "README no longer documents the referenced CLI verification command"
            )

    def test_contrib_readme_still_documents_plugin_inventory_command(self):
        contrib_readme = _read(os.path.join(REPO_ROOT, "contrib", "README.md"))
        assert "archon plugins --ci" in contrib_readme, (
            "contrib/README.md inventory command changed — update CONTRIBUTING.md links"
        )
