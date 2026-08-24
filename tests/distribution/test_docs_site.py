"""Docs site + vulnerability advisory program: structure guards.

Keeps the mkdocs scaffold honest as root docs move: if a page goes stale,
a link breaks, or the security contact disappears from SECURITY.md, CI
fails here instead of shipping an empty docs site.
"""

from __future__ import annotations

import os
import re

import yaml

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
MKDOCS_YML = os.path.join(REPO_ROOT, "mkdocs.yml")
DOCS_SITE = os.path.join(REPO_ROOT, "docs-site")
ADVISORY = os.path.join(REPO_ROOT, ".github", "ISSUE_TEMPLATE", "security_advisory.md")
SECURITY_MD = os.path.join(REPO_ROOT, "SECURITY.md")

EXPECTED_PAGES = ("index", "quickstart", "architecture", "security", "benchmarks")


def _read(*parts: str) -> str:
    path = os.path.join(REPO_ROOT, *parts)
    assert os.path.isfile(path), f"{path} missing"
    return open(path, encoding="utf-8").read()


class TestMkdocsConfig:
    def test_mkdocs_yml_exists_and_parses(self):
        config = yaml.safe_load(open(MKDOCS_YML, encoding="utf-8"))
        assert isinstance(config, dict)

    def test_site_name_and_repo_url(self):
        config = yaml.safe_load(open(MKDOCS_YML, encoding="utf-8"))
        assert config["site_name"] == "Archon"
        assert config["repo_url"] == "https://github.com/Yasirrazaa/archon"

    def test_nav_orders_the_five_pages(self):
        config = yaml.safe_load(open(MKDOCS_YML, encoding="utf-8"))
        nav_entries = [
            next(iter(entry.values())) if isinstance(entry, dict) else entry
            for entry in config["nav"]
        ]
        normalized = [str(v).lstrip("./") for v in nav_entries]
        assert [f"{page}.md" for page in EXPECTED_PAGES] == normalized


class TestDocsSitePages:
    def test_each_page_exists_and_is_non_trivial(self):
        for page in EXPECTED_PAGES:
            path = os.path.join(DOCS_SITE, f"{page}.md")
            assert os.path.isfile(path), f"docs-site/{page}.md missing"
            lines = open(path, encoding="utf-8").read().splitlines()
            assert len(lines) > 10, f"docs-site/{page}.md is too thin ({len(lines)} lines)"

    def test_quickstart_mirrors_armor_steps(self):
        text = _read("docs-site", "quickstart.md")
        assert "archon register" in text, "quickstart must cover registration"
        assert "serve" in text, "quickstart must cover running the proxy"

    def test_security_page_links_root_security_doc(self):
        text = _read("docs-site", "security.md")
        assert "SECURITY.md" in text, "security page must point at the canonical doc"

    def test_benchmarks_page_states_published_numbers_honestly(self):
        text = _read("docs-site", "benchmarks.md")
        assert "66.67" in text or "RESULTS.md" in text
        assert "pending" in text.lower(), "LLM-tier status must be stated"


class TestSecurityAdvisoryProgram:
    def test_advisory_template_exists_with_core_sections(self):
        text = _read(".github", "ISSUE_TEMPLATE", "security_advisory.md").lower()
        assert "severity" in text
        assert "reproduction" in text

    def test_security_md_has_concrete_contact(self):
        text = _read("SECURITY.md")
        assert re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", text), (
            "SECURITY.md must list an email-style contact address"
        )
