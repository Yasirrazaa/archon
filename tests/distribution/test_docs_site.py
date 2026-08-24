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

ARCHITECTURE_DIAGRAM = "architecture-diagram"

TUTORIALS = (
    "first-memory-poisoning-battle",
    "first-tool-sandbox-battle",
    "multi-agent-trust-boundary",
    "mcp-rug-pull",
    "supply-chain-pinning",
    "approval-fatigue-trust",
    "rogue-stego-channels",
    "beyond-asi-gap-patterns",
)


def _read(*parts: str) -> str:
    path = os.path.join(REPO_ROOT, *parts)
    assert os.path.isfile(path), f"{path} missing"
    return open(path, encoding="utf-8").read()


def _mkdocs_config() -> dict:
    """Load mkdocs.yml; falls back past safe_load because superfences'
    mermaid ``format`` uses the ``!!python/name`` tag, which needs a
    python-name resolver even when pymdownx itself is not installed."""
    with open(MKDOCS_YML, encoding="utf-8") as fh:
        text = fh.read()
    try:
        return yaml.safe_load(text)
    except yaml.constructor.ConstructorError:
        class PythonNameLoader(yaml.SafeLoader):
            pass

        PythonNameLoader.add_multi_constructor(
            "tag:yaml.org,2002:python/name:", lambda _loader, suffix, _node: suffix
        )
        return yaml.load(text, Loader=PythonNameLoader)


class TestMkdocsConfig:
    def test_mkdocs_yml_exists_and_parses(self):
        config = _mkdocs_config()
        assert isinstance(config, dict)

    def test_site_name_and_repo_url(self):
        config = _mkdocs_config()
        assert config["site_name"] == "Archon"
        assert config["repo_url"] == "https://github.com/Yasirrazaa/archon"

    def test_nav_keeps_the_five_core_pages_in_order(self):
        config = _mkdocs_config()
        nav_entries = [
            next(iter(entry.values())) if isinstance(entry, dict) else entry
            for entry in config["nav"]
        ]
        normalized = [str(v).lstrip("./") for v in nav_entries]
        cursor = 0
        for page in EXPECTED_PAGES:
            while cursor < len(normalized) and normalized[cursor] != f"{page}.md":
                cursor += 1
            assert cursor < len(normalized), (
                f"nav dropped core page {page}.md or reordered the core pages"
            )


class TestArchitectureDiagramPage:
    def test_page_exists_with_at_least_three_mermaid_fences(self):
        text = _read("docs-site", f"{ARCHITECTURE_DIAGRAM}.md")
        fences = re.findall(r"^```mermaid", text, flags=re.MULTILINE)
        assert len(fences) >= 3, f"expected >=3 mermaid fences, found {len(fences)}"

    def test_diagrams_cover_request_flow_battle_loop_and_deployment(self):
        text = _read("docs-site", f"{ARCHITECTURE_DIAGRAM}.md").lower()
        assert "archon-armor" in text
        assert "battlemanager" in text or "red/blue" in text.replace("-", "/")
        assert "cloud run" in text
        assert "cloud trace" in text


class TestTutorials:
    def test_index_exists_and_links_every_tutorial(self):
        index = _read("docs-site", "tutorials", "index.md")
        for slug in TUTORIALS:
            assert f"{slug}.md" in index, f"tutorials/index.md must link {slug}"

    def test_every_tutorial_exists_and_is_non_trivial(self):
        for slug in TUTORIALS:
            path = os.path.join(DOCS_SITE, "tutorials", f"{slug}.md")
            assert os.path.isfile(path), f"docs-site/tutorials/{slug}.md missing"
            lines = open(path, encoding="utf-8").read().splitlines()
            assert len(lines) > 20, f"tutorial {slug} is too thin ({len(lines)} lines)"

    def test_every_tutorial_states_threat_model_and_asi_mapping(self):
        for slug in TUTORIALS:
            text = _read("docs-site", "tutorials", f"{slug}.md")
            assert "## Threat model" in text, f"{slug} needs a Threat model section"
            assert re.search(r"ASI\d{2}", text), f"{slug} must state its OWASP ASI mapping"

    def test_every_tutorial_has_a_copy_pasteable_uv_run_command(self):
        for slug in TUTORIALS:
            text = _read("docs-site", "tutorials", f"{slug}.md")
            fences = re.findall(r"```(?:bash|shell)\n(.*?)```", text, flags=re.DOTALL)
            assert any("uv run" in fence for fence in fences), (
                f"{slug} must include at least one `uv run` command in a bash fence"
            )

    def test_every_tutorial_has_defense_toggle_section(self):
        for slug in TUTORIALS:
            text = _read("docs-site", "tutorials", f"{slug}.md")
            assert "## Defense toggle" in text, f"{slug} needs a Defense toggle section"

    def test_mkdocs_nav_includes_tutorials_and_architecture_diagram(self):
        config = _mkdocs_config()
        nav_entries = [
            next(iter(entry.values())) if isinstance(entry, dict) else entry
            for entry in config["nav"]
        ]
        normalized = [str(v).lstrip("./") for v in nav_entries]
        assert "architecture-diagram.md" in normalized
        assert "tutorials/index.md" in normalized
        for slug in TUTORIALS:
            assert f"tutorials/{slug}.md" in normalized

    def test_superfences_mermaid_config_present(self):
        config = _mkdocs_config()
        exts = config.get("markdown_extensions", [])
        names = {
            next(iter(e)) if isinstance(e, dict) else e for e in exts
        }
        assert "pymdownx.superfences" in names, "mermaid rendering needs superfences"
        fences = []
        for ext in exts:
            if isinstance(ext, dict) and "pymdownx.superfences" in ext:
                fences = ext["pymdownx.superfences"].get("custom_fences", [])
        assert any(
            f.get("name") == "mermaid" and f.get("class") == "mermaid"
            for f in fences
        ), "superfences custom_fences must register mermaid"


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
