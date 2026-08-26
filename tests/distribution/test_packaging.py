"""Distribution packaging: Homebrew formula + npm wrapper must stay valid.

These tests keep the packaging artifacts honest as versions/entry points move:
a broken formula or shim fails CI here instead of failing on a user's machine.
"""

from __future__ import annotations

import json
import os
import re

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
FORMULA = os.path.join(REPO_ROOT, "packaging", "homebrew", "archon.rb")
NPM_DIR = os.path.join(REPO_ROOT, "packaging", "npm", "archon-security")


class TestHomebrewFormula:
    def test_formula_exists(self):
        assert os.path.isfile(FORMULA), "packaging/homebrew/archon.rb missing"

    def test_formula_class_and_structure(self):
        text = open(FORMULA, encoding="utf-8").read()
        assert re.search(r"class\s+Archon\s*<\s*Formula", text)
        assert "url" in text, "formula needs a source url"
        assert re.search(r'depends_on\s+"(python|uv|python@)', text), (
            "formula must declare a python/uv dependency"
        )

    def test_formula_installs_cli_entrypoint(self):
        text = open(FORMULA, encoding="utf-8").read()
        # The installed binary must be the real CLI entry point.
        assert '"archon"' in text or "'archon'" in text

    def test_formula_has_test_block(self):
        text = open(FORMULA, encoding="utf-8").read()
        assert re.search(r"test\s+do", text), "homebrew requires a test block"


class TestNpmWrapper:
    def test_package_json_valid(self):
        pkg = json.load(open(os.path.join(NPM_DIR, "package.json"), encoding="utf-8"))
        assert pkg["name"] == "archon-security"
        assert re.match(r"^\d+\.\d+\.\d+$", pkg["version"])
        assert "bin" in pkg and "archon" in pkg["bin"]

    def test_bin_shim_exists_and_invokes_python_cli(self):
        pkg = json.load(open(os.path.join(NPM_DIR, "package.json"), encoding="utf-8"))
        shim = os.path.join(NPM_DIR, pkg["bin"]["archon"])
        assert os.path.isfile(shim), f"{shim} missing"
        text = open(shim, encoding="utf-8").read()
        assert "archon" in text, "shim must invoke the archon CLI"
        assert re.search(r"(uv|pipx|pip)\b", text), (
            "shim must route through uv/pipx/pip"
        )

    def test_wrapper_readme_documents_prereqs(self):
        readme = os.path.join(NPM_DIR, "README.md")
        assert os.path.isfile(readme)
        text = open(readme, encoding="utf-8").read().lower()
        assert "uv" in text or "pipx" in text


class TestUvxPackaging:
    """Sprint 98: the repo must stay installable/runnable via `uvx`."""

    PYPROJECT = os.path.join(REPO_ROOT, "pyproject.toml")
    UVX_DOC = os.path.join(REPO_ROOT, "packaging", "uvx.md")
    UVX_ONE_LINER = "uvx --from git+https://github.com/Yasirrazaa/archon archon"

    def test_pyproject_declares_archon_script(self):
        text = open(self.PYPROJECT, encoding="utf-8").read()
        scripts = re.search(r"\[project\.scripts\]([^\[]*)", text)
        assert scripts, "[project.scripts] section missing"
        assert re.search(r'^archon\s*=\s*"archon_cli\.main:main"', scripts.group(1), re.M), (
            "uvx needs a console script named 'archon'"
        )

    def test_build_backend_supports_wheel_install(self):
        text = open(self.PYPROJECT, encoding="utf-8").read()
        assert re.search(r"build-backend\s*=\s*\"hatchling\.build\"", text)
        wheel = re.search(r"\[tool\.hatch\.build\.targets\.wheel\]\n(.*?)(?=\n\[)", text, re.S)
        assert wheel, "wheel build target missing"
        assert "packages/archon_cli" in wheel.group(1)

    def test_uvx_doc_exists_with_one_liner(self):
        assert os.path.isfile(self.UVX_DOC), "packaging/uvx.md missing"
        text = open(self.UVX_DOC, encoding="utf-8").read()
        assert self.UVX_ONE_LINER in text

    def test_readme_mentions_uvx(self):
        readme = os.path.join(REPO_ROOT, "README.md")
        text = open(readme, encoding="utf-8").read().lower()
        assert "uvx" in text
