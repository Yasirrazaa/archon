"""Sprint W8-D — Editor-grade DX wiring for the archon.yaml config schema.

Wave 7 shipped schemas/archon-config.schema.json; this pins the editor wiring
so VS Code users get autocomplete + validation on archon.yaml out of the box
(promptfoo-grade DX closure). Guards: .vscode/settings.json maps the shipped
schema onto both YAML targets and the referenced schema file must actually
exist at that relative path.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
VSCODE = REPO_ROOT / ".vscode"
SETTINGS = VSCODE / "settings.json"
EXTENSIONS = VSCODE / "extensions.json"
README = REPO_ROOT / "README.md"


def _load_json(path: Path) -> dict:
    assert path.is_file(), f"missing file: {path}"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{path.name} is not a JSON object"
    return data


class TestSettings:
    def test_settings_exists_and_parses(self) -> None:
        assert SETTINGS.is_file()
        json.loads(SETTINGS.read_text(encoding="utf-8"))

    def test_schema_mapped_to_both_yaml_targets(self) -> None:
        settings = _load_json(SETTINGS)
        schemas = settings["yaml.schemas"]
        targets = schemas["./schemas/archon-config.schema.json"]
        assert "examples/archon.yaml" in targets
        assert "archon.yaml" in targets

    def test_referenced_schema_path_resolves_from_repo_root(self) -> None:
        # Critical regression guard: a renamed/moved schema silently kills
        # editor validation. Resolve the relative path exactly as VS Code does.
        settings = _load_json(SETTINGS)
        schemas = settings["yaml.schemas"]
        (relative, *_rest) = schemas.keys()
        assert (REPO_ROOT / relative).is_file()

    def test_schemastore_enabled(self) -> None:
        settings = _load_json(SETTINGS)
        assert settings["yaml.schemaStore.enable"] is True

    def test_format_on_save_disabled(self) -> None:
        settings = _load_json(SETTINGS)
        assert settings["editor.formatOnSave"] is False

    def test_archon_yaml_associated_with_yaml_language(self) -> None:
        settings = _load_json(SETTINGS)
        assert settings["files.associations"]["archon.yaml"] == "yaml"


class TestExtensions:
    def test_extensions_exists_and_parses(self) -> None:
        assert EXTENSIONS.is_file()
        data = json.loads(EXTENSIONS.read_text(encoding="utf-8"))
        recs = data.get("recommendations", [])
        assert isinstance(recs, list)

    def test_recommends_vscode_yaml_extension(self) -> None:
        recs = _load_json(EXTENSIONS).get("recommendations", [])
        assert "redhat.vscode-yaml" in recs

    def test_recommends_python_and_ruff_extensions(self) -> None:
        recs = _load_json(EXTENSIONS).get("recommendations", [])
        assert "ms-python.python" in recs
        assert "charliermarsh.ruff" in recs


class TestReadme:
    def test_readme_documents_editor_autocomplete_wiring(self) -> None:
        text = README.read_text(encoding="utf-8")
        assert ("yaml.schemas" in text) or ("autocomplete" in text.lower())
