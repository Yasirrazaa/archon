"""Sprint 95 — PIMiner strategy-library seeding.

Seeds ``strategies/`` at the repo root with seven distilled strategy cards
matching the markdown schema :class:`StrategyLibrary` parses (Target scope /
Task scope / Mechanism / Template / Examples / Failure conditions). Cards are
honest, research-derived descriptions distilled from PIMiner (arXiv:2608.05108);
templates are generic placeholders only.
"""

from __future__ import annotations

from pathlib import Path

from archon_core.attacks.piminer import (
    _STRATEGY_SECTIONS,
    ROUTER_TOP_K,
    StrategyLibrary,
    build_router_prompt,
)

SEED_DIR = Path(__file__).resolve().parents[2] / "strategies"

EXPECTED_SEEDS = frozenset(
    {
        "fabricated_procedure_gate",
        "forged_chat_turn",
        "entity_data_poisoning",
        "authenticated_principal_voice_forge",
        "appended_output_directive",
        "authority_shed_docstring",
        "false_history_forge",
    }
)


def _seed_library() -> StrategyLibrary:
    return StrategyLibrary(SEED_DIR)


# ------------------------------------------------------------------- seeding --


def test_seed_dir_contains_exactly_the_seven_strategy_files():
    files = {p.stem for p in SEED_DIR.glob("*.md")} - {"README"}
    assert files == EXPECTED_SEEDS


def test_load_dir_convenience_loads_all_seven():
    lib = StrategyLibrary.load_dir("strategies")
    assert set(lib.names) == EXPECTED_SEEDS


def test_all_seed_cards_have_all_required_sections():
    lib = _seed_library()
    for name in lib.names:
        missing = [s for s in _STRATEGY_SECTIONS if not lib.text(name) or True]
        card_sections = _card_section_names(lib.text(name))
        assert card_sections == set(_STRATEGY_SECTIONS), f"{name}: missing {missing}"


def test_seed_card_mechanisms_are_unique():
    lib = _seed_library()
    mechanisms = [
        lib.text(name).split("## Mechanism", 1)[1].split("##", 1)[0].strip()
        for name in lib.names
    ]
    normalized = [" ".join(m.split()) for m in mechanisms]
    assert len(set(normalized)) == len(EXPECTED_SEEDS)


def test_every_seed_cites_the_piminer_paper():
    lib = _seed_library()
    for name in lib.names:
        assert "arXiv:2608.05108" in lib.text(name), name


def test_seed_templates_are_generic_placeholders_not_exploits():
    lib = _seed_library()
    for name in lib.names:
        template = (
            lib.text(name).split("## Template", 1)[1].split("##", 1)[0].strip()
        )
        assert "{{" in template and "}}" in template, f"{name}: template too literal"
        assert len(template) < 600


def test_readme_documents_the_library_and_schema():
    readme = SEED_DIR / "README.md"
    assert readme.is_file()
    text = readme.read_text(encoding="utf-8")
    assert "StrategyLibrary" in text
    assert "Failure conditions" in text
    for stem in EXPECTED_SEEDS:
        assert stem in text, f"README does not list {stem}"


def test_seeded_library_feeds_router_prompt_round_trip():
    lib = _seed_library()
    prompt = build_router_prompt("agent summarizing invoices", lib.summaries())
    assert len(lib.summaries()) == len(EXPECTED_SEEDS)
    # Every summary carries target/task/mechanism routing lines.
    for summary in lib.summaries():
        assert "target:" in summary
        assert "task:" in summary
        assert "mechanism:" in summary
    assert f"Top-K={ROUTER_TOP_K}" in prompt


def _card_section_names(text: str) -> set[str]:
    return {
        line.lstrip("#").strip() for line in text.splitlines() if line.startswith("## ")
    }
