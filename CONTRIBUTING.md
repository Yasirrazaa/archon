# Contributing to Archon

Thanks for your interest in improving Archon — an adversarial AI agent security
testing framework. This guide covers everything you need to get a development
environment running and land a contribution.

## Dev setup

Archon uses [uv](https://docs.astral.sh/uv/) exclusively. Python **3.11+** is required.

```bash
# Clone and install dependencies into a local .venv
uv sync

# ALWAYS run project tools through `uv run` so you hit the locked venv:
uv run pytest -q
uv run ruff check packages/ src/ tests/
```

Never invoke bare `python` or a globally-installed `pytest` — always `uv run <tool>`.

## Branch conventions

- `main` — stable; releases are cut from here.
- `hackathon-v2` — the current active development branch (v3 platform work).
  Feature branches fork from it; keep PRs targeted at the branch that owns the work.

## Test-driven development (TDD)

We practice **tests-first**: write the failing guard/unit test, watch it fail for
the right reason, then implement until green. Guard tests that pin down docs,
packaging, and CLI contracts live under `tests/distribution/`; behavior tests sit
next to the package they cover (`tests/armor/`, etc.). CI runs the full suite on
Python 3.11–3.13 with an **85% coverage gate** — new code must not drag coverage down.

## Code style

Linting is [ruff](https://docs.astral.sh/ruff/) with:

- `line-length = 100`
- `select = ["E4", "E7", "E9", "F", "I"]`, `ignore = ["E731"]`

Check before pushing:

```bash
uv run ruff check packages/ src/ tests/
```

## Running lint / tests / coverage locally

```bash
# Lint (same as CI)
uv run ruff check packages/ src/ tests/

# Full test suite
uv run pytest -q

# Coverage gate (85% minimum, same as CI)
uv run pytest --cov=packages --cov-report=term-missing --cov-fail-under=85 -q

# A single file while iterating
uv run pytest tests/distribution/test_community.py -q
```

## Adding a probe pack

Community probe packs live in [`contrib/`](contrib/README.md). Follow the rules
there — module-level `PROBES: list[Probe]`, namespace-prefixed names,
`contrib_`-prefixed categories, ≥5 unique non-trivial probes — then verify with:

```bash
uv run pytest tests/armor/test_contrib_gallery.py -q
```

See [contrib/README.md](contrib/README.md) for the full index and submission steps.

## Adding an attack target

Live attack targets implement the `TargetAdapter` ABC
(`packages/archon_core/targets/base.py`). Your adapter receives probe calls,
executes them against mutable state, and reports ground truth via
`resp.raw["attack_success"]: bool` — attackers such as `BranchingAttacker` treat
this flag as environment-state evidence that overrides lexical scoring.
Derive `attack_success` from real state transitions (a secret leaked, a sandbox
file mutated, a trust boundary crossed), never from string matching alone.

## Pull request checklist

- [ ] Tests written first (red), implementation makes them green
- [ ] `uv run pytest -q` passes locally
- [ ] `uv run ruff check packages/ src/ tests/` clean
- [ ] Coverage gate still satisfied (`--cov-fail-under=85`)
- [ ] Docs/changelog updated if user-facing (see `CHANGELOG.md`, Keep-a-Changelog format)
- [ ] No secrets committed; no public issue opened for security findings

Commit sign-off (`git commit -s`, DCO) is welcome but optional.

## Security issues

**Do not open public GitHub issues for security vulnerabilities.** Follow the
coordinated disclosure process in [SECURITY.md](SECURITY.md) §5 — email
security@archon.dev using the security advisory template. Non-security bugs and
feature requests use GitHub issues.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE) ("Copyright (c) 2026 Archon Contributors").
