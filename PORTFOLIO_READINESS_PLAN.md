# Archon — Portfolio Readiness Plan

## Executive Summary

**Archon** is a multi-turn adversarial agent-security testing framework built for the Lambda × Berkeley RDI AgentBeats Security Arena. It placed **13th overall, 6th Defend** on the private leaderboard with **49.7% avg win rate (14.4% Attack, 85.1% Defense)**.

This plan transforms Archon from a competition submission into a **production-quality portfolio project** demonstrating:
- **Agent-to-Agent (A2A) protocol** mastery
- **Google ADK** integration
- **Advanced Red/Blue teaming** architecture
- **Multi-turn stateful adversarial reasoning**
- **Defense-in-depth** security pipelines
- **Reproducible evaluation** infrastructure

---

## Current State Assessment

### ✅ Strengths (Portfolio-Ready)
| Area | Status | Evidence |
|------|--------|----------|
| Core Architecture | ✅ Strong | Generic orchestrator + plugin system, clean separation |
| A2A Protocol | ✅ Complete | All agents implement `AgentExecutor`, proper agent cards |
| Google ADK | ✅ Integrated | Used in agents, compatible with ADK patterns |
| Attacker (GOAT Loop) | ✅ Advanced | 7-round stateful, inline scoring, reconstruction attacks |
| Defender (4-Layer) | ✅ SOTA | Layer 0-4 with PPA, dynamic invariants, exchange classifier |
| Scenario Plugins | ✅ Extensible | 5 scenarios, injection + direct attack types |
| Normal User Test | ✅ Implemented | Helpfulness gate for leaderboard eligibility |
| Test Coverage | ✅ 286 tests | Unit tests across attacker/defender modules |
| Battle Logs | ✅ Rich | HTML + Markdown reports with extracted values |

### ⚠️ Gaps (Need Work for Portfolio)
| Area | Gap | Priority |
|------|-----|----------|
| **Documentation** | No architecture diagram, no API docs, no contribution guide | **P0** |
| **Quickstart** | Requires manual multi-process startup, no Docker Compose | **P0** |
| **CI/CD** | No GitHub Actions, no automated testing on push | **P0** |
| **Configuration** | Hardcoded ports, no env-driven config schema | **P1** |
| **Packaging** | `pyproject.toml` named `agentbeats-tutorial`, not `archon` | **P1** |
| **Demo/Showcase** | No notebook, no recorded battle, no live demo script | **P1** |
| **Security** | API keys in `.env`, no secret scanning, no threat model doc | **P1** |
| **Code Quality** | No pre-commit hooks, no linting in CI, some type ignores | **P2** |
| **Benchmarking** | No automated regression suite for defense/attack scores | **P2** |

---

## Phase 1: Foundation & Polish (Week 1)

### 1.1 Rebrand & Package Metadata
- [ ] Rename package in `pyproject.toml`: `agentbeats-tutorial` → `archon`
- [ ] Update `name`, `description`, `authors`, `license`, `classifiers`
- [ ] Add `readme = "README.md"`, `repository`, `homepage` URLs
- [ ] Add optional dependencies: `dev`, `docs`, `benchmark`
- [ ] Bump version to `0.1.0` (pre-1.0 for portfolio)

### 1.2 Configuration Management
- [ ] Create `config/schema.py` with Pydantic settings (pydantic-settings)
- [ ] Centralize all ports, timeouts, model names, API keys
- [ ] Support `.env` + `config.yaml` with precedence
- [ ] Add `Config` class with validation and defaults

### 1.3 Docker & Orchestration
- [ ] Write `Dockerfile` (multi-stage: builder → runtime, non-root user)
- [ ] Write `docker-compose.yml`:
  - `orchestrator` (port 9010)
  - `attacker` (port 9021)
  - `defender` (port 9020)
  - `normal_user` (port 9022)
  - `redis` (optional, for distributed task store)
- [ ] Add `docker-compose.override.yml.example` for local dev
- [ ] Add `Makefile` targets: `up`, `down`, `logs`, `test`, `benchmark`

### 1.4 Quickstart Script
- [ ] Create `scripts/quickstart.sh`:
  - Checks Docker/uv
  - Starts all services
  - Runs a sample battle (`portfolioiq`)
  - Opens battle log HTML in browser
- [ ] Add `uv run archon-battle portfolioiq` CLI entry point

---

## Phase 2: Documentation & Showcase (Week 1–2)

### 2.1 README Overhaul
Structure:
```
# Archon: Adversarial Agent Security Arena
- Badges: build, license, python version, A2A compatible
- One-paragraph pitch + competition results
- Architecture diagram (Mermaid or embedded PNG)
- Quickstart (Docker + 3 commands)
- Core Concepts (A2A, Green/Purple agents, Scenarios)
- Attacker Architecture (GOAT loop, reconstruction)
- Defender Architecture (4-layer pipeline)
- Scenarios table
- Running Battles
- Extending with New Scenarios
- Benchmarks & Results
- Contributing
- License
```

### 2.2 Architecture Documentation
- [ ] `docs/architecture.md`:
  - System overview diagram
  - Data flow (orchestrator → agents → A2A)
  - Round lifecycle
  - State management
  - LLM call budget enforcement
- [ ] `docs/attacker.md`: GOAT loop, techniques, inline scoring
- [ ] `docs/defender.md`: 4-layer pipeline, constitutional prompts
- [ ] `docs/scenarios.md`: Plugin API, creating new scenarios
- [ ] `docs/api.md`: A2A message formats, context schemas

### 2.3 Competition Results Showcase
- [ ] `docs/competition-results.md`:
  - Private leaderboard screenshot/table
  - Per-scenario win rates (attack/defend)
  - Battle log examples (successful attack, successful defense)
  - Ablation: what contributed most to defense score

### 2.4 Jupyter Notebook Demo
- [ ] `notebooks/archon_demo.ipynb`:
  - Load scenario
  - Run single battle programmatically
  - Visualize battle log (interactive HTML)
  - Compare attacker strategies
  - Show defender pipeline internals

### 2.5 Recorded Battle Assets
- [ ] Record 2-3 battles (asciinema or screen capture)
- [ ] Save HTML battle logs to `assets/battle-logs/`
- [ ] Embed in README

---

## Phase 3: CI/CD & Quality Gates (Week 2)

### 3.1 GitHub Actions Workflows
| Workfile | Triggers | Jobs |
|----------|----------|------|
| `ci.yml` | push, PR | lint, typecheck, test, build |
| `benchmark.yml` | schedule, manual | run full arena suite, publish artifacts |
| `release.yml` | tag push | build, publish to PyPI, create GitHub Release |
| `security.yml` | push, schedule | bandit, pip-audit, trivy, secret scan |

### 3.2 Pre-commit Hooks
- [ ] `.pre-commit-config.yaml`:
  - `ruff` (lint + format)
  - `mypy` (strict mode)
  - `pytest` (fast unit tests only)
  - `bandit` (security)
  - `check-yaml`, `check-toml`, `end-of-file-fixer`

### 3.3 Test Infrastructure
- [ ] `pytest.ini`: markers (`unit`, `integration`, `slow`, `benchmark`)
- [ ] `tests/conftest.py`: fixtures for agents, mock LLM
- [ ] Add integration test: full battle with mock agents
- [ ] Add property-based tests for `layer0_sanitize_input`, `spotlighting_wrap`

### 3.4 Code Quality
- [ ] Enable `mypy --strict` in CI (fix all errors)
- [ ] Add `ruff` config with `select = ["E", "F", "I", "W", "UP", "B", "C4", "SIM", "T20"]`
- [ ] Add `pyproject.toml` `[tool.ruff]` and `[tool.mypy]`
- [ ] Run `bandit -r` and fix findings

---

## Phase 4: Advanced Portfolio Features (Week 2–3)

### 4.1 Benchmark Suite
- [ ] `scripts/benchmark.py`:
  - Run all 5 scenarios × N battles
  - Aggregate win rates, latency, LLM calls
  - Output JSON + Markdown report
  - Compare against baseline (saved in `benchmarks/baseline.json`)
- [ ] GitHub Action to run benchmark nightly, fail on regression >5%

### 4.2 Threat Model Document
- [ ] `docs/THREAT_MODEL.md` (STRIDE):
  - Assets: agent endpoints, API keys, battle logs
  - Threats: prompt injection, tool leakage, DoS via LLM loops
  - Mitigations: Layer 0-4, timeout enforcement, call budgets
  - Residual risks

### 4.3 Extensibility Showcase
- [ ] Create 6th scenario: `custom_scenario_template/`
  - Step-by-step guide in `docs/creating-scenarios.md`
  - Example: "CodeReviewSabotage" (inject malicious code review comments)
- [ ] Document plugin API with type hints

### 4.4 Observability
- [ ] Add structured JSON logging (`structlog`)
- [ ] Add OpenTelemetry spans for round lifecycle
- [ ] Export metrics: rounds_defended, llm_calls, latency_p95

### 4.5 Security Hardening
- [ ] Move API keys to secret manager pattern (env only, no `.env` in repo)
- [ ] Add `detect-secrets` baseline
- [ ] Add `pip-audit` to CI
- [ ] Document BYOK (Bring Your Own Key) model

---

## Phase 5: Polish & Publish (Week 3)

### 5.1 GitHub Repository Setup
- [ ] Create repo: `github.com/yourname/archon`
- [ ] Branch protection: `main` requires PR + CI pass
- [ ] Labels: `bug`, `enhancement`, `scenario`, `benchmark`, `docs`
- [ ] Issue templates: bug, feature, scenario proposal
- [ ] Discussion categories: Q&A, Showcase, Ideas

### 5.2 Release Preparation
- [ ] `CHANGELOG.md` (Keep a Changelog format)
- [ ] Tag `v0.1.0` with release notes
- [ ] Publish to PyPI (optional, for installability)
- [ ] Add to `awesome-agent-security` lists

### 5.3 Portfolio Presentation Assets
- [ ] **One-pager PDF**: Architecture + Results + Tech Stack
- [ ] **30-second demo video**: Battle running in terminal + HTML log
- [ ] **Talking points** for interviews:
  - "Why A2A over REST?" → interoperability, streaming, agent cards
  - "How does the defender avoid false positives?" → Layer 1 paraphrase path, exchange classifier
  - "What's the reconstruction attack?" → defender is stateless, attacker accumulates fragments
  - "How do you handle the 4-LLM-call budget?" → inline scoring, adaptive temperature, guarded calls

---

## Technical Debt & Refactoring (Ongoing)

| File | Issue | Fix |
|------|-------|-----|
| `orchestrator.py` | 1200 lines, mixed concerns | Split into `battle_runner.py`, `normal_user_runner.py`, `result_formatter.py` |
| `goat_loop.py` | Large function soup | Extract `StrategySelector`, `FragmentCollector`, `SignalExtractor` classes |
| `pyrit_defense.py` | Async sync mixing, global state | Make pure functions, inject `generate_fn` cleanly |
| `agent.py` (attacker/defender) | Tight coupling to OpenAI | Abstract `LLMClient` protocol, support multiple providers |
| Templates | Jinja2 in `templates/` | Consider `promptdown` or structured prompt format |

---

## Success Criteria (Definition of Done)

| Criterion | Target |
|-----------|--------|
| `make up` starts full stack in <60s | ✅ |
| `make test` passes in <120s | ✅ |
| `make benchmark` produces report | ✅ |
| README renders beautifully on GitHub | ✅ |
| `docs/` builds with Sphinx/MkDocs | ✅ |
| CI green on `main` | ✅ |
| No `bandit` HIGH findings | ✅ |
| `mypy --strict` passes | ✅ |
| Battle log HTML opens in browser | ✅ |
| Notebook runs end-to-end | ✅ |
| Can add 6th scenario in <30 min | ✅ |

---

## Timeline Summary

| Week | Focus | Deliverables |
|------|-------|--------------|
| 1 | Foundation | Docker, Config, Quickstart, Rebrand |
| 1–2 | Docs & Showcase | README, Arch docs, Notebook, Battle logs |
| 2 | CI/CD | GitHub Actions, Pre-commit, Quality gates |
| 2–3 | Advanced | Benchmarks, Threat model, 6th scenario |
| 3 | Publish | Repo setup, Release, Portfolio assets |

---

## Risk Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| API costs during benchmark | Medium | High | Use local models (Ollama) for CI, cloud only for release |
| A2A SDK breaking changes | Low | Medium | Pin versions, test against SDK updates |
| Competition NDA restrictions | Low | High | Verify all code is original or competition-permitted |
| Docker complexity for reviewers | Medium | Medium | Provide hosted demo link + screenshots |

---

## Appendix: File Tree (Target)

```
archon/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml
│   │   ├── benchmark.yml
│   │   ├── release.yml
│   │   └── security.yml
│   └── ISSUE_TEMPLATE/
├── .pre-commit-config.yaml
├── Dockerfile
├── docker-compose.yml
├── docker-compose.override.yml.example
├── Makefile
├── pyproject.toml
├── README.md
├── CHANGELOG.md
├── LICENSE
├── config/
│   ├── __init__.py
│   └── schema.py
├── scripts/
│   ├── quickstart.sh
│   ├── benchmark.py
│   └── run_battle.py
├── src/
│   └── archon/
│       ├── __init__.py
│       ├── cli.py
│       ├── config.py
│       ├── logging.py
│       ├── models.py
│       └── llm_client.py
├── scenarios/
│   └── security_arena/
│       ├── __init__.py
│       ├── orchestrator.py
│       ├── arena_common.py
│       ├── plugins/
│       │   ├── base.py
│       │   ├── registry.py
│       │   ├── portfolioiq.py
│       │   ├── thingularity.py
│       │   ├── gymjailbreak.py
│       │   ├── resume_downgrade.py
│       │   └── example_medical.py
│       └── agents/
│           ├── attacker/
│           │   ├── agent.py
│           │   ├── goat_loop.py
│           │   ├── pyrit_converters.py
│           │   └── templates/
│           ├── defender/
│           │   ├── agent.py
│           │   ├── pyrit_defense.py
│           │   └── templates/
│           └── normal_user/
│               ├── agent.py
│               └── templates/
├── tests/
│   ├── conftest.py
│   ├── unit/
│   ├── integration/
│   └── benchmarks/
├── docs/
│   ├── architecture.md
│   ├── attacker.md
│   ├── defender.md
│   ├── scenarios.md
│   ├── api.md
│   ├── competition-results.md
│   ├── creating-scenarios.md
│   └── THREAT_MODEL.md
├── notebooks/
│   └── archon_demo.ipynb
├── assets/
│   ├── battle-logs/
│   └── architecture.png
└── benchmarks/
    └── baseline.json
```

---

*Generated as part of Archon portfolio readiness assessment. Update as work progresses.*