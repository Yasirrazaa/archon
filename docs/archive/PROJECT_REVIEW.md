# Archon — Deep Project Review

> ⚠️ **ARCHIVE NOTICE (Aug 22, 2026):** Architecture facts here remain accurate; strategy sections are superseded by [`BLUEPRINT_HACKATHON.md`](../../BLUEPRINT_HACKATHON.md) §3–§5 (core-first architecture, verified gaps, competition layer).


# Archon — Deep Project Review

> **Date:** July 1, 2026
> **Purpose:** Comprehensive architectural review, strengths/weaknesses analysis, and transformation readiness assessment

---

## 1. Executive Summary

Archon is an **adversarial AI agent security testing framework** built for the Lambda × Berkeley RDI AgentBeats Security Arena competition using A2A protocol and Google ADK. It ranked **13th overall** (18 Attack and 6 Defend) on the Private leaderboard with an avg win rate of 49.7% (14.4% Attack and 85.1% Defense win rate) — a strong result, but with clear gaps to the top.

**What makes this project special:**

- One of the few tools that tests **attack AND defense** in the same framework
- **Multi-turn agentic battles** (7 rounds) with persistent attacker state
- **7-layer defense pipeline** rivaling production-grade systems
- **Scenario-agnostic architecture** that generalizes to unseen scenarios

---

## 2. Architecture Deep Dive

### 2.1 The Three-Layer Architecture

```
┌──────────────────────────────────────────────────────┐
│                  Layer 1: CLI & Runner                │
│  src/agentbeats/                                      │
│  ├── run_scenario.py     # Entry point                │
│  ├── client_cli.py       # A2A client                 │
│  ├── client.py           # Message sending            │
│  ├── green_executor.py   # Orchestrator wrapper       │
│  ├── models.py           # EvalRequest/Result         │
│  └── tool_provider.py    # Agent communication        │
├──────────────────────────────────────────────────────┤
│                  Layer 2: Orchestrator                │
│  scenarios/security_arena/                            │
│  ├── orchestrator.py     # Battle manager             │
│  ├── arena_common.py     # Shared models              │
│  └── plugins/            # Scenario plugin system     │
│      ├── base.py         # ScenarioPlugin ABC         │
│      ├── registry.py     # Plugin loader              │
│      └── portfolioiq.py, thingularity.py, ...         │
├──────────────────────────────────────────────────────┤
│                  Layer 3: Agents                      │
│  agents/                                              │
│  ├── attacker/           # Red team                   │
│  │   ├── agent.py        # GOAT-loop                   │
│  │   ├── goat_loop.py    # Signal extraction          │
│  │   ├── diagnosis.py    # Response diagnosis         │
│  │   ├── strategy_router.py  # Surface routing        │
│  │   ├── contract_sequential.py  # Chaining           │
│  │   └── pyrit_converters.py  # Obfuscation           │
│  └── defender/           # Blue team                  │
│      ├── agent.py        # 7-layer pipeline           │
│      ├── normalization.py  # 14 deterministic trans.  │
│      ├── threat_classifier.py  # Rule-based classif.  │
│      ├── segmenter.py    # Trust segmentation         │
│      ├── execution_modes.py  # 4-mode scaling         │
│      ├── pyrit_defense.py  # Invariants, spotlighting │
│      └── output_guardrails.py  # PII/code sanitize   │
└──────────────────────────────────────────────────────┘
```

### 2.2 Data Flow

```
Scenario TOML
      │
      ▼
run_scenario.py
      │
      ├──► Start agents (attacker, defender, orchestrator)
      │
      ▼
Orchestrator (A2A Server)
      │
      ├──► Load ScenarioPlugin
      │
      ▼
Battle Loop (7 rounds):
      │
      ├──► Context.to_json(include_attack_info=True) ──► Attacker
      │                                                       │
      │                                                       ▼
      │                                               GOAT Loop (1 LLM call)
      │                                                       │
      │◄──────────────────────────────────────────────────────┘
      │
      ├──► Context.apply_input_template(attack)
      │
      ├──► Context.to_json(include_attack_info=False) ──► Defender
      │                                                         │
      │                                                         ▼
      │                                                 7-Layer Pipeline
      │                                                  (2-3 LLM calls)
      │                                                         │
      │◄────────────────────────────────────────────────────────┘
      │
      ├──► Scenario.check_success(response)
      │
      └──► Save results (JSON, HTML, Markdown)
```

### 2.3 A2A Protocol Architecture

The project uses AgentBeats A2A (Agent-to-Agent) protocol — a design decision that introduces both strengths and limitations:

**How it works:**
- Each agent runs as a separate HTTP server (uvicorn + Starlette)
- Communication happens via A2A's JSON-RPC-like messaging
- The orchestrator ("Green Agent") coordinates the battle
- Each round creates new conversations (defender is stateless)

**Strengths:**
- Microservice-like separation of concerns
- Agents can be independently developed, tested, and scaled
- HTTP boundary enforces clean interfaces

**Weaknesses:**
- Significant overhead for local testing (3+ server processes)
- Complex startup/shutdown orchestration
- Makes the tool harder to use as a simple CLI
- Competition-specific protocol doesn't generalize well

---

## 3. Component Analysis

### 3.1 CLI Layer (src/agentbeats/) — Score: 6/10

**What it does well:**
- Clean entry point (`agentbeats-run` command)
- TOML parsing is straightforward
- Agent lifecycle management (start → wait → run → cleanup)

**What needs work:**
- **No subcommand structure** — everything is `agentbeats-run scenario.toml`
- **No help/--help beyond argparse** — missing `init`, `list`, `config` commands
- **No configuration system** — relies entirely on TOML files
- **No caching** — every run starts fresh
- **No progress indicators** — --show-logs is all-or-nothing
- **Error handling** — process cleanup is fragile (SIGTERM then SIGKILL)

### 3.2 Orchestrator (orchestrator.py) — Score: 7/10

**What it does well:**
- Clean battle loop logic
- Comprehensive error tracking (timeouts, crashes per agent type)
- Beautiful HTML report generation (self-contained, dark theme)
- Normal user test integration
- Results saving with multiple formats (JSON, HTML, Markdown)

**What needs work:**
- **Too coupled to A2A** — switching protocols would require major rework
- **No streaming results** — everything is buffered until completion
- **No live dashboard** — HTML reports are post-hoc only
- **No comparison mode** — can't compare two runs side-by-side

### 3.3 Scenario Plugin System — Score: 8/10

**What it does well:**
- Clean ABC with well-defined interface
- `ScenarioContext` dataclass cleanly separates attacker vs. defender views
- `to_json(include_attack_info)` pattern is elegant
- `format_input()` with `**kwargs` provides flexibility
- `check_success()` returns `(bool, Any)` tuple

**What needs work:**
- **Only 5 plugins** — needs a marketplace of community plugins
- **No plugin discovery** — `registry.py` is a static dict
- **No plugin validation** — no schema for config validation
- **No plugin versioning** — no way to track plugin versions

### 3.4 Attacker Agent — Score: 8/10

**What it does well:**
- GOAT-style adaptive loop with 10+ strategies
- `round_data` persistence across 7 rounds
- Defender response diagnosis (5 categories, 5 failure modes)
- Surface/family routing with diversity rules
- Contract awareness (parses output_format)
- Sequential attack chaining
- Fragment reconstruction attacks
- PyRIT obfuscation converters

**What needs work:**
- **Fixed strategy set** — no way to add new strategies at runtime
- **No Meta Agent / evolutionary strategy** — promptfoo's best strategy
- **Branch scoring is simple** — uses character-count heuristics
- **No multilingual attacks** — significant vulnerability in non-English

### 3.5 Defender Agent — Score: 9/10

**What it does well:**
- **7-layer pipeline** is genuinely state-of-the-art
- **14 deterministic transforms** (normalization.py) — 0 LLM calls
- **Threat classification** with 6 categories
- **Trust boundary segmentation** with position-decay scoring
- **4 execution modes** (STANDARD → MINIMAL)
- **Output guardrails** (PII, code, reference sanitization)
- **4 LLM call budget management** — never exceeds limit

**What needs work:**
- **Invariant dict has hardcoded scenario names** — only 5 known + `_default`
- **No few-shot examples** in system prompt for defense
- **No adversarial training** — static defense that doesn't learn

### 3.6 Templates (Jinja2) — Score: 7/10

**What it does well:**
- Clean separation of prompt logic from code
- Scenario-agnostic templates work across all 5 scenarios
- Constitution-style system prompt (PERMITTED / RESTRICTED / GRAY AREA)

**What needs work:**
- **No template inheritance** — all templates are standalone
- **No template testing** — no way to validate prompts independently
- **Limited Jinja2 usage** — mostly just variable substitution

### 3.7 Reporting — Score: 8/10

**What it does well:**
- Self-contained HTML reports with dark theme
- Markdown battle logs
- JSON results for programmatic consumption
- Error logging (result.err)

**What needs work:**
- **No comparison view** — can't diff two runs
- **No history tracking** — results overwrite previous runs
- **No sharing** — HTML is local only
- **No assertion system** — no pass/fail criteria beyond win/loss

---

## 4. Code Quality Assessment

### 4.1 Testing — Score: 8/10

| Metric | Count |
|--------|-------|
| Test files | 14 |
| Tests | 286 |
| Coverage | High (TDD-verified per the docs) |

**Strengths:**
- Comprehensive unit tests for all new modules
- Good test organization (one file per module)
- Async test support (pytest-asyncio)

**Weaknesses:**
- **No integration tests** — all tests are unit-level
- **No end-to-end battle tests** — can't verify full pipeline
- **Mocking is inconsistent** — some tests mock LLM, others don't

### 4.2 Type Safety — Score: 6/10

- Uses modern Python type hints extensively
- Pydantic v2 for data models
- **Missing:** No mypy configuration in CI
- **Missing:** Several modules use `Any` where specific types would work

### 4.3 Documentation — Score: 7/10

**Good:** README.md, ARCHITECTURE.md, RESEARCH_REPORT.md, plan.md
**Needs:** API reference, CLI usage guide, plugin development guide, tutorial

### 4.4 Dependencies — Score: 6/10

```toml
dependencies = [
    "a2a-sdk>=0.3.5",          # Heavy, competition-specific
    "google-adk>=1.14.1",       # Google Agent Development Kit
    "google-genai>=1.36.0",     # Google GenAI SDK
    "jinja2>=3.1.0",
    "openai>=2.8.1",
    "pydantic>=2.11.9",
    "python-dotenv>=1.1.1",
    "uvicorn>=0.35.0",
]
```

**Issues:**
- **A2A SDK is the biggest dependency** — 300+ lines of protocol code just for competition
- **Google ADK + GenAI** — unclear why these are needed (not used in agent code)
- **No dependency pinning** — `>=` allows breaking changes
- **Heavy runtime** — uvicorn + starlette for what could be simple function calls

---

## 5. Strengths Summary

| Strength | Details | Competitive Advantage |
|----------|---------|---------------------|
| **Multi-turn agentic testing** | 7-round battles with stateful attacker | Unique — no other tool does this |
| **Attack + Defense in one** | Both red and blue team agents | Eliminates tool-switching |
| **7-layer defense pipeline** | Production-grade defense engineering | Rivals dedicated guardrail tools |
| **Scenario-agnostic architecture** | Works on unseen scenarios | Critical for generalization |
| **Normal user test** | Ensures defender helpfulness | Prevents over-refusal |
| **Rich reporting** | JSON, HTML, Markdown | Production-ready output |
| **Comprehensive attacker** | Diagnosis, routing, chaining, contract awareness | Sophisticated multi-turn attacks |
| **Deterministic preprocessing** | 14 transforms, 0 LLM calls | Catches 30%+ attacks before LLM |
| **LLM budget management** | 4-call limit enforced | Realistic resource constraints |
| **Test coverage** | 286 tests, TDD-verified | Reliable codebase |

---

## 6. Weaknesses Summary

| Weakness | Impact | Fix Difficulty |
|----------|--------|---------------|
| **A2A protocol coupling** | Makes generalization hard | High |
| **Single provider** | Can't test different models | Medium |
| **No subcommand CLI** | Poor developer experience | Medium |
| **No web UI** | Can't compare/share results | High |
| **5 attack plugins only** | Limited attack surface vs promptfoo's 157 | High |
| **No caching** | Wastes API calls on re-runs | Low |
| **No CI/CD mode** | Can't integrate into pipelines | Medium |
| **Hardcoded invariants** | Fragile for new scenarios | Low |
| **No plugin marketplace** | Hard for community to contribute | High |
| **No streaming** | Users wait silently for results | Medium |
| **No comparison mode** | Can't A/B test strategies | Medium |

---

## 7. Transformation Readiness Assessment

### What Can Be Repurposed (80%+ reuse)

| Component | Reuse Strategy |
|-----------|---------------|
| **Defender agents** (normalization, classification, segmentation, guardrails) | Package as standalone library (`agentbeats-guardrails`) |
| **Attacker agents** (diagnosis, routing, chaining, converters) | Package as `agentbeats-attack` library |
| **ScenarioPlugin ABC** | Generalize to support arbitrary test definitions |
| **HTML report templates** | Extract and enhance with comparison views |
| **GOAT loop** | Extract as general-purpose multi-turn engine |
| **PyRIT converters** | Package as standalone obfuscation library |
| **Output guardrails** | Package as `agentbeats-output` library |

### What Needs Significant Rework

| Component | Effort | New Approach |
|-----------|--------|-------------|
| **CLI** | 2-3 weeks | Subcommand-based with Click/Typer |
| **Configuration** | 1-2 weeks | YAML-based with JSON Schema validation |
| **Provider system** | 2-3 weeks | ABC with OpenAI, Anthropic, Azure adapters |
| **A2A decoupling** | 1-2 weeks | Extract agent communication to pluggable adapter |
| **Plugin system** | 2-3 weeks | Package-based discovery with metadata |
| **Web UI** | 4-6 weeks | FastAPI + React dashboard |
| **Caching** | 1 week | SQLite/LMDB-based result cache |
| **CI/CD mode** | 1 week | JSON output + exit codes + assertions |
| **Plugin marketplace** | 4-8 weeks | GitHub-based registry with auto-indexing |

---

## 8. Key Metrics

| Metric | Current | Target (promptfoo-class) |
|--------|---------|--------------------------|
| **Attack plugins** | 7 strategies | 50+ |
| **Defense layers** | 7 | 10+ |
| **Provider support** | 1 | 10+ |
| **CLI commands** | 1 (`run`) | 8+ (`eval`, `redteam`, `view`, `init`, `compare`, `list`, `config`, `serve`) |
| **Output formats** | 3 (JSON, HTML, MD) | 5+ (add CSV, PDF) |
| **Configuration** | TOML | YAML + TOML + JSON |
| **Install** | pip + uv | pip, npm, Docker |
| **CI/CD support** | ❌ | ✅ (exit codes, assertions, JSON output) |
| **Web UI** | Static HTML | Live dashboard |
| **Plugin marketplace** | ❌ | ✅ |
| **Documentation** | 4 markdown files | Full docs site + API reference + tutorials |

---

## 9. Conclusion

Archon is a **hidden gem** in the LLM security landscape. It has capabilities (multi-turn agentic battles, combined attack+defense, 7-layer defense pipeline) that **no other open-source tool provides** — including promptfoo.

The path to becoming a promptfoo-class tool is clear:

1. **Decouple from competition infrastructure** (A2A, TOML, single model)
2. **Build proper CLI** with subcommands and YAML config
3. **Add multi-provider support** for model-agnostic testing
4. **Create web UI** for interactive results exploration
5. **Establish plugin ecosystem** for community contributions
6. **Add CI/CD integration** for pipeline usage

The core IP (attack algorithms, defense pipeline, reporting) is already world-class. What's needed is **packaging and presentation** — turning a competition codebase into a polished developer tool.

See [ROADMAP.md](../../ROADMAP.md) for the detailed transformation plan.
