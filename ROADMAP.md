# Transformation Roadmap: AgentBeats → General-Purpose LLM Security Testing Tool

> ✅ **v3 PREFACE (Aug 22, 2026):** The phases below remain valid, but execution order is now **core-first** per [`BLUEPRINT_HACKATHON.md`](./BLUEPRINT_HACKATHON.md) §3: (1) `archon-armor` defense proxy, (2) `Registry` ABC + provider/target seams, (3) CLI + config, (4) cloud/observability integrations. Hackathon integrations (ADK/Gemini/GCP) are optional adapters in `integrations/`, never core dependencies. Phase 0.1 (A2A decoupling) and 0.2 (multi-provider) are absorbed into the `TargetAdapter`/`Provider` ABCs.


# Transformation Roadmap: AgentBeats → General-Purpose LLM Security Testing Tool

> **From:** Competition-specific framework (Archon)
> **To:** General-purpose CLI tool for LLM evaluation, red teaming, and defense testing
> **Model:** Promptfoo, Garak, DeepEval

---

## Strategic Vision

Transform Archon from a competition-specific framework into a **general-purpose, open-source CLI tool** for LLM security testing that combines:

- 🗡️ **Multi-turn adversarial red teaming** (like PyRIT, but better)
- 🛡️ **Production-grade defense evaluation** (like LLM Guard, but attack-aware)
- 🧪 **Quantitative security metrics** (like DeepEval, but security-focused)
- 🖥️ **Beautiful web UI** (like promptfoo `view`)
- 🔌 **Extensible plugin ecosystem** (like Garak probes/detectors)

---

## Phase 0: Foundation — Decouple from Competition (Weeks 1-3)

**Goal:** Make the tool usable outside the competition context with zero breaking changes.

### 0.1 Decouple from A2A Protocol

**Current state:** Agents communicate via A2A HTTP protocol (separate server processes).

**Target:** Support both A2A and direct in-process execution.

```python
# New interface
class AgentBackend(ABC):
    """Pluggable agent communication backend."""
    async def send_message(self, message: str, agent_type: str) -> str: ...

class A2ABackend(AgentBackend):
    """Existing A2A HTTP protocol."""

class InProcessBackend(AgentBackend):
    """Direct in-process execution (no server needed)."""
```

**Why:** Eliminates the overhead of running 3+ server processes for local testing. Makes the tool usable as a simple library.

**Files to create/modify:**
- `src/agentbeats/backends/__init__.py` — Backend ABC
- `src/agentbeats/backends/a2a.py` — Existing A2A protocol (migrate from tool_provider.py)
- `src/agentbeats/backends/inprocess.py` — New in-process backend
- `src/agentbeats/backends/grpc.py` — Optional gRPC backend for performance

### 0.2 Add Multi-Provider Support

**Current state:** Hardcoded `openai/gpt-oss-20b` via OpenAI-compatible client.

**Target:** Provider-agnostic with adapters for OpenAI, Anthropic, Azure, Google, local models.

```python
class LLMProvider(ABC):
    """Abstract LLM provider."""
    async def generate(self, messages: list[dict], **kwargs) -> str: ...

class OpenAIProvider(LLMProvider): ...
class AnthropicProvider(LLMProvider): ...
class AzureProvider(LLMProvider): ...
class LocalProvider(LLMProvider): ...
class CustomHTTPProvider(LLMProvider): ...
```

**Why:** Foundation for all comparison features. Users need to test across models.

**Files to create:**
- `src/agentbeats/providers/__init__.py` — Provider ABC and registry
- `src/agentbeats/providers/openai_.py`
- `src/agentbeats/providers/anthropic.py`
- `src/agentbeats/providers/azure.py`
- `src/agentbeats/providers/local.py`
- `src/agentbeats/providers/custom.py`

### 0.3 Replace TOML with YAML Configuration

**Current state:** Competition-specific TOML format.

**Target:** Declarative YAML with JSON Schema validation (like promptfoo).

```yaml
# agentbeats-config.yaml (future)
version: "1.0"

redteam:
  plugins:
    - injection
    - jailbreak
    - pii_leak
    - tool_disclosure
  strategies:
    - crescendo
    - chain
    - reconstruction
  numRounds: 7

providers:
  - openai:gpt-4o
    config:
      temperature: 0.8
  - anthropic:claude-3-5-sonnet

defender:
  layers:
    - normalization
    - classification
    - segmentation
    - task_shield
  execution_mode: standard

assertions:
  - type: win_rate
    threshold: 0.7
  - type: normal_user_pass
    required: true
```

**Files to create:**
- `src/agentbeats/config/` — YAML loading, validation, migration tools
- `src/agentbeats/config/schema.py` — JSON Schema for validation
- `src/agentbeats/config/migrate.py` — TOML → YAML migration tool

---

## Phase 1: CLI Overhaul (Weeks 3-5)

**Goal:** Professional-grade CLI with subcommands, help, and developer experience.

### 1.1 Subcommand Architecture

```bash
# Target CLI interface
agentbeats eval <config.yaml>        # Run evaluation
agentbeats redteam <config.yaml>     # Run red teaming
agentbeats view [results-dir]        # Launch web UI
agentbeats init [project-name]       # Create new project
agentbeats compare <run1> <run2>     # Compare two evaluation runs
agentbeats list [plugins|scenarios]  # List available plugins
agentbeats config validate <file>    # Validate config
agentbeats serve [--port PORT]       # Start API server
```

**Why:** Developer tools live or die by their CLI UX. This is the most important Phase 1 improvement.

**Implementation:** Use [Click](https://click.palletsprojects.com/) or [Typer](https://typer.tiangolo.com/) for CLI framework. Add rich output with [Rich](https://rich.readthedocs.io/).

### 1.2 Progress & Logging

- **Progress bars** for battle rounds
- **Structured logging** (JSON mode for CI)
- **Verbose/debug/quiet** levels
- **Live table updates** for round-by-round results

### 1.3 Init Command

```bash
agentbeats init my-project
# Creates:
# my-project/
# ├── agentbeats-config.yaml
# ├── scenarios/
# ├── plugins/
# ├── results/
# └── README.md
```

---

## Phase 2: Plugin Ecosystem (Weeks 5-8)

**Goal:** 50+ attack plugins, 20+ defense plugins, community contribution pipeline.

### 2.1 Plugin Architecture

```python
# New plugin interfaces (replacing current static registry)

class AttackPlugin(ABC):
    name: str
    category: str  # "injection", "jailbreak", "pii", "tool_disclosure", etc.
    async def generate(self, context: AttackContext) -> str: ...

class DefensePlugin(ABC):
    name: str
    layer: int  # Which layer this plugin runs at
    async def process(self, input: str, context: DefenseContext) -> DefenseResult: ...

class AssertionPlugin(ABC):
    name: str
    async def evaluate(self, response: str, expected: Any) -> AssertionResult: ...
```

### 2.2 Plugin Discovery

- **File-system based**: Scan `~/.agentbeats/plugins/` and `./plugins/`
- **Package-based**: Load from pip-installed packages (`agentbeats-plugin-*`)
- **GitHub-based**: Clone from repositories (like `npx skills add`)
- **Plugin metadata**: `plugin.yaml` with name, version, description, dependencies

### 2.3 Initial Plugin Library (Target: 50+)

| Category | Current | Target | Examples |
|----------|---------|--------|---------|
| **Injection** | 1 | 15 | Direct, indirect, RAG, context, multi-modal, encoded |
| **Jailbreak** | 1 | 12 | DAN, GCG, crescendo, many-shot, roleplay, fictional |
| **PII/Data** | 1 | 8 | SSN, credit card, API key, PII, medical, financial |
| **Tool/Function** | 2 | 8 | Tool listing, function call, system prompt, debug mode |
| **Safety** | 0 | 5 | Hate, toxicity, self-harm, violence, sexual |
| **Supply Chain** | 0 | 3 | Package hallucination, dependency confusion, code injection |
| **Custom** | 0 | Open | User-defined plugins via simple Python API |

### 2.4 Defense Plugin Library

| Category | Current | Target |
|----------|---------|--------|
| **Normalization** | 14 transforms | 25+ (add emoji, morse, braille, URL encoding variants) |
| **Classification** | 6 categories | 12+ (add multilingual, multimodal, adversarial suffix) |
| **Guardrails** | 3 (PII, code, refs) | 10+ (add toxicity, bias, factual consistency, URL safety) |

---

## Phase 3: Web UI (Weeks 8-12)

**Goal:** Interactive web dashboard for exploring results, comparing runs, and monitoring.

### 3.1 Architecture

```
Frontend (React/Next.js)          Backend (FastAPI)
┌─────────────────────┐           ┌─────────────────────┐
│  Dashboard           │◄─HTTP──►│  /api/runs           │
│  ├── Run comparison  │          │  /api/plugins        │
│  ├── Battle timeline │          │  /api/providers      │
│  ├── Heat maps       │          │  /api/compare        │
│  └── Filter/Search   │          │  /api/reports        │
└─────────────────────┘           └─────────────────────┘
                                         │
                                         ▼
                                  SQLite/PostgreSQL
                                  (run history, configs, results)
```

### 3.2 Key Views

| View | Purpose |
|------|---------|
| **Dashboard** | Overview of all runs, win rates, trends |
| **Run Detail** | Round-by-round battle timeline with expandable messages |
| **Comparison** | Side-by-side comparison of two runs |
| **Heat Map** | Attack plugin × defense layer success rates |
| **History** | Time-series of evaluation results |
| **Plugins** | Browse, install, configure plugins |
| **Share** | Generate shareable links to results |

### 3.3 Technology Choices

| Component | Recommendation | Reason |
|-----------|---------------|--------|
| **Backend** | FastAPI + SQLAlchemy | Python native, async, auto-docs |
| **Frontend** | React + Tailwind + D3 | Fast, beautiful, interactive |
| **Database** | SQLite (local), PostgreSQL (server) | Minimal setup for local use |
| **Deployment** | Docker Compose | Single command to deploy |
| **Auth** | None (local), API key (server) | Simple for local use |

---

## Phase 4: CI/CD & Production Features (Weeks 12-14)

**Goal:** Seamless integration into development pipelines.

### 4.1 CI/CD Mode

```bash
# GitHub Actions example
- name: Security Red Team
  run: |
    agentbeats eval config.yaml --ci --json output.json
    agentbeats config validate config.yaml --ci
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

**Features:**
- **Exit codes**: 0 = all assertions pass, 1 = some fail, 2 = error
- **JSON output**: Machine-readable results for other tools
- **Minimal mode**: No fancy output, just results
- **Assertion gates**: Define thresholds that block PRs

### 4.2 Caching & Resumability

```python
# Cache layer
class ResultCache:
    def __init__(self, backend: str = "sqlite"):
        # SQLite by default, configurable to Redis/S3
    
    async def get(self, key: str) -> CachedResult | None: ...
    async def set(self, key: str, result: CachedResult): ...
    
    # Key = hash(config + scenario + round + provider)
    # Invalidated when config changes
```

### 4.3 Comparison Engine

```bash
agentbeats compare results/run-001/ results/run-002/ --output diff.html
```

- Win rate delta
- Attack plugin effectiveness change
- Defense layer performance change
- Token usage comparison
- Latency comparison

---

## Phase 5: Ecosystem & Community (Weeks 14-18)

**Goal:** Self-sustaining open-source community.

### 5.1 Plugin Registry

```
agentbeats plugin search "pii"
agentbeats plugin install prompt-injection
agentbeats plugin publish my-plugin/  # (requires auth)
```

- **Central registry** at `registry.agentbeats.dev`
- **Community ratings** and usage stats
- **Auto-update** notifications
- **Dependency resolution**

### 5.2 Documentation Site

- Quickstart tutorial (5 minutes to first eval)
- Plugin development guide
- Provider integration guide
- API reference
- Architecture documentation
- Video tutorials

### 5.3 Distribution

| Platform | Command |
|----------|---------|
| **pip** | `pip install agentbeats` |
| **npm** | `npx agentbeats` (via Pyodide or WASM) |
| **Docker** | `docker run agentbeats/agentbeats` |
| **Homebrew** | `brew install agentbeats` |
| **GitHub Releases** | Download binary for Linux/macOS/Windows |

---

## Detailed Phasing Timeline

```
Week 1-3:    Phase 0 — Foundation
             ├── Decouple A2A protocol
             ├── Multi-provider ABC + 3 adapters
             ├── YAML config loader
             └── Backward compatibility layer

Week 3-5:    Phase 1 — CLI Overhaul
             ├── Click/Typer subcommands
             ├── `init` command
             ├── Progress bars + structured logging
             └── Config validation

Week 5-8:    Phase 2 — Plugin Ecosystem
             ├── Plugin ABCs (attack, defense, assertion)
             ├── File-system + package discovery
             ├── 20 initial attack plugins
             ├── 10 initial defense plugins
             └── Plugin documentation

Week 8-12:   Phase 3 — Web UI
             ├── FastAPI backend
             ├── React dashboard
             ├── Comparison view
             ├── Run timeline
             └── Share functionality

Week 12-14:  Phase 4 — CI/CD & Production
             ├── CI mode (exit codes, JSON, minimal)
             ├── Caching layer (SQLite)
             ├── Comparison engine
             └── GitHub Action

Week 14-18:  Phase 5 — Ecosystem
             ├── Plugin registry website
             ├── Documentation site
             ├── Multiple distribution formats
             └── Community + contribution guide

Week 18-20:  Phase 6 — Polish & Scale
             ├── Performance optimization
             ├── Security audit
             ├── Bug bash + beta testers
             └── v1.0 release
```

---

## Resource Estimate

| Phase | Engineering Effort | Key Skills | Dependencies |
|-------|-------------------|------------|--------------|
| **0** | 2-3 weeks / 1-2 devs | Python, async, protocol design | None |
| **1** | 2-3 weeks / 1 dev | CLI design, Click/Typer, Rich | Phase 0 |
| **2** | 3-4 weeks / 1-2 devs | Plugin architecture, Python packaging | Phase 0 |
| **3** | 4-6 weeks / 2 devs | FastAPI, React, D3, SQL | Phase 0-1 |
| **4** | 2-3 weeks / 1 dev | CI/CD, caching, GitHub Actions | Phase 1-2 |
| **5** | 4-6 weeks / 1-2 devs | Web dev, docs, community management | Phase 2-3 |
| **6** | 2-4 weeks / 1-2 devs | Performance, testing, security | All phases |

**Total:** ~20-28 weeks / 1-2 developers

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| A2A decoupling breaks competition compatibility | Medium | High | Maintain backward compat adapter |
| YAML config too complex | Low | Medium | Provide `agentbeats init` with wizard |
| Plugin API changes break community plugins | Medium | High | Semantic versioning + migration guide |
| Web UI scope creep | High | Medium | Ship MVP first, iterate on feedback |
| Multi-provider inconsistencies | Medium | Medium | Comprehensive integration test suite |
| Community adoption slow | Medium | Medium | Invest in tutorials + examples |

---

## Success Metrics

| Metric | Current | 3-month target | 6-month target | 12-month target |
|--------|---------|---------------|----------------|-----------------|
| **GitHub stars** | ~50 | 500 | 2,000 | 10,000 |
| **Attack plugins** | 7 | 25 | 50 | 100+ |
| **Defense plugins** | 10 | 15 | 25 | 40+ |
| **CLI commands** | 1 | 5 | 8 | 10+ |
| **Provider support** | 1 | 4 | 8 | 15+ |
| **Web UI** | ❌ | Alpha | Beta | v1.0 |
| **CI/CD** | ❌ | ✅ Basic | ✅ Full | ✅ Native GH Action |
| **pip downloads/month** | ~0 | 1,000 | 10,000 | 50,000+ |
| **Contributors** | 1 | 3 | 10 | 25+ |

---

## Appendix: Feature Priority Matrix

```
                   High Impact                 Low Impact
                ┌─────────────────┬─────────────────────┐
   High Effort  │  Web UI          │  gRPC backend       │
                │  Plugin ecosystem│  WASM distribution  │
                │  Documentation   │  Mobile app         │
                ├─────────────────┼─────────────────────┤
   Low Effort   │  CLI subcommands │  Color themes       │
                │  Multi-provider  │  ASCII art banners  │
                │  YAML config     │  Sound effects      │
                │  CI/CD mode      │                     │
                │  Caching         │                     │
                └─────────────────┴─────────────────────┘
```

**Focus on the top-left quadrant first** — high impact, low effort. Then move clockwise.

---

## Quick Wins (Can ship in <1 week each)

1. **`agentbeats list` command** — Show available scenarios, plugins, providers
2. **YAML config support** — Alongside existing TOML
3. **OpenAI provider** — So users can test with their own API keys
4. **`--ci` flag** — Exit codes and JSON output
5. **`init` command** — Bootstrap new evaluation projects
6. **Caching** — SQLite-based result cache
7. **Structured logging** — JSON mode for log aggregation
8. **Progress bars** — Visual feedback during multi-round battles

---

## Conclusion

This project has **unique, world-class core IP** — the multi-turn agentic battle system, 7-layer defense pipeline, and combined attack+defense evaluation. What's missing is the **packaging and polish** that turns a competition entry into a developer tool.

The transformation is achievable in **20-28 weeks** with 1-2 developers, following the phased approach above. The highest-ROI first steps are:

1. ✅ **Phase 0.2: Multi-provider** — Unlocks model comparison (1 week)
2. ✅ **Phase 1: CLI subcommands** — Professional developer experience (2 weeks)
3. ✅ **Phase 2.3: 20 initial plugins** — Competitive plugin count (3 weeks)

These three steps alone would make the tool competitive with promptfoo for security-focused use cases, leveraging the unique multi-turn agentic testing that no other tool provides.
