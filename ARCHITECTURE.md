# Architecture Decision Record

> **Date:** August 23, 2026 · **Branch:** `hackathon-v2`
> This ADR documents the **current product architecture** (`packages/` monorepo).
> For the legacy competition stack internals, see `scenarios/security_arena/`.

## Design Principles

### 1. Core-First, Integration-Ring Architecture

```
archon/
├── packages/
│   ├── archon_core/        # Pure library. Zero vendor deps. Importable anywhere.
│   │   ├── attacks/        # AttackStrategy implementations (GOAT, branching, trace-driven)
│   │   ├── defenses/       # DefenseLayer implementations (8-layer pipeline)
│   │   ├── targets/        # TargetAdapter implementations (HTTP, MCP, sandbox, memory, multiagent)
│   │   ├── providers/      # LLMProvider implementations (OpenAI-compat, Gemini, Anthropic)
│   │   ├── reporting/      # Severity scoring, compliance reports
│   │   ├── registry/       # Agent registry (memory, SQLite, Postgres, versioned)
│   │   ├── observability/  # OTel tracer, scrubbing, JSONL export
│   │   ├── security/       # HMAC auth, rate limiting
│   │   └── config.py       # YAML policy-as-code
│   ├── archon_armor/       # THE deployable artifact: FastAPI defense proxy
│   │   ├── server.py       # OpenAI-compatible /v1/chat/completions endpoint
│   │   ├── battles.py      # BattleManager for attack campaigns
│   │   ├── probes.py       # Probe corpus (222 probes, OWASP-mapped)
│   │   ├── baselines.py    # Policy-CI baseline stores
│   │   ├── compare.py      # A-vs-B battle comparison
│   │   ├── checkpoints.py  # Crash-safe long-battle persistence
│   │   ├── ui.py           # Zero-dependency fleet dashboard
│   │   └── fleet.py        # Fleet summary + CI gate
│   └── archon_cli/         # CLI: archon scan | battle | serve | report | fleet | plugins
├── src/agentbeats/         # Legacy competition harness (frozen; compat only)
├── scenarios/security_arena/  # Competition plugins (compat layer over archon_core)
├── contrib/                # Community probe packs (finance/healthcare/devops)
├── deploy/helm/            # Helm chart for Kubernetes deployment
└── packaging/              # Homebrew formula + npm wrapper
```

### 2. Dependency Rule (enforced by import-linter)

```
archon_cli → archon_armor → archon_core
                          → agentbeats (compat)
archon_core never imports:
  - cloud SDKs (GCP, AWS, Azure)
  - A2A protocol
  - HTTP frameworks (FastAPI, etc.)
```

This is what "core-first" means mechanically. Integrations go in `integrations/` (optional adapters).

### 3. Five Extension Seams (stable ABCs)

Every axis of growth is a single interface third parties implement without touching core:

```python
# attacks/base.py
class AttackStrategy(ABC):
    """A stateful multi-turn attack campaign."""
    name: str
    surfaces: frozenset[AttackSurface]
    @abstractmethod
    async def next_payload(self, ctx: BattleContext) -> AttackPayload: ...
    def observe(self, signal: RoundSignal) -> None: ...

# defenses/base.py
class DefenseLayer(ABC):
    """One stage of the request/response pipeline."""
    name: str
    llm_budget: int = 0
    @abstractmethod
    async def process(self, exchange: Exchange) -> Exchange: ...

# providers/base.py
class LLMProvider(ABC):
    @abstractmethod
    async def generate(self, messages: list[dict], **kwargs) -> Completion: ...

# targets/base.py
class TargetAdapter(ABC):
    """Anything that speaks like an agent can be tested."""
    @abstractmethod
    async def send(self, payload: str) -> TargetResponse: ...

# registry/base.py
class Registry(ABC):
    @abstractmethod
    async def register(self, card: AgentCard) -> str: ...
    @abstractmethod
    async def get(self, agent_id: str) -> AgentCard | None: ...
```

### 4. Defense Pipeline Architecture

```
agent ──► POST /v1/chat/completions ──► [L0 normalize] ──► [L1 classify]
              │                                              │
              ▼                                              ▼
        X-Agent-ID header ──► Registry lookup (policy)   [L2 spotlight] ──► upstream LLM ──► [L3 shield] ──► [L4 classifier] ──► response
```

**8 Defense Layers:**

| Layer | Name | LLM Calls | Description |
|---|---|---|---|
| L0 | Normalization | 0 | Deterministic obfuscation decoding (14 transforms) |
| L1 | Threat Classification | 0 | Rule-based threat classification with policy blocking |
| L1.5 | Segmentation | 0 | Trust-boundary segmentation with position-decay scoring |
| L2 | Spotlighting | 0 | Polymorphic Prompt Assembling spotlighting wrap |
| L2.5 | Execution Mode | 0 | Maps accumulated suspicion to trust-level execution mode |
| L3 | Task Shield | 1 | Constitution-style system prompt with dynamic invariants |
| L4 | Exchange Classifier | 1 | Classifies (input, response) pair for hidden risks |
| L5 | Output Guardrails | 0 | PII detection, unsafe code sanitization, unverified reference checking |

**Total LLM budget:** ≤4 calls per exchange (deterministic tier: 0 calls).

### 5. Attack Engine Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    BranchingAttacker                          │
│  Hydra-style fan-out/pivot/prune with deterministic verdicts │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│  Round 1      │    │  Round 2      │    │  Round N      │
│  Seed fan-out │    │  Mutation     │    │  Convergence  │
│  (3 payloads) │    │  (LLM mutate) │    │  (best path)  │
└───────┬───────┘    └───────┬───────┘    └───────┬───────┘
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│  Score        │    │  Score        │    │  Score        │
│  (deterministic│    │  (deterministic│    │  (deterministic│
│  lexical)     │    │  lexical)     │    │  lexical)     │
└───────────────┘    └───────────────┘    └───────────────┘
```

**Key design choice:** Verdicts are **never** LLM-judged. The LLMProvider is used only to *generate* mutations; scoring uses deterministic lexical signals (refusal markers, leak markers, secret patterns). This makes attacks cheap, reproducible, and air-gap friendly.

### 6. Observable Pipeline

Every request flows through the defense pipeline with OTel spans:

```
armor.request (root span)
├── normalization (L0)
├── threat_classification (L1)
├── segmentation (L1.5)
├── spotlighting (L2)
├── execution_mode (L2.5)
├── upstream_llm_call (L3)
├── exchange_classifier (L4)
└── output_guardrails (L5)
```

Each span carries attributes: `layer`, `blocked`, `verdict`, `risk_score`, `evidence`.
Exported to Cloud Trace via OTLP/HTTP when `ARCHON_OTEL_EXPORTER=otlp`.

### 7. Key Research Foundations

| Technique | Source | Application |
|-----------|--------|-------------|
| GOAT (Generative Offensive Agent Tester) | Meta Research, 2024 | Attacker strategy selection loop |
| PyRIT (Python Risk Identification Toolkit) | Microsoft | Obfuscation converters, scorer architecture |
| Task Shield | AgentDojo benchmark | Defender constitution prompt, ASR reduction to 2.07% |
| Polymorphic Prompt Assembling (PPA) | 2025 research | Randomized prompt structure, ASR reduction to 1.83% |
| Spotlighting | Microsoft | Delimiter-based untrusted input isolation |
| Constitutional Classifiers | Anthropic | Output-layer intent verification via backtranslation |
| Crescendo Attack | Promptfoo/Microsoft | Multi-turn gradual escalation strategy |
| Many-Shot Jailbreaking (MSJ) | Anthropic | Role mimicry detection in Layer 0 |
| Hydra Strategy | Promptfoo | Adaptive multi-turn branching with shared learnings |
| Agent Breaker | Garak/NVIDIA | Tool-analyzing multi-turn attacks |
| OWASP Agentic Top-10 (2026) | OWASP | Threat taxonomy and standards alignment |

### 8. Scenario Plugin Interface

Each scenario plugin (`ScenarioPlugin` ABC) provides:
- `get_attack_type()`: INJECTION or DIRECT
- `get_domain_description()`: Context about the domain
- `get_attacker_goal()`: Specific measurable objective
- `get_attack_constraints()`: Rules the attacker must follow
- `get_defender_role()`: Defender's persona
- `get_defender_task_description()`: What the defender does
- `get_output_format()`: Expected response structure
- `get_security_guidelines()`: Attack warnings for the defender
- `format_input(content)`: Template with PLACE_ATTACK_HERE substitution
- `check_success(response)`: Whether the attack succeeded

Adding a new scenario requires only implementing this interface — no core code changes.

### 9. Enterprise Deployment Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    ARCHON PLATFORM (Production)                   │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│  archon-armor │    │  archon-cli   │    │  archon fleet │
│  (FastAPI)    │    │  (CI/CD)      │    │  (Dashboard)  │
└───────┬───────┘    └───────┬───────┘    └───────┬───────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
                    ┌─────────┴─────────┐
                    │  archon_core       │
                    │  (Pure library)    │
                    └─────────┬─────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│  Registry     │    │  Observability│    │  Security     │
│  (Postgres)   │    │  (OTel)       │    │  (HMAC+RL)   │
└───────────────┘    └───────────────┘    └───────────────┘
```

**Deployment options:**
- **Docker:** `docker-compose up` with mounted `/data` volume
- **Kubernetes:** Helm chart at `deploy/helm/archon-armor/`
- **Cloud Run:** Per `DEPLOY_GCP.md` instructions
- **Bare metal:** `pip install archon[otel,postgres]`

---

*This ADR is maintained alongside code on `hackathon-v2`. Bump date on substantive architecture changes.*
