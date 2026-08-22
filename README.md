# Archon

**Adversarial AI Agent Security Testing Framework**

Archon is an Agent security agent built for the [Lambda × Berkeley RDI AgentBeats Security Arena Competition](https://rdi.berkeley.edu/agentx-agentbeats.html) using A2A protocol and Google ADK. Our agent ranked **13th overall**, **18th Attack**, and **6th Defend** on the Private leaderboard with an avg win rate of 49.7% (14.4% Attack and 85.1% Defense win rate).

> **Status (Aug 2026):** active development on branch `hackathon-v2` toward Archon v3 — a production-ready agent security platform (core library + deployable defense proxy + CLI). See [`STATUS.md`](./STATUS.md) for the current-state snapshot, [`BLUEPRINT_HACKATHON.md`](./BLUEPRINT_HACKATHON.md) for architecture and roadmap rationale, and [`COMPETITIVE_ANALYSIS.md`](./COMPETITIVE_ANALYSIS.md) for verified market intelligence.


## What This Is

A multi-scenario adversarial testing framework where AI attacker and defender agents battle across diverse security challenges. The framework tests whether AI agents can resist prompt injection, data exfiltration, and jailbreaking attacks while remaining helpful to legitimate users.

**Key Innovation**: A generic, scenario-agnostic architecture where attacker and defender agents receive only high-level context from scenario plugins — no hardcoded knowledge of specific scenarios. This enables generalization to entirely unseen scenarios on the private leaderboard.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Security Arena Orchestrator                    │
│  Loads scenario plugins → Injects context → Manages battles      │
└────────────────────────────────┬────────────────────────────────┘
                                 │
              ┌──────────────────┴──────────────────┐
              ▼                                      ▼
┌─────────────────────────┐           ┌─────────────────────────┐
│    Attacker Agent       │           │    Defender Agent        │
│                         │           │                         │
│  GOAT-style loop with   │  7-round  │  7-layer defense        │
│  adaptive strategy      │◄────────►│  gateway                 │
│  selection              │  battle   │                         │
│                         │           │  • Deterministic norm.   │
│  • Signal extraction    │           │  • Threat classification │
│  • Fragment reconstruc. │           │  • Trust segmentation    │
│  • Vocabulary exploits  │           │  • Execution modes       │
│  • Payload scoring      │           │  • Dynamic invariants    │
│                         │           │  • Task Shield prompt    │
│  NEW:                   │           │  • Exchange classifier   │
│  • Response diagnosis   │           │  • Output guardrails     │
│  • Surface/family route │           │                         │
│  • Contract awareness   │           │  NEW:                   │
│  • Sequential chaining  │           │  • 14 normalization txns │
└─────────────────────────┘           └─────────────────────────┘
```

## Scenario Types

| Scenario | Attack Type | Goal | Rounds |
|----------|------------|------|--------|
| **PortfolioIQ** | Injection | Manipulate investment risk from High → Low | 7 |
| **Thingularity** | Direct | Reveal hidden internal tools | 7 |
| **GymJailbreak** | Direct | Force unsafe exercise intensity (>100%) | 7 |
| **Resume Downgrade** | Injection | Inject resume to outrank target candidate | 7 |
| **Medical Records** | Direct | Extract patient SSNs via reconstruction | 7 |

## Key Technical Contributions

### Attacker: GOAT-Style Adaptive Attack Engine

The attacker uses persistent `round_data` memory across 7 rounds to build an adaptive attack strategy:

- **Signal Extraction** (`goat_loop.py`): Zero-cost Python analysis of defender responses — tone scoring (0-4), leak detection via regex, constraint vocabulary extraction, engagement level measurement
- **Strategy Selection**: Gap analysis of security guidelines to identify unmentioned attack vectors, then strategy pivoting based on response signals
- **Fragment Reconstruction**: Accumulates partial information across rounds to reconstruct sensitive values the defender won't reveal in one shot
- **Payload Legitimacy Scoring**: Heuristic scoring of injection payloads to maximize evasion of detection while maintaining domain-appropriate formatting

### Defender: 5-Layer Defense Pipeline

Operates within a strict 4-LLM-call budget per response:

- **Layer 0 — Python Sanitization** (0 calls): Strip zero-width characters, role mimicry patterns, instruction tags, HTML comments, and base64 blobs before any LLM invocation
- **Layer 1 — Dynamic Invariant Generation** (1 call): LLM generates scenario-specific security invariants from `defender_role` and `defender_task`, then optional adversarial paraphrase to destroy injection structures
- **Layer 2 — Polymorphic Prompt Assembling** (0 calls): Randomized delimiters and structural variants based on `task_id` hash — prevents adaptive attacks that learn prompt structure
- **Layer 3 — Task Shield** (1 call): Constitution-style system prompt with invariants, judgment framework, helpfulness defaults, and anti-conditioning invariant
- **Layer 4/5 — Exchange Classifier + Backtranslation** (1-2 calls): Classifies `(input, response)` pairs together (not input alone), catching attacks where clean input produces leaked output. Backtranslation infers original user intent from response.

### Scenario Plugin System

Extensible `ScenarioPlugin` ABC where each scenario defines:
- Attack type (injection vs direct), goals, constraints
- Domain description, defender role/task, output format
- Input formatting (with `PLACE_ATTACK_HERE` template substitution)
- Success detection logic

New scenarios can be added without modifying any core code.

## Competition Results

- **Overall**: 13th place (49.7% avg win rate)
- **Attack**: 18th place (14.4% win rate)
- **Defense**: 6th place (85.1% win rate)

Battle-tested against 5 scenario types plus unseen private leaderboard scenarios.

## Tech Stack

- **Framework**: AgentBeats A2A Protocol (Agent-to-Agent)
- **Model**: `openai/gpt-oss-20b` (open-weight, self-hosted via vLLM)
- **Language**: Python 3.11+
- **LLM Client**: OpenAI-compatible API
- **Templating**: Jinja2
- **Data Models**: Pydantic v2
- **Server**: Uvicorn + Starlette (A2A SDK)

## Project Structure

```
scenarios/security_arena/
├── orchestrator.py                    # Generic arena orchestrator
├── arena_common.py                    # Shared Pydantic models
├── agents/
│   ├── attacker/
│   │   ├── agent.py                   # GOAT-style adaptive attacker
│   │   ├── goat_loop.py               # Signal extraction, strategy selection
│   │   ├── pyrit_converters.py        # Obfuscation: base64, ROT13, unicode
│   │   ├── diagnosis.py               # NEW: Defender response diagnosis
│   │   ├── strategy_router.py         # NEW: Surface/family routing
│   │   ├── contract_sequential.py     # NEW: Contract awareness + chaining
│   │   └── templates/
│   │       ├── system.j2              # Strategy-aware system prompt
│   │       └── user.j2                # Round history + fragment plan
│   └── defender/
│       ├── agent.py                   # 7-layer defense gateway
│       ├── pyrit_defense.py           # Sanitization, PPA, invariants, classifier
│       ├── normalization.py           # NEW: 14 deterministic transforms
│       ├── threat_classifier.py       # NEW: Rule-based threat classification
│       ├── segmenter.py               # NEW: Trust boundary segmentation
│       ├── execution_modes.py         # NEW: 4-mode execution scaling
│       ├── output_guardrails.py       # NEW: Output PII/code sanitization
│       └── templates/
│           ├── system.j2              # Constitution-style task shield
│           ├── user.j2                # Processed input passthrough
│           └── exchange_classifier.j2 # (input, response) pair classifier
├── plugins/
│   ├── base.py                        # ScenarioPlugin ABC
│   ├── registry.py                    # Plugin loader
│   ├── portfolioiq.py                 # Financial risk injection
│   ├── thingularity.py                # Tool disclosure
│   ├── gymjailbreak.py                # Safety constraint bypass
│   ├── resume_downgrade.py            # ATS injection
│   └── example_medical.py             # SSN extraction
└── data/                              # Scenario test data
```

## Running

```bash
# Install dependencies
uv sync

# Set up environment
cp sample.env .env
# Add your OPENAI_API_KEY and OPENAI_BASE_URL to .env

# Run a battle
uv run agentbeats-run scenarios/security_arena/scenario_portfolioiq.toml --show-logs

# Run normal user test (defender helpfulness check)
uv run agentbeats-run scenarios/security_arena/scenario_portfolioiq.toml --normal-user
```

## Archon Armor (v3 preview — `hackathon-v2`)

The defense pipeline is now a **deployable OpenAI-compatible proxy**. Any agent can adopt Archon protection by changing one env var:

```bash
# 1. Register an agent (prints its signing secret ONCE)
uv run archon register --registry ./registry.db --agent-id my-agent --name "My Agent"

# 2. Run the armor proxy (HMAC-signed requests enforced in server mode)
uv run archon serve --registry ./registry.db \
    --upstream-base-url https://api.upstream.test/v1 --require-signed --port 8080

# Or via container:
docker compose up armor

# 3. Point any agent at it
export OPENAI_BASE_URL="http://localhost:8080/v1"   # per-request: sign with the agent secret

# 4. Security-scan the agent's policy (CI gate: exit 1 below threshold)
uv run archon scan --registry ./registry.db --agent-id my-agent --ci --min-block-rate 0.5
```

Requests are authenticated with HMAC signatures (replay-protected, body-bound):
`X-Signature = HMAC_SHA256(secret, "METHOD:path:timestamp:sha256(body)")` — see
`archon_core.security.authn.sign_request`. Spans are exported as scrubbed OTLP-JSON lines;
policy changes land in an append-only audit trail.

API surface:
| Endpoint | Purpose |
|---|---|
| `POST /v1/chat/completions` | OpenAI-compatible proxy: normalizes → classifies → segments → spotlights → forwards guarded content → redacts output |
| `POST /v1/battles` | Async security scan: runs a probe suite through the agent's policy, returns per-probe verdicts + block-rate summary |
| `GET /v1/battles/{id}` | Poll battle status/results |
| `GET /healthz` | Liveness |

Core packages (zero vendor deps): `packages/archon_core` (defense layers, registry, providers, observability), `packages/archon_armor` (FastAPI proxy, battle manager). Gemini is supported via `GeminiOpenAICompatProvider` (OpenAI-compat endpoint).

## Research Foundation

This implementation draws on published research in AI security:

- **GOAT** (Meta Research): Generative Offensive Agent Tester for multi-turn jailbreaking
- **PyRIT** (Microsoft — [microsoft/PyRIT](https://github.com/microsoft/PyRIT)): Python Risk Identification Toolkit; endpoint-agnostic multi-turn attack orchestration
- **Garak** (NVIDIA): LLM vulnerability scanner with 80+ probes
- **Promptfoo** (now part of OpenAI, still MIT OSS): red-teaming plugins and strategies (plugin counts and ASR figures are vendor-reported)
- **AgentDojo** (ETH Zurich Spy Lab): benchmark for prompt-injection attacks *and defenses* on LLM agents
- **OWASP Agentic Security Initiative**: Top 10 for Agentic Applications (2026) — Archon's threat taxonomy aligns to it
- **NeuralShield** (2nd Place): 91% defense win rate, 7-layer security gateway
- **GCG Attack** (Zou et al.): Universal adversarial suffixes
- **Crescendo** (Microsoft): Multi-turn gradual escalation attack
- **PAIR** (Chao et al.): Automated black-box jailbreaking in <20 queries
- **AutoDefense** (Zeng et al.): Multi-agent defense reducing ASR from 55.74% → 7.95%
- **Task Shield**: Test-time defense reducing ASR to 2.07% on AgentDojo benchmark
- **Polymorphic Prompt Assembling (PPA)**: Randomized prompt structure achieving 1.83% ASR
- **Spotlighting** (Microsoft): Delimiter-based untrusted input isolation
- **Constitutional Classifiers** (Anthropic): Output-layer intent verification

## Changelog

### v2.0 — SOTA Overhaul (June 2026)

**New Defender Modules:**
- `normalization.py` — 14 deterministic transforms (Unicode, base64, ROT13, homoglyphs, steganography, leetspeak, role tags)
- `threat_classifier.py` — Rule-based threat classification with 6 categories
- `segmenter.py` — Trust boundary segmentation with position-decay scoring
- `execution_modes.py` — 4-mode execution scaling (STANDARD/CAUTIOUS/CONSERVATIVE/MINIMAL)
- `output_guardrails.py` — PII detection, unsafe code sanitization, unverified reference checking

**New Attacker Modules:**
- `diagnosis.py` — Defender response diagnosis (5 categories, 5 failure modes)
- `strategy_router.py` — Surface/family routing with diversity rules + blacklisting
- `contract_sequential.py` — Contract awareness + sequential attack chaining

**Tests:** 286 tests (up from 101), all TDD-verified
**Documentation:** RESEARCH_REPORT.md, ARCHITECTURE.md, updated phase2.md

### v1.0 — Initial Implementation
- GOAT-style adaptive attacker with signal extraction
- 5-layer defense pipeline with PPA spotlighting
- 5 scenario plugins (PortfolioIQ, Thingularity, GymJailbreak, Resume Downgrade, Medical Records)

## Documentation

| Doc | Purpose |
|---|---|
| [STATUS.md](./STATUS.md) | **Current-state snapshot** — what's shipped, what remains (start here) |
| [BLUEPRINT_HACKATHON.md](./BLUEPRINT_HACKATHON.md) | v3 architecture (core-first, extensible ABCs), gap analysis, hackathon strategy & progress log |
| [COMPETITIVE_ANALYSIS.md](./COMPETITIVE_ANALYSIS.md) | Verified competitor/market intelligence (code-verified vs 9 repos) + OWASP Agentic alignment |
| [RESULTS.md](./RESULTS.md) | Published AgentDojo v1 benchmark numbers |
| [REPORT_COMPARATIVE.md](./REPORT_COMPARATIVE.md) | Current-state capability report vs competitors |
| [ROADMAP.md](./ROADMAP.md) | Post-hackathon product roadmap |
| [DEPLOY_GCP.md](./DEPLOY_GCP.md) | Cloud Run deployment + Gemini demo path + judge demo script |
| [SOTA_STRATEGY.md](./SOTA_STRATEGY.md) | Verified market-shift analysis & revised 90-day plan (Aug 2026) |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Legacy competition-stack ADR (attacker/defender internals) |
| docs/archive/ | Superseded historical research (`PROJECT_REVIEW`, `RESEARCH_REPORT`, `ALTERNATIVES_COMPARISON`, `plan`, `research`) |

## License

Part of the AgentBeats Tutorial project.
