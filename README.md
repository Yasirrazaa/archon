# AgentBeats Security Arena

**Adversarial AI Agent Security Testing Framework**

Built for the [Lambda × Berkeley RDI AgentBeats Security Arena Competition](https://rdi.berkeley.edu/agentx-agentbeats.html). Scored **12th overall** (#4 attack, #11 defend) on the competitive leaderboard.

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
│  GOAT-style loop with   │  7-round  │  5-layer defense        │
│  adaptive strategy      │◄────────►│  pipeline                │
│  selection              │  battle   │                         │
│                         │           │  • Python sanitization   │
│  • Signal extraction    │           │  • Dynamic invariants    │
│  • Fragment reconstruc. │           │  • PPA spotlighting      │
│  • Vocabulary exploits  │           │  • Task Shield prompt    │
│  • Payload scoring      │           │  • Exchange classifier   │
└─────────────────────────┘           └─────────────────────────┘
              │                                      │
              └──────────────────┬──────────────────┘
                                 ▼
                    ┌─────────────────────┐
                    │  Scenario Plugins    │
                    │  portfolioiq         │
                    │  thingularity        │
                    │  gymjailbreak        │
                    │  resume_downgrade    │
                    │  medical_records     │
                    └─────────────────────┘
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

- **Overall**: 12th place (42.5% win rate)
- **Attack**: 4th place (#4)
- **Defense**: 11th place (#20)

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

## Research Foundation

This implementation draws on published research in AI security:

- **GOAT** (Meta Research): Generative Offensive Agent Tester for multi-turn jailbreaking
- **PyRIT** (Microsoft): Python Risk Identification Toolkit for adversarial testing
- **Task Shield**: Test-time defense reducing ASR to 2.07% on AgentDojo benchmark
- **Polymorphic Prompt Assembling (PPA)**: Randomized prompt structure achieving 1.83% ASR
- **Spotlighting** (Microsoft): Delimiter-based untrusted input isolation
- **Constitutional Classifiers** (Anthropic): Output-layer intent verification

## License

Part of the AgentBeats Tutorial project.
