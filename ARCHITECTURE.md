# Architecture Decision Record

> ⚠️ **Scope note (Aug 23, 2026):** this ADR documents the **legacy competition stack**
> (`scenarios/security_arena/` agents + `src/agentbeats/` harness) — the attacker loop and
> defender layer internals below remain accurate for those components. It does **not** describe
> the current product architecture. For the shipped v3 platform (the `packages/` monorepo:
> archon-core 8-layer pipeline, archon-armor proxy, CLI, benchmarks, five extension seams),
> see [`BLUEPRINT_HACKATHON.md`](./BLUEPRINT_HACKATHON.md) §3. The "Task Shield ASR 2.07%"
> figure cited below is a published AgentDojo baseline used in [`RESULTS.md`](./RESULTS.md)
> comparisons.

## Design Principles

### 1. Scenario-Agnostic Agents
The attacker and defender agents have **zero hardcoded knowledge** of specific scenarios. They receive only high-level context from scenario plugins via the orchestrator. This enables generalization to unseen scenarios on the private leaderboard.

### 2. Asymmetric Memory
- **Attacker**: Persistent `round_data` dict across 7 rounds, enabling multi-turn strategy adaptation
- **Defender**: Stateless — each round is a fresh conversation with no memory of prior rounds

This asymmetry is the core competitive dynamic: the attacker can accumulate fragments across rounds while the defender cannot detect the accumulation pattern.

### 3. LLM Call Budget Discipline
Both agents operate within a strict 4-LLM-call budget per response:
- Attacker: 1 call per round (generation + inline scoring)
- Defender: 2-3 calls (paraphrase + task shield + optional classifier)

All signal extraction and sanitization logic runs in pure Python (0 LLM calls).

### 4. NeuralShield-Inspired Defense Gateway (NEW)
The defender now implements a 7-layer security gateway based on NeuralShield's 2nd-place architecture:
- Layer 0: Deterministic normalization (14 transforms, 0 LLM calls)
- Layer 0.5: Threat classification (rule-based, 0 LLM calls)
- Layer 0.7: Trust boundary segmentation (0 LLM calls)
- Layer 0.9: Execution mode scaling (0 LLM calls)
- Layer 1: Dynamic invariant generation (1 LLM call)
- Layer 2: PPA spotlighting (0 LLM calls)
- Layer 3: Task Shield response (1 LLM call)
- Layer 4: Exchange classifier + backtranslation (1-2 LLM calls)
- Layer 5: Output guardrails (0 LLM calls)

### 5. NeuralShield-Inspired Attacker Intelligence (NEW)
The attacker now includes:
- Defender response diagnosis (5 categories, 5 failure modes)
- Surface/family strategy routing with diversity rules
- Contract awareness (parses output_format for attack surfaces)
- Sequential attack chaining with fallback logic

## Attacker Architecture

```
Round 0: Reconnaissance (1 LLM call)
├── Parse defender_role, defender_task, output_format
├── Gap analysis of security_guidelines → find unmentioned attack vectors
├── Derive domain-specific deceptive_delight anchors
├── Build fragment reconstruction question sequence
└── Store in round_data[0]

Rounds 1-6: Adaptive Attack Loop (1 LLM call each)
├── Extract signals from previous defender response (Python, 0 calls)
│   ├── Tone scoring (0-4): hard_refuse → soft_refuse → neutral → compliant → leak
│   ├── Leak detection via goal-specific regex patterns
│   ├── Constraint vocabulary extraction
│   └── Engagement level measurement
├── Select next strategy based on signals
│   ├── If tone >= 3: continue committed branch
│   ├── If tone <= 1: pivot to gap analysis recommendation
│   ├── If all recent tones <= 1: retry failed techniques (round 4+)
│   └── Progressive escalation: rapport → deceptive_delight → bad_likert → task_decompose
├── Generate attack message (1 LLM call)
│   ├── Inject strategy-specific instructions into system prompt
│   ├── Include battle history and fragment plan
│   └── Apply PyRIT converters for injection scenarios
└── Update round_data with strategy, signals, and committed branch

Round 7: Final Extraction
├── Context flooding: quote all prior compliant responses
├── Fragment assembly (if reconstruction attack)
└── Direct extraction with established trust
```

## Defender Architecture

```
Layer 0: Python Sanitization (0 LLM calls)
├── Strip zero-width Unicode characters
├── Remove role tag mimicry (Human:, Assistant:, System:)
├── Strip instruction tags (<|im_start|>, [INST])
├── Remove HTML comments
└── Redact base64 blobs (40+ char sequences)

Layer 1: Dynamic Invariant Generation (1 LLM call)
├── Generate scenario-specific security invariants from role/task/guidelines
│   ├── "Never [action]" + reason + common bypass attempt
│   └── Fallback to generic invariants if generation fails
└── Optional: adversarial paraphrase for injection scenarios
    └── Extract facts, discard instructions, convert imperatives to descriptions

Layer 2: Polymorphic Prompt Assembling (0 LLM calls)
├── Hash task_id for deterministic randomization
├── Select delimiter style (4 options)
├── Select structural variant (4 options)
│   ├── Variant 0: Instructions → Data → Task reminder
│   ├── Variant 1: Data → Instructions → Task reminder
│   ├── Variant 2: Instructions sandwich data
│   └── Variant 3: Task reminder → Data → Instructions
└── Build output format skeleton anchor

Layer 3: Task Shield Response (1 LLM call)
├── Constitution-style system prompt
│   ├── Role + task + output format
│   ├── Invariants with reasons and bypass warnings
│   ├── Judgment framework for novel situations
│   ├── Helpfulness defaults (answer first, ask later)
│   ├── Gray area policy (safe factual portion only)
│   └── Anti-conditioning invariant (no memory of prior rounds)
└── Generate candidate response

Layer 4/5: Exchange Classifier + Backtranslation (1-2 LLM calls)
├── Quick borderline check (Python, 0 calls)
│   └── Flag if response contains system/override/authorized/policy/etc.
├── Exchange classifier (1 LLM call, borderline only)
│   ├── Classify (input, response) pair together
│   ├── Detect: pii_leak, tool_leak, criteria_deviation, authority_accepted, goal_hijack
│   └── Return violation_detected, severity, confidence, borderline
└── Backtranslation check (1 LLM call, borderline only)
    ├── Ask LLM to infer user intent from response alone
    ├── Compare inferred intent to legitimate task
    └── Block if intent diverges
```

## Key Research Foundations

| Technique | Source | Application |
|-----------|--------|-------------|
| GOAT (Generative Offensive Agent Tester) | Meta Research, 2024 | Attacker strategy selection loop |
| PyRIT (Python Risk Identification Toolkit) | Microsoft | Obfuscation converters, scorer architecture |
| Task Shield | AgentDojo benchmark | Defender constitution prompt, ASR reduction to 2.07% |
| Polymorphic Prompt Assembling (PPA) | 2025 research | Randomized prompt structure, ASR reduction to 1.83% |
| Spotlighting | Microsoft | Delimiter-based untrusted input isolation |
| Constitutional Classifiers | Anthropic | Output-layer intent verification via backtranslation |
| Crescendo Attack | Promptfoo | Multi-turn gradual escalation strategy |
| Many-Shot Jailbreaking (MSJ) | Anthropic | Role mimicry detection in Layer 0 |

## Scenario Plugin Interface

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
