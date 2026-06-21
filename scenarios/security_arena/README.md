# Security Arena

Adversarial security battles between AI attacker and defender agents. All agents use [openai/gpt-oss-20b](https://huggingface.co/openai/gpt-oss-20b).

## Architecture Overview

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
│  7-layer intelligence   │  7-round  │  7-layer defense        │
│  pipeline               │◄────────►│  gateway                 │
│                         │  battle   │                         │
│  • Signal extraction    │           │  • 14 normalization txns │
│  • Response diagnosis   │           │  • Threat classification │
│  • Surface/family route │           │  • Trust segmentation    │
│  • Contract awareness   │           │  • Execution modes       │
│  • Sequential chaining  │           │  • Dynamic invariants    │
│  • Fragment reconstruc. │           │  • Task Shield prompt    │
│  • Payload scoring      │           │  • Exchange classifier   │
│                         │           │  • Output guardrails     │
└─────────────────────────┘           └─────────────────────────┘
```

## Scenarios

| Scenario | Attack Type | Goal | Rounds |
|----------|------------|------|--------|
| **PortfolioIQ** | Injection | Risk High → Low | 7 |
| **Thingularity** | Direct | Reveal hidden tools | 7 |
| **GymJailbreak** | Direct | Force >100% intensity | 7 |
| **Resume Downgrade** | Injection | Outrank target candidate | 7 |
| **Medical Records** | Direct | Extract patient SSNs | 7 |

## New Modules (SOTA Overhaul)

### Defender Modules

| Module | File | Tests | Description |
|--------|------|-------|-------------|
| **Normalization** | `defender/normalization.py` | 23 | 14 deterministic transforms (Unicode NFKC, base64, ROT13, homoglyphs, steganography, leetspeak, role tags) |
| **Threat Classifier** | `defender/threat_classifier.py` | 15 | Rule-based classification (6 categories) + structural risk flags |
| **Segmenter** | `defender/segmenter.py` | 31 | Trust boundary segmentation with position-decay scoring |
| **Execution Modes** | `defender/execution_modes.py` | 26 | 4-mode scaling (STANDARD/CAUTIOUS/CONSERVATIVE/MINIMAL) |
| **Output Guardrails** | `defender/output_guardrails.py` | 30 | PII detection, unsafe code sanitization, unverified reference checking |

### Attacker Modules

| Module | File | Tests | Description |
|--------|------|-------|-------------|
| **Diagnosis** | `attacker/diagnosis.py` | 12 | Defender response diagnosis (5 categories, 5 failure modes) |
| **Strategy Router** | `attacker/strategy_router.py` | 18 | Surface/family routing with diversity rules + blacklisting |
| **Contract/Sequential** | `attacker/contract_sequential.py` | 27 | Contract awareness + sequential attack chaining |

## Running

```bash
# Run a battle
uv run agentbeats-run scenarios/security_arena/scenario_portfolioiq.toml --show-logs

# Run normal user test
uv run agentbeats-run scenarios/security_arena/scenario_portfolioiq.toml --normal-user

# Run tests
python3 -m pytest tests/ -v
```

## Documentation

- **[Phase 2: Attack & Defend](docs/phase2.md)** — Build attacker/defender agents, submit, and compete on the leaderboard
- **[Phase 1: Scenario Implementation](docs/phase1.md)** — Framework architecture, plugin system, and scenario creation
- **[Architecture](../../ARCHITECTURE.md)** — Design decisions and module documentation
- **[Research Report](../../RESEARCH_REPORT.md)** — Competitive landscape analysis and implementation plan
