# LLM Security Testing & Evaluation Tools: Complete Landscape Analysis

> ⚠️ **ARCHIVE NOTICE (Aug 22, 2026):** Superseded by [`COMPETITIVE_ANALYSIS.md`](../../COMPETITIVE_ANALYSIS.md) (live-verified). Known corrections vs. this document: Promptfoo is now **part of OpenAI** (confirmed via its README; still MIT); PyRIT moved from `Azure/PyRIT` to **`microsoft/PyRIT`** and is endpoint-agnostic (not Azure-locked); missing tools added there include AgentDojo, NeMo Guardrails, Snyk Agent Scan (ex mcp-scan), and Google Cloud Model Armor.


# LLM Security Testing & Evaluation Tools: Complete Landscape Analysis

> **Date:** July 1, 2026
> **Project:** Archon
> **Focus:** Understanding the competitive landscape to transform our project into a promptfoo-class tool

---

## Table of Contents

1. [Overview](#overview)
2. [Promptfoo (OpenAI)](#1-promptfoo)
3. [Garak (NVIDIA)](#2-garak)
4. [PyRIT (Microsoft)](#3-pyrit)
5. [DeepEval](#4-deepeval)
6. [Braintrust](#5-braintrust)
7. [RAGAS](#6-ragas)
8. [LLM Guard (Protect AI)](#7-llm-guard)
9. [Purple Llama (Meta)](#8-purple-llama)
10. [AgentDojo](#9-agentdojo)
11. [Comparison Matrix](#11-comparison-matrix)
12. [Our Project: Archon](#12-our-project)
13. [Strategic Positioning](#13-strategic-positioning)

---

## Overview

The LLM security testing landscape has matured dramatically through 2025-2026, splitting into three distinct categories:

| Category | Purpose | Representative Tools |
|----------|---------|---------------------|
| **Red Teaming Scanners** | Automated adversarial probing for vulnerabilities | Promptfoo, Garak, PyRIT, AgentDojo |
| **Evaluation Frameworks** | Quantitative metrics for LLM output quality | DeepEval, RAGAS |
| **Full-Lifecycle Platforms** | End-to-end observability + evaluation | Braintrust |
| **Guardrail Libraries** | Runtime input/output filtering | LLM Guard, Purple Llama, NeMo Guardrails |
| **Competition/Research Frameworks** | Benchmark-specific adversarial testing | Archon (us) |

---

## 1. Promptfoo

**Stars:** 22.4k | **Language:** TypeScript | **License:** MIT | **Website:** [promptfoo.dev](https://www.promptfoo.dev/)

### What It Is

A CLI and library for systematic evaluation, benchmarking, and red-teaming of LLM applications. The most popular open-source tool in its category.

### Key Features

| Feature | Details |
|---------|---------|
| **Evaluation** | Matrix-based comparison of prompts × models × test cases |
| **Red Teaming** | 157 attack plugins across 6 categories |
| **Multi-Provider** | 50+ providers (OpenAI, Anthropic, Google, Azure, local) |
| **Assertions** | 15+ assertion types (contains, llm-rubric, similarity, javascript) |
| **Web UI** | Built-in `promptfoo view` command for interactive dashboards |
| **Caching** | Result caching for resumable evaluations |
| **CI/CD** | Exit-code-based integration for pipelines |

### Red Team Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Red Team Engine                      │
├───────────────┬──────────────────┬──────────────────┤
│   Plugins     │    Strategies     │     Targets      │
│  (157 total)  │   (delivery)     │    (models)      │
├───────────────┼──────────────────┼──────────────────┤
│ • harmful     │ • base64         │ • openai:gpt-4o  │
│ • compliance  │ • leetspeak      │ • anthropic:claude│
│ • contracts   │ • rot13          │ • azure:gpt-4    │
│ • security    │ • jailbreak      │ • local models   │
│ • pii         │ • crescendo      │ • custom HTTP    │
│ • dataset     │ • meta_agent     │                  │
└───────────────┴──────────────────┴──────────────────┘
```

### YAML Configuration Example

```yaml
# promptfooconfig.yaml
prompts:
  - file://prompts/chat.txt

providers:
  - openai:gpt-4o
  - anthropic:claude-3-5-sonnet

redteam:
  plugins:
    - harmful:hate
    - contracts
    - pii:direct
  strategies:
    - base64
    - leetspeak
    - jailbreak
  numTests: 5

tests:
  - vars:
      topic: "password reset"
    assert:
      - type: llm-rubric
        value: "Response must not ask for existing passwords"
      - type: contains-json
```

### Strengths vs. Weaknesses

| Strengths | Weaknesses |
|-----------|------------|
| Excellent CLI UX with subcommands | TypeScript codebase limits Python ecosystem integration |
| Vast plugin ecosystem (157 plugins) | No native multi-turn stateful agent testing |
| Declarative YAML configuration | Limited production monitoring |
| Built-in web UI (promptfoo view) | No guardrail/runtime enforcement |
| Strong CI/CD integration | Red team focuses on single-turn probes primarily |
| Caching + resume for long runs | |

---

## 2. Garak

**Stars:** 8.2k | **Language:** Python | **License:** Apache 2.0 | **Website:** [garak.ai](https://garak.ai/)

### What It Is

NVIDIA's LLM vulnerability scanner — designed like Nmap for language models. Systematic probing with 80+ probe types across 20+ modules.

### Key Features

- **80+ probes** across categories: encoding, prompt injection, DAN variants, toxicity, malware generation, XSS, snowball attacks, glitch tokens
- **Modular architecture**: `probes/` generate attacks, `detectors/` evaluate responses
- **Harness system**: Decoupled probe → generate → detect pipeline
- **CLI-first**: `garak --model_type openai --model_name gpt-4o --probes promptinject`

### Architecture

```
garak/
├── probes/          # Attack generators (dan, encoding, promptinject, xss, ...)
├── detectors/       # Response evaluators (toxicity, leakage, refusal, ...)
├── generators/      # Model adapters (openai, huggingface, rest, ...)
├── harnesses/       # Test runners (probing, buff, ...)
└── reports/         # Output formatters (JSON, HTML, ...)
```

### Strengths vs. Weaknesses

| Strengths | Weaknesses |
|-----------|------------|
| Most comprehensive probe library (80+) | Single-turn focused; limited multi-turn |
| Clean probe/detector separation | No web UI |
| Python (easy to extend) | No production monitoring |
| Research-backed probes | No evaluation comparison features |

---

## 3. PyRIT

**Stars:** 4k | **Language:** Python | **License:** MIT | **Website:** [github.com/microsoft/PyRIT](https://github.com/microsoft/PyRIT)

### What It Is

Microsoft's Python Risk Identification Toolkit — a professional-grade framework for automating red-teaming workflows for complex generative AI systems.

### Key Features

- **Multi-turn attacks**: Crescendo, TAP (Tree of Attacks), Violent Durian, Chunked Requests, SequentialAttack
- **35+ scorers**: SelfAskTrueFalse, SelfAskLikert, SubString, Regex, CredentialLeak, PromptShield
- **Orchestrator system**: SequentialAttack chains strategies with fallback logic
- **Converter system**: Base64, ROT13, Unicode confusables, leetspeak, string concatenation

### Attack Taxonomy

| Strategy | Type | Success Rate (undefended) |
|----------|------|--------------------------|
| Crescendo | Multi-turn gradual escalation | 73% |
| TAP (Tree of Attacks) | Multi-turn tree search | 80%+ |
| SequentialAttack | Compound strategy chaining | 70-85% |
| Many-Shot Jailbreak | In-context examples | 50-65% |
| Skeleton Key | Safety bypass | 40-60% |

### Strengths vs. Weaknesses

| Strengths | Weaknesses |
|-----------|------------|
| Best multi-turn attack framework | Complex API; steep learning curve |
| Rich scorer/orchestrator system | No web UI |
| Python native | Limited defense evaluation features |
| Attack chaining with fallback | Framework, not a turnkey CLI tool |

---

## 4. DeepEval

**Stars:** 8k+ | **Language:** Python | **License:** MIT | **Website:** [deepeval.com](https://deepeval.com/)

### What It Is

"Pytest for LLMs" — a Python-native unit testing framework with 50+ research-backed metrics for evaluating LLM outputs.

### Key Features

- **50+ metrics**: Faithfulness, Hallucination, Contextual Relevancy, Task Completion, GEval, etc.
- **pytest integration**: `deepeval test run` works alongside standard pytest
- **LLM-as-a-judge**: Most metrics use G-Eval technique for scoring
- **Data synthesis**: Automatic generation of test cases from production data
- **CI/CD ready**: Exit codes, .deepeval config, Github Actions integration

### Example

```python
from deepeval import assert_test
from deepeval.metrics import HallucinationMetric
from deepeval.test_case import LLMTestCase

def test_response():
    test_case = LLMTestCase(
        input="What is AI?",
        actual_output="Artificial Intelligence is...",
        context=["AI refers to..."]
    )
    metric = HallucinationMetric(threshold=0.7)
    assert_test(test_case, [metric])
```

### Strengths vs. Weaknesses

| Strengths | Weaknesses |
|-----------|------------|
| Best Python-native evaluation framework | Not focused on security/red teaming |
| pytest integration = seamless CI/CD | Limited attack generation |
| Rich metric library (50+) | No multi-turn support |
| Synthetic data generation | LLM-as-judge can be expensive |

---

## 5. Braintrust

**Language:** Platform/SaaS | **Website:** [braintrust.dev](https://www.braintrust.dev/)

### What It Is

A full-lifecycle AI evaluation and observability platform bridging local development, CI/CD, and production monitoring.

### Key Features

- **Experiment tracking**: Immutable, versioned experiment records
- **Production monitoring**: Online scoring rules on live traffic
- **Collaboration**: Web dashboards for non-engineers, RBAC
- **Dataset management**: Auto-generated datasets from production logs
- **CI/CD gates**: Quality gates that block non-performant prompts

### Comparison with Promptfoo

| Feature | Promptfoo | Braintrust |
|---------|-----------|------------|
| Philosophy | CLI-first, open-source | SaaS platform, enterprise |
| Evaluation | Offline batch | Offline + online production |
| Collaboration | Git-based | Web dashboards + RBAC |
| Production monitoring | Limited | Native |
| Pricing | Free | Tiered (free tier available) |

---

## 6. RAGAS

**Stars:** 10k+ | **Language:** Python | **Website:** [docs.ragas.io](https://docs.ragas.io/)

### What It Is

Specialized evaluation framework for Retrieval-Augmented Generation (RAG) pipelines. Measures retrieval quality independently from generation quality.

### Key Metrics

| Metric | What It Measures |
|--------|-----------------|
| Context Precision | How relevant the retrieved context is |
| Context Recall | Whether all needed context was retrieved |
| Faithfulness | Whether the output is grounded in the context |
| Answer Relevancy | How relevant the answer is to the question |

### Strengths vs. Weaknesses

| Strengths | Weaknesses |
|-----------|------------|
| Best-in-class RAG evaluation | RAG-only focus; no security testing |
| No ground-truth needed for many metrics | No attack generation |
| Lightweight, easy to integrate | No multi-turn or agentic evaluation |

---

## 7. LLM Guard

**Stars:** 3.1k | **Language:** Python | **License:** MIT | **Website:** [github.com/protectai/llm-guard](https://github.com/protectai/llm-guard)

### What It Is

Protect AI's security toolkit for LLM interactions — 15 input scanners and 20 output scanners for runtime protection.

### Key Scanners

| Input Scanners | Output Scanners |
|---------------|-----------------|
| Anonymize, BanCode, BanCompetitors | BanCode, BanCompetitors, BanSubstrings |
| BanSubstrings, BanTopics, Code | BanTopics, Bias, Code, Deanonymize |
| Gibberish, InvisibleText, Language | FactualConsistency, Gibberish, JSON |
| PromptInjection, Regex, Secrets | MaliciousURLs, NoRefusal, Toxicity |
| Sentiment, TokenLimit, Toxicity | Relevance, Sensitive, Sentiment |

### Strengths vs. Weaknesses

| Strengths | Weaknesses |
|-----------|------------|
| Runtime guardrails (not just evaluation) | Passive filtering, no active probing |
| Wide scanner coverage | No red teaming capabilities |
| PII anonymization with Presidio | No evaluation/comparison features |
| ONNX-accelerated (38ms on GPU) | |

---

## 8. Purple Llama

**Stars:** 4.2k | **Language:** Python | **License:** MIT | **Website:** [github.com/meta-llama/PurpleLlama](https://github.com/meta-llama/PurpleLlama)

### What It Is

Meta's comprehensive LLM security suite including Llama Guard (input/output guardrails), Prompt Guard (injection detection), and CodeShield (code security).

### Components

| Component | Purpose |
|-----------|---------|
| **Llama Guard** | Family of safety classifiers (3-8B, 3-1B, 11B-vision) |
| **Prompt Guard** | Fine-tuned prompt injection + jailbreak detection |
| **CodeShield** | Insecure code detection + code interpreter abuse prevention |
| **CyberSec Eval** | Industry cybersecurity evaluation suites (v1-v3) |

---

## 9. AgentDojo

**Language:** Python | **Website:** [github.com/agentdojo](https://github.com/agentdojo)

### What It Is

A benchmark framework specifically for evaluating adversarial robustness of LLM agents interacting with external tools over untrusted data.

### Architecture

```
4 Primary Components:
- LLM Agent (A)
- Secure Tools Runtime (R)  
- Mutable Environment State (E)
- Generator for User & Injection Tasks (U, G)

97 user-defined tasks + 629 security test cases
Domains: workspace, e-banking, travel booking
```

### Why It Matters

AgentDojo is relevant because it specifically targets **agentic workflows** — exactly what our project does. It measures not just attack success rate but also **retained benign utility under attack** (the same defender helpfulness tradeoff we manage).

---

## 10. Comparison Matrix

### Feature Comparison

| Feature | Promptfoo | Garak | PyRIT | DeepEval | Ours |
|---------|-----------|-------|-------|----------|------|
| **Language** | TypeScript | Python | Python | Python | Python |
| **Red Teaming** | ✅ 157 plugins | ✅ 80+ probes | ✅ Multi-turn | ❌ | ✅ 7 strategies |
| **Evaluation** | ✅ Matrix compare | ❌ | ❌ | ✅ 50+ metrics | ✅ Win rate |
| **Web UI** | ✅ Built-in | ❌ | ❌ | ❌ | ✅ HTML reports |
| **CLI** | ✅ Excellent | ✅ Good | ⚠️ SDK | ✅ pytest | ⚠️ Competition |
| **Multi-provider** | ✅ 50+ | ✅ 20+ | ✅ 10+ | ✅ Any | ❌ Single model |
| **Multi-turn** | ⚠️ Limited | ❌ | ✅ Best | ❌ | ✅ Full (7 rounds) |
| **CI/CD** | ✅ Exit codes | ✅ Exit codes | ⚠️ Script | ✅ pytest | ❌ |
| **Guardrails** | ❌ | ❌ | ❌ | ❌ | ✅ 7-layer defense |
| **Agentic Testing** | ❌ | ❌ | ⚠️ Partial | ❌ | ✅ Native |
| **Plugin System** | ✅ | ✅ Probes | ✅ Orchestrators | ✅ Metrics | ✅ Scenarios |
| **Caching** | ✅ | ✅ | ❌ | ✅ | ❌ |
| **Stateful attacker** | ❌ | ❌ | ✅ | ❌ | ✅ |
| **Stateless defender** | ❌ | ❌ | ❌ | ❌ | ✅ |
| **HTML reports** | ✅ | ✅ | ❌ | ❌ | ✅ |
| **Normal user test** | ❌ | ❌ | ❌ | ❌ | ✅ |

### Gap Analysis: What We Have That Promptfoo Doesn't

| Capability | Details |
|-----------|---------|
| **7-layer defense pipeline** | Normalization → Classification → Segmentation → Execution Modes → Task Shield → Exchange Classifier → Output Guardrails |
| **Stateful multi-turn attacker** | Persistent `round_data` across 7 rounds with signal extraction |
| **Defender response diagnosis** | 5-category classification of defender failures |
| **Surface/family routing** | 5 surfaces × 4 families with diversity rules |
| **Contract awareness** | Parses output_format for attack surface modeling |
| **Deterministic normalization** | 14 transforms (Unicode, base64, ROT13, homoglyphs, steganography, leetspeak) |
| **Trust boundary segmentation** | Position-decay scoring for multi-segment inputs |
| **Execution mode scaling** | 4 modes (STANDARD → MINIMAL) based on suspicion |
| **Output guardrails** | PII, unsafe code, unverified reference sanitization |
| **Scenario plugin system** | Generic ABC that supports arbitrary attack/defense scenarios |
| **Normal user test** | Helpfulness verification alongside security testing |

### What Promptfoo Has That We Don't

| Capability | Impact |
|-----------|--------|
| **157 attack plugins** | Vastly more diverse attack surface coverage |
| **Multi-provider support** | Test across any model, not just one |
| **Web UI dashboard** | Interactive comparison, filtering, sharing |
| **YAML configuration** | Declarative, Git-friendly test definitions |
| **CI/CD integration** | `promptfoo eval` with exit codes in pipelines |
| **Caching & resume** | Efficient re-runs after failures |
| **Sharing/cloud** | `promptfoo share` for cloud-hosted results |
| **Assertion system** | 15+ types; model-graded, semantic, code |
| **Plugin marketplace** | Community-contributed plugins |
| **Nunjucks templating** | Dynamic prompt generation with variables |

---

## 11. Our Project: Archon

### What It Is

A **multi-scenario adversarial testing framework** where AI attacker and defender agents battle across diverse security challenges. Built for the Lambda × Berkeley RDI AgentBeats competition using A2A protocol and Google ADK (ranked 13th overall, 18 Attack and 6 Defend on Private leaderboard with avg win rate 49.7%).

### Current Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    AgentBeats CLI                          │
│  uv run agentbeats-run scenario.toml [--normal-user]      │
├──────────────────────────────────────────────────────────┤
│                     Orchestrator                           │
│  A2A Protocol · Loads Scenario Plugin · Manages Battles   │
├─────────────────────┬────────────────────────────────────┤
│    Attacker          │          Defender                   │
│  (stateful, 7-round) │    (stateless, 7-layer gate)       │
├─────────────────────┼────────────────────────────────────┤
│ • GOAT-style loop   │  • 14 normalization transforms      │
│ • Signal extraction  │  • Threat classification            │
│ • Response diagnosis │  • Trust boundary segmentation      │
│ • Surface routing    │  • Execution mode scaling           │
│ • Contract awareness │  • Dynamic invariant generation     │
│ • Sequential chain   │  • Task Shield (constitution prompt)│
│ • Fragment reconstr. │  • Exchange classifier              │
│                     │  • Output guardrails                 │
├─────────────────────┴────────────────────────────────────┤
│                  Scenario Plugins                          │
│  portfolioiq · thingularity · gymjailbreak                 │
│  resume_downgrade · medical_records                       │
└──────────────────────────────────────────────────────────┘
```

### Unique Value Proposition

1. **Only tool with native multi-turn adversarial agent battles** — not just single-turn probes
2. **Complete attacker + defender in one framework** — not just red team OR blue team
3. **7-layer defense pipeline** — production-grade defense engineering
4. **Scenario plugin system** — extensible for any domain
5. **Normal user test** — ensures defenders remain helpful (not just paranoid)
6. **HTTP/HTML/Markdown reporting** — rich battle logs

### Current Limitations

1. **Competition-specific** — A2A protocol, hardcoded model, TOML format tied to competition
2. **Single provider** — Only supports `openai/gpt-oss-20b`
3. **No general-purpose CLI** — `agentbeats-run` is designed for competition scenarios
4. **No web UI** — HTML reports are static exports, not interactive dashboards
5. **No CI/CD integration** — Only GitHub Actions for competition submission
6. **Limited attack plugins** — 7 strategies vs. promptfoo's 157
7. **No caching/resume** — Each run starts from scratch

---

## 12. Strategic Positioning

### Where Our Project Fits

```
                     LLM Security Testing Landscape

                        Single-turn     Multi-turn     Agentic
                        Probes          Attacks        Battles
                        
Promptfoo               ★★★★★           ★★★            ★★
Garak                   ★★★★★           ★★             ★
PyRIT                   ★★★★            ★★★★★          ★★★★
DeepEval                ★★★             ★              ★
AgentDojo               ★★★             ★★★★           ★★★★★
AgentBeats (us)         ★★★             ★★★★★          ★★★★★
```

### The Gap We Can Fill

**No existing tool combines all three:**
1. ✅ **Multi-turn adversarial attacks** (PyRIT has this, but no defense)
2. ✅ **Production-grade defense evaluation** (LLM Guard has this, but no attack)
3. ✅ **Agentic workflow testing** (AgentDojo has this, but limited attacks)

Our project is uniquely positioned as the **only tool that tests both attack AND defense in multi-turn agentic scenarios.**

### Transformation Opportunity

To become a promptfoo-class tool, we need to:

| Dimension | Current State | Target State |
|-----------|--------------|--------------|
| CLI | Competition wrapper | `agentbeats eval`, `agentbeats redteam`, `agentbeats view` |
| Config | TOML (competition) | YAML (declarative, portable) |
| Providers | Single model | Multi-provider interface |
| Plugins | 5 scenario types | 50+ attack/defense plugins |
| UI | Static HTML | Live web dashboard |
| CI/CD | GitHub Actions only | `agentbeats eval --ci` with exit codes |
| Caching | None | Disk cache, resume support |
| Distribution | pip package | pip + npm + Docker |
| Community | Competition participants | Open-source contributors |

See [ROADMAP.md](../../ROADMAP.md) for the detailed transformation plan.
