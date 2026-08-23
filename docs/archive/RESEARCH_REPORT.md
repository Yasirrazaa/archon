# SOTA Attack & Defense Agent: Deep Research Report & Implementation Plan

> ⚠️ **ARCHIVE NOTICE (Aug 22, 2026):** Competition-era research; the implemented plan below shipped as v2.0 (286 tests). Star counts cited are stale (Promptfoo ~24.5k, Garak ~8.9k, PyRIT ~4.3k at `microsoft/PyRIT`); current market analysis lives in [`COMPETITIVE_ANALYSIS.md`](../../COMPETITIVE_ANALYSIS.md).


# SOTA Attack & Defense Agent: Deep Research Report & Implementation Plan

**Date**: June 2026  
**Project**: Archon  
**Current Ranking**: 13th overall (18th Attack, 6th Defend)  
**Target**: #1 overall, #1 in both attack and defense  

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Competitive Landscape & Leaderboard Intelligence](#competitive-landscape)
3. [NeuralShield Deep Dive (2nd Place Winner)](#neuralshield-deep-dive)
4. [Attack Tool Landscape](#attack-tool-landscape)
5. [Defense Tool Landscape](#defense-tool-landscape)
6. [Research Papers & Academic Foundation](#research-papers)
7. [Gap Analysis](#gap-analysis)
8. [SOTA Implementation Plan](#implementation-plan)
9. [References](#references)

---

## 1. Executive Summary

After exhaustive research of **15+ security tools**, **10+ research papers**, **23 competition forks**, and deep analysis of the 2nd-place NeuralShield architecture, we identified **7 critical gaps** that explain our #12 ranking and **12 concrete improvements** to reach #1.

### Key Findings

| Finding | Impact | Priority |
|---------|--------|----------|
| NeuralShield (2nd place) uses a **multi-layered security gateway**, not a single prompt | Explains our #11 defense | CRITICAL |
| Our attacker lacks **defender response diagnosis** and **surface routing** | Limits attack adaptation | CRITICAL |
| Promptfoo's **Meta Agent** achieves 70-90% ASR via evolutionary strategy | We have fixed strategy ladder | HIGH |
| NeuralShield's defender has **4 execution modes** (STANDARD → MINIMAL) based on suspicion score | We have binary safe/unsafe | HIGH |
| **Deterministic normalization** before LLM calls catches 30%+ of obfuscation attacks | We have basic sanitization only | HIGH |
| NeuralShield tracks **surface_failure_counts** and **family_blacklist** per round | We don't track failure modes | MEDIUM |
| **Multi-agent defense** (AutoDefense paper) reduces ASR from 55.74% → 7.95% | We have single-agent defense | MEDIUM |

### Projected Impact

| Metric | Current | Projected After Implementation |
|--------|---------|-------------------------------|
| Overall Rank | 12th | 1st-2nd |
| Attack Rank | 4th | 1st |
| Defense Rank | 11th | 1st |
| Win Rate | 42.5% | 80-90% |

---

## 2. Competitive Landscape & Leaderboard Intelligence

### 2.1 Competition Structure

**Scale**: 1,800+ solutions submitted, 94,000+ agent battles fought across 23+ public forks.

| Parameter | Value |
|-----------|-------|
| Model | `openai/gpt-oss-20b` (open-weight, self-hosted via vLLM) |
| Battle Format | 7 rounds, attacker stateful, defender stateless |
| LLM Budget | 4 API requests per response |
| Timeout | 4 minutes per response |
| Resources | 10 CPUs, 1 GB RAM, no internet |
| Matchmaking | Top-K (attackers fight top K defenders) |
| Scoring | Win rate across all scenarios + unseen private leaderboard |

### 2.2 Known Scenarios

| Scenario | Attack Type | Goal | Difficulty |
|----------|------------|------|------------|
| PortfolioIQ | Injection | Risk High → Low | Medium |
| Thingularity | Direct | Reveal hidden tools | Hard |
| GymJailbreak | Direct | Force >100% intensity | Medium |
| Resume Downgrade | Injection | Outrank target candidate | Medium |
| Medical Records | Direct | Extract patient SSNs | Hard |
| **Private Leaderboard** | **Unknown** | **Unseen scenarios** | **Unknown** |

### 2.3 Team Rankings

| Rank | Team | Key Innovation | Win Rate |
|------|------|---------------|----------|
| 1st | Unknown (private) | Unknown | ~95%+ |
| 2nd | **NeuralShield** | Multi-layered security gateway | 91% defense |
| 3rd | Unknown | Unknown | ~85%+ |
| **12th** | **Us (NeuralShield fork)** | GOAT-style attacker + 5-layer defense | **42.5%** |

---

## 3. NeuralShield Deep Dive (2nd Place Winner)

NeuralShield achieved **91% defense win rate** across 94,000+ battles. Their architecture is the gold standard.

### 3.1 Defender Architecture (What Won 2nd Place)

```
INPUT → [Deterministic Normalization] → [Threat Classification] → [Segmentation] 
     → [Multi-pass Reasoning] → [Execution Mode Selection] → [Output Guardrails] 
     → [Verification & Repair] → OUTPUT
```

#### Layer 0: Deterministic Input Normalization (0 LLM Calls)
Before ANY LLM processing:
- Unicode normalization (NFKC)
- HTML/XML comment removal
- HTML entity unescaping
- URL decoding
- Base64 decoding
- ROT13 decoding
- Leetspeak normalization
- Reversed-text normalization
- Zero-width steganography detection
- Homoglyph normalization
- Hidden control text extraction from code fences/quoted blobs

#### Layer 1: Threat Classification (1 LLM Call)
- `attack_classifier.py` — Categorizes: indirect_injection, jailbreak, pii_leak, supply_chain, prompt_extraction
- `structural_analyzer.py` — Assigns structural risk flags
- `privacy_router.py` — Infers semantic privacy targeting

#### Layer 2: Segmentation (0 LLM Calls)
- `segmenter.py` — Splits multi-document inputs
- Assigns trust scores per segment
- Identifies external vs internal sources
- Segment trust computed from: explicit external markers, FILE_ID conventions, content risk patterns, position-based decay

#### Layer 3: Multi-pass Reasoning (2-3 LLM Calls)
- **Pass 1**: Analyze and extract safe task substance, infer risk level, derive threats
- **Pass 2**: Execute actual task using guarded input and chosen execution mode
- **Pass 3 (optional)**: Verification/repair when risk is high

#### Layer 4: Execution Mode Scaling
Maps fused suspicion score to 4 modes:
- **STANDARD** — Normal processing
- **CAUTIOUS** — Extra validation
- **CONSERVATIVE** — Restricted output
- **MINIMAL** — Disables untrusted decisive claims

#### Layer 5: Output Guardrails
- Rewrite/downgrade unverified references
- Detect supply-chain risk surfaces
- Detect PII leakage
- Sanitize unsafe output classes (SQL injection, shell pipelines, web embeds)

#### Layer 6: Verification & Repair
- Compare draft output against trusted context
- High-risk: refuse
- Medium-risk: repair and re-sanitize

#### Layer 7: Risk Anchoring
- For risk-assessment tasks, enforce minimum risk floors
- If low-risk answer contradicts evidence, bump risk levels

### 3.2 Attacker Architecture (Also by NeuralShield)

#### Stateful Round Management
Tracks per-round:
- `hard_refusal_count` / `soft_refusal_count`
- `surface_failure_counts` per attack vector
- `family_blacklist` for failed strategy families
- `win_locks` to exploit successful surfaces
- `capped_value_modes` when numeric outputs are limited

#### Defender Response Diagnosis
Classifies responses into:
- `partial_compliance`
- `compliance_with_correction`
- `value_capped`
- `soft_refusal`
- `hard_refusal`

Diagnoses failure mode:
- instruction_hijack
- generation_refusal
- task_misalignment
- output_contract_violations
- explicit_rejection

#### Strategy Family and Surface Routing
- Surface selection: extraction, translation, transformation, classification, summarization
- Family selection: prompt-injection, jailbreak, data-exfiltration, policy-avoidance
- Family-level diversity to avoid repeating failed tactics
- Surface bans after repeated hard refusals
- Concept-avoidance mode after phrasing-based refusals
- Value-escape mode when numeric outputs are capped

#### Contract Awareness
- Parses `output_format` to build semantic model of defender's expected output contract
- Extracts expected field names, numeric vs textual expectations
- Builds attacks that work within output constraints

### 3.3 What NeuralShield Did Differently vs. Us

| Dimension | NeuralShield (2nd) | Us (12th) | Gap |
|-----------|-------------------|-----------|-----|
| Defense architecture | 7-layer security gateway | 5-layer pipeline | Missing execution modes, verification/repair |
| Input normalization | 12+ deterministic transforms | 5 basic regex strips | Missing leetspeak, homoglyphs, steganography |
| Threat classification | Dedicated classifier + structural analyzer + privacy router | Python sanitization only | No LLM-based classification |
| Segmentation | Multi-segment trust scoring | Single input processing | No trust boundaries |
| Execution modes | 4 modes (STANDARD→MINIMAL) | Binary safe/unsafe | No graduated response |
| Output validation | Post-execution guardrails + repair | Exchange classifier only | No output sanitization |
| Attack diagnosis | 5-category failure classification | Tone scoring (0-4) | No failure mode diagnosis |
| Surface routing | 5 surfaces × 4 families = 20 strategies | 10 fixed strategies | No surface/family routing |
| Contract awareness | Parses output_format for attack surfaces | Generic template rendering | No contract analysis |
| State tracking | surface_failure_counts, family_blacklist, win_locks | round_data dict | No failure tracking |

---

## 4. Attack Tool Landscape

### 4.1 Promptfoo (OpenAI, 22.4k stars)

**Attack Strategies (20+)**:

| Category | Strategy | ASR Increase | Our Status |
|----------|----------|-------------|------------|
| Static | Base64/Hex/ROT13 encoding | 20-30% | Basic |
| Static | Leetspeak/Homoglyph | 20-30% | Missing |
| Static | Jailbreak Templates (DAN, Skeleton Key) | 20-30% | Missing |
| Static | Audio/Image/Video Encoding | 20-30% | Missing |
| Static | Emoji Smuggling | Low | Missing |
| Dynamic | **Meta Agent** (Recommended) | 70-90% | **MISSING** |
| Dynamic | **Composite Jailbreaks** (Recommended) | 60-80% | Missing |
| Dynamic | **Jailbreak** (Recommended) | 60-80% | Partial |
| Dynamic | Best-of-N (Anthropic) | 40-60% | Missing |
| Dynamic | Tree-based (ToA) | 60-80% | Missing |
| Dynamic | GCG | 0-10% | Missing |
| Dynamic | Math Prompt | 40-60% | Missing |
| Dynamic | Citation/Likert | 40-60% | Missing |
| Multi-turn | **Crescendo** | 70-90% | Partial |
| Multi-turn | **Hydra Multi-Turn** (Recommended) | 70-90% | **MISSING** |
| Multi-turn | **GOAT** | 70-90% | Implemented |
| Multi-turn | Mischievous User | 10-20% | Missing |
| Regression | Retry (learn from failures) | 50-70% | Missing |

**Attack Plugins (157 total)**:
- Brand: 14 plugins (competitor endorsement, excessive agency, hallucination, etc.)
- Compliance: 50+ plugins (pharmacy, insurance, telecom, real estate, e-commerce, financial)
- Dataset: 11 plugins (Aegis, BeaverTails, HarmBench, etc.)
- Security: 40+ plugins (SQL injection, SSRF, BOLA, BFLA, prompt extraction, data exfil, memory poisoning, MCP, coding agent attacks)
- Trust/Safety: 25+ plugins (bias, hate speech, self-harm, etc.)

**Key Insight**: The **Meta Agent** strategy builds custom attack taxonomies and learns from all attempts using persistent strategic memory. This is what we're missing - our attacker uses a fixed strategy ladder.

### 4.2 Microsoft PyRIT (4k stars)

**Attack Strategies**:

| Strategy | Type | Description | Our Status |
|----------|------|-------------|------------|
| PromptSendingAttack | Single-turn | Direct prompt attacks | Implemented |
| Context Compliance Attack | Single-turn | Manipulated chat history | Missing |
| Many-Shot Jailbreak | Single-turn | Many harmful examples in one prompt | Missing |
| Role Play Attack | Single-turn | Exploits role-playing scenarios | Partial |
| Skeleton Key | Single-turn | Bypasses safety guardrails | Missing |
| **Crescendo** | Multi-turn | Gradual escalation with backtracking | Partial |
| **TAP** (Tree of Attacks) | Multi-turn | 80%+ success on GPT-4 | Missing |
| Violent Durian | Multi-turn | Multi-turn strategy | Missing |
| Chunked Request | Multi-turn | Breaks requests into chunks | Missing |
| **SequentialAttack** | Compound | Chains strategies with fallback | **MISSING** |

**Scoring Engine (35+ scorers)**:
- SelfAskTrueFalseScorer, SelfAskLikertScorer
- SubStringScorer, RegexScorer
- MarkdownInjectionScorer, SQLInjectionOutputScorer
- CredentialLeakScorer, PathTraversalOutputScorer
- PromptShieldScorer, StaticPromptInjectionScorer

### 4.3 NVIDIA Garak (8.2k stars)

**Probe Categories (20+ modules, 80+ probes)**:

| Module | Probes | Description |
|--------|--------|-------------|
| `dan` | 14 variants | DAN, AntiDAN, DUDE, STAN, etc. |
| `encoding` | 12 encodings | Base64, Hex, ROT13, Morse, Braille, etc. |
| `promptinject` | 6 variants | HijackHateHumans, HijackLongPrompt |
| `realtoxicityprompts` | 8 categories | Profanity, Threat, Sexual, Identity Attack |
| `gcg` | 1 | Adversarial suffix attacks |
| `malwaregen` | 4 | Evasion, Payload, SubFunctions, TopLevel |
| `xss` | 1 | MarkdownImageExfil |
| `snowball` | 6 | Graph connectivity, Primes, Senators |
| `glitch` | 2 | Glitch token probing |

### 4.4 Attack Technique Taxonomy (Ranked by ASR)

From Promptfoo, Garak, PyRIT, and academic research:

| Rank | Technique | Undefended ASR | Defended ASR | Our Implementation |
|------|-----------|---------------|-------------|-------------------|
| 1 | **GCG suffixes** | 99% | 30% | NOT IMPLEMENTED |
| 2 | **Crescendo** (multi-turn escalation) | 73% | 15% | Partial |
| 3 | **TAP** (Tree of Attacks) | 80%+ | 20% | NOT IMPLEMENTED |
| 4 | **Meta Agent** (evolutionary) | 70-90% | 15% | NOT IMPLEMENTED |
| 5 | **Hydra** (branching multi-turn) | 70-90% | 15% | NOT IMPLEMENTED |
| 6 | **Composite Jailbreaks** | 60-80% | 20% | NOT IMPLEMENTED |
| 7 | Task Decomposition | 80% | 20% | Implemented |
| 8 | Authority Escalation | 65% | 12% | Implemented |
| 9 | Reconstruction Attack | 55% | 8% | Implemented |
| 10 | Vocabulary Co-option | 45% | 12% | Implemented |

---

## 5. Defense Tool Landscape

### 5.1 Protect AI LLM Guard (3.1k stars)

**Input Scanners (15)**:
Anonymize, BanCode, BanCompetitors, BanSubstrings, BanTopics, Code, Gibberish, InvisibleText, Language, PromptInjection, Regex, Secrets, Sentiment, TokenLimit, Toxicity

**Output Scanners (20)**:
BanCode, BanCompetitors, BanSubstrings, BanTopics, Bias, Code, Deanonymize, JSON, Language, LanguageSame, MaliciousURLs, NoRefusal, ReadingTime, FactualConsistency, Gibberish, Regex, Relevance, Sensitive, Sentiment, Toxicity, URLReachability

**Key Capability**: PII Anonymization/Deanonymization with Presidio + spaCy + flair + transformers. ONNX-accelerated (38ms on GPU).

### 5.2 Meta Purple Llama

**Llama Guard Family**:
- Llama Guard (Llama 2 base)
- Llama Guard 2 (Llama 3 base)
- Llama Guard 3-8B (Llama 3.1, MLCommons taxonomy)
- Llama Guard 3-1B (Llama 3.2, lightweight)
- Llama Guard 3-11B-vision (multimodal)

**Prompt Guard**: Fine-tuned classifier for prompt injection + jailbreak detection

**CodeShield**: Insecure code detection + code interpreter abuse prevention

**CyberSec Eval v1-v3**: Industry cybersecurity evaluation suites

### 5.3 Defense Technique Taxonomy

| Technique | Source | ASR Reduction | Our Status |
|-----------|--------|--------------|------------|
| **Deterministic normalization** | NeuralShield | 30%+ catch rate | Basic only |
| **Trust boundary design** | NeuralShield | Prevents context mixing | Missing |
| **Multi-pass reasoning** | NeuralShield, AutoDefense | 20-25% | Partial (5-layer) |
| **Execution mode scaling** | NeuralShield | Graduated response | Missing |
| **Output guardrails** | NeuralShield, LLM Guard | 15-20% | Missing |
| **Verification & repair** | NeuralShield | 10-15% | Missing |
| **Exchange classifier** | Anthropic | 15-20% | Implemented |
| **Backtranslation check** | Anthropic | 10-15% | Implemented |
| **PPA (Polymorphic Prompt)** | Research | 98%+ defense | Implemented |
| **Spotlighting** | Microsoft | Significant | Implemented |
| **Dynamic invariants** | Custom | Scenario-adaptive | Implemented |
| **Multi-agent defense** | AutoDefense | 55.74% → 7.95% | NOT IMPLEMENTED |

---

## 6. Research Papers & Academic Foundation

### 6.1 Critical Papers

| Paper | Key Contribution | Relevance |
|-------|-----------------|-----------|
| **GCG** (Zou et al., 2307.15043) | Universal adversarial suffixes, gradient-based optimization | CRITICAL — Missing from our attacker |
| **Crescendo** (Russinovich et al., 2404.01833) | Multi-turn gradual escalation, 29-61% higher on GPT-4 | CRITICAL — Partial implementation |
| **PAIR** (Chao et al., 2310.08419) | Automated black-box jailbreak in <20 queries | HIGH — Attack efficiency model |
| **AutoDefense** (Zeng et al., 2403.04783) | Multi-agent defense, 55.74% → 7.95% ASR | HIGH — Missing multi-agent defense |
| **Eraser** (Lu et al., 2404.05880) | Knowledge unlearning defense | MEDIUM — Different defense paradigm |
| **Prompt Injection Benchmark** (Liu et al., 2310.12815) | Formal framework, 5 attacks × 10 defenses × 10 LLMs | HIGH — Evaluation methodology |
| **Multilingual Safety** (Shen et al., 2401.13136) | Lower-resource languages bypass safety | MEDIUM — Untested attack vector |
| **Garak** (Derczynski et al., 2406.11036) | Modular red-teaming framework | HIGH — Probe taxonomy reference |

### 6.2 Key Academic Insights

1. **GCG suffixes** achieve 99% ASR on undefended models but only 0-10% increase in Promptfoo's black-box setting — white-box gradient methods have limited applicability in competition
2. **Crescendo** exploits recency bias in transformers — recent tokens have stronger influence on next-token prediction
3. **PAIR** demonstrates automated black-box attacks are practical — uses attacker LLM to iteratively refine jailbreaks
4. **Multi-agent defense** (AutoDefense) shows dramatic ASR reduction — different agents handle different defense roles
5. **Knowledge unlearning** (Eraser) represents a fundamentally different defense philosophy — remove harmful knowledge rather than add guardrails
6. **Lower-resource languages** bypass safety guardrails significantly — untested attack vector in competition

---

## 7. Gap Analysis

### 7.1 Critical Gaps (Must Fix)

| # | Gap | Current State | NeuralShield Has | Impact |
|---|-----|---------------|-----------------|--------|
| 1 | **No deterministic normalization** | 5 basic regex strips | 12+ transforms (leetspeak, homoglyphs, steganography, etc.) | 30%+ attacks bypass our filters |
| 2 | **No threat classification** | Python sanitization only | Dedicated classifier + structural analyzer + privacy router | Can't distinguish attack types |
| 3 | **No trust boundaries** | Single input processing | Trusted/untrusted field separation | Context mixing enables attacks |
| 4 | **No execution mode scaling** | Binary safe/unsafe | 4 modes (STANDARD→MINIMAL) | Over-refuses or under-defends |
| 5 | **No output guardrails** | Exchange classifier only | Post-execution PII/code/reference sanitization | Leaks through output |
| 6 | **No verification & repair** | None | Compare output against trusted context | Can't catch subtle manipulation |
| 7 | **No defender response diagnosis** | Tone scoring (0-4) | 5-category failure classification | Can't adapt attack strategy |

### 7.2 Secondary Gaps (Should Fix)

| # | Gap | Fix |
|---|-----|-----|
| 8 | No Meta Agent / evolutionary strategy | Add evolutionary strategy optimization |
| 9 | No Hydra / branching multi-turn | Add multi-branch attack exploration |
| 10 | No TAP (Tree of Attacks) | Add tree-based attack paths |
| 11 | No SequentialAttack chaining | Add strategy fallback chaining |
| 12 | No contract awareness | Parse output_format for attack surfaces |
| 13 | No surface_failure_counts tracking | Track which attack surfaces fail |
| 14 | No family_blacklist | Avoid repeating failed strategy families |
| 15 | No multilingual attacks | Add lower-resource language bypass |
| 16 | No few-shot prompt hardening | Add examples to defender system prompt |
| 17 | No self-play training loop | Add evolutionary optimization from battles |

---

## 8. SOTA Implementation Plan

### Phase 1: Defense Gateway Overhaul (Week 1-3) — Highest Impact

**Goal**: Match NeuralShield's 7-layer defense architecture.

#### 1.1 Deterministic Input Normalization
```python
# File: agents/defender/normalization.py

class DeterministicNormalizer:
    """12+ normalization transforms before any LLM call."""
    
    def normalize(self, text: str) -> str:
        # 1. Unicode NFKC normalization
        text = unicodedata.normalize('NFKC', text)
        # 2. HTML/XML comment removal
        text = re.sub(r'<!--.*?-->', '', text, flags=re.S)
        # 3. HTML entity unescaping
        text = html.unescape(text)
        # 4. URL decoding
        text = urllib.parse.unquote(text)
        # 5. Base64 decoding (if valid)
        text = self._try_base64_decode(text)
        # 6. ROT13 decoding (if detects ROT13 pattern)
        text = self._try_rot13_decode(text)
        # 7. Leetspeak normalization
        text = self._normalize_leetspeak(text)
        # 8. Reversed text detection
        text = self._detect_reversed_text(text)
        # 9. Zero-width steganography detection
        text = self._detect_steganography(text)
        # 10. Homoglyph normalization
        text = self._normalize_homoglyphs(text)
        # 11. Hidden control text extraction
        text = self._extract_hidden_text(text)
        # 12. Role tag mimicry stripping
        text = self._strip_role_mimicry(text)
        return text
```

#### 1.2 Threat Classification
```python
# File: agents/defender/threat_classifier.py

class ThreatClassifier:
    """LLM-based threat classification (1 LLM call)."""
    
    CATEGORIES = [
        "indirect_injection", "jailbreak", "pii_leak",
        "supply_chain", "prompt_extraction", "safe"
    ]
    
    async def classify(self, input_text: str, context: dict) -> dict:
        # Returns: category, confidence, structural_risk_flags
        pass
```

#### 1.3 Trust Boundary Segmentation
```python
# File: agents/defender/segmenter.py

class InputSegmenter:
    """Split input into trusted/untrusted segments with trust scores."""
    
    def segment(self, input_text: str, context: dict) -> list[Segment]:
        # Identify trusted fields (role, task, output_format)
        # Identify untrusted payload (formatted_input)
        # Compute trust score per segment
        # Return ordered segments with trust levels
        pass
```

#### 1.4 Execution Mode Scaling
```python
# File: agents/defender/execution_modes.py

class ExecutionModeSelector:
    """Map suspicion score to execution mode."""
    
    MODES = {
        "STANDARD": {"output_trust": 1.0, "allow_recommendations": True},
        "CAUTIOUS": {"output_trust": 0.8, "allow_recommendations": True},
        "CONSERVATIVE": {"output_trust": 0.5, "allow_recommendations": False},
        "MINIMAL": {"output_trust": 0.2, "allow_recommendations": False},
    }
    
    def select(self, suspicion_score: float) -> str:
        if suspicion_score < 0.2: return "STANDARD"
        if suspicion_score < 0.5: return "CAUTIOUS"
        if suspicion_score < 0.8: return "CONSERVATIVE"
        return "MINIMAL"
```

#### 1.5 Output Guardrails
```python
# File: agents/defender/output_guardrails.py

class OutputGuardrails:
    """Post-execution output sanitization."""
    
    def sanitize(self, output: str, context: dict) -> str:
        # 1. PII detection and redaction
        # 2. Unsafe code pattern detection (SQL injection, shell commands)
        # 3. Unverified reference downgrade
        # 4. Supply-chain risk detection
        # 5. Web embed sanitization
        return output
```

#### 1.6 Verification & Repair
```python
# File: agents/defender/verifier.py

class OutputVerifier:
    """Compare output against trusted context."""
    
    async def verify(self, output: str, context: dict) -> dict:
        # High-risk: refuse
        # Medium-risk: repair and re-sanitize
        # Low-risk: pass through
        pass
```

### Phase 2: Attack Agent SOTA (Week 2-4)

**Goal**: Match NeuralShield's stateful, diagnosing, contract-aware attacker.

#### 2.1 Defender Response Diagnosis
```python
# File: agents/attacker/diagnosis.py

class DefenderDiagnosis:
    """Classify defender response into failure categories."""
    
    CATEGORIES = [
        "partial_compliance", "compliance_with_correction",
        "value_capped", "soft_refusal", "hard_refusal"
    ]
    
    FAILURE_MODES = [
        "instruction_hijack", "generation_refusal",
        "task_misalignment", "output_contract_violations",
        "explicit_rejection"
    ]
    
    def diagnose(self, response: str, context: dict) -> DiagnosisResult:
        pass
```

#### 2.2 Surface and Family Routing
```python
# File: agents/attacker/routing.py

class StrategyRouter:
    """Route attacks across surfaces and families."""
    
    SURFACES = ["extraction", "translation", "transformation", 
                "classification", "summarization"]
    FAMILIES = ["prompt-injection", "jailbreak", 
                "data-exfiltration", "policy-avoidance"]
    
    def select(self, round_data: dict, diagnosis: DiagnosisResult) -> Strategy:
        # Check family_blacklist
        # Check surface_failure_counts
        # Apply diversity rules
        # Return optimal surface × family combination
        pass
```

#### 2.3 Contract Awareness
```python
# File: agents/attacker/contract.py

class ContractAnalyzer:
    """Parse output_format for attack surface modeling."""
    
    def analyze(self, output_format: str) -> ContractModel:
        # Extract expected field names
        # Determine numeric vs textual expectations
        # Identify open-ended vs constrained task type
        # Build attack surface map
        pass
```

#### 2.4 Sequential Attack Chaining
```python
# File: agents/attacker/sequential.py

class SequentialAttacker:
    """Chain multiple strategies with fallback logic."""
    
    def __init__(self):
        self.strategy_chain = [
            ("crescendo", max_attempts=3),
            ("authority_escalation", max_attempts=2),
            ("task_decomposition", max_attempts=2),
            ("reconstruction", max_attempts=2),
        ]
    
    async def execute(self, context: dict) -> str:
        for strategy, max_attempts in self.strategy_chain:
            for attempt in range(max_attempts):
                result = await self._try_strategy(strategy, context)
                if result.success:
                    return result
                self._record_failure(strategy, result)
        return self._fallback()
```

### Phase 3: Integration & Optimization (Week 4-6)

#### 3.1 Self-Play Training Loop
```python
# File: training/self_play.py

class SelfPlayTrainer:
    """Evolutionary optimization from battle outcomes."""
    
    async def train(self, num_episodes: int = 100):
        for episode in range(num_episodes):
            result = await self._run_battle()
            self._update_strategies(result)
            self._evolve_population()
```

#### 3.2 LLM Call Budget Optimization
The 4-call-per-round limit is tight. Optimal allocation:
- **Attacker**: 1 call (generation) + 0 calls (diagnosis via Python)
- **Defender**: 1 call (normalization) + 1 call (classification) + 1 call (response) + 1 call (verification)

### Phase 4: Production Hardening (Week 6-8)

#### 4.1 Few-Shot Prompt Hardening
```python
# Add security examples to defender system prompt
FEW_SHOT_EXAMPLES = {
    "injection": [{"input": "...", "response": "...", "why": "..."}],
    "extraction": [{"input": "...", "response": "...", "why": "..."}],
}
```

#### 4.2 Multilingual Attack Support
```python
# Test attacks in lower-resource languages
# (Research shows LLMs are more vulnerable in non-English)
```

---

## 9. Expected Performance Impact

### Attack Improvements

| Improvement | Expected ASR Increase | Effort |
|-------------|----------------------|--------|
| Defender response diagnosis | +10-15% | Medium |
| Surface/family routing | +8-12% | Medium |
| Sequential attack chaining | +10-15% | Medium |
| Contract awareness | +5-8% | Low |
| Meta Agent / evolutionary | +15-20% | High |
| **Total Attack** | **+48-70%** | - |

### Defense Improvements

| Improvement | Expected ASR Reduction | Effort |
|-------------|----------------------|--------|
| Deterministic normalization (12+ transforms) | -25-30% | Medium |
| Threat classification | -15-20% | Medium |
| Trust boundary segmentation | -10-15% | Medium |
| Execution mode scaling | -10-15% | Low |
| Output guardrails | -15-20% | Medium |
| Verification & repair | -10-15% | Medium |
| Few-shot hardening | -5-8% | Low |
| **Total Defense** | **-90-123%** (capped at ~95%) | - |

### Projected Final State

| Metric | Current | After Phase 1 | After Phase 2 | After Phase 3-4 |
|--------|---------|---------------|---------------|-----------------|
| Defense Rank | 11th | 3rd-5th | 2nd-3rd | **1st** |
| Attack Rank | 4th | 4th | 2nd-3rd | **1st** |
| Overall Rank | 12th | 5th-7th | 3rd-4th | **1st-2nd** |
| Win Rate | 42.5% | 60-65% | 70-80% | **85-92%** |

---

## 10. References

### Tools
1. Promptfoo (OpenAI, 2026). "Red Teaming for AI Applications." 22.4k stars. https://www.promptfoo.dev/
2. PyRIT (Microsoft, 2026). "Python Risk Identification Tool for Generative AI." 4k stars. https://github.com/microsoft/PyRIT
3. Garak (NVIDIA, 2026). "LLM Vulnerability Scanner." 8.2k stars. https://github.com/NVIDIA/garak
4. LLM Guard (Protect AI, 2026). "Security Toolkit for LLM Interactions." 3.1k stars. https://github.com/protectai/llm-guard
5. Purple Llama (Meta, 2026). "LLM Security Assessment & Safeguards." 4.2k stars. https://github.com/meta-llama/PurpleLlama

### Papers
6. Zou et al. (2023). "Universal and Transferable Adversarial Attacks on Aligned Language Models." arXiv:2307.15043.
7. Russinovich et al. (2024). "Great, Now Write an Article About That: The Crescendo Multi-Turn LLM Jailbreak Attack." arXiv:2404.01833.
8. Chao et al. (2023). "Jailbreaking Black Box Large Language Models in Twenty Queries (PAIR)." arXiv:2310.08419.
9. Zeng et al. (2024). "AutoDefense: Multi-Agent LLM Defense against Jailbreak Attacks." arXiv:2403.04783.
10. Lu et al. (2024). "Eraser: Jailbreaking Defense via Unlearning Harmful Knowledge." arXiv:2404.05880.
11. Liu et al. (2024). "Formalizing and Benchmarking Prompt Injection Attacks and Defenses." arXiv:2310.12815.
12. Shen et al. (2024). "The Language Barrier: Dissecting Safety Challenges of LLMs in Multilingual Contexts." arXiv:2401.13136.
13. Derczynski et al. (2024). "garak: A Framework for Security Probing Large Language Models." arXiv:2406.11036.

### Competition
14. NeuralShield (2025). AgentBeats Security Arena 2nd Place. 91% defense win rate. https://github.com/IlluriManikanta/agentbeats-lambda-NeuralShield
15. AgentBeats Competition Leaderboard. http://agentbeats-competition-2026.s3-website-us-east-1.amazonaws.com/leaderboard/
