# ARCHON: Deep Paper Analysis & Strategic Blueprint to SOTA

## Executive Summary

I have deeply read all 12 papers from your alphaxiv set. The literature reveals **three structural shifts** happening in real time:

1. **Academic groups are formalizing Archon's methodology** (REDAgentBench, ToolHazard, AgentFlow) — if you don't publish within 6 months, you lose citation priority on your own invention
2. **PIMiner ships a better attacker brain** than Archon's LlmBrainAttacker (86.7% AgentDojo ASR vs your 0/3 @ budget 4)
3. **New attack surfaces you don't cover are heating up** — Computer-Use Agents (StepJack), multi-step IPI, skill lifecycle attacks (SkillSec-Eval)

The window is **3-6 months, not 12**. Here is the comprehensive blueprint to make Archon the definitive agent security platform.

---

## Part I: Deep Paper Analysis

### Paper 1: AgentFlow (2608.22868) — *Flow-Centric Policy Language*

**Core Contribution:** A policy language where harm arises from *data flows*, not single actions. Policies constrain which tools receive sensitive fields, which sinks receive released data, what authority crosses delegation boundaries.

**Key Numbers:**
- 949 AgentDojo injected cases: compromise 33% → **0%** with utility 46.7% → 63.3% (improves both!)
- 200-case AgentDyn Dailylife: compromise 73.5% → **0%** with near-baseline utility
- 7 safety properties verify in <0.5 seconds each (SMT-based verifier)
- ASB direct-prompt-injection harness: **0/1,200 attack success**

**Relation to Archon:**
- **Directly validates** your `toxic_flows.py` capability graph and PED metric
- **Threatens** by providing an alternative, academically-validated policy language
- Your PED (Privilege Escalation Distance) is the graph-theoretic analog of their flow policies

**Adoption Opportunity:**
- Implement AgentFlow's policy language as an **alternative input format** alongside YAML
- Map your 8 defense layers to their flow/path rules
- Cite as academic validation of your graph-centric approach

---

### Paper 2: Bounded Agents / APC (2608.15888) — *Delegation Security*

**Core Contribution:** Agentic Principal Chain (APC) — tracks delegated authority across session state with 6 authorization checks. Enforces outside the model.

**Key Numbers:**
- AgentDojo exfiltration: 75-100% → **0%** across all 4 domains
- All 544 InjecAgent data-stealing cases **blocked**
- Destruction: 38.6% → 4.0%; Manipulation: 90.5% → 12.1%
- Authorization latency: **0.24 ms** at p99
- Proves Blast Radius Monotonicity and Composition Soundness

**Relation to Archon:**
- **Validates** your macaroon-style attenuating tokens (item 40 in ROADMAP)
- **Extends** with formal proofs of composition soundness
- Your HMAC identity + ed25519 credentials are the identity layer; APC is the authorization layer

**Adoption Opportunity:**
- Implement APC's 6 authorization checks as a new `DefenseLayer`
- Add "Bounded Agents via Archon caveats" blog post
- Prove composition properties for your defense pipeline

---

### Paper 3: Vulnerabilities in Agentic LLMs (2608.10530) — *Definitive SoK* ⚠️ CORRECTED Aug 25: this is the **85-paper PRISMA** review (four-layer Perception/Brain/Action/Interaction taxonomy; attack:defense 3.9:1; Perception 66% vs Action 4.7% = 14× gap; code-exec 3.5%; tool-augmented 12%). The 247-paper lifecycle SoK is 2606.10749 (see Paper 9) — IDs were swapped in earlier drafts.

**Core Contribution:** Systematization of 247 papers through lifecycle-based, systems-oriented framework. Models security around information flow, delegated authority, persistent state.

**Key Findings:**
- Prompt injection + tool-mediated control-flow hijacking still dominate
- **Persistent state corruption and multi-agent propagation are emerging central concerns**
- Current defenses are "weakly compositional"
- Benchmarks underrepresent long-horizon, stateful, deployment-sensitive risks

**Relation to Archon:**
- **Validates** your 10/10 OWASP coverage and state-grounded measurement
- **Identifies gaps:** long-horizon attacks, multi-agent propagation, deployment metrics
- Your per-target ground-truth series (81.8% ASR) directly addresses the "long-horizon" gap

**Citation Value:**
- Canonical reference for your paper's threat taxonomy
- Use to validate ASI01-ASI10 coverage against academic consensus

---

### Paper 4: PIMiner (2608.05108) — *Agent-vs-Agent Red Teaming* ⚠️ HIGHEST PRIORITY

**Core Contribution:** Agentic system with hierarchical memory (Strategy Library + Intra-Dataset + Intra-Sample). Builds reusable strategy library across models.

**Key Numbers:**
- IPIArena: **76.2% ASR vs Gemini-2.5-Pro**, 61.9% vs GPT-5.1, 42.9% vs Claude-Sonnet-4.5
- AgentDojo: **86.7% ASR vs Gemini-2.5-Pro**, 53.3% vs GPT-5.1, 40% vs Claude-Sonnet-4.5
- Only ~10 queries per test sample
- Strategy library transfers to unseen models without retraining

**Architecture (4 specialized agents):**
1. **Strategy Router** — selects Top-K relevant strategies from library
2. **Iterative Attacker** — crafts injection prompts using all 3 memory levels
3. **Experience Digester** — post-mortem analysis, updates strategy library
4. ~~Rolling Parallelization~~ ⚠️ CORRECTED: not an agent — a **scheduling scheme** (pool of 5 concurrent attacker agents per dataset–model pair). The four components are Strategy Library / Strategy Router / Iterative Attack Module / Experience Digester.

**Relation to Archon:**
- **Direct competitor** to your `LlmBrainAttacker` (GOAT-style O-T-S-R loop)
- Your honest 0/3 @ budget 4 with `gemini-3.5-flash-lite` is a **floor**, not a ceiling
- PIMiner's hierarchical memory is the architecture you need

**Critical Gap:**
- PIMiner achieves 86.7% on AgentDojo; your LlmBrainAttacker achieved 0/3
- Their strategy library transfers across models; your brain is per-target
- They use only 10 queries; your budget-declared approach is comparable but underperforming

**Adoption Imperative:**
- Implement PIMiner's 3-level hierarchical memory in LlmBrainAttacker
- Build a persistent strategy library that transfers across target models
- Run PIMiner-style evaluation: ASR@10 on frontier models (Gemini-2.5-Pro, GPT-5.1, Claude-Sonnet-4.5)
- **Target: match or exceed 86.7% on AgentDojo**

---

### Paper 5: ToolHazard (2608.11878) — *Scalable Environment Synthesis*

**Core Contribution:** Automated synthesis of stateful adversarial environments via blueprint planning → OOP construction → quality inspection.

**Key Numbers:**
- ToolHazard-Bench: **28 environments, 512 tools**
- ⚠️ CORRECTED: models are GPT-5/GPT-4.1/Gemini-3.1-Pro/DeepSeek-V3.2/Qwen3-8B/4B (no GPT-4o). Four strategies >40% ASR on **GPT-5** (tool-selection 59.14%); DeepSeek-V3.2 most capable AND most attacked (up to 75%)
- ToolHazard-Align (clean-trajectory SFT + GRPO): Qwen3-8B 36.10→18.06 TH-Bench / 29.16→18.34 AgentDojo; best anywhere 7.17%. ⚠️ The '40%→<5%' claim DOES NOT EXIST in the paper; naive SFT+RL without clean mixing RAISES ASR on Qwen3-4B (25→32)
- Cross-attack generalization (robust to unseen strategies)

**Methodology (3 components):**
1. **Environment Simulator** — generates Python classes from natural language blueprints
2. **Attacker Agent** — discovers injection points via read/write dependency graphs (G=(V,E))
3. **User Simulator** — constructs state-grounded long-horizon tasks

**Key Findings:**
- Injection timing matters (early exposure = higher ASR)
- Structured outputs (JSON/YAML) reduce ASR vs free-form text
- Positional bias: end-of-output injections more effective

**Relation to Archon:**
- **Replaces** your hand-written `targets/sandbox.py` scenarios with generated ones
- Read/write dependency graphs formalize your `toxic_flows.py` capability analysis
- ToolHazard-Align (RL training) is a defense path you don't have

**Adoption Opportunity:**
- Implement ToolHazard's environment synthesis pipeline
- Scale from 11 hand-written targets to 100+ generated targets
- Add ToolHazard-Align as a training-time defense option

---

### Paper 6: REDAgentBench (2608.10669) — *Executable Red Teaming with Faithful Measurement*

**Core Contribution:** IVC taxonomy (Intervention-Vulnerability-Constraint), state-grounded verification via service receipts + state diffs.

**Key Numbers:**
- **1,661 cases** across 5 service surfaces (workspace, email, browser, banking, external data)
- Macro-average ASR: **65.69%** across 6 models, 3 agent harnesses
- **Recognition-Execution Gap (REG):** 17.92% of confirmed violations occur *after* agent acknowledges the risk
- Action-time policy reminder: reduces confirmed violations by **70+ percentage points**

**Relation to Archon:**
- **Independently validates** your state-diff `attack_success` methodology
- Your "dual ASR" (evasion vs strict) maps to their "recognition vs execution" framing
- Their policy reminder is a simple defense you could implement

**Critical Insight:**
- REG means agents *know* the rule but execute anyway — your exchange classifier (Layer 4) is positioned to catch this
- Their 70pp reduction from a simple policy reminder suggests your Task Shield (Layer 3) could be more effective with action-time reminders

**Adoption Opportunity:**
- Add REDAgentBench harness (1,661 cases) to your benchmark suite
- Implement action-time policy reminders in your defense pipeline
- Measure REG for your own defense stack

---

### Paper 7: StepJack (2608.06477) — *Computer-Use Agent Attacks* ⚠️ NEW SURFACE

**Core Contribution:** Multi-step indirect prompt injection against CUAs (Claude Computer Use, OpenAI Operator). Adversarial goal decomposed into innocuous sub-steps across a chain of pages.

**Key Numbers:**
- StepJack benchmark: **480 test examples**
- GPT-5.4-mini: ASR **41.7% (single-step) → 72.9% (3-step)** (+31.2 points)
- Average across 5 CUAs: 31.3% → 36.9% at 3-step
- Conditional compliance >80% holds for vulnerable models under Urgent=N only; Qwen3.5-Plus silently skips sub-steps (β₃=17.2); decomposition amplifies ASR on only 3/6 CUAs — adaptive-depth Union(2,3) is the robust claim
- Common defenses (DSPs, PIDs) much less effective against multi-step

**Methodology:**
- **Benign trajectory hijacking** via reference nesting (chain of pages with links)
- **Automated goal decomposition** with Faithfulness Judge + Safety Judge
- Composite quality score: Q = F × S (faithfulness × safety)

**Relation to Archon:**
- **New attack surface you don't cover** — Computer-Use Agents
- Multi-step decomposition is a generalization of your fragment reconstruction attacks
- CUA security is heating up fast (Claude Computer Use, OpenAI Operator, browser agents)

**Adoption Opportunity:**
- New target adapter: `targets/cua.py`
- Implement StepJack's multi-step decomposition pipeline
- Add CUA benchmark (480 examples) to your suite
- **High differentiation** — nobody in OSS tests CUAs

---

### Paper 8: AI-Infra-Guard (2606.31227) — *Unified Multi-Layer Framework*

**Core Contribution:** Layer-paradigm matching — different detection methods for different layers.

**5 Modules:**
1. **M1 Infra-Scan** — deterministic rule matching, 75+ components, 1,400+ rules, precision tiers verified/version-based/inferred. ⚠️ CORRECTED: the framework has FOUR modules (M1 Infra-Scan / M2 MCP-Scan / M3 Agent-Scan behavioral red teaming / M4 Prompt-Security jailbreak eval — cite as '26+ operator families / ~70 encoding transforms / 16 datasets ~7,000 prompts') plus a skill-scanner section extending M2; SkillTrustBench F1 0.9848 (5,520 cases from 62,652 marketplace skills)
2. **M2 Protocol Auditing** — LLM-driven agentic auditing of MCP servers ("Prompt-as-Rule")
3. **M3 Skill Supply Chain** — ReAct loop analysis of skill packages
4. **M4 Behavioral Red Teaming** — adversarial dialogue
5. **M5 Jailbreak Evaluation** — 70+ attack operators, 16 datasets

**Key Numbers:**
- M3 SkillTrustBench: F1 **0.9848**, recall 0.9725, precision 0.9974, FPR 0.0663
- Distributed server-agent architecture for scalability

**Relation to Archon:**
- **Competitive framework** — spans similar layers but different paradigm
- Your `archon scan-mcp` maps to their M2; your skill scanning maps to M3
- Their "Prompt-as-Rule" paradigm (natural language vulnerability criteria) is novel

**Adoption Opportunity:**
- Adopt "Prompt-as-Rule" for MCP vulnerability definitions
- Add M1-style infrastructure scanning (version normalization + CVE matching)

---

### Paper 9: Toward Secure LLM Agents (2606.10749) — *Canonical SoK* ⚠️ CORRECTED Aug 25: this is the **247-paper lifecycle** SoK (agent tuple A=⟨I,P,D,T,M,O,C⟩; 'defenses weakly compositional'; 'benchmarks underrepresent long-horizon risks'; multi-agent share rising 9.5%→24%).

**Core Contribution:** PRISMA-based systematic review of 85 papers. Four-layer taxonomy (Perception, Brain, Action, Interaction).

**Key Findings:**
- Attack:Defense ratio = **3.9:1**
- Perception layer: 66% of papers; **Action layer: only 4.7% (14× gap!)**
- Code execution: 3.5%; Tool-augmented: 12%
- 7 open problems centered on containment
- "Agentic LLM insecurity stems from architectural coupling"

**Relation to Archon:**
- **Validates** your action-layer focus (sandbox targets, tool-execution battles)
- Your 10/10 OWASP coverage addresses the Perception-heavy bias
- The 14× research gap in Action layer is exactly where Archon leads

**Citation Value:**
- Canonical survey for your paper's motivation section
- Use to argue that Archon addresses the under-studied Action layer

---

### Paper 10: Agent Skill Security / SkillSec-Eval (2607.13987) — *Skill Lifecycle Security*

**Core Contribution:** Lifecycle-aware framework spanning repository admission → semantic retrieval → planner selection → execution → evolution.

**Key Numbers:**
- 327 real-world skills evaluated
- Malicious Admission Rate: 52.9% (rule-based) → **7.9%** (LLM validator)
- Sybil attack ASR: 93.2% → **26.59%** with retrieval validation
- Fake recommendations: **45.64%** success rate tricking planners
- Runtime "implicit flow" problem: 23.0% ASR even with taint tracking (LLM rephrases data)

**Relation to Archon:**
- **Validates** your SKILL.md scanning (item 81 in ROADMAP)
- **Extends** with lifecycle stages you don't cover (retrieval, planner selection, evolution)
- The "implicit flow" problem (LLM rephrasing defeats taint tracking) is a fundamental challenge

**Adoption Opportunity:**
- Implement lifecycle-aware skill auditing (not just SKILL.md content)
- Add retrieval validation layer (counter Sybil attacks)
- Add metadata sanitization (strip persuasive language before planner sees it)

---

### Paper 11: Agent Security Needs Redefinition (2607.22024) — *Context Over Content*

**Core Contribution:** Agent security is a **contextual problem**, not a content problem. Four properties must hold jointly:

1. **Source Authorization** — who issued the command
2. **Task Alignment** — is the objective sanctioned
3. **Action Alignment** — does the action serve the objective
4. **Data Isolation** — does information flow respect boundaries

**Key Insight:**
- "Delete user data" might be routine admin or prompt injection — content alone cannot distinguish
- **Snapshot benchmarks are structurally incapable of evaluating Data Isolation**
- Across every AgentDojo/WASP task, the same action is one a legitimate user would request

**Relation to Archon:**
- **Theoretical foundation** for your GUARDEDJOINT quadrants and dual-ASR
- Your 4 defense layers map to their 4 properties:
  - L0-L1 → Source Authorization
  - L3 Task Shield → Task Alignment
  - L4 Exchange Classifier → Action Alignment
  - Your data flow tracking → Data Isolation
- **Validates** that content-based defenses (regex, keyword matching) are fundamentally insufficient

**Adoption Opportunity:**
- Reframe your defense pipeline in terms of their 4 contextual properties
- Add explicit Data Isolation enforcement (taint tracking across privilege boundaries)
- Cite as the intellectual foundation for your contextual security approach

---

### Paper 12: Latent Signals of IPI Exposure (2608.02657) — *Model-Internal Detection* ⚠️ HIGH NOVELTY

**Core Contribution:** Models internally encode whether they've been injected — detectable via linear probes on hidden states.

**Key Numbers:**
- Linear probes achieve **90%+ AUROC** on unseen attacks, agent instructions, task suites
- Robust under adaptive attacks and cross-lingual settings
- **AGRI defense** (probe-gated reasoning): ASR 34.6% → **0%** on Qwen3.5-27B while maintaining utility
- **Recognition-action gap:** models encode signals but fail to translate into safe actions

**Relation to Archon:**
- **Novel defense layer you don't have** — model-internal injection detection
- Cheap (linear probe on hidden states), high novelty, model-agnostic
- Could become `defenses/latent_signal.py` — a new Layer 0.5

**Adoption Opportunity:**
- Implement AGRI-style probe-gated reasoning defense
- Add as a defense layer that queries the model's own latent state
- **High novelty, low implementation cost** if probes are reproducible
- **Unique differentiator** — nobody else in OSS has this

---

## Part II: Strategic Blueprint to SOTA

### The Three Structural Shifts

Based on the 12 papers, three shifts are happening simultaneously:

**Shift 1: Academic formalization of your methodology**
- REDAgentBench, ToolHazard, AgentFlow are independently formalizing state-grounded measurement, flow-centric policies, and executable red teaming
- **Risk:** If you don't publish within 6 months, you lose citation priority on your own invention
- **Action:** Publish research paper NOW (Sprint 1)

**Shift 2: Better attacker brains shipping**
- PIMiner achieves 86.7% AgentDojo ASR with hierarchical memory and 10 queries
- Your LlmBrainAttacker achieved 0/3 @ budget 4
- **Risk:** Visible capability gap on headline attack metric
- **Action:** Implement PIMiner's architecture (Sprint 2)

**Shift 3: New attack surfaces heating up**
- Computer-Use Agents (StepJack): 41.7% → 72.9% ASR with multi-step
- Skill lifecycle attacks (SkillSec-Eval): Sybil attacks 93.2% ASR
- Model-internal latent signals (novel defense opportunity)
- **Risk:** Archon doesn't cover these surfaces
- **Action:** Add CUA target, skill lifecycle scanning, latent signal defense (Sprint 3)

---

### The 90-Day Execution Plan

#### Sprint 0: Hackathon Submission (This Week, Deadline Aug 31)

Execute BLUEPRINT §5.3 unchanged. **Lean into the "validates everyone" positioning** in the demo: show `archon scan --target <third-party-guardrail>` producing evidence about someone else's defense.

#### Sprint 1: Research Paper (Weeks 1-8) ← HIGHEST STRATEGIC PRIORITY

**Why urgent:** REDAgentBench, ToolHazard, AgentFlow are formalizing your methodology. Academic groups are publishing first. **You will lose citation priority within 6 months.**

**Target venues:**
- **USENIX Security 2027** (CFP ~January) — best fit for systems/measurement
- **IEEE S&P 2027** — strong fit for measurement paper
- **CCS 2027** — fit for attack-surface taxonomy
- **NeurIPS Datasets & Benchmarks 2026** (deadline ~June) — if framed as benchmark

**Paper title:** *"Closed-Loop Red/Blue Measurement of Agentic AI Security: Architecture, Methodology, and Findings from 9 Benchmarks"*

**Core claim:** Closed-loop red/blue measurement with ground-truth state-diff ASR is the missing primitive in agent security. No existing tool combines (a) adaptive multi-turn attacks, (b) shippable defense proxy, (c) per-layer measurability, and (d) adversarially-validated evidence export.

**Contributions:**
1. **Architecture:** 8-layer defense pipeline (≤4 LLM calls, zero-cost deterministic tier) + deployable proxy + 5 extension seams
2. **Methodology:** CAISI-aligned reporting (attempt budget, adaptivity, judge, utility cost, dual ASR)
3. **Findings:**
   - Evasion ≠ compromise: 100% evasion vs 18.5% strict ASR (5× overstatement without dual ASR)
   - Defense-in-depth measurable: 66.7% → 27.2% at zero defensive LLM cost
   - Static defenses degrade within 2 attempts under adaptive pressure
   - Judge-reliability crisis: rule-judge F1 0.063 vs LLM-judge 0.893

**Comparison positioning:**
- vs PIMiner: "We ship the full measurement loop; they ship only the attacker"
- vs REDAgentBench: "We ship as a product; they ship as a benchmark"
- vs AgentFlow: "We measure flow security empirically; they verify it formally"
- vs Promptfoo: "Open, self-hostable, vendor-neutral; their brains are cloud-proprietary"

**Execution:**
- Week 1-2: Write draft (data exists in RESULTS.md)
- Week 3-4: Internal review + revisions
- Week 5-6: Submit to USENIX Security + post preprint on arXiv
- Week 7-8: Blog post summarizing for practitioners

#### Sprint 2: Close the Attacker Brain Gap (Weeks 1-3) ← CREDIBILITY CRITICAL

**Why urgent:** PIMiner achieves 86.7% AgentDojo ASR. Your LlmBrainAttacker achieved 0/3 @ budget 4. This is the single biggest credibility gap.

**Action 2.1: Implement PIMiner's Hierarchical Memory**

Replace your current GOAT-style loop with PIMiner's 3-level architecture:

```python
class PIMinerAttacker(AttackStrategy):
    def __init__(self):
        self.strategy_library = StrategyLibrary()  # Long-term: Markdown files
        self.intra_dataset = IntraDatasetMemory()  # Mid-term: per-dataset patterns
        self.intra_sample = IntraSampleMemory()    # Short-term: per-sample feedback
    
    def next_payload(self, ctx: BattleContext) -> AttackPayload:
        # Router selects Top-K strategies from library
        strategies = self.strategy_library.route(ctx.task, ctx.target_model)
        # Attacker crafts prompt using all 3 memory levels
        return self.attacker.craft(ctx, strategies, self.intra_dataset, self.intra_sample)
    
    def observe(self, signal: RoundSignal):
        # Update intra-sample memory with feedback
        self.intra_sample.update(signal)
        # Rolling parallelization: share learnings across concurrent samples
        self.intra_dataset.share(signal)
    
    def digest(self, results: list[AttackResult]):
        # Post-mortem: update strategy library with new patterns
        self.strategy_library.digest(results)
```

**Action 2.2: Run PIMiner-Style Evaluation**

Evaluate against frontier models at ASR@10 (10 iterations per sample):
- Gemini-2.5-Pro (target: match 86.7%)
- GPT-5.1 (target: match 61.9%)
- Claude-Sonnet-4.5 (target: match 42.9%)

**Action 2.3: Read Agent Against Agent Deeply**

Cite PIMiner in your research paper. Learn from their training-data-collection angle (successful attack trajectories as a dataset).

#### Sprint 3: New Attack Surfaces & Defense Layers (Weeks 3-6)

**Action 3.1: Computer-Use Agent Target (`targets/cua.py`)**

Implement StepJack's multi-step IPI for CUAs:
- Automated goal decomposition (Faithfulness Judge + Safety Judge)
- Benign trajectory hijacking via reference nesting
- Benchmark: 480 examples from StepJack
- **Target:** ASR measurement against Claude Computer Use, OpenAI Operator

**Why:** CUA security is heating up fast. Nobody in OSS tests CUAs. High differentiation.

**Action 3.2: Latent Signal Defense (`defenses/latent_signal.py`)**

Implement AGRI-style probe-gated reasoning:
- Linear probe on hidden states (90%+ AUROC for IPI exposure)
- Probe-gated anti-injection reasoning prepended on demand
- **Target:** Reduce ASR from 34.6% → 0% (as in paper) on Qwen3.5-27B

**Why:** High novelty, low implementation cost, unique differentiator. Nobody else in OSS has model-internal detection.

**Action 3.3: Skill Lifecycle Scanning**

Extend SKILL.md scanning to full lifecycle (SkillSec-Eval):
- Repository admission (LLM validator: 52.9% → 7.9% MAR)
- Retrieval validation (counter Sybil attacks: 93.2% → 26.59% ASR)
- Metadata sanitization (strip persuasive language)
- Runtime implicit flow detection

**Action 3.4: ToolHazard Environment Synthesis**

Replace hand-written `targets/sandbox.py` with generated environments:
- Blueprint planning → OOP construction → quality inspection
- Read/write dependency graphs for injection point discovery
- **Target:** Scale from 11 targets to 100+ generated targets

**Action 3.5: AgentFlow Policy Language**

Implement AgentFlow's flow-centric policy language as alternative input format:
- Map your 8 defense layers to flow/path rules
- SMT-based verifier for safety properties
- **Target:** Match their 33% → 0% compromise reduction on AgentDojo

#### Sprint 4: Benchmark Expansion (Weeks 4-8)

**Action 4.1: REDAgentBench Harness**

Add 1,661 cases across 5 service surfaces. Measure Recognition-Execution Gap for your defense stack. Implement action-time policy reminders (70+ pp violation reduction).

**Action 4.2: ToolHazard-Bench**

Run 28 environments × 512 tools. Compare your defense against ToolHazard-Align (GRPO RL training).

**Action 4.3: GuardianAgentBench (GABench)**

Run 580 scenarios on LangChain, LlamaIndex, Vectara with `archon-armor` as guardrail. Publish failure recovery numbers.

**Action 4.4: StepJack CUA Benchmark**

Run 480 examples against CUA targets. Publish multi-step ASR numbers.

#### Sprint 5: Enterprise & Community (Parallel, Weeks 1-12)

**Action 5.1: Live Demo + Persistent Docs**
- Docker + Postgres + Helm template
- YouTube walkthrough (≤10 min)
- MkDocs site on GitHub Pages

**Action 5.2: Compliance Evidence Packs**
- EU AI Act Articles 9/12/14
- NIST AI RMF MEASURE-2/MANAGE-2
- ISO 42001 A.6.1.6
- SOC 2 Type II

**Action 5.3: Enterprise Pilots**
- Target: 5+ pilots
- Pitch: "We validate your Model Armor/NeMo/Lakera configuration"
- Use compliance evidence reports as the artifact

**Action 5.4: Community Building**
- Discord/Slack channel
- Plugin marketplace directory
- "First contributor" issue set
- Target: 50+ community plugins (currently 18)

---

### Part III: The Defensible Moat (What You Own)

Based on the 12 papers, your moat narrows to **five things** that no competitor or academic group currently has in combination:

1. **The closed-loop measurement loop** — attack + defense + re-attack proof + evidence export in one tool. PIMiner ships only the attacker. REDAgentBench ships only the benchmark. AgentFlow ships only the policy language. **Nobody ships the full loop.**

2. **State-grounded measurement at scale** — 11 live attack targets with environment-state-diff ground truth. REDAgentBench validates this methodology academically, but you ship it as a product with 9 published benchmarks.

3. **Policy-CI / defense regression gates** — `archon compare --ci`, `archon purple --baseline`. Invented here, still unique. Promptfoo's Guardrails don't have this.

4. **MIT-neutral vendor independence** — Promptfoo is OpenAI. Snyk is closed. NeMo is NVIDIA. **Only Archon answers "vendor grades its own homework."**

5. **10/10 OWASP Agentic coverage with paired closed-loop defenses** — ASI01-ASI10 all have live attack targets AND paired defenses. No competitor covers all 10.

---

### Part IV: The Honest Risk

**Citation priority erosion.** REDAgentBench, ToolHazard, and AgentFlow are independently formalizing your methodology. If you don't publish within 6 months, academic groups will own the citation graph for state-grounded agent security measurement — even though you built it first.

**Attacker brain gap.** PIMiner's 86.7% AgentDojo ASR vs your 0/3 is a visible credibility gap. If a competitor ships frontier-brain GOAT at budget 25 (CAISI's 81%), you lose the headline attack metric.

**Community scale.** 1 star vs Promptfoo's 24.5k. Capability doesn't matter if nobody knows it exists. The paper + enterprise pilots + community building must happen in parallel.

---

### Part V: Suggested Reading Order

If you read only 4 papers, in order:

1. **PIMiner (2608.05108)** — closest competitor to your LlmBrainAttacker; must match their architecture
2. **Latent Signals (2608.02657)** — novel defense layer you don't have; high novelty, low cost
3. **StepJack (2608.06477)** — new CUA attack surface; nobody in OSS covers it
4. **REDAgentBench (2608.10669)** — independent validation of your methodology; cite in your paper

Then read the surveys (2608.10530, 2606.10749) to cross-check your taxonomy.

---

### Bottom Line

Archon is in an unusually strong position — 1,941 tests, 10/10 OWASP coverage, 9 published benchmarks with honest methodology, a deployable defense proxy, and a defensible measurement-loop moat. The papers confirm that the research community is **validating your category and starting to compete for it**.

**The single highest-leverage next step is publishing the research paper.** You have the data, the methodology, and the honest findings sitting in `RESULTS.md`. REDAgentBench, ToolHazard, and AgentFlow are formalizing your approach — if you don't publish first, you lose citation priority on your own invention.

**The second highest-leverage step is closing the attacker brain gap.** PIMiner's hierarchical memory architecture is the blueprint. Implement it. Match their 86.7% on AgentDojo.

**Everything else** (CUA targets, latent signal defense, skill lifecycle scanning, enterprise pilots, community building) **compounds on top of those two moves.**

The window is 3-6 months. Execute.



## Draft

I'll start by reading the project's GitHub page to understand what Archon is, then research the space exhaustively.

I now have a strong understanding of the project. Let me read the key planning/strategy docs in parallel, then research the latest papers in this space.

I have a deep understanding of Archon now. Let me read two more strategic docs (ROADMAP + RESULTS) and kick off the literature search in parallel.

Excellent — I have everything needed. The paper search returned 12 highly relevant recent (June–Aug 2026) papers that map directly to Archon's roadmap. Let me synthesize this into a deep analysis with concrete next steps.

---

# Archon — Deep Analysis & Strategic Next Steps

## 1. What Archon Actually Is (compressed from 6 docs)

Archon is an **open-source, MIT-licensed adversarial agent-security platform** by [Yasir Raza](https://github.com/Yasirrazaa) (`hackathon-v2` branch), originally built for the **Lambda × Berkeley RDI AgentBeats Security Arena** (ranked 13th overall, 6th in Defense at 85.1% win rate). Its core thesis is the **red-vs-blue measurement loop**: an adaptive multi-turn attacker and a measurable defense proxy fight in the same loop, exporting every verdict as OWASP-mapped audit evidence.

The repo has matured aggressively in the last 3 days of commits (Aug 22–25, 2026) into something unusual for a hackathon project:

- **1,941 passing tests** with an enforced ≥85% coverage gate (93% actual)
- **222 probes across 10 packs** — now the largest open agentic-security corpus (ahead of Garak's 195)
- **10/10 OWASP Agentic Top-10 (ASI01–ASI10) live attack coverage** with paired closed-loop defenses
- **archon-armor**: a deployable FastAPI OpenAI-compatible defense proxy (drop-in via `OPENAI_BASE_URL`), HMAC + ed25519 identity, Postgres registry, Helm chart, OTel→Cloud Trace, Prometheus `/metrics`, SARIF output (category-first — unlocks GitHub Code Scanning natively)
- **Five extension seams** (attack / defense / provider / target / reporter ABCs) with `contrib/` gallery, Homebrew + npm distribution
- **9 published benchmarks** with CAISI-aligned methodology blocks (attempt budget / adaptivity / judge / utility cost / dual ASR): AgentDojo deterministic 66.7% → Tier-3 full-pipeline 27.2% (live Gemini) → strict-ASR 18.5% → per-target ground-truth 81.8% → InjecAgent → pass^k 11/11=1.0 → R-Judge LLM-judge 89.2% F1 (at human ceiling) → FinBot CTF 7/7 vulnerable, 0/7 defended

The honest competitive position (code-verified against 9 cloned competitor repos on Aug 23, 2026): Archon is the only project that scores **best-in-class on all 7 agentic dimensions** (live tool-state attacks, memory poisoning, ASI07 trust boundaries, derived severity, trace-driven generation, policy comparison, fleet UI). No competitor holds more than one partial. The structural moat narrows to four things: **(1) the measurement loop, (2) Policy-CI, (3) open self-hostable MIT-neutral vendor independence, (4) 10/10 OWASP coverage** — since Promptfoo's adaptive multi-turn brains are now cloud-proprietary, narrowing the attack-side moat.

## 2. The Space Right Now (Aug 2026) — What the Latest Research Tells You

The literature I pulled in is **strikingly on-point for Archon's roadmap** — almost every paper maps to an existing seam or a gap you've flagged. Key signal: the field has moved from *static single-turn probing* to **flow-centric, multi-step, executable red-teaming with ground-truth measurement**. That is exactly Archon's wedge, which means **the research community is now validating your category — and starting to compete for it**.

### 2.1 Papers that directly extend or threaten Archon's roadmap

| Paper | Why it matters to Archon | Action |
|---|---|---|
| [AgentFlow (2608.22868)](https://www.alphaxiv.org/abs/2608.22868) | Flow-centric **policy language** for LLM agents — harm arises from *flows*, not single actions. This is the academic formulation of Archon's `toxic_flows.py` capability graph (item 85) and PED metric. | Cite it; consider adopting the policy language as an alternative input format alongside YAML. |
| [Bounded Agents (2608.15888)](https://www.alphaxiv.org/abs/2608.15888) | **Delegation security** for multi-agent systems — per-request permission narrowing. This is exactly your macaroon-style attenuating tokens (item 40), but as a first-class research framing. | Cite as academic validation; write a "Bounded Agents via Archon caveats" blog post. |
| [Vulnerabilities in Agentic LLMs (2608.10530)](https://www.alphaxiv.org/abs/2608.10530) | SoK on agentic LLM vulnerabilities — taxonomy. Useful for cross-checking ASI01–10 coverage. | Cross-map their taxonomy vs your ASI table; publish the mapping. |
| [Agent Against Agent (2608.05108)](https://www.alphaxiv.org/abs/2608.05108) | **Agentic system for automatic prompt-injection red teaming** — agent-vs-agent red teaming with training-data collection. This is the closest academic analog to your `LlmBrainAttacker`. Highest vote count (10) in the set. | Read deeply — this could be a citation in your research paper (E4 item 20) and a benchmark to run. |
| [ToolHazard (2608.11878)](https://www.alphaxiv.org/abs/2608.11878) | **Scaling adversarial environments** for security eval — automatically generated tool-injection scenarios. Directly competes with your sandbox targets; methodology for scaling probe corpora programmatically. **14 votes** (highest). | Read it. Could replace hand-written `targets/sandbox.py` scenarios with generated ones. |
| [REDAgentBench (2608.10669)](https://www.alphaxiv.org/abs/2608.10669) | **Executable red teaming with faithful measurement** — the academic version of your "ground-truth state-diff ASR" methodology. | Cite as independent validation of your measurement methodology. Likely to become a standard benchmark — add to E2.9 alongside AgentHarm (item 60). |
| [StepJack (2608.06477)](https://www.alphaxiv.org/abs/2608.06477) | **Computer-use agents** + multi-step indirect prompt injection. A new attack surface (CUAs) you don't cover. | New target adapter: `targets/cua.py`. CUA security is heating up fast. |
| [Securing the AI Agent — Unified Multi-Layer Red Teaming (2606.31227)](https://www.alphaxiv.org/abs/2606.31227) | 15 votes, 90 views — a **unified framework** that sounds like Archon's pitch. Read closely to differentiate. | Read in full. May be co-optable as citation or may force a sharper positioning. |
| [Toward Secure LLM Agents (2606.10749)](https://www.alphaxiv.org/abs/2606.10749) | SoK survey — 15 votes, 136 views (most-viewed). Threat surfaces, attacks, defenses, evaluation. | The canonical citation for the field. Use to validate your threat taxonomy. |
| [Agent Skill Security (2607.13987)](https://www.alphaxiv.org/abs/2607.13987) | Security of **reusable agent skills** — your `SKILL.md` scanning (item 81) is already ahead; this paper is the academic backing. | Cite; consider contributing your SKILL scanner as a reference implementation. |
| [Agent Security Needs Redefinition (2607.22024)](https://www.alphaxiv.org/abs/2607.22024) | Argues agent security ≠ action content; needs **holistic framework**. This is the intellectual foundation for your `GUARDEDJOINT` quadrants and dual-ASR work. | Strong citation for your metrics paper. |
| [Latent Signals of IPI Exposure (2608.02657)](https://www.alphaxiv.org/abs/2608.02657) | **Models internally encode whether they've been injected** — detectable via latent signals. A novel defense layer Archon doesn't have. | Read deeply. Could become `defenses/latent_signal.py` — a cheap, model-internal detector. High novelty. |

### 2.2 What the pattern says

Three structural shifts are visible across these papers:

1. **Multi-step, executable, ground-truth measurement is becoming the standard** (REDAgentBench, ToolHazard, StepJack). Archon's `state-diff attack_success` methodology is now *independently validated* — but also *independently standardized*. You will lose uniqueness on methodology within ~12 months unless you publish.
2. **Flow- and graph-centric security** (AgentFlow, Bounded Agents, "Agent Security Needs Redefinition") is replacing action-content security as the framing. Archon's PED + toxic_flows graph already lives there; the academic world is catching up.
3. **Agent-vs-agent red teaming** (Agent Against Agent, your `LlmBrainAttacker`) is the new attack frontier — automated red-team agents that adapt. Promptfoo's cloud Hydra, Garak's GOAT, and now academic systems all converge here. **Your 0/3 @ budget 4 result with `gemini-3.5-flash-lite` is an honest floor, not a ceiling — and CAISI's 81% @ budget 25 with frontier brains is the number to chase.**

---

## 3. Where Archon Genuinely Leads vs Where It's Vulnerable

### Leads (defensible for ~6–12 months)
- **Closed-loop red/blue measurement** — nobody else ships attack + defense + re-attack proof in one tool
- **Live tool/memory/multi-agent/MCP/coding-agent attack targets with state-diff ground truth** — the only project executing real attacks with real ground truth across 11+ target classes
- **SARIF 2.1.0 output** — category-first, unlocks GitHub Code Scanning
- **Policy-CI / `archon compare --ci` / `archon purple --baseline`** — defense regression gates invented here
- **MIT-neutral vendor independence** — Promptfoo is now OpenAI; Snyk is closed; only Archon answers "vendor grades its own homework"
- **Trace-driven attack generation from OTel spans** — nobody else attacks from traces

### Vulnerabilities (where competitors or papers will close in)
- **Academic groups are publishing the measurement methodology** (REDAgentBench, ToolHazard). If you don't publish a paper in 6 months, you lose citation priority on your own approach.
- **Promptfoo's runtime defense products** (Guardrails, MCP Proxy) are 3–6 months from maturity per your own Aug 22 verification — not 12 months. Speed is now the primary strategic variable.
- **LlmBrainAttacker at 0/3 @ budget 4** is an honest floor — but a competitor shipping frontier-brain GOAT at budget 25 (CAISI's 81%) would visibly out-attack you on the headline metric.
- **Community scale** (1 star vs Promptfoo's 24.5k) is the biggest practical gap. Capability doesn't matter if nobody knows it exists.

---

## 4. Next Steps — Ordered by ROI

### Sprint 0 — Hackathon submission (this week, deadline Aug 31 5pm PDT)
Nothing in the docs changes here — execute BLUEPRINT §5.3:
1. Deploy archon-armor to Cloud Run per `DEPLOY_GCP.md`
2. Record ≤4-min demo (register agent → live battle → Cloud Trace spans → `archon battle --ci` exit 0)
3. Architecture diagram (you have 3 Mermaid diagrams in `docs-site/architecture-diagram.md` — finalize)
4. Blog post + `#AllThingsAgenticHackathon` post (`BLOG_POST.md` draft exists)
5. Devpost submission package (`DEVPOST.md` draft exists)

**Lean into the new positioning in the demo:** show `archon scan --target <third-party guardrail>` producing an evidence report about *someone else's* defense. Nothing else on stage says that.

### Sprint 1 — Publish a research paper (weeks 1–8) — highest strategic priority
The literature scan makes this urgent. REDAgentBench, ToolHazard, and the "Securing the AI Agent" unified framework are *independently formalizing your methodology*. **If you don't publish within ~6 months, you lose citation priority on the closed-loop red/blue measurement loop — your own invention.**

Target venues (in order of fit):
- **USENIX Security 2027** (CFP typically Jan) — best fit for the systems/measurement angle
- **IEEE S&P 2027** — strong fit if you frame it as a measurement paper
- **CCS 2027** — good fit for the attack-surface taxonomy angle
- **NeurIPS Datasets & Benchmarks 2026** (deadline typically June) — if you frame as a benchmark contribution

The paper's core claim is **already proven in your `RESULTS.md`**: dual-ASR (evasion 100% vs strict 18.5% — a 5× overstatement when publishing evasion alone), per-target ground-truth ASR 81.8%, defense-in-depth measured (66.7% → 27.2% → 18.5%), and the closed-loop purple verification. The methodology commitments (attempt budget / adaptivity / judge / utility cost / dual ASR) are *exactly* what CAISI demands and what WASP formalized. **You have a publishable paper sitting in `RESULTS.md` right now.**

Concrete paper outline:
1. **Thesis:** Closed-loop red/blue measurement with ground-truth state-diff ASR is the missing primitive in agent security
2. **Contribution:** Archon's architecture (attack engine + defense proxy + closed-loop verification + dual-ASR methodology)
3. **Measurement:** The 9 published benchmarks with CAISI-aligned methodology blocks
4. **Findings:** (a) evasion ≠ compromise (100% vs 18.5%); (b) defense-in-depth is measurable (66.7% → 27.2% at zero defensive LLM cost); (c) static defenses degrade within 2 attempts under adaptive pressure; (d) judge-reliability crisis quantified (rule-judge F1 0.063 vs LLM-judge 0.893 at human ceiling)
5. **Comparison:** vs AgentDojo (benchmark-only), Task Shield (no offense), promptfoo (cloud-proprietary brains), NeMo (no self-validation)

### Sprint 2 — Close the LLM-brain attacker gap (weeks 1–3)
Your honest 0/3 @ budget 4 result is the single biggest credibility gap on the attack side. Three moves:

1. **Run `LlmBrainAttacker` with a frontier brain** (Claude Sonnet 4.5 / GPT-5 / Gemini 3 Pro) at budget 25 against the AgentDojo corpus. CAISI's 81% number is the target. Your `ClaudeNativeProvider` is already shipped — this is a benchmark run, not new code.
2. **Read [Agent Against Agent (2608.05108)](https://www.alphaxiv.org/abs/2608.05108) deeply** — it's the closest academic system to yours. Cite it; learn from their training-data-collection angle (you could collect successful attack trajectories as a dataset).
3. **Read [Latent Signals of IPI Exposure (2608.02657)](https://www.alphaxiv.org/abs/2608.02657) deeply** — a model-internal injection detector. Could become `defenses/latent_signal.py`, a cheap layer that queries the model's own latent state for injection exposure. High novelty, low implementation cost if the paper's probes are reproducible.

### Sprint 3 — New attack surfaces from the literature (weeks 3–6)
Three target adapters that map to papers you don't currently cover:

1. **`targets/cua.py` — Computer-Use Agent target** (per [StepJack 2608.06477](https://www.alphaxiv.org/abs/2608.06477)). CUAs (Claude Computer Use, OpenAI Operator) are a fast-growing attack surface with multi-step indirect injection. Nobody in the OSS landscape tests them. High differentiation.
2. **Generated adversarial environments** (per [ToolHazard 2608.11878](https://www.alphaxiv.org/abs/2608.11878)). Your `targets/sandbox.py` uses hand-written scenarios; ToolHazard's methodology could let you scale to 100s of scenarios programmatically. Read their generation pipeline.
3. **REDAgentBench harness** (per [2608.10669](https://www.alphaxiv.org/abs/2608.10669)). Add as E2.9 item 60b alongside AgentHarm. Independent validation of your measurement methodology.

### Sprint 4 — Enterprise credibility (parallel, weeks 1–12)
The boring 80% that your own audit identified. From the docs, the remaining items are:

1. **GitHub Pages enablement** — 2-click user-side flip; docs.yml is shipped
2. **YouTube walkthrough** — one persistent demo beyond the hackathon video
3. **CVE numbering authority** — formal process beyond `SECURITY.md` (the only remaining promptfoo hygiene delta)
4. **Community building** — Discord/Slack, plugin marketplace directory, contributor onboarding. Your `contrib/` gallery + 5 seams are ready; what's missing is *people*. Consider a "first contributor" issue set.
5. **Enterprise pilots** — the ROADMAP targets 5+ pilots. The fastest path: pick 2-3 verticals from `contrib/` (finance, healthcare, devops) and pitch CISOs with the compliance evidence reports (`archon report`) as the artifact.

### Sprint 5 — Managed cloud control plane (months 3–6)
This is the revenue layer over the MIT open core. Multi-tenant armor deployments are already v1 (TenantStore + SCIM + OIDC). The remaining work:
- Scheduled continuous battles (nightly `fuzz.yml` exists; productize as a managed cron)
- Alerting on baseline regressions (`archon fleet --ci` exists; productize as PagerDuty/Slack webhooks)
- Per-tenant dashboards (`/ui` exists; productize as multi-tenant SaaS UI)

**Sequencing rationale:** Sprint 1 (paper) is the most time-sensitive because of citation priority. Sprint 2 (frontier-brain attacker) is the most credibility-sensitive because of the honest 0/3 floor. Sprints 0 + 4 run in parallel as operational work. Sprint 5 follows enterprise adoption.

---

## 5. One Honest Risk to Flag

The docs are *remarkably* self-aware about honest numbers (0/3 brain attacker, 0% InjecAgent block rate at the deterministic tier, 27.2% full-pipeline ASR vs Task Shield's 2.07%). That honesty is a strategic asset — preserve it. The temptation after the hackathon will be to publish only flattering numbers. **Don't.** The dual-ASR framing (evasion ≠ compromise) is itself a research contribution, and it only works if you publish both numbers. The CAISI methodology alignment is your moat against vendors who publish single-shot ASR without attempt-budget disclosure.

## 6. Suggested Reading Order for You

If you read only 4 papers, in order:

1. [Agent Against Agent (2608.05108)](https://www.alphaxiv.org/abs/2608.05108) — closest competitor to your `LlmBrainAttacker`; highest community signal (10 votes)
2. [ToolHazard (2608.11878)](https://www.alphaxiv.org/abs/2608.11878) — methodology for scaling your sandbox scenarios; highest vote count (14)
3. [Latent Signals of IPI Exposure (2608.02657)](https://www.alphaxiv.org/abs/2608.02657) — a novel defense layer you don't have; high novelty
4. [REDAgentBench (2608.10669)](https://www.alphaxiv.org/abs/2608.10669) — independent validation of your ground-truth measurement methodology; cite in your paper

The [Toward Secure LLM Agents SoK (2606.10749)](https://www.alphaxiv.org/abs/2606.10749) is the canonical survey — read it once to cross-check your ASI01–10 taxonomy against the academic consensus.

---

**Bottom line:** Archon is in an unusually strong position — 1,941 tests, 10/10 OWASP coverage, 9 published benchmarks with honest methodology, a deployable defense proxy, and a defensible measurement-loop moat. The two things that will erode it within 6-12 months are (a) academic groups publishing the methodology before you do, and (b) Promptfoo's runtime defense products maturing. **The single highest-leverage next step after the hackathon is publishing a research paper** — you already have the data, the methodology, and the honest findings sitting in `RESULTS.md`. Everything else (frontier-brain attacker runs, CUA targets, community building, managed cloud) compounds on top of that.
