# Archon — Competitive & Market Landscape Research

> **Date:** July 8, 2026  
> **Subject:** Competitive context for Archon (AgentBeats Security Arena entry; 13th overall, 18th Attack, 6th Defend, 49.7% avg win rate, 14.4% Attack, 85.1% Defense)  
> **Scope:** AgentBeats competition specifics, broader LLM/agent security tooling, market demand drivers, and gap analysis.

---

## 1. AgentBeats Competition Specifics

### 1.1 What it is

The **AgentX – AgentBeats Competition** is run by **Berkeley RDI** in conjunction with the Agentic AI MOOC (~40K registered learners) and is sponsored by **Lambda, Nebius, OpenAI, Google DeepMind, Amazon, Snowflake, Meta, Hugging Face, and Sierra**. Total prize pool exceeds **$1M** in cash, cloud credits and inference credits. The competition uses an "Agentified Agent Assessment (AAA)" paradigm: a 🟢 **green agent** (evaluator) defines tasks, environment and scoring; a 🟣 **purple agent** (contestant) is the AI under test. They communicate via the **A2A protocol**, so a purple agent built once works against any benchmark on the platform ([AgentX-AgentBeats main page](https://rdi.berkeley.edu/agentx-agentbeats.html)).

### 1.2 Timeline & Structure

| Phase | Dates | Role | What is built |
|------|-------|------|---------------|
| **Phase 1** | Oct 16, 2025 → Jan 31, 2026 | Green | New benchmarks / agentified versions of existing benchmarks |
| **Phase 2** | Mar 2, 2026 → Jun 2, 2026 | Purple | Purple agents scored on top green agents; 4 sprints (3 wk each) + Sprint 4 grand finale (breadth) |
| **Lambda Agent Security Custom Track** | Feb 23 → Mar 30, 2026 | Purple | "Red-teaming and automated security testing challenge" (cash prizes $5K / $3K / $1K for top 3 in each phase) |

Phase 2 Sprint 3 (Apr 13 – May 3) is where **Agent Safety** runs using **Pi-Bench** as its canonical green agent ([AgentX-AgentBeats main page](https://rdi.berkeley.edu/agentx-agentbeats.html)).

### 1.3 Scenarios / Tasks Used

- **Pi-Bench** (Agent Safety, Phase 1 1st place; sprint 3 evaluator): policy-compliance benchmark across 9 diagnostic dimensions (Compliance, Understanding, Robustness, Process, Restraint, Conflict Resolution, Detection, Explainability, Adaptation) and 7 policy surfaces (Access, Privacy, Disclosure, Process, Safety, Governance, Ambiguity) covering retail, healthcare, finance, HR. Scoring is **deterministic — no LLM judges** ([AgentX-AgentBeats main page — Pi-Bench description](https://rdi.berkeley.edu/agentx-agentbeats.html)).
- **NAAMSE** (Phase 1 Agent Safety 2nd place): green agent that mutates an initial corpus of **>125,000 jailbreak prompts + 50,000 benign prompts** using **25+ mutation strategies** and an evolutionary/genetic algorithm; scores via behavioral analysis ([AgentX-AgentBeats main page — NAAMSE description](https://rdi.berkeley.edu/agentx-agentbeats.html)).
- **AVER** (Phase 1 Agent Safety 3rd place): benchmark for AI error detection/recovery; 47 tasks across 5 error categories; current models score 0% on explicit error detection ([AgentX-AgentBeats main page — AVER description](https://rdi.berkeley.edu/agentx-agentbeats.html)).
- **CyberGym** (Cybersecurity Agent track): evaluates exploit/PoC generation for libFuzzer-style bugs (top purple agent: **Pegasus** in Phase 2; **AgentWhetters** 2nd place; **AgentSlug / RCA-Bench** and **Ethernaut Arena** also won Phase 1 places) ([AgentX-AgentBeats main page](https://rdi.berkeley.edu/agentx-agentbeats.html)).

Archon's internal scenario plugins (PortfolioIQ, Thingularity, GymJailbreak, Resume Downgrade, Medical Records) match the multi-turn injection + direct-attack style these green agents exercise ([README.md L26–40](README.md)).

### 1.4 Top Teams (Phase 2, publicly named)

| Track | 1st Place | 1st Place (tie) |
|------|-----------|-----------------|
| Agent Safety (Sprint 3, Pi-Bench) | **durga-sandeep/safetyagent** (single-model LiteLLM A2A agent, ALLOW/ALLOW-CONDITIONAL/DENY/ESCALATE) | **Pegasus** (policy-literacy-first, 12-rule system prompt + deterministic tool-call post-processor) |
| Coding (SWE-bench Pro) | **AgentWhetters** (GPT-5.4 flat loop) | — |
| Coding (Terminal Bench 2.0) | — | **AgentSWE** (RLM), **Purple Terminal Agent** (Mixture-of-Model REPL agent, ~$9.5/run) |
| Cybersecurity (CyberGym) | **Pegasus** | — |
| τ²-Bench | **AgentSWE** | — |
| Computer Use (CAR-bench) | **CAReful** | — |
| Computer Use (OSWorld-Verified) | **Entouch** | — |
| Game Agent (Sprint 1 — Minecraft) | **AgentWhetters** (Sprint 4 general-purpose 1st) | — |

**Lambda Agent Security Custom Track** (Phase 2) winners are **not publicly identified** on the main Berkeley RDI page. A team informally referenced as "NeuralShield" (cited in Archon's own [ARCHITECTURE.md](ARCHITECTURE.md) as the inspiration for its 7-layer defense gateway) and reported by Archon authors as 2nd with ~91% defense is **not verifiable from public Berkeley RDI leaderboard material** retrieved on 2026-07-08; treating as **not publicly identified**.

Source: [AgentX-AgentBeats winners section](https://rdi.berkeley.edu/agentx-agentbeats.html).

---

## 2. Broader Competitive Landscape

### 2.1 Open-source tools (focus: red team / guardrail / eval / platform)

| Tool | Org | Focus | Language | Notable Strength | Source |
|------|-----|-------|----------|------------------|--------|
| **Promptfoo** | Promptfoo | Red-team + eval platform | TS/Node | 157 attack plugins, CI/CD, web UI | [github.com/promptfoo/promptfoo](https://github.com/promptfoo/promptfoo) |
| **Garak** | NVIDIA | Vulnerability scanner | Python | 80+ probes, broad LLM coverage | [github.com/NVIDIA/Garak](https://github.com/NVIDIA/Garak) |
| **PyRIT** | Microsoft | Red-team framework | Python | Multi-turn orchestrator, attacker+target DSL | [github.com/Azure/PyRIT](https://github.com/Azure/PyRIT) |
| **DeepEval** | Confident AI | Eval (safety/quality) | Python | 40+ metrics incl. safety/bias | [github.com/confident-ai/deepeval](https://github.com/confident-ai/deepeval) |
| **RAGAS** | Ragas | RAG evaluation | Python | Faithfulness / context precision | [github.com/explodinggradients/ragas](https://github.com/explodinggradients/ragas) |
| **LLM Guard** | Protect AI | Runtime guardrails | Python | 35 input/output scanners | [github.com/protectai/llm-guard](https://github.com/protectai/llm-guard) |
| **Purple Llama** | Meta | Safety tools + Llama Guard | Python | Llama Guard family of guard models | [github.com/meta-llama/PurpleLlama](https://github.com/meta-llama/PurpleLlama) |
| **AgentDojo** | ETH Zürich | Agent benchmark | Python | Prompt-injection benchmark for tool-using agents | [github.com/ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo) |
| **Mindgard** | Mindgard | Red-team SaaS | Python/TS | Automated eval + library | [mindgard.ai](https://mindgard.ai) |
| **PyGuard / Counterfit** | Microsoft | Adversarial ML | Python | Classic ML model attacks | [github.com/Azure/counterfit](https://github.com/Azure/counterfit) |

### 2.2 Commercial / SaaS players

| Vendor | Focus | Pricing | Differentiator | Source |
|--------|-------|---------|----------------|--------|
| **Lakera** | AI-native security platform (Guard + Red) | SaaS, enterprise pricing | Gandalf agent red-team; Prompt-injection & PII scanners; SD | [lakera.ai](https://www.lakera.ai) |
| **HiddenLayer** | "Total AI Security" — model & app security | Enterprise SaaS | Model supply-chain, adversarial-input, SaaS+endpoint | [hiddenlayer.com](https://hiddenlayer.com) |
| **Prompt Security** | GenAI risk management | Enterprise SaaS | Discovery, posture, runtime controls | [prompt.security](https://prompt.security) |
| **Arthur AI** | "Ship reliable AI agents fast" — observability/eval | SaaS, per-seat | Full eval + monitoring, agent reliability focus | [arthur.ai](https://arthur.ai) |
| **Robust Intelligence** (Cisco) | AI firewall / model validation | Enterprise | Acquired by Cisco 2024; RTI platform + Cisco AI Defense | [robustintelligence.com](https://www.robustintelligence.com) |
| **TrojAI** (Eigent.AI) | Model backdoor / Trojan detection | Enterprise | NIST-evaluated; govt/defence focus | [troj.ai](https://troj.ai) |
| **Lasso Security** | GenAI gateway + DLP | SaaS | Shadow-AI discovery, prompt DLP | [lasso.security](https://www.lasso.security) |
| **Pangea** | Guardrails + audit | Usage-based | Prompt-injection, PII redaction, content moderation APIs | [pangea.cloud](https://pangea.cloud) |
| **Patronus AI** | Eval + red-team | SaaS | "Lynx" judge + "Evaluator" framework | [patronus.ai](https://www.patronus.ai) |
| **CalypsoAI** | Model security + observability | Enterprise | Acquired by F5 (2025) for app-layer GenAI security | [calypsoai.com](https://calypsoai.com) |
| **Mindgard** | Automated red team | SaaS | Enterprise attack library + STEPS framework | [mindgard.ai](https://mindgard.ai) |
| **DeepKeep / Noma Security / Zilla Security / Breadcrumb AI** | Governance | Enterprise | AI governance & asset inventory | various |

### 2.3 Enterprise platform vendors adding LLM security (2024–2026)

- **CrowdStrike** — Charlotte AI agent threat detection & LLM workload protection ([crowdstrike.com](https://www.crowdstrike.com)).
- **Palo Alto Networks** — AI Security Posture Management (AI-SPM) module in Prisma Cloud ([paloaltonetworks.com](https://www.paloaltonetworks.com)).
- **Wiz** — AI-SPM extension inside CNAPP, scanning for AI service misconfigurations ([wiz.io](https://www.wiz.io)).
- **Microsoft** — **PyRIT** (open-source) + **Microsoft Defender for AI** (Azure AI Content Safety + Defender for Cloud AI workloads).
- **Google** — **Secure AI Framework (SAIF)** + Model Armor (preview 2025) for Gemini-based apps.
- **AWS** — Bedrock Guardrails + Amazon Q security add-ons.
- **Cisco** — Acquired **Robust Intelligence** (2024) → **AI Defense** runtime firewall.
- **F5** — Acquired **CalypsoAI** (2025); integrating into F5 Application Delivery.
- **SentinelOne / Tenable / Check Point / Trend** — Each added AI-workload posture modules in 2025.

### 2.4 Summary observation

> **Red team** is crowded but **single-turn dominant**. **Guardrails** are crowded but **agentic-runtime weak**. **Eval** tools (Braintrust, DeepEval, RAGAS) lack adversarial depth. **Enterprise platforms** are just beginning to bolt LLM security onto existing CNAPP/SIEM stacks. **No incumbent ships multi-turn attack + multi-layer defense + scenario plugins in one CLI** — the Archon slot.

---

## 3. Market Needs — Who Needs This Badly

### 3.1 Industries & use cases most exposed

| Industry | Use cases | Why it's urgent |
|----------|-----------|-----------------|
| **Financial services** | RAG research assistants, advisor copilots, trading agents, KYC chatbots | Regulators (SEC, OCC, FCA) increasing scrutiny; PII/transaction data exfiltration risk |
| **Healthcare** | Clinical decision support, EHR copilots, patient-facing triage, RCM automation | HIPAA + state privacy laws; agentic EHR tools (FHIR) access PHI |
| **Government / Public sector** | Citizen-service chatbots, document-analysis agents | EO 14110 (Biden, Oct 2023), Trump-era rollback Jan 2025 but NIST AI RMF still active; procurement gating |
| **SaaS / B2B** | Customer-support copilots, in-app assistants, code-gen tools | Multi-tenant prompt-injection exposure; SOC2 + ISO 42001 mandates |
| **Legal** | Contract review agents, e-discovery | Privilege leakage, hallucinated citations |
| **Cybersecurity** | SOC analyst copilots, autonomous SecOps | Adversarial inputs (prompt injection) can be weaponised against the SOC itself |
| **Retail / e-commerce** | Personal shoppers, marketing copy agents | Brand-safety + customer-PII |

### 3.2 Regulatory drivers

- **EU AI Act** — High-risk AI providers must demonstrate risk management, transparency and human oversight (Regulation (EU) 2024/1689; phased applicability from Aug 2024 through Aug 2026) ([artificialintelligenceact.eu](https://artificialintelligenceact.eu)).
- **NIST AI RMF 1.0** + **Generative AI Profile (NIST AI 600-1, July 2024)** — Voluntary framework increasingly referenced in US federal procurement ([nist.gov AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)).
- **ISO/IEC 42001:2023** — AI Management System standard; certifiable.
- **Executive Order 14110** (US, Oct 2023; partially revoked Jan 2025) — Originally required safety testing of dual-use foundation models; remaining NIST obligations still in force.
- **SEC cybersecurity disclosure rules** (Jul 2023) — Material incidents must be disclosed within 4 days; AI-driven breaches qualify.
- **State-level US laws** — Colorado AI Act (SB 24-205, 2026), California AB 2013/2885 (training-data transparency), NYC Local Law 144 (AI hiring bias audit).

### 3.3 High-profile incidents driving board-level urgency

- **Chevrolet / Tay**-style chatbot incidents (2023–2024 — multiple car-brand dealer bots agreeing to sell cars for $1).
- **Samsung ChatGPT leak** (2023) — engineers pasted proprietary source code into ChatGPT.
- **Air Canada chatbot hallucination lawsuit** (2024) — tribunal ruled airline liable for bad advice.
- **Microsoft Copilot "EchoLeak"** / similar indirect prompt-injection disclosures in 2024–2025.
- **DeepSeek exposure** (early 2025) — highlighting supply-chain & data-exfil risk.
- **OWASP Top 10 for LLM Applications (2025)** and **MITRE ATLAS** are now standard references for boards.

### 3.4 Buying centres & budget signals

| Buyer | Pain | Typical budget |
|-------|------|---------------|
| **CISO / AI risk lead** | Continuous AI-risk reporting, board-level metrics | $50K–$500K/year platform |
| **AI / ML platform team** | CI/CD gates for model promotion | $10K–$100K/year |
| **Red team / AppSec** | Need automated multi-turn attack tooling | $5K–$50K/year |
| **Compliance / GRC** | ISO 42001 / EU AI Act audit trails | $20K–$200K/year (often part of GRC platform) |
| **Product / Trust & Safety** | Reduce over-refusal, ship faster | $10K–$100K/year |

The 2025 Gartner Hype Cycle for AI Security / Generative AI placed **AI TRiSM (Trust, Risk, Security Management)** in the "Peak of Inflated Expectations" and predicted **>40% of enterprise GenAI apps will require AI security tooling by 2028** (paraphrased from Gartner press coverage; specific report behind paywall).

---

## 4. Gap Analysis & Opportunities for Archon

### 4.1 Archon's unique capabilities (from repo)

1. **Multi-turn stateful attacker** — 7-round GOAT-style loop with persistent `round_data` memory across rounds ([README.md L66–73](README.md)).
2. **Signal extraction & fragment reconstruction** — accumulates partial information across rounds to reconstruct sensitive values the defender won't reveal in one shot ([README.md L67–72](README.md)).
3. **5×4 = 20 surface/family attack strategies** — adaptive pivot based on defender response signals ([README.md L77](README.md)).
4. **7-layer defense pipeline** — Python sanitization → dynamic invariants → PPA spotlighting → Task Shield prompt → exchange classifier → output guardrails (PII/code) ([README.md L94–109](README.md), [ARCHITECTURE.md](ARCHITECTURE.md)).
5. **14 deterministic normalization transforms** — pre-LLM Python filtering that catches 30%+ attacks with zero model calls.
6. **Scenario plugins** — 5 plugins (PortfolioIQ, Thingularity, GymJailbreak, Resume Downgrade, Medical Records); agents have **zero hardcoded scenario knowledge** ([README.md L26–40](README.md)).
7. **Normal-user test** — verifies defender remains helpful to legitimate users (over-refusal metric).
8. **Contract awareness + execution modes** — exploits format constraints, picks graduated response to suspicion.
9. **Defender response diagnosis** — 5-category failure classification ([README.md L82–83](README.md)).
10. **A2A-protocol-native** — built for interop with any AgentBeats-style green agent.

### 4.2 Gaps in current tooling that Archon can fill

| # | Gap | How Archon fills it |
|---|-----|---------------------|
| G1 | **No tool tests attack AND defense together** | Archon's 7-round battle does both in one run. |
| G2 | **No tool does multi-turn stateful agentic testing** | Persistent attacker memory across 7 rounds. |
| G3 | **No defender "WHY did it fail?" diagnosis** | 5-category failure classification + 5 failure modes. |
| G4 | **No scenario-agnostic architecture** | Agents receive only high-level context from scenario plugins. |
| G5 | **No tool balances security + helpfulness** | Normal-user test prevents over-refusal regression. |
| G6 | **No production-grade defense pipeline** | 7-layer defense gateway, defense-in-depth. |
| G7 | **No open-source CLI + plugin ecosystem for agents** | Python CLI + pluggable scenario backend (proposed in ROADMAP.md). |

### 4.3 Top 10 high-value opportunities (impact × feasibility)

| # | Opportunity | Impact | Feasibility | Why now |
|---|-------------|--------|-------------|---------|
| 1 | **Decouple from A2A / in-process mode** | H | H | Removes 3-process overhead; unblocks local-dev UX |
| 2 | **Multi-provider (OpenAI/Anthropic/Azure/local)** | H | H | Cannot sell without OpenAI/Anthropic parity |
| 3 | **CI/CD gate mode (exit codes, JSON, GitHub Action)** | H | H | DevSecOps budget line item in 2025–2026 |
| 4 | **HTML / interactive web report** | H | M | Buyer demo differentiator vs Promptfoo CLI |
| 5 | **Plugin marketplace (community attack/defense plugins)** | H | M | Mirrors Promptfoo's 157-plugin gravity |
| 6 | **SaaS hosted version (managed battles)** | H | M | Removes friction for non-Python shops |
| 7 | **EU AI Act / NIST AI RMF compliance report templates** | H | M | Audit-friendly export is a clear unmet need |
| 8 | **Industry scenario packs (finance / health / legal)** | H | M | Vertical SaaS play |
| 9 | **Adversarial training loop (self-improving attacker)** | M | M | Meta-attacker research angle, conference papers |
| 10 | **Public leaderboard ("Archon Bench")** | M | L | Community moat; mirrors AgentBeats gravity |

### 4.4 Potential product / business directions

#### Direction A — **Open-source dev tool (default)**

- License: Apache-2.0; pip / Docker / npm.
- Wedge: free `archon eval`, `archon redteam`, `archon view` subcommands.
- Monetize via enterprise tier (RBAC, SSO, audit logs, hosted) — *follows the Promptfoo / Sentry / GitLab open-core playbook*.

#### Direction B — **Compliance-as-code SaaS (vertical)**

- Archon packaged with EU AI Act / NIST AI 600-1 / ISO 42001 templates, audit-export, signed test reports.
- Target: Fortune-500 GRC + AI risk teams; $20K–$200K/year per customer.
- Wedge: replace manual red-team engagements (~$50–150K per engagement) with continuous testing.

#### Direction C — **Agentic Security Benchmark / Consulting**

- "Archon Bench" hosted leaderboard where vendors submit their agents; consultancy arm does bespoke purple-team engagements.
- Hybrid: free OSS framework drives top-of-funnel; consulting and benchmark-as-a-service drive revenue.
- Mirrors Trail of Bits / NCC Group AI Red Team service line, but at lower cost.

**Recommended primary direction: A → B.** Ship the open-source framework first (Phase 1 of ROADMAP.md), then layer on the compliance-reporting SaaS tier once usage proves the multi-turn-attack-and-defense moat.

---

## Sources

1. Berkeley RDI — AgentX AgentBeats main page: https://rdi.berkeley.edu/agentx-agentbeats.html
2. AgentBeats platform: https://agentbeats.dev
3. Archon project files: README.md, ARCHITECTURE.md, ROADMAP.md, COMPETITIVE_ANALYSIS.md (local repo)
4. Lakera: https://www.lakera.ai
5. HiddenLayer: https://hiddenlayer.com
6. Prompt Security: https://prompt.security
7. Arthur AI: https://arthur.ai
8. Robust Intelligence (Cisco): https://www.robustintelligence.com
9. TrojAI: https://troj.ai
10. Promptfoo: https://github.com/promptfoo/promptfoo
11. NVIDIA Garak: https://github.com/NVIDIA/Garak
12. Microsoft PyRIT: https://github.com/Azure/PyRIT
13. Protect AI LLM Guard: https://github.com/protectai/llm-guard
14. Meta Purple Llama: https://github.com/meta-llama/PurpleLlama
15. ETH Zürich AgentDojo: https://github.com/ethz-spylab/agentdojo
16. DeepEval: https://github.com/confident-ai/deepeval
17. RAGAS: https://github.com/explodinggradients/ragas
18. NIST AI Risk Management Framework: https://www.nist.gov/itl/ai-risk-management-framework
19. EU AI Act (analysis portal): https://artificialintelligenceact.eu
20. CalypsoAI (F5): https://calypsoai.com
21. Cisco AI Defense (post-Robust Intelligence acquisition): https://www.cisco.com/site/us/en/products/security/index.html
22. AWS Bedrock Guardrails: https://aws.amazon.com/bedrock/guardrails/
23. Microsoft Defender for Cloud AI Workloads: https://learn.microsoft.com/en-us/azure/defender-for-cloud/ai-workload-protections
24. Google Model Armor / SAIF: https://cloud.google.com/security/ai
25. CrowdStrike Charlotte AI / AI Security: https://www.crowdstrike.com
26. Palo Alto Prisma Cloud AI Security: https://www.paloaltonetworks.com/prisma/cloud
27. Wiz AI-SPM: https://www.wiz.io
28. OWASP Top 10 for LLM Applications: https://owasp.org/www-project-top-10-for-large-language-model-applications/
29. MITRE ATLAS: https://atlas.mitre.org
30. Mindgard: https://mindgard.ai
31. Lasso Security: https://www.lasso.security
32. Pangea Cloud: https://pangea.cloud
33. Patronus AI: https://www.patronus.ai
34. F5 / CalypsoAI acquisition coverage (general press 2025)
