# Agent Security Landscape 2026 — Master Synthesis

> Compiled Aug 23, 2026 from parallel deep-research waves: commercial vendor
> analysis (~20 vendors), protocol-layer security (MCP/A2A/identity), benchmark
> and metrics survey (15+ benchmarks), standards/regulation sweep (US/EU/sector),
> plus code-verified audits of nine OSS competitors cloned in-repo.
> Companion docs: `../COMPETITIVE_ANALYSIS.md` (OSS scorecards), `../ROADMAP.md`
> v5 (enterprise phases), `../REPORT_COMPARATIVE.md` (capability evidence).

---

## 1. Executive Summary

**The market is consolidating faster than it is maturing.** Every 2023–24
pure-play category creator of scale has been absorbed (Lakera→Check Point,
Prompt Security→SentinelOne, Protect AI→Palo Alto, CalypsoAI→F5, Robust
Intelligence→Cisco, SplxAI→Zscaler). Survivors raised early and big (Zenity
$185M, Noma $132M) or occupy defensible wedges (Mindgard/testing research,
Patronus/simulation). Gartner has no Magic Quadrant yet — pre-MQ window — but
named Zenity "the company to beat" in April 2026.

**The protocol layer has deliberately delegated trust decisions to third
parties.** The official MCP Registry proves provenance but scans no code; A2A
v1.0 ships unsigned-by-default agent cards with optional auth and no replay
protection ("a wire format, not a security model"). That delegation *is* the
market opportunity.

**Research has moved from "can we attack agents" to "how do we measure defense
honestly."** NIST CAISI showed novel adaptive attacks reach 81% task-hijacking
vs 11% for known baselines, and aggregate ASR climbs 57%→80% at 25 attempts —
single-score benchmarks are structurally misleading. The judge reliability
crisis ("A Coin Flip for Safety", arXiv:2603.06594) means adversarial verdicts
are near-random without calibrated human sets.

**Regulation now has teeth and dates.** EU AI Act Art. 50 transparency became
enforceable Aug 2, 2026 (fines to €35M/7%). FTC's warning phase ends Dec 31,
2026 ($53,088/violation from 2027). Colorado SB 26-189 lands Jan 1, 2027.
Cyber-insurance questionnaires already demand per-event audit logs and agent
identity answers; AIUC-1 and CSA STAR-for-Agentic certifications are live.

**Archon's position:** full coverage on all seven agentic-security dimensions
no competitor covers well (see §6), MIT-neutral at exactly the moment
vendor-neutrality became a buying objection (promptfoo→OpenAI), and an
evidence stack that maps directly onto what auditors and insurers will demand
in 2027.

---

## 2. Commercial Landscape

### 2.1 The M&A wave (2025–2026)

| Acquired | Acquirer | Price | Category lost |
|---|---|---|---|
| Lakera | Check Point | ~$300M | Guardrails + Gandalf dataset |
| Prompt Security | SentinelOne | ~$180M | MCP gateway + monitoring |
| Protect AI | Palo Alto (Prisma AIRS) | ~$700M | Platform |
| CalypsoAI | F5 | $180M | Test + guard |
| Robust Intelligence | Cisco | ~$400M | Platform (JPMorgan customer) |
| SplxAI | Zscaler | n/d | Test + guard inside Zero Trust Exchange |
| Arize | Dynatrace | $915M deal | Observability/eval |

Independent survivors: **Zenity** ($185M, Gartner favorite), **Noma** ($132M),
**HiddenLayer** ($56M, Agent Harness), **Mindgard** ($42M, testing research),
**Patronus** ($70M, simulation/world models).

### 2.2 Pricing structures

- Hyperscalers publish per-use prices; Model Armor: $0.10/1M tokens after 2M free.
- ~11 of ~20 tracked vendors are quote-only at $80K–$200K/yr.
- Emerging per-agent / per-MCP-server pricing (not yet standardized).
- No self-serve SMB price point exists — the "Datadog-for-agent-security" seat is empty.

### 2.3 Analyst posture

Gartner pre-MQ: Market Guide for AI TRiSM (Feb 2025), Cool Vendors in Agentic
AI TRiSM (Sep 2025, Zenity named), "Securing Agent Actions, Not Prompts" +
"Zenity Is the Company to Beat" (Apr 2026). Expect a first MQ within ~12 months.

### 2.4 White space (validated gaps)

1. Cross-framework agent IAM outside hyperscalers (Entra Agent ID owns Azure only).
2. A2A traffic security — zero commercial controls.
3. SMB self-serve pricing.
4. Continuous compliance evidence wired to runtime decisions ("blocked action = audit artifact").
5. MCP supply-chain attestation/scoring (registry proves ownership, not safety).
6. Coding-agent harness security (only HiddenLayer markets a product).
7. Simulation-grounded red teaming packaged for enterprises.
8. Insurance/liability telemetry layer.

---

## 3. Protocol Layer

### 3.1 MCP

- Official registry (preview Jul 2026) requires provenance (DNS Ed25519 TXT /
  HTTPS domain / npm ownership) but performs NO code scanning — verification
  establishes provenance; enterprises must establish acceptable risk themselves.
- Incident record: Invariant tool poisoning + shadowing (Apr 2025);
  CVE-2025-54136 "MCPoison" rug-pull (CVSS 8.8); CVE-2025-6514 mcp-remote RCE
  (9.6); postmark-mcp backdoor (first malicious registry server, Sep 2025);
  SANDWORM_MODE npm worm (Feb 2026); Hades PyPI campaign (Jun 2026); OX
  Security: 2,000+ credential leaks via malicious MCP servers.
- Scale of exposure: 5.5% of public servers carry poisoned metadata (Invariant);
  MCPTox (AAAI-26): ASR up to 72.8% across 45 live servers, refusal <3%;
  UpGuard: 3–15 lookalikes per official brand server.
- Scanner paradigms (static / behavioral probing / runtime proxies) show
  near-zero inter-scanner agreement — behavioral probing (Archon's lane) is the
  differentiator vs static-only Snyk agent-scan.

### 3.2 A2A

v1.0 GA Apr 2026 under Linux Foundation. AgentCard at
`/.well-known/agent-card.json`, JWS card signing defined (§8.4) but unsigned by
default; authentication optional; no replay protection. "A wire format, not a
security model." Archon's ASI07 trust-boundary attacks are the only open-source
exploitation harness targeting this surface.

### 3.3 Identity & delegation

IETF wave: AIMS draft (WIMSE+SPIFFE+OAuth), attenuating agent tokens
(macaroon-style capability chains; DeepMind arXiv:2602.11865 legitimizes).
Only 22% of orgs treat agents as independent identity-bearing entities (CSA).
Azure Entra Agent ID = hyperscaler leader; no cross-framework independent IAM.

### 3.4 Gateways & sandboxes

LiteLLM had two serious 2026 CVEs (pre-auth SQLi, unauth RCE on CISA KEV) —
proxy code quality matters. Cloudflare added protocol-level MCP detection +
DLP; Kong enforces RFC 8707 audience binding; LF agentgateway (Rust) covers
LLM+MCP+A2A. Sandboxing converged on Firecracker microVMs (E2B, 5–30ms cold
start). Session security research: HMAC conversation chains; Contextual
Integrity Verification (per-token trust labels enforced inside attention, 0%
ASR); OWASP MCP cheat-sheet mandates ECDSA P-256 message signing.

---

## 4. Research Frontier

### 4.1 Attack reality check (NIST CAISI + academia)

- Novel adaptive attacks: **81% task-hijacking** vs 11% strongest known baseline.
- Multi-attempt effect: aggregate ASR 57%→80% at 25 attempts/task; Best-of-N
  follows a power law (89% on GPT-4o at 10K samples). **Attempt budgets MUST be
  published with any ASR number.**
- Capability confound: DeepSeek R1 hijacked 37–49% vs frontier models ~3–4%.
- 94.4% of SOTA agents vulnerable to prompt injection; 100% to inter-agent
  trust exploits (Lupinacci et al.). Adaptive attacks penetrate eight IPI
  defenses at ~50% success.
- LLM+tools implies RCE risk unless proven otherwise (LLMSmith: 19 RCE flaws
  across 11 frameworks).
- Indirect PI is structurally resistant to input validation → runtime +
  provenance defenses required, matching Archon's architecture.

### 4.2 Attack techniques worth tracking

- **Tool-Guard finding:** cross-tool description poisoning manipulates planners
  even when the poisoned tool is never selected; defense = isolated planning +
  influenced-list quarantine + pre-execution intent validation.
- **Cognitive poisoning** (TRUST-BENCH/VISTA-GUARD): malicious tools behave
  plausibly during exploration and harm only when hidden state aligns;
  trajectory-aware final-action risk scoring beats prompt-centric heuristics.
- **Conjunctive prompt attacks:** trigger key in user query + hidden template
  in compromised remote agent — each benign alone, harmful when combined;
  motivates composition-aware defenses and min/mean/max ASR reporting.
- **ChannelGuard thesis:** safe models do NOT compose into safe multi-agent systems.
- **Microsoft AI Red Team Taxonomy v2.0** (Jun 2026): seven new failure modes —
  agentic supply-chain compromise, goal hijacking, inter-agent trust escalation,
  CUA visual attacks, session context contamination, MCP/plugin abuse,
  capability disclosure-as-pivot. Most-exploited weakness in engagements:
  human-in-the-loop bypass (consent fatigue, compound-action decomposition).

### 4.3 Metrics Archon adopts

| Metric | Source | Archon use |
|---|---|---|
| GUARDEDJOINT | CaMeL (arXiv:2503.18813) | KPI style: unsafe actions prevented without breaking utility |
| Unsafe Action Rate (UAR) | SoK arXiv:2603.22928 | CI gate metric alongside block rate |
| Privilege Escalation Distance (PED) | SoK — no incumbent publishes it | Per-customer tool-graph shortest-path reporting |
| CoRIx | NIST ARIA AI 700-2 | Compliance-compatible contextual robustness index |
| Dual ASR (intermediate + end-to-end) | WASP | Expose "security through incompetence" gap |
| XSTest over-refusal companion | XSTest | Guard against defense = broken utility |

Judge discipline: never self-family judging; require κ≥0.7 calibrated human
sets for published claims; report attempt budget, per-task distribution,
adaptivity level, and utility cost with every number.

---

## 5. Standards, Regulation & Procurement

### 5.1 Dates that matter

| Date | Event |
|---|---|
| Aug 2, 2026 | EU AI Act Art. 50 transparency enforceable (done) |
| Oct 19, 2026 | FDA GenAI device docket comments close |
| Oct 26, 2026 | Colorado ADMT rules comments close |
| Dec 2, 2026 | EU synthetic-content marking deadline; FTC warning phase ends Dec 31 |
| Jan 1, 2027 | Colorado SB 26-189 effective; FTC penalties begin ($53,088/violation) |

### 5.2 Standards to align now

ISO/IEC 27090 (first international AI-security threat taxonomy, publication
H2 2026); ETSI EN 304 223 (names indirect PI); ETSI TS 104 158 AICIE incident
expression; ETSI TR 104 276 inter-agent comms; ITU-T SG17 cluster (X.S-AIA,
X.aiidm); IEEE P3945 tool-access interfaces; OWASP Agentic Top 10 (ASI01–10)
and MCP Top 10.

### 5.3 Certifications (live)

- **AIUC-1**: first certs Apr 2026 (UiPath, Cursor, Harvey); quarterly refreshes;
  CSA STAR Level 2; auditors Schellman/Zertia/BSI.
- **CSA STAR for Agentic**: L1 self-assessment / L2 third-party audit /
  Continuous telemetry; maps to AICM, ISO 42001, EU AI Act, NIST RMF.

### 5.4 Insurance & procurement evidence demands

Insurers: per-event audit logs ≥90-day retention; agent identity answers;
LMA 5400/5403 exclusions make cryptographic attribution determinative for
coverage; covenant language emerging: tamper-evident logs ≥24 months +
quarterly adversarial testing (Archon Policy-CI maps directly).
Government: GSA GSAR 552.239-7001 (eyes-off processing, 72-hour incident
reporting, 90-day forensic preservation); FedRAMP 20x path; EU MCC-AI clauses.
Auditor artifact #1 predicted finding area: signed sampled decision traces
linked to controls catalogue — exactly Archon's audit trail + compliance
report output.

---

## 6. Where Archon Wins Today

Code-verified (649 tests green). Full table: COMPETITIVE_ANALYSIS §7.1 /
REPORT_COMPARATIVE §3.1.

1. Closed-loop verified security (attack → shield → re-attack proof)
2. Self-hosted runtime enforcement proxy (OpenAI-compatible)
3. Live tool-execution battles with environment-state ground truth
4. Live memory/vector-store poisoning + remediation loop
5. ASI07 multi-agent trust-boundary exploitation
6. Evidence-derived severity scoring (CVSS-style vectors)
7. Trace-driven attack generation from OTel spans

Plus: comparison engine (Policy-CI regression gates), checkpoint/resume,
fleet dashboard, 120-probe corpus incl. encoding evasion + latent injection,
AgentDojo harness with published numbers, Homebrew/npm distribution.

## 7. Honest Gaps (enterprise readiness)

See ROADMAP v5 Phase E for closure plans: corpus breadth vs garak's 195;
OWASP Agentic 6/10 (ASI04/08/09/10 open); deterministic-tier benchmark needs
LLM-layer re-run; SOC 2 / ISO certification runway; docs site; live demo.

## 8. Strategic Bets

1. **Measurement honesty as brand**: publish attempt budgets, judge calibration,
   dual ASR — nobody else does; regulators and insurers will demand it.
2. **Evidence stack as product**: audit trail + severity vectors + compliance
   reports = insurance premium artifacts and ISO 42001 evidence packs.
3. **Protocol-layer expansion**: MCP behavioral scanning (shipped) → A2A
   boundary enforcement → tool-drift detection (registry revalidation triggers).
4. **Neutrality window**: post-promptfoo-acquisition, MIT-neutral closed-loop
   security has a 12–18 month window before platform consolidation closes it.
