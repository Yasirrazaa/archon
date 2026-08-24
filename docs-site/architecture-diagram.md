# Architecture Diagrams

Three views of Archon v3: the per-request defense path through **archon-armor**,
the closed-loop red/blue battle engine, and the GCP deployment topology.
Rationale lives in [Architecture](architecture.md) and
[`BLUEPRINT_HACKATHON.md` §3](https://github.com/Yasirrazaa/archon/blob/main/BLUEPRINT_HACKATHON.md).

## 1. Request flow: agent → archon-armor → upstream LLM

Every request is authenticated, replay-checked, gated by the kill switch and
rate limiter, then inspected by the layered defense pipeline before it ever
reaches the upstream model. Responses pass output redaction on the way back,
and every stage emits an OTel span.

```mermaid
sequenceDiagram
    autonumber
    participant A as Client agent<br/>(any framework)
    participant R as Registry<br/>(SQLite / policy store)
    participant P as archon-armor proxy<br/>(POST /v1/chat/completions)
    participant L as Defense pipeline
    participant U as Upstream LLM<br/>(Gemini / OpenAI-compat)
    participant T as OTel exporter<br/>→ Cloud Trace

    A->>P: signed request (HMAC or Ed25519 identity,<br/>X-Agent-ID + body-bound signature)
    P->>P: nonce replay check
    P->>R: lookup agent policy (+ kill-switch state)
    R-->>P: SecurityPolicy / REVOKED?
    alt revoked or replayed
        P-->>A: 401 rejected (fail closed)
    end
    P->>P: token-bucket rate limit
    P->>L: user content
    L->>L: L0 normalization (unicode/encoding collapse)
    L->>L: L1 threat classification (category blocklist)
    L->>L: L2 segmentation (role-tag forgery detection)
    L->>L: L3 spotlighting (untrusted-input delimiting)
    L->>L: L4 execution mode (tool-call gating)
    L->>L: optional external guardrail seam<br/>(NeMo rails / Model Armor proxy)
    alt blocked at any layer
        L-->>P: block verdict + layer attribution
        P-->>A: refusal content
    else clean
        L->>U: forwarded prompt
        U-->>L: completion
        L->>L: L5 output guardrails (PII / secret redaction)
        L-->>P: response + per-exchange verdict
        P-->>A: OpenAI-compatible response
    end
    L--)T: armor.request span + per-layer spans with verdict attrs
    P--)T: audit trail (append-only)
```

Key properties:

- Any agent is protected by changing one env var: `OPENAI_BASE_URL=http://localhost:8080/v1`.
- Every layer emits OTel spans plus a per-exchange verdict, so defense
  effectiveness is *measurable* — see it live in Cloud Trace.
- Third-party guardrails bolt in through the `ExternalGuardrailLayer` seam;
  they can be attacked like any other target (`OpenAICompatProxyTarget`).

## 2. Closed-loop red/blue: BattleManager ↔ targets

Archon's differentiator versus Garak/Promptfoo/PyRIT is the closed loop:
adaptive attacks run against live targets, verdicts come from ground-truth
state diffs, and every regression gates Policy-CI.

```mermaid
flowchart LR
    subgraph RED[Red side]
        CORPUS[Probe packs<br/>core 4 · encoding_evasion 15 · latent_injection 15<br/>owasp_llm_10 56 · harmless_helpfulness 12]
        ADAPTIVE[Adaptive attackers<br/>BranchingAttacker GOAT-style<br/>LayerTargetingAttacker<br/>TraceDrivenAttacker]
    end

    subgraph BLUE[Blue side]
        BM[BattleManager<br/>async submit / poll / checkpoint]
        PIPE[Defense pipeline<br/>normalize → classify → segment<br/>→ spotlight → execution_mode<br/>→ output_guardrails]
        ARMOR[archon-armor proxy]
    end

    subgraph TARGETS[Live attack targets]
        SBX[sandbox<br/>real tool exec + env diff]
        MEM[memory<br/>poisonable vector store]
        MA[multiagent<br/>trust boundary swarm]
        MCP[mcp_battles<br/>description hijack routing]
        SC[supplychain<br/>rug-pull feed]
        TRUST[trust<br/>approval-fatigue HITL]
        ROGUE[rogue<br/>stego covert channels]
        GAPS[gaps<br/>recon · config tamper · staged payload]
    end

    VERDICT{{Compare / purple verdict<br/>ground-truth state diff,<br/>not lexical markers}}
    CI{{Policy-CI gate<br/>archon compare --ci /<br/>purple --ci}}

    CORPUS --> BM
    ADAPTIVE --> BM
    BM --> TARGETS
    TARGETS --> VERDICT
    PIPE -. protects .-> TARGETS
    ARMOR -. third-party mode .-> TARGETS
    BM --> VERDICT
    VERDICT --> REPORT[Battle JSON / HTML / Markdown<br/>compliance evidence artifacts]
    REPORT --> CI
    CI -->|regression| FAIL[exit 1 — merge blocked]
```

The loop closes when a battle result feeds back into policy: flip a paired
defense on (pinning, boundary sanitization, hardened approver, …) and re-run
the same battle to watch the attack fail — each tutorial below does exactly
that.

## 3. Deployment topology (GCP)

The hackathon reference deployment: one stateless Cloud Run service, object
storage for evidence, and trace export for observability. Everything runs
identically on a laptop via `uv run archon serve`.

```mermaid
flowchart TB
    subgraph CLIENTS[Agents & CI]
        AGENT[Client agents<br/>OPENAI_BASE_URL → armor]
        CICD[CI pipelines<br/>archon scan --ci · compare --ci · purple --ci]
    end

    subgraph CLOUDRUN[Cloud Run]
        ARMOR[archon-armor<br/>FastAPI :8080<br/>identity → kill switch → rate limit<br/>→ defense pipeline]
        BATTLES[/v1/battles<br/>BattleManager API/]
    end

    subgraph GCP[GCP services]
        GCS[(Cloud Storage /data<br/>battle reports · evidence chain)]
        TRACE[(Cloud Trace<br/>per-layer OTel spans)]
        GEMINI[Upstream Gemini<br/>OpenAI-compatible endpoint]
    end

    AGENT --> ARMOR
    CICD --> BATTLES
    BATTLES --> ARMOR
    ARMOR --> GEMINI
    ARMOR --> TRACE
    ARMOR --> GCS
    BATTLES --> GCS

    REGISTRY[(Registry SQLite<br/>agent identities · policies · baselines)] --- ARMOR
    UI[Fleet dashboard<br/>archon ui] --> REGISTRY
```

Deploy path: `deploy/` (Cloud Run) with `DEPLOY_GCP.md` as the step-by-step
guide; local parity via `docker compose up armor`.
