# Architecture

Archon v3 follows a **core-first** design: a pure library with zero vendor dependencies,
plus deployable artifacts built on top. Full rationale in
[`BLUEPRINT_HACKATHON.md` §3](https://github.com/Yasirrazaa/archon/blob/main/BLUEPRINT_HACKATHON.md).

## Package layout

- `packages/archon_core` — defense layers, registry, providers, observability. Importable
  anywhere; never imports integrations or cloud SDKs.
- `packages/archon_armor` — the flagship artifact: an OpenAI-compatible FastAPI defense
  proxy (`POST /v1/chat/completions`) plus the async battle manager (`POST /v1/battles`).
- `packages/archon_cli` — `archon register | serve | scan | compare | report | ui`.

**Dependency rule (enforced by import-linter):** `integrations/*` and `scenarios/*` may
import `packages/*`; nothing inside `packages/*` may import them back.

## The five extension seams (stable ABCs)

Every axis of growth is one interface third parties implement without touching core:

| Seam | ABC | Purpose |
|---|---|---|
| Attacks | `AttackStrategy` | Stateful multi-turn attack campaigns |
| Defenses | `DefenseLayer` | One pipeline stage; LLM budget is first-class |
| Providers | `Provider` | OpenAI-compat, Anthropic, Gemini, local/vLLM |
| Targets | `TargetAdapter` | Anything that speaks like an agent can be tested |
| Reporting | `Reporter` | JSON / HTML / Markdown battle reports |

## archon-armor request flow

```
agent ──► POST /v1/chat/completions ──► [normalize] ──► [classify] ──► [segment]
                                                                              │
        upstream ◄── [redact output] ◄── [spotlight] ◄── policy check ◄───────┘
```

Every layer emits OTel spans and a per-exchange verdict, so defense effectiveness is
measurable rather than asserted. Policy changes land in an append-only audit trail.

The legacy competition stack (attacker/defender arena agents) is documented in
[`ARCHITECTURE.md`](https://github.com/Yasirrazaa/archon/blob/main/ARCHITECTURE.md).
