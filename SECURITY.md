# SECURITY.md — archon-armor threat model

**Scope:** the archon-armor defense proxy (`packages/archon_armor/`) and its
supporting core (`packages/archon_core/`): identity verification, rate
limiting, registry, audit trail, and observability wiring.

**Last reviewed:** 2026-08 (Sprint IMP-7)

---

## 1. Trust model — what armor trusts / doesn't trust

archon-armor is a zero-trust reverse proxy in front of upstream LLM APIs.
Every request is treated as potentially hostile.

### Trusted

- **The process itself.** Code running inside the armor container, its
  dependencies (as pinned at build time), and its configuration environment.
- **The registry contents.** `AgentCard` records (agent id, per-agent signing
  secret, `SecurityPolicy`) are trusted once loaded. See §5 for why this is a
  real limitation with the default SQLite store.
- **The upstream LLM endpoint** configured by each agent's
  `SecurityPolicy.upstream_base_url` — armor authenticates *callers*, it does
  not authenticate *to* the upstream beyond whatever key the operator injects.
- **Server clock** for timestamp-window checks (see §3).

### Not trusted

- **Request bodies.** All content passes the guard pipeline
  (normalization → threat classification → segmentation → spotlighting →
  execution-mode wrapping) before any byte reaches an upstream model, and
  output guardrails on the way back.
- **Caller-supplied headers.** `X-Agent-ID` alone grants nothing; it must
  resolve to a registered agent AND satisfy the HMAC signature check when
  signed mode is on.
- **Timestamps supplied by callers** — they are only accepted within a skew
  window of server time.
- **Prompt content claiming authority.** "Ignore previous instructions",
  fake system messages, and tool/output injection patterns are classified and
  blocked by policy, not believed.

---

## 2. Authentication boundary

Signed mode uses per-agent shared secrets generated server-side at
registration and stored on the agent's `AgentCard` (`api_secret`,
server-side only).

**Canonical signing string:**

```
signature = HMAC_SHA256(secret, "{METHOD}:{path}:{timestamp}:{sha256(body)}")
```

**Headers:** `X-Agent-ID`, `X-Timestamp` (unix seconds), `X-Signature`
(hex-encoded). Implementation:
`packages/archon_core/security/authn.py` (`HmacVerifier`, `sign_request`).

**Properties:**

- **Body binding.** The SHA-256 body digest inside the signed message binds
  each signature to the exact payload — substituting a different body
  invalidates the signature (`hmac.compare_digest`, constant-time).
- **Replay window.** Timestamps more than **±300 s** from server time
  (`tolerance_seconds=300`) are rejected as expired/future replay.
- **Replay protection — nonce store (Sprint IMP-7).** The former
  within-window replay gap is closed by an opt-in `NonceStore`
  (`packages/archon_core/security/authn.py`): a verifier constructed as
  `HmacVerifier(registry, nonce_store=NonceStore())` additionally requires
  an `X-Nonce` header and rejects any nonce reuse within the TTL
  (default 600 s) with `replay detected`. Nonces are single-use, tracked on
  a monotonic clock with opportunistic pruning and a bounded entry count.
  **Server mode enables this by default** (`server.py build_app`), so
  production clients MUST send a fresh `X-Nonce` per request. Verifiers
  built *without* a nonce store retain the legacy window-only semantics
  described above. Caveats: the store is in-memory and per-process — it
  resets on restart and is not shared across replicas (same trade-offs as
  §3); for strict multi-replica guarantees use a shared store (e.g. Redis).
- **Legacy mode danger.** `create_app(..., identity=None)` falls back to
  `AllowAllVerifier`, which trusts the bare `X-Agent-ID` header. This exists
  for dev/test only. The container entry point (`server.py`) always wires
  `HmacVerifier`; never deploy an app built without one.

---

## 3. Rate limiting

`TokenBucketRateLimiter` (`packages/archon_core/security/ratelimit.py`),
keyed by authenticated agent id. The container default is capacity 60 burst /
10 req/s refill (`server.py`). Requests exceeding the bucket get HTTP 429.

**Limitations:** buckets are **in-memory and per-process** — they reset on
restart and are not shared across replicas. Behind a multi-instance load
balancer, effective limits multiply by instance count. For strict global
limits, front armor with a shared limiter (e.g., Redis-backed) or API-gateway
quota.

---

## 4. Known limitations (honest list)

1. **SQLite default stores.** Without `ARCHON_DATABASE_URL`, the registry and
   audit trail are local SQLite files (defaulting under `/tmp` in dev). This
   is single-process, not replicated, and lives on ephemeral container
   storage unless mounted. Use Postgres in production (§6).
2. **No internal TLS.** Armor terminates plain HTTP internally
   (`uvicorn ... --port 8080`). TLS is expected to terminate at the platform
   front door (Cloud Run / load balancer). Traffic between the front door and
   armor is unencrypted within the VPC/network boundary — do not expose the
   uvicorn port publicly.
3. **Registry file integrity is unverified.** Registry state (including
   per-agent signing secrets and security policies) is read from storage
   without any integrity check or signature. Anyone with write access to the
   registry file/database can mint identities, weaken policies, or replace
   secrets. Protect storage with filesystem/DB permissions and IAM; there is
   currently no built-in tamper detection.
4. **Per-process nonce store** (see §2): replay protection is in-memory and
   not shared across replicas — a restart resets it (a captured request
   replayed after restart, inside the timestamp window, can succeed once per
   replica), and a replay routed to a different replica is not caught.
   Verifiers built without a nonce store retain window-only semantics. Use a
   shared store (e.g., Redis) for strict guarantees.
5. **Per-process rate limiting** (see §3).
6. **Secrets on the AgentCard.** Signing secrets live alongside registry
   data. There is no HSM/KMS envelope encryption or rotation mechanism yet;
   rotation means re-registering the agent.
7. **Fuzz coverage is best-effort.** `tests/armor/test_fuzz_parsers.py`
   covers malformed JSON, oversized payloads, unicode/null-byte tricks,
   deeply nested JSON, wrong-typed fields, and bad auth inputs (invariant:
   hostile input yields 4xx, never 5xx), but this is not a substitute for a
   dedicated fuzzing campaign.

---

## 5. Reporting a vulnerability

**Please do not open public GitHub issues for security reports.**

- **Contact:** `security@archon.dev` *(placeholder until the domain is confirmed —
  replace with the project's real, monitored inbox and add a PGP key before public
  launch)*
- **Report format:** use the structured advisory template at
  [`.github/ISSUE_TEMPLATE/security_advisory.md`](./.github/ISSUE_TEMPLATE/security_advisory.md)
  — or just include in your email the affected component/package, reproduction steps or
  PoC, observed vs. expected behavior, and your assessment of impact.
- **Expected response times:**
  - Acknowledgement: within **2 business days**
  - Initial triage & severity assessment: within **7 days**
  - Fix or mitigation target: **30 days** for high/critical findings
- **Coordinated disclosure:** we practice coordinated disclosure. Please give
  us up to **90 days** to ship a fix before publishing details; we will
  credit reporters by name (unless you prefer anonymity) in release notes.
- **Please include:** affected component/package, reproduction steps or PoC,
  observed vs. expected behavior, and your assessment of impact.

---

## 6. Operator hardening checklist

Before exposing archon-armor to real traffic:

- [ ] **Postgres instead of SQLite.** Set `ARCHON_DATABASE_URL` to a managed
      Postgres DSN so the registry survives restarts and scales across
      replicas. Do not run production on the default SQLite paths.
- [ ] **Observability on.** Set `ARCHON_OTEL_EXPORTER=otlp` and
      `OTEL_EXPORTER_OTLP_ENDPOINT` to your collector so every request span
      (with attribute scrubbing enabled) lands somewhere you can alert on.
- [ ] **Signed mode enforced.** Ensure requests are verified with
      `HmacVerifier` (the container entry point does this by default). Never
      build the app with `identity=None` / `AllowAllVerifier` outside tests.
      Keep the timestamp tolerance tight for your latency budget. Server mode
      also wires a `NonceStore` by default, so clients must send a fresh
      `X-Nonce` header per request; if you build the verifier yourself, pass
      `nonce_store=NonceStore()` to keep replay protection on.
- [ ] **IAM front door.** Deploy on Cloud Run (or equivalent) with IAM-based
      authentication. Do **not** deploy with `--allow-unauthenticated`;
      armor's own HMAC layer is defense-in-depth, not a substitute for
      network-level access control.
- [ ] **Protect storage.** Lock down registry/audit file permissions or DB
      credentials; anyone who can write the registry can mint identities.
- [ ] **Shared/global rate limiting** if you run multiple replicas and need
      enforceable global quotas.
- [ ] **Rotate agent secrets** on a schedule and on staff/agent offboarding
      (re-register the agent with a fresh secret).
