# Demo Video Script — ~4 minutes

> Record at 1080p. Every beat lists: what to show, the command, and the talking point. Screenshots marked 📸 are also your Devpost/GCP-proof stills.

## Beat 0 — Cold open (0:00–0:20)
**Show:** terminal, repo README.
**Say:** "AI agents fail in production because security tools are half a loop — scanners attack but can't defend, guardrails defend but can't prove anything. Archon is both halves in one system. Let me attack an agent, shield it, and re-attack to prove the shield works."

## Beat 1 — Register + baseline scan (0:20–1:00)
```bash
uv run archon register --agent-id demo-agent --name "Demo" --upstream-base-url https://generativelanguage.googleapis.com/v1beta/openai ...
uv run archon scan --registry registry.db --agent-id demo-agent --pack owasp_llm_10
```
**Say:** "202 probes across OWASP LLM Top 10, the Agentic Top 10, HarmBench domains. Baseline: the unshielded agent leaks."
📸 Screenshot: scan report with block rate.

## Beat 2 — Live tool-execution attack (1:00–1:40)
Run a sandbox battle showing `attack_success` from environment state (money actually moved), then memory poisoning on a real store.
**Say:** "These aren't string matches — ground truth is the environment diff. The transfer executed; the poisoned memory entry leaked the secret."

## Beat 3 — Deploy the shield (1:40–2:20)
```bash
uv run archon serve --registry registry.db   # archon-armor proxy
# point agent's OPENAI_BASE_URL at armor; fire signed request
```
**Show:** attack request → `x-archon-blocked: true`; benign request → Gemini answers.
**Say:** "Drop-in OpenAI-compatible proxy. HMAC workload identity, replay protection, per-agent policy, 8-layer pipeline."
📸 Screenshot: blocked vs allowed side by side.

## Beat 4 — GCP proof: Cloud Run + Cloud Trace (2:20–3:10) ← **mandatory**
**Show:** Cloud Run dashboard (service archon-armor, .run.app URL), then **Cloud Trace span tree** for one request: `armor.request` → normalization → threat_classification (blocked=true) → …
**Say:** "Deployed on Cloud Run with GCS-backed state. Every request emits OpenTelemetry spans to Cloud Trace — you can see each defense layer's verdict for this exact request."
📸 Screenshots: Cloud Run overview + Cloud Trace span tree (**primary judge proof**).

## Beat 5 — Closed-loop purple verification (3:10–3:40)
```bash
uv run archon purple --registry registry.db --agent-a unprotected --agent-b demo-agent --ci
```
**Show:** delta verdict markdown — newly_blocked probes, block-rate delta, verdict: improved.
**Say:** "Same attacks, before and after the shield. The improvement is measured, not promised. Exit code gates CI."

## Beat 6 — Kill switch + close (3:40–4:00)
```bash
uv run archon kill-switch --store /data/killswitch.db --agent demo-agent
```
**Show:** MTTC milliseconds in output; revoked agent gets 503.
**Say:** "Atomic kill switch with measured time-to-containment, audit-trailed. Compliance evidence packs map every decision to EU AI Act, NIST, and ISO 42001 controls. Archon — red team and blue team, proven in one loop."

---

## Shot list / Devpost stills
1. Scan report (Beat 1)
2. Sandbox attack_success evidence (Beat 2)
3. Blocked vs allowed requests (Beat 3)
4. **Cloud Run service dashboard** (Beat 4)
5. **Cloud Trace span tree** (Beat 4 — most important)
6. Purple delta verdict (Beat 5)
7. Kill-switch MTTC output (Beat 6)

## Architecture diagram (for Devpost image slot)
Draw from docs-site/architecture.md: Client → archon-armor (identity → kill switch → rate limit → 8-layer pipeline → upstream Gemini) with side panels: Registry/Policy store, OTel→Cloud Trace, Battle engine ↔ targets (sandbox/memory/multiagent/MCP/supply-chain), Evidence/compliance reporting.
