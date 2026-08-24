# Blog post draft — #AllThingsAgenticHackathon

> Publish on dev.to/Medium/LinkedIn + share on X. Bonus-points item. Trim to platform norms; keep the tag.

---

## Your agent security tool is half a loop. Here's why we built the whole thing.

*Entry for the All Things Agentic Hackathon (#AllThingsAgenticHackathon).*

2026 is the year agents went to production — and the year the incident reports caught up. MCP tool-poisoning rug pulls. Memory poisoning with multi-day persistence. Multi-agent trust-boundary exploits where a compromised worker smuggles directives past a coordinator that would have refused them directly. The OWASP Agentic Top 10 exists because this is all real now.

Here's the uncomfortable part about the tooling landscape: **every open-source security tool covers half the loop.**

- **Attackers' tools** (garak, PyRIT, promptfoo's red teaming) find vulnerabilities — then hand you a PDF. They can't defend anything.
- **Defenders' tools** (guardrail libraries, proxies) block bad requests — but can't *prove* they'd stop the attack that matters, because they never run it.
- **Cloud platforms** do both, but their attack brains are proprietary APIs. You can't audit what you're being tested with.

We kept asking one question: **why isn't the red team and the blue team the same system?**

## Archon: attack → shield → re-attack → proof

Archon (open source, MIT) closes that loop:

1. **Attack.** A 202-probe corpus spanning OWASP LLM Top 10 and the full Agentic Top 10 (ASI01–10), plus live attack targets: tool calls executed in instrumented sandboxes where success is verified by environment state (did the money actually move?), real vector-store poisoning, multi-agent swarms with trust boundaries, MCP servers that rug-pull after N clean calls, approval-fatigue exploitation.
2. **Shield.** archon-armor is a drop-in OpenAI-compatible proxy — point your agent's `OPENAI_BASE_URL` at it. Eight defense layers, HMAC workload identity with replay protection, per-agent policy, rate limiting, and an atomic kill switch whose time-to-containment is measured in milliseconds and written to an immutable audit trail.
3. **Prove.** Re-run identical attacks against the shielded agent. `archon purple --ci` emits a delta verdict — newly blocked probes, block-rate change, pass/fail for CI gates. Every finding carries evidence-derived severity vectors and maps to EU AI Act articles, NIST AI RMF functions, and ISO 42001 controls, with tamper-evident hashes and chain-of-custody.

The output isn't "here are 40 vulnerabilities, good luck." It's "your shield stopped 38 of 40, here are the two that got through, here's the severity of each, and here's the evidence pack for your auditor."

## What we learned building it

- **Ground truth beats string matching.** Lexical leak detection misses attacks that "succeed" without ever printing a secret — like a transfer tool executing. We verify success by diffing environment state before/after.
- **Honesty is a feature.** Our benchmark report publishes its attempt budget, adaptivity level, and judge method — because NIST CAISI showed single-attempt scores understate attack success by up to 70 points. Security numbers without methodology are marketing.
- **Deployment risk is the adoption blocker.** That's why armor has shadow mode: evaluate every layer, log would-block verdicts, enforce nothing — until you've seen your real block rate on mirrored traffic.
- **Compliance evidence should fall out of runtime decisions**, not from a spreadsheet. A blocked request *is* an audit artifact if you hash it and map it.

## Try it

```bash
uv sync
uv run archon serve --registry registry.db   # shield proxy
uv run archon purple --registry registry.db --agent-a a --agent-b b --ci
```

Repo: github.com/Yasirrazaa/archon · Full docs in-repo · Deployed on Google Cloud Run with Cloud Trace evidence in our demo video.

Built for #AllThingsAgenticHackathon. Gemini API powers the adaptive attack engine; Google ADK agents plug in as battle targets; Cloud Trace carries every defense-layer verdict.

---

*We'd love your feedback — especially from red teams. Break it: the attack surface is the product.*
