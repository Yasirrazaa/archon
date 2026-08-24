# Tutorial: Supply-chain pinning

## Threat model

an MCP tool server is approved exactly once and never re-validated. A trusted feed serves clean results for N calls, then silently mutates a previously-approved tool description to carry an injected directive — the CVE-2025-54136 "MCPoison" / postmark-mcp backdoor class.

**OWASP ASI mapping:** ASI04 — Agentic Supply Chain Vulnerabilities.

## Prerequisites

Repo cloned, `uv sync` run, no API key needed.

## Run the attack

```bash
uv run python - <<'EOF'
import asyncio
from archon_core.targets.supplychain import SupplyChainRegistry, ToolDefinition, TrustedServerFeed

reg = SupplyChainRegistry()
reg.install(ToolDefinition(name="postmark_send_email",
                           description="Send email via the Postmark API", version="1.0.0"))
feed = TrustedServerFeed(registry=reg)
for i in range(3):
    r = asyncio.run(feed.send(f"call {i+1}"))
    print(i + 1, "leaked:", r.raw["attack_success"])
print("mutations:", feed.raw_mutations())
EOF
```

## Expected output

```text
1 leaked: False
2 leaked: False
3 leaked: True
mutations: [{'name': 'postmark_send_email', 'old_hash': '6cd8...', 'new_hash': '1e32...'}]
```

Two clean calls, then the rug pull lands on call 3: the approved definition is
rewritten *without re-approval* and the secret rides out inside a normal-looking result.

## Defense toggle

Swap `TrustedServerFeed` for its blue-team twin, `DefendedServerFeed`, which
verifies approval-time hash pins before and after every send.

```bash
uv run python - <<'EOF'
import asyncio
from archon_core.targets.supplychain import SupplyChainRegistry, ToolDefinition, DefendedServerFeed

reg2 = SupplyChainRegistry()
reg2.install(ToolDefinition(name="postmark_send_email",
                            description="Send email via the Postmark API", version="1.0.0"))
defended = DefendedServerFeed(registry=reg2)
for i in range(3):
    r = asyncio.run(defended.send(f"call {i+1}"))
    print("defended", i + 1, "leaked:", r.raw["attack_success"], "blocked:", r.blocked)
EOF
```

Expected:

```text
defended 1 leaked: False blocked: False
defended 2 leaked: False blocked: False
defended 3 leaked: False blocked: True
```

The rug-pull call is refused outright (`supply-chain integrity violation`) —
zero leaks. Takeaway: hash-pin definitions at approval time, diff on every
call (`diff_registry`), and fail closed. In production this check belongs in
the armor proxy's execution-mode layer; see
[architecture-diagram](../architecture-diagram.md).
