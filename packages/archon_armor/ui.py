"""Read-only web dashboard for archon-armor: fleet view over the registry.

Serves a dependency-free single page (vanilla JS, no CDN) plus JSON APIs:

    GET /ui               dashboard HTML
    GET /ui/api/summary   registered agents + policy posture
    GET /ui/api/battles   recent battle summaries (when a manager is wired)

Run standalone:
    uvicorn archon_armor.ui:create_standalone_app --factory --port 8081
or via the CLI:
    archon ui --registry ./registry.db --port 8081
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from archon_core.registry.base import Registry

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Archon Armor — Fleet Dashboard</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: system-ui, sans-serif; background:#0d1117; color:#e6edf3; margin:2rem; }
  h1 { font-weight:600; } h1 span { color:#58a6ff; }
  table { border-collapse:collapse; width:100%; margin-top:1rem; }
  th, td { text-align:left; padding:.5rem .75rem; border-bottom:1px solid #21262d; }
  th { color:#8b949e; font-weight:500; text-transform:uppercase; font-size:.75rem; }
  .pill { display:inline-block; padding:.1rem .5rem; border-radius:999px;
          background:#1f6feb33; color:#58a6ff; font-size:.75rem; margin:.1rem; }
  .muted { color:#8b949e; }
  #meta { margin-top:.5rem; color:#8b949e; font-size:.85rem; }
</style>
</head>
<body>
<h1>Archon <span>Armor</span> — Fleet Dashboard</h1>
<div id="meta">Loading…</div>
<table id="agents">
  <thead><tr><th>Agent</th><th>Version</th><th>Upstream</th><th>Block categories</th><th>Min confidence</th><th>Output guardrails</th><th>LLM budget</th></tr></thead>
  <tbody></tbody>
</table>
<script>
async function refresh() {
  const s = await (await fetch('/ui/api/summary')).json();
  document.getElementById('meta').textContent =
    `${s.total_agents} agent(s) under armor`;
  const tbody = document.querySelector('#agents tbody');
  tbody.innerHTML = '';
  for (const a of s.agents) {
    const tr = document.createElement('tr');
    const cats = a.policy.block_categories.map(c => `<span class="pill">${c}</span>`).join('');
    tr.innerHTML = `<td><strong>${a.name}</strong> <span class="muted">${a.agent_id}</span></td>
      <td>${a.version}</td><td class="muted">${a.policy.upstream_base_url || '—'}</td>
      <td>${cats}</td><td>${a.policy.min_confidence}</td>
      <td>${a.policy.output_guardrails ? 'on' : 'off'}</td>
      <td>${a.policy.max_llm_budget}</td>`;
    tbody.appendChild(tr);
  }
}
refresh();
setInterval(refresh, 10000);
</script>
</body>
</html>"""


def _agent_payload(card: Any) -> dict[str, Any]:
    p = card.policy
    return {
        "agent_id": card.agent_id,
        "name": card.name,
        "version": card.version,
        "policy": {
            "block_categories": list(p.block_categories),
            "min_confidence": p.min_confidence,
            "output_guardrails": p.output_guardrails,
            "max_llm_budget": p.max_llm_budget,
            "upstream_base_url": p.upstream_base_url,
        },
    }


def create_ui_app(registry: Registry, battles: Any | None = None) -> FastAPI:
    app = FastAPI(title="archon-armor-ui", docs_url=None, redoc_url=None)

    @app.get("/ui", response_class=HTMLResponse)
    def dashboard() -> str:
        return _DASHBOARD_HTML

    @app.get("/ui/api/summary")
    def summary() -> JSONResponse:
        agents = [_agent_payload(c) for c in registry.list_agents()]
        return JSONResponse({"total_agents": len(agents), "agents": agents})

    @app.get("/ui/api/battles")
    def battle_list() -> JSONResponse:
        if battles is None:
            return JSONResponse([])
        return JSONResponse(
            [
                {
                    "battle_id": b.battle_id,
                    "agent_id": b.agent_id,
                    "status": b.status,
                    "summary": b.summary,
                }
                for b in battles.recent()
            ]
        )

    return app


def create_standalone_app() -> FastAPI:
    """Env-driven factory for `uvicorn archon_armor.ui:create_standalone_app`."""
    from archon_core.registry.sqlite import SqliteRegistry

    path = os.environ.get("ARCHON_REGISTRY_PATH", "/tmp/archon-registry.db")
    return create_ui_app(SqliteRegistry(path))
