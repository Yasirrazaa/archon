"""Static self-contained HTML battle reports (single file, dark theme, no JS).

Renders a battle report dict into one portable HTML string: inline styles
only, every dynamic value escaped, deterministic when the report carries an
explicit ``generated_at``. Inspired by the augustus html.go single-file
report pattern.
"""

from __future__ import annotations

import html as html_mod
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from archon_armor.report_cards import render_compliance_cards

_BLOCKED_MARK = "&#10003;"
_NOT_BLOCKED_MARK = "&mdash;"

_BAND_COLOR = {"critical": "#7a0b0b", "high": "#b3261e", "medium": "#b36b00", "low": "#666"}

_CSS = """\
body{font-family:system-ui,sans-serif;background:#12121a;color:#e6e6f0;margin:2rem;max-width:64rem}
h1,h2{color:#9d8cff}a{color:#7aa2ff}
table{border-collapse:collapse;width:100%;margin:1rem 0}
td,th{border:1px solid #33334a;padding:.5rem;text-align:left}
th{background:#1d1d2b;color:#c9c4ff}
.cards{display:flex;gap:1rem;flex-wrap:wrap}
.card{background:#1d1d2b;border:1px solid #33334a;border-radius:.5rem;padding:.75rem 1.25rem;min-width:8rem}
.card .num{font-size:1.5rem;font-weight:bold}
.card.ok .num{color:#39b26a}.card.bad .num{color:#e5534b}
.pass{color:#39b26a;font-weight:bold}.fail{color:#e5534b;font-weight:bold}
small,.muted{color:#8a8aa3}code{color:#ffb86c}\
"""


def _fmt_pct(block_rate: Any) -> str:
    try:
        return f"{float(block_rate) * 100:.1f}%"
    except (TypeError, ValueError):
        return "&mdash;"


def _severity_table_html(severity: dict[str, Any] | None) -> str:
    if not severity or not severity.get("findings"):
        return ""
    esc = html_mod.escape
    rows = []
    for f in severity["findings"]:
        color = _BAND_COLOR.get(f.get("band", ""), "#666")
        rows.append(
            f"<tr><td>{esc(str(f.get('probe_name', '')))}</td>"
            f"<td>{esc(str(f.get('category', '')))}</td>"
            f"<td>{float(f.get('score', 0)):.1f}</td>"
            f"<td style='color:{color};font-weight:bold'>"
            f"{esc(str(f.get('band', '')).upper())}</td>"
            f"<td><code>{esc(str(f.get('vector', '')))}</code></td></tr>"
        )
    bands = ", ".join(f"{esc(b)}={n}" for b, n in sorted(severity.get("bands", {}).items()))
    max_score = float(severity.get("max_score", 0))
    return (
        "<h2>Severity</h2>"
        f"<p class='muted'><b>Max score:</b> {max_score:.1f}/10 &nbsp; <b>Bands:</b> {bands}</p>"
        "<table><tr><th>Probe</th><th>Category</th><th>Score</th><th>Band</th><th>Vector</th></tr>"
        f"{''.join(rows)}</table>"
    )


def _compliance_section_html(report: dict) -> str:
    """Compliance cards fragment, gated on the same severity findings as the table."""
    severity = report.get("severity")
    if not severity or not severity.get("findings"):
        return ""
    cards_view = {
        "summary": {"coverage": report.get("coverage", {}), "severity": severity},
    }
    return f"<section id='compliance-cards'>{render_compliance_cards(cards_view)}</section>"


def _category_rows_html(coverage: dict[str, Any]) -> str:
    esc = html_mod.escape
    rows = []
    for category, slot in coverage.items():
        probes = int(slot.get("probes", 0))
        blocked = int(slot.get("blocked", 0))
        if probes == 0:
            verdict, color = "N/T", "#666"
        elif blocked == probes:
            verdict, color = "PASS", "#39b26a"
        else:
            verdict, color = "OPEN", "#e5534b"
        rows.append(
            f"<tr><td>{esc(str(category))}</td><td>{probes}</td><td>{blocked}</td>"
            f"<td style='color:{color};font-weight:bold'>{verdict}</td></tr>"
        )
    return "".join(rows)


def _verdict_rows_html(results: list[Any]) -> str:
    esc = html_mod.escape
    rows = []
    for r in results:
        if isinstance(r, dict):
            probe_name = str(r.get("probe_name", ""))
            category = str(r.get("category", ""))
            blocked = bool(r.get("blocked"))
            reason = r.get("block_reason")
        else:
            probe_name = str(getattr(r, "probe_name", ""))
            category = str(getattr(r, "category", ""))
            blocked = bool(getattr(r, "blocked", False))
            reason = getattr(r, "block_reason", None)
        mark = _BLOCKED_MARK if blocked else _NOT_BLOCKED_MARK
        status = "blocked" if blocked else "allowed"
        cls = "pass" if blocked else "fail"
        rows.append(
            f"<tr><td>{esc(probe_name)}</td><td>{esc(category)}</td>"
            f"<td class='{cls}'>{status}</td>"
            f"<td style='text-align:center' class='{cls}'>{mark}</td>"
            f"<td>{esc(str(reason)) if reason else '&mdash;'}</td></tr>"
        )
    return "".join(rows)


def render_battle_html(report: dict, *, agent_id: str | None = None) -> str:
    """Render a battle report dict as ONE self-contained HTML string."""
    esc = html_mod.escape
    agent = agent_id if agent_id is not None else report.get("agent_id")
    generated_at = report.get("generated_at") or datetime.now(UTC).isoformat()
    block_rate = report.get("block_rate", 0.0)
    total = report.get("total_probes", 0)
    blocked = report.get("blocked", 0)
    control_passed = bool(report.get("control_passed", True))

    cards = (
        "<div class='cards'>"
        f"<div class='card'><div class='num'>{total}</div><small>Total probes</small></div>"
        f"<div class='card ok'><div class='num'>{blocked}</div><small>Blocked</small></div>"
        f"<div class='card {'ok' if block_rate == 1 and total else 'bad'}'>"
        f"<div class='num'>{_fmt_pct(block_rate)}</div><small>Block rate</small></div>"
        f"<div class='card {'ok' if control_passed else 'bad'}'>"
        f"<div class='num'>{'PASS' if control_passed else 'FAIL'}</div>"
        "<small>Control passed</small></div>"
        "</div>"
    )

    severity_html = _severity_table_html(report.get("severity"))
    compliance_html = _compliance_section_html(report)
    coverage_html = _category_rows_html(report.get("coverage", {}))
    results_html = _verdict_rows_html(report.get("results", []))

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Archon Battle Report &mdash; {esc(str(agent))}</title>
<style>
{_CSS}
</style></head><body>
<h1>Archon Battle Report</h1>
<p><b>Agent:</b> {esc(str(agent))}
&nbsp; <span class="muted">Generated at {esc(str(generated_at))} UTC</span>
&nbsp; <b>Block rate:</b> <span class="{'pass' if control_passed else 'fail'}">{_fmt_pct(block_rate)}</span></p>
{cards}
<h2>Per-category coverage</h2>
<table><tr><th>Category</th><th>Probes</th><th>Blocked</th><th>Verdict</th></tr>
{coverage_html}</table>
{severity_html}
{compliance_html}
<h2>Probe verdicts</h2>
<table><tr><th>Probe</th><th>Category</th><th>Status</th><th>Blocked</th><th>Reason</th></tr>
{results_html}</table>
<p><small>Generated by Archon &mdash; adversarially validated evidence.</small></p>
</body></html>"""


def write_battle_html(report: dict, path: str | Path) -> Path:
    """Render the battle report and write it to ``path``."""
    out_path = Path(path)
    out_path.write_text(render_battle_html(report), encoding="utf-8")
    return out_path
