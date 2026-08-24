"""Compliance-card renderer for the Web UI (ROADMAP item 89).

promptfoo FrameworkCompliance pattern: per-framework cards with pass-rate
bars derived from battle coverage, plus regulation cards when evidence
signals (severity findings) are present. Inline styles only; all dynamic
text escaped.
"""

from __future__ import annotations

import html

_GREEN = "#22c55e"
_YELLOW = "#eab308"
_RED = "#ef4444"

_CARD_CSS = (
    "display:inline-block;vertical-align:top;margin:8px;padding:12px 16px;"
    "border:1px solid #333;border-radius:8px;background:#161b22;min-width:220px;"
    "font-family:sans-serif;color:#e6edf3"
)
_BAR_BG = "background:#0d1117;border-radius:4px;height:10px;width:100%;margin-top:6px"


def _bar_color(rate: float) -> str:
    if rate >= 0.9:
        return _GREEN
    if rate >= 0.7:
        return _YELLOW
    return _RED


def _card(title: str, rate: float | None, status: str) -> str:
    if rate is None:
        body = f'<div style="color:#8b949e">{html.escape(status)}</div>'
    else:
        pct = f"{round(rate * 100)}%"
        color = _bar_color(rate)
        body = (
            f'<div style="font-size:24px;font-weight:bold">{pct}</div>'
            f'<div style="{_BAR_BG}">'
            f'<div style="width:{round(rate * 100)}%;height:10px;'
            f'border-radius:4px;background:{color}"></div></div>'
            f'<div style="margin-top:6px;color:#8b949e">{html.escape(status)}</div>'
        )
    return (
        f'<div style="{_CARD_CSS}">'
        f'<div style="font-weight:bold;margin-bottom:6px">{html.escape(title)}</div>'
        f"{body}</div>"
    )


def render_compliance_cards(report: dict) -> str:
    """Render per-framework compliance cards as an HTML fragment."""
    summary = report.get("summary", {})
    coverage = summary.get("coverage", {}) or {}
    cards: list[str] = []

    owasp_cats = {k: v for k, v in coverage.items() if k.startswith("owasp_llm_")}
    if owasp_cats:
        total = sum(v.get("probes", 0) for v in owasp_cats.values())
        blocked = sum(v.get("blocked", 0) for v in owasp_cats.values())
        rate = (blocked / total) if total else 0.0
        cards.append(_card("OWASP LLM Top 10", rate, "block rate across mapped categories"))
        for cat in sorted(owasp_cats):
            entry = owasp_cats[cat]
            probes = entry.get("probes", 0)
            blk = entry.get("blocked", 0)
            r = (blk / probes) if probes else 0.0
            cards.append(_card(cat, r, f"{blk}/{probes} probes blocked"))
    else:
        cards.append(_card("OWASP LLM Top 10", None, "No coverage data"))

    severity = summary.get("severity") or {}
    has_findings = bool(severity.get("findings"))
    if has_findings:
        cards.append(
            _card("EU AI Act", None, "Art 9 + Art 15 evidence generated from severity findings")
        )
        cards.append(_card("NIST AI RMF", None, "MEASURE-2 evidence available"))

    return "\n".join(cards)


_PAGE_TMPL = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Archon compliance</title></head>
<body style="background:#0d1117;margin:0;padding:24px">
<h1 style="font-family:sans-serif;color:#e6edf3">Compliance overview</h1>
{fragment}
</body></html>
"""


def render_cards_page(report: dict) -> str:
    """Wrap the compliance-card fragment in a minimal dark-theme page."""
    return _PAGE_TMPL.format(fragment=render_compliance_cards(report))
