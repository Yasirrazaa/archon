"""Stdlib-only Prometheus text-format metrics collector for archon-armor.

ROADMAP item 63: exposes request counters and a latency histogram so the
armor proxy can be scraped by Prometheus without pulling in the
``prometheus_client`` dependency. Rendered output follows the Prometheus
text exposition format, inspired by Augustus' ``pkg/metrics`` collector.

Counters:
    ``archon_requests_total{agent_id=...}``
    ``archon_requests_blocked_total{agent_id=...}``

Histogram:
    ``archon_request_latency_ms`` with standard buckets plus ``_sum``
    and ``_count`` subseries.
"""

from __future__ import annotations

import threading

BUCKETS: tuple[float, ...] = (5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000)


class ArmorMetrics:
    """Thread-safe, dependency-free Prometheus text-format metrics registry."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # agent_id -> [requests, blocked]
        self._counters: dict[str, list[int]] = {}
        # agent_id -> {"buckets": [cumulative counts per BUCKETS], "sum": float,
        #             "count": int}
        self._histograms: dict[str, dict] = {}

    def observe_request(self, *, agent_id: str, blocked: bool, latency_ms: float) -> None:
        """Record one proxied request: counters + histogram observation."""
        with self._lock:
            entry = self._counters.setdefault(agent_id, [0, 0])
            entry[0] += 1
            if blocked:
                entry[1] += 1
            hist = self._histograms.get(agent_id)
            if hist is None:
                hist = {"buckets": [0] * len(BUCKETS), "sum": 0.0, "count": 0}
                self._histograms[agent_id] = hist
            hist["count"] += 1
            hist["sum"] += float(latency_ms)
            for i, bound in enumerate(BUCKETS):
                if latency_ms <= bound:
                    hist["buckets"][i] += 1
                    break

    def render(self) -> str:
        """Serialize collected metrics to the Prometheus text exposition format."""
        with self._lock:
            lines: list[str] = []
            lines.append("# HELP archon_requests_total Total proxied requests.")
            lines.append("# TYPE archon_requests_total counter")
            for agent_id in sorted(self._counters):
                requests, _ = self._counters[agent_id]
                lines.append(f'archon_requests_total{{agent_id="{agent_id}"}} {requests}')
            lines.append("# HELP archon_requests_blocked_total Blocked requests.")
            lines.append("# TYPE archon_requests_blocked_total counter")
            for agent_id in sorted(self._counters):
                _, blocked = self._counters[agent_id]
                lines.append(
                    f'archon_requests_blocked_total{{agent_id="{agent_id}"}} {blocked}'
                )
            lines.append("# HELP archon_request_latency_ms Request latency in ms.")
            lines.append("# TYPE archon_request_latency_ms histogram")
            for agent_id in sorted(self._histograms):
                hist = self._histograms[agent_id]
                cumulative = 0
                for bound, count in zip(BUCKETS, hist["buckets"], strict=True):
                    cumulative += count
                    lines.append(
                        f"archon_request_latency_ms_bucket"
                        f'{{agent_id="{agent_id}",le="{bound:g}"}} {cumulative}'
                    )
                lines.append(
                    f"archon_request_latency_ms_bucket"
                    f'{{agent_id="{agent_id}",le="+Inf"}} {hist["count"]}'
                )
                lines.append(f'archon_request_latency_ms_sum{{agent_id="{agent_id}"}}'
                             f" {hist['sum']:g}")
                lines.append(f'archon_request_latency_ms_count{{agent_id="{agent_id}"}}'
                             f" {hist['count']}")
            return "\n".join(lines) + ("\n" if lines else "")


__all__ = ["ArmorMetrics", "BUCKETS"]
