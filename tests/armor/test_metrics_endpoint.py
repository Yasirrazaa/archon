"""Sprint IMP-63: ArmorMetrics Prometheus text-format collector tests."""

import re
import threading

import pytest
from archon_armor.metrics import ArmorMetrics
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture()
def metrics() -> ArmorMetrics:
    return ArmorMetrics()


class TestCounters:
    def test_requests_total_per_agent(self, metrics: ArmorMetrics) -> None:
        metrics.observe_request(agent_id="a1", blocked=False, latency_ms=1.0)
        metrics.observe_request(agent_id="a1", blocked=False, latency_ms=2.0)
        rendered = metrics.render()
        assert "archon_requests_total{agent_id=\"a1\"} 2" in rendered

    def test_separate_agents_counted_independently(self, metrics: ArmorMetrics) -> None:
        metrics.observe_request(agent_id="a1", blocked=False, latency_ms=1.0)
        metrics.observe_request(agent_id="a2", blocked=False, latency_ms=1.0)
        metrics.observe_request(agent_id="a2", blocked=False, latency_ms=1.0)
        rendered = metrics.render()
        assert "archon_requests_total{agent_id=\"a1\"} 1" in rendered
        assert "archon_requests_total{agent_id=\"a2\"} 2" in rendered

    def test_blocked_counter_is_separate(self, metrics: ArmorMetrics) -> None:
        metrics.observe_request(agent_id="a1", blocked=True, latency_ms=3.0)
        metrics.observe_request(agent_id="a1", blocked=False, latency_ms=3.0)
        metrics.observe_request(agent_id="a1", blocked=True, latency_ms=3.0)
        rendered = metrics.render()
        assert "archon_requests_blocked_total{agent_id=\"a1\"} 2" in rendered
        assert "archon_requests_total{agent_id=\"a1\"} 3" in rendered

    def test_blocked_never_exceeds_total(self, metrics: ArmorMetrics) -> None:
        for i in range(10):
            metrics.observe_request(
                agent_id="a1", blocked=i % 2 == 0, latency_ms=float(i)
            )
        rendered = metrics.render()
        total = int(re.search(r"archon_requests_total\{agent_id=\"a1\"\} (\d+)", rendered).group(1))
        blocked = int(
            re.search(r"archon_requests_blocked_total\{agent_id=\"a1\"\} (\d+)", rendered).group(1)
        )
        assert total == 10
        assert blocked == 5


class TestHistogram:
    BUCKETS = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]

    def test_latency_lands_in_correct_buckets(self, metrics: ArmorMetrics) -> None:
        metrics.observe_request(agent_id="a1", blocked=False, latency_ms=7.0)
        metrics.observe_request(agent_id="a1", blocked=False, latency_ms=60.0)
        metrics.observe_request(agent_id="a1", blocked=False, latency_ms=6000.0)
        rendered = metrics.render()
        # cumulative: le=25 catches 7.0 only; le=100 catches 7+60; +Inf catches all
        assert 'archon_request_latency_ms_bucket{agent_id="a1",le="5"} 0' in rendered
        assert 'archon_request_latency_ms_bucket{agent_id="a1",le="25"} 1' in rendered
        assert 'archon_request_latency_ms_bucket{agent_id="a1",le="100"} 2' in rendered
        assert 'archon_request_latency_ms_bucket{agent_id="a1",le="+Inf"} 3' in rendered

    def test_histogram_sum_and_count(self, metrics: ArmorMetrics) -> None:
        metrics.observe_request(agent_id="a1", blocked=False, latency_ms=10.5)
        metrics.observe_request(agent_id="a1", blocked=False, latency_ms=4.5)
        rendered = metrics.render()
        assert "archon_request_latency_ms_sum{agent_id=\"a1\"} 15" in rendered
        assert "archon_request_latency_ms_count{agent_id=\"a1\"} 2" in rendered

    def test_all_standard_buckets_present_in_order(self, metrics: ArmorMetrics) -> None:
        metrics.observe_request(agent_id="a1", blocked=False, latency_ms=1.0)
        lines = [
            line
            for line in metrics.render().splitlines()
            if "_bucket{" in line and "a1" in line
        ]
        expected_les = [f'"{b}"' for b in self.BUCKETS] + ['"+Inf"']
        actual_les = [re.search(r'le="([^"]+)"', line).group(1) for line in lines]
        assert actual_les == ["5", "10", "25", "50", "100", "250", "500",
                             "1000", "2500", "5000", "+Inf"]
        assert [f'"{le}"' for le in actual_les] == expected_les

    def test_inf_bucket_equals_count(self, metrics: ArmorMetrics) -> None:
        for i in range(7):
            metrics.observe_request(agent_id="a9", blocked=False, latency_ms=i * 100.0)
        rendered = metrics.render()
        inf = int(re.search(
            r'archon_request_latency_ms_bucket\{agent_id="a9",le="\+Inf"\} (\d+)', rendered
        ).group(1))
        count = int(re.search(
            r"archon_request_latency_ms_count\{agent_id=\"a9\"\} (\d+)", rendered
        ).group(1))
        assert inf == count == 7


class TestRenderFormat:
    def test_empty_collector_renders_without_error(self, metrics: ArmorMetrics) -> None:
        rendered = metrics.render()
        assert isinstance(rendered, str)

    def test_rendered_line_shape_matches_prometheus_text_format(
        self, metrics: ArmorMetrics
    ) -> None:
        metrics.observe_request(agent_id="a1", blocked=False, latency_ms=12.0)
        pattern = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*(\{[^}]*\})? [0-9.eE+-]+$')
        for line in metrics.render().splitlines():
            if line.startswith("#"):  # HELP/TYPE comments are part of the format
                continue
            assert pattern.match(line), f"bad line: {line!r}"

    def test_agent_ids_sorted_deterministically(self, metrics: ArmorMetrics) -> None:
        for agent in ("c3", "a1", "b2"):
            metrics.observe_request(agent_id=agent, blocked=False, latency_ms=1.0)
        agents = re.findall(r'archon_requests_total\{agent_id="([^"]+)"\}', metrics.render())
        assert agents == sorted(agents) == ["a1", "b2", "c3"]

    def test_render_is_repeatable_and_does_not_reset_state(self, metrics: ArmorMetrics) -> None:
        metrics.observe_request(agent_id="a1", blocked=False, latency_ms=1.0)
        first = metrics.render()
        second = metrics.render()
        assert first == second
        metrics.observe_request(agent_id="a1", blocked=False, latency_ms=1.0)
        third = metrics.render()
        assert third != first
        assert "archon_requests_total{agent_id=\"a1\"} 2" in third


class TestAccumulationAndThreadSafety:
    def test_accumulation_over_many_observations(self, metrics: ArmorMetrics) -> None:
        n = 500
        for i in range(n):
            metrics.observe_request(
                agent_id=f"a{i % 3}", blocked=i % 5 == 0, latency_ms=float(i % 700)
            )
        rendered = metrics.render()
        totals = {
            aid: int(cnt)
            for aid, cnt in re.findall(
                r'archon_requests_total\{agent_id="([^"]+)"\} (\d+)', rendered
            )
        }
        assert sum(totals.values()) == n
        assert set(totals) == {"a0", "a1", "a2"}

    def test_concurrent_observation_keeps_totals_consistent(self, metrics: ArmorMetrics) -> None:
        threads = []
        per_thread = 100
        for t in range(8):
            def worker(idx: int = t) -> None:
                for _ in range(per_thread):
                    metrics.observe_request(
                        agent_id=f"w{idx}", blocked=False, latency_ms=1.0
                    )
            threads.append(threading.Thread(target=worker))
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        rendered = metrics.render()
        total = sum(
            int(cnt)
            for _, cnt in re.findall(
                r'archon_requests_total\{agent_id="(w\d+)"\} (\d+)', rendered
            )
        )
        assert total == 8 * per_thread


class TestFastAPISmoke:
    def test_metrics_endpoint_via_test_client(self, metrics: ArmorMetrics) -> None:
        app = FastAPI()

        @app.get("/metrics")
        def serve_metrics() -> object:
            from fastapi.responses import PlainTextResponse

            return PlainTextResponse(metrics.render(), media_type="text/plain")

        client = TestClient(app)
        metrics.observe_request(agent_id="smoke-agent", blocked=True, latency_ms=42.0)
        response = client.get("/metrics")
        assert response.status_code == 200
        body = response.text
        assert "archon_requests_total{agent_id=\"smoke-agent\"} 1" in body
        assert "archon_requests_blocked_total{agent_id=\"smoke-agent\"} 1" in body
        assert 'archon_request_latency_ms_bucket{agent_id="smoke-agent",le="50"} 1' in body


if __name__ == "__main__":
    pytest.main([__file__])
