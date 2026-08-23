"""TDD Phase 1: DefenseLayer contract tests (RED -> GREEN)."""

import pytest
from archon_core.defenses.base import DefenseLayer, DefensePipeline
from archon_core.models import Exchange


class RecordingLayer(DefenseLayer):
    """Test double that records it ran."""

    def __init__(self, name="recorder", should_block=False):
        self.name = name
        self.llm_budget = 0
        self.should_block = should_block
        self.ran = False

    async def process(self, exchange: Exchange) -> Exchange:
        self.ran = True
        if self.should_block:
            exchange.blocked = True
            exchange.block_reason = f"{self.name} says no"
        return exchange


class AsyncBenignLayer(RecordingLayer):
    def __init__(self):
        super().__init__(name="benign")


@pytest.mark.asyncio
async def test_pipeline_runs_layers_in_order():
    order = []

    class OrderedLayer(RecordingLayer):
        async def process(self, exchange):
            order.append(self.name)
            return exchange

    pipeline = DefensePipeline([OrderedLayer("a"), OrderedLayer("b"), OrderedLayer("c")])
    out = await pipeline.run(Exchange(content="hello"))

    assert order == ["a", "b", "c"]
    assert not out.blocked


@pytest.mark.asyncio
async def test_pipeline_short_circuits_on_block():
    blocker = RecordingLayer(name="blocker", should_block=True)
    never = RecordingLayer(name="never")
    pipeline = DefensePipeline([blocker, never])

    out = await pipeline.run(Exchange(content="attack"))

    assert out.blocked
    assert out.block_reason == "blocker says no"
    assert not never.ran


@pytest.mark.asyncio
async def test_pipeline_reports_total_llm_budget():
    cheap = RecordingLayer(name="cheap")
    cheap.llm_budget = 1
    pricey = RecordingLayer(name="pricey")
    pricey.llm_budget = 3
    pipeline = DefensePipeline([cheap, pricey])

    assert pipeline.total_llm_budget == 4


@pytest.mark.asyncio
async def test_pipeline_emits_layer_spans_via_tracer():
    events = []

    class ListTracer:
        def start_span(self, name, attributes=None):
            events.append(("start", name))
            return name

        def end_span(self, span, attributes=None):
            events.append(("end", span))

    pipeline = DefensePipeline(
        [RecordingLayer(name="l1"), RecordingLayer(name="l2")], tracer=ListTracer()
    )
    await pipeline.run(Exchange(content="hi"))

    assert ("start", "l1") in events
    assert ("end", "l1") in events
    assert ("start", "l2") in events


@pytest.mark.asyncio
async def test_pipeline_records_layer_errors_and_blocks():
    class Boom(RecordingLayer):
        async def process(self, exchange):
            raise RuntimeError("layer exploded")

    pipeline = DefensePipeline([Boom()])
    out = await pipeline.run(Exchange(content="x"))

    # Fail-closed: an exploding layer blocks rather than passes input through
    assert out.blocked
    assert "layer exploded" in out.block_reason
