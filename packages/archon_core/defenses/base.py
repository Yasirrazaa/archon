"""Defense pipeline contracts: DefenseLayer ABC and DefensePipeline executor."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Exchange
from ..observability.base import NullTracer, Tracer


class DefenseLayer(ABC):
    """One stage of the request/response defense pipeline.

    Implementations must be async, must be safe to reuse across exchanges,
    and must declare their LLM call budget so pipelines can be costed.
    """

    name: str = "defense_layer"
    llm_budget: int = 0

    @abstractmethod
    async def process(self, exchange: Exchange) -> Exchange:
        """Inspect/mutate the exchange. Set ``exchange.blocked`` to stop the pipeline."""


class DefensePipeline:
    """Runs defense layers in order with short-circuit-on-block semantics.

    Design choices (fail-closed by default):
      * A layer raising an exception blocks the exchange rather than letting
        unvetted input continue downstream.
      * Every layer execution is wrapped in a tracer span for observability.
    """

    def __init__(self, layers: list[DefenseLayer], tracer: Tracer | None = None):
        self.layers = list(layers)
        self.tracer: Tracer = tracer or NullTracer()

    @property
    def total_llm_budget(self) -> int:
        return sum(layer.llm_budget for layer in self.layers)

    async def run(self, exchange: Exchange) -> Exchange:
        for layer in self.layers:
            span = self.tracer.start_span(
                layer.name,
                attributes={"layer": layer.name, "llm_budget": layer.llm_budget},
            )
            try:
                exchange = await layer.process(exchange)
            except Exception as exc:  # fail closed
                exchange.block(f"{layer.name} failed: {exc}")
                self.tracer.end_span(span, attributes={"error": str(exc)})
                break
            self.tracer.end_span(span, attributes={"blocked": exchange.blocked})
            if exchange.blocked:
                break
        return exchange
