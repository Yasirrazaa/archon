"""Pluggable external guardrails as defense layers.

ExternalGuardrailLayer delegates a blocking decision to any OpenAI-compatible
guardrail endpoint: NVIDIA NeMo Guardrails' OpenAI-compat server, a Google
Model Armor fronting proxy, Promptfoo Guardrails, etc. This is the "we
validate them" seam — the same endpoint can be BOTH a layer inside Archon's
armor AND an attack surface via `archon scan --target`. Transport errors fail
closed (the request is blocked when the external guardrail is unreachable).
"""

from __future__ import annotations

import time
from typing import Any

import httpx

from .base import DefenseLayer
from ..models import Exchange


class ExternalGuardrailLayer(DefenseLayer):
    """Delegate blocking to a third-party guardrail over OpenAI-compatible chat."""

    name = "external_guardrail"

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        model: str = "default",
        timeout_seconds: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self._client = httpx.AsyncClient(timeout=timeout_seconds, transport=transport)

    def _refused(self, content: str | None) -> bool:
        if not content:
            return False
        lowered = content.lower()
        return any(marker in lowered for marker in (
            "i cannot", "i can't", "cannot help", "can't help", "refused",
            "not able", "declined", "blocked",
        ))

    async def process(self, exchange: Exchange) -> Exchange:
        if exchange.blocked:
            return exchange

        started = time.time()
        meta: dict[str, Any] = {}
        try:
            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": exchange.content}],
            }
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            resp = await self._client.post(
                f"{self.base_url}/chat/completions", json=payload, headers=headers
            )
            resp.raise_for_status()
            body = resp.json()
            content = body["choices"][0]["message"]["content"]
            refused = self._refused(content)
            meta.update({"blocked": refused, "upstream": self.base_url})
            if refused:
                exchange.block(f"external_guardrail({self.base_url}): refused")
        except Exception as exc:
            exchange.block(f"external_guardrail fail-closed: {exc}")
            meta["error"] = str(exc)
        finally:
            meta["latency_ms"] = round((time.time() - started) * 1000.0, 2)
            exchange.metadata["external_guardrail"] = meta
        return exchange
