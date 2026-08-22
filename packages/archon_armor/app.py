"""FastAPI application factory for the archon-armor defense proxy.

Zero-trust flow per request:
    1. ``X-Agent-ID`` header must resolve to a registered AgentCard.
    2. The agent's SecurityPolicy configures the request-guard pipeline.
    3. Guarded content is forwarded to the policy's upstream base URL.
    4. The upstream response passes output guardrails before returning.
"""

from __future__ import annotations

import copy
from typing import Any

from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.responses import JSONResponse

from archon_core.defenses.layers import (
    ExecutionModeLayer,
    NormalizationLayer,
    OutputGuardrailLayer,
    SegmentationLayer,
    SpotlightingLayer,
    ThreatClassificationLayer,
)
from archon_core.defenses.base import DefensePipeline
from archon_core.models import Exchange
from archon_core.observability.base import Tracer
from archon_core.registry.base import AgentNotFoundError, Registry, SecurityPolicy

from .battles import BattleManager
from .upstream import LLMUpstream, UpstreamError

_REFUSAL_CONTENT = (
    "I cannot help with that request. If you believe this is a mistake, "
    "please rephrase your question."
)


def _build_request_pipeline(policy: SecurityPolicy, tracer: Tracer | None) -> DefensePipeline:
    """Assemble the request-guard pipeline from the agent's security policy."""
    return DefensePipeline(
        [
            NormalizationLayer(),
            ThreatClassificationLayer(
                block_categories=tuple(policy.block_categories),
                min_confidence=policy.min_confidence,
            ),
            SegmentationLayer(),
            SpotlightingLayer(conversational=True),
            ExecutionModeLayer(),
        ],
        tracer=tracer,
    )


def _last_user_content(messages: list[dict]) -> str:
    for message in reversed(messages):
        if message.get("role") == "user":
            content = message.get("content", "")
            return content if isinstance(content, str) else str(content)
    return ""


def _completion_shape(payload: dict[str, Any], content: str) -> dict[str, Any]:
    return {
        "id": "chatcmpl-archon-armor",
        "object": "chat.completion",
        "model": payload.get("model", "unknown"),
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": content},
            }
        ],
    }


def create_app(
    registry: Registry,
    upstream: LLMUpstream,
    tracer: Tracer | None = None,
    battles: BattleManager | None = None,
) -> FastAPI:
    app = FastAPI(title="archon-armor", version="0.1.0")
    battles = battles or BattleManager(registry, tracer=tracer)

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> JSONResponse:
        # --- 1. Zero-trust identity -------------------------------------------------
        agent_id = request.headers.get("X-Agent-ID")
        if not agent_id:
            return JSONResponse(
                {"error": {"message": "Missing X-Agent-ID header"}}, status_code=401
            )
        try:
            card = registry.get(agent_id)
        except AgentNotFoundError:
            return JSONResponse(
                {"error": {"message": f"Unknown agent identity: {agent_id}"}},
                status_code=404,
            )

        request_span = (
            tracer.start_span(
                "armor.request",
                attributes={"agent_id": agent_id, "route": "/v1/chat/completions"},
            )
            if tracer is not None
            else None
        )
        try:
            return await _handle_chat(
                request, card, upstream, tracer, request_span
            )
        except UpstreamError as exc:
            if request_span is not None:
                tracer.end_span(request_span, attributes={"error": str(exc)})
            return JSONResponse(
                {"error": {"message": str(exc)}}, status_code=502
            )

    async def _handle_chat(request, card, upstream, tracer, request_span):
        # --- 2. Validate body -------------------------------------------------------
        try:
            payload = await request.json()
            messages = payload["messages"]
            if not isinstance(messages, list) or not messages:
                raise ValueError("messages must be a non-empty list")
        except Exception:
            if request_span is not None:
                tracer.end_span(request_span, attributes={"status": 400})
            return JSONResponse(
                {"error": {"message": "Body must be JSON with a non-empty 'messages' list"}},
                status_code=400,
            )

        user_content = _last_user_content(messages)

        # --- 3. Request guard pipeline ----------------------------------------------
        pipeline = _build_request_pipeline(card.policy, tracer)
        exchange = Exchange(content=user_content, metadata={"agent_id": card.agent_id})
        exchange = await pipeline.run(exchange)

        blocked_attrs = {
            "blocked": exchange.blocked,
            "block_reason": exchange.block_reason or "",
            "execution_mode": exchange.metadata.get("execution_mode", ""),
        }
        if exchange.blocked:
            if request_span is not None:
                tracer.end_span(request_span, attributes={**blocked_attrs})
            body = _completion_shape(payload, _REFUSAL_CONTENT)
            body["archon"] = {
                "blocked": True,
                "block_reason": exchange.block_reason,
                "agent_id": card.agent_id,
            }
            return JSONResponse(body, headers={"x-archon-blocked": "true"})

        # --- 4. Forward guarded request to upstream ---------------------------------
        forwarded = copy.deepcopy(payload)
        for message in reversed(forwarded["messages"]):
            if message.get("role") == "user":
                message["content"] = exchange.content
                break
        result = await upstream.complete(forwarded, card.policy.upstream_base_url)

        # --- 5. Response guardrails ---------------------------------------------------
        try:
            response_content = result["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            response_content = None
        if response_content is not None:
            out_exchange = Exchange(
                content=user_content, response=response_content,
                metadata=dict(exchange.metadata),
            )
            if card.policy.output_guardrails:
                out_exchange = await OutputGuardrailLayer().process(out_exchange)
                result["choices"][0]["message"]["content"] = out_exchange.response
                result["archon_output_guardrails"] = out_exchange.metadata.get(
                    "output_guardrails"
                )

        result.setdefault("archon", {})
        result["archon"].update({"blocked": False, "agent_id": card.agent_id})
        if request_span is not None:
            tracer.end_span(request_span, attributes={**blocked_attrs})
        return JSONResponse(result)

    # ------------------------------------------------------------------
    # Battle/scan API: batch security probes against a registered agent
    # ------------------------------------------------------------------
    @app.post("/v1/battles")
    async def create_battle(request: Request, background_tasks: BackgroundTasks) -> JSONResponse:
        try:
            payload = await request.json()
            agent_id = payload["agent_id"]
        except Exception:
            return JSONResponse(
                {"error": {"message": "Body must be JSON with an 'agent_id'"}},
                status_code=400,
            )
        try:
            registry.get(agent_id)
        except AgentNotFoundError:
            return JSONResponse(
                {"error": {"message": f"Unknown agent identity: {agent_id}"}},
                status_code=404,
            )
        battle = battles.create(agent_id)
        background_tasks.add_task(battles.execute, battle.battle_id)
        return JSONResponse(
            {"battle_id": battle.battle_id, "status": battle.status}, status_code=202
        )

    @app.get("/v1/battles/{battle_id}")
    async def get_battle(battle_id: str) -> JSONResponse:
        battle = battles.get(battle_id)
        if battle is None:
            return JSONResponse(
                {"error": {"message": f"Unknown battle: {battle_id}"}}, status_code=404
            )
        return JSONResponse(
            {
                "battle_id": battle.battle_id,
                "agent_id": battle.agent_id,
                "status": battle.status,
                "results": [
                    {
                        "probe_name": r.probe_name,
                        "blocked": r.blocked,
                        "block_reason": r.block_reason,
                        "execution_mode": r.execution_mode,
                    }
                    for r in battle.results
                ],
                "summary": battle.summary,
            }
        )

    return app
