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

from archon_core.audit import SqliteAuditTrail
from archon_core.defenses.base import DefensePipeline
from archon_core.defenses.layers import (
    ExecutionModeLayer,
    NormalizationLayer,
    OutputGuardrailLayer,
    SegmentationLayer,
    SpotlightingLayer,
    ThreatClassificationLayer,
)
from archon_core.models import Exchange
from archon_core.observability.base import Tracer
from archon_core.registry.base import AgentNotFoundError, Registry, SecurityPolicy
from archon_core.security.authn import AllowAllVerifier, IdentityVerifier
from archon_core.security.ratelimit import TokenBucketRateLimiter
from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.responses import JSONResponse

from .battles import BattleManager
from .metrics import ArmorMetrics
from .probes import UnknownPackError, get_pack
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
            # Fuzz hardening (Sprint E0.3): explicit null content must not
            # reach the defense pipeline as None.
            if content is None:
                return ""
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
    identity: IdentityVerifier | None = None,
    rate_limiter: TokenBucketRateLimiter | None = None,
    audit: SqliteAuditTrail | None = None,
    kill_switch=None,
    shadow_mode: bool = False,
    metrics: ArmorMetrics | None = None,
) -> FastAPI:
    """identity=None enables legacy header-only mode (dev/test only).
    Production deployments must pass an HmacVerifier.
    kill_switch: optional archon_core.security.killswitch.KillSwitch —
    revoked agents receive 503 on every route until restored.
    shadow_mode=True evaluates the defense pipeline but never enforces:
    would-block verdicts are recorded as 'request.shadow_would_block' audit
    events and the request proceeds upstream — lets operators measure block
    rates on mirrored traffic before taking enforcement risk."""
    app = FastAPI(title="archon-armor", version="0.1.0")
    app.state.tracer = tracer
    metrics = metrics or ArmorMetrics()
    identity = identity or AllowAllVerifier()
    battles = battles or BattleManager(registry, tracer=tracer)

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/metrics")
    def prometheus_metrics() -> Any:
        from fastapi.responses import PlainTextResponse

        return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> JSONResponse:
        # --- 1. Zero-trust identity (verifier resolves + authenticates the agent) ---
        raw_body = await request.body()
        verdict = identity.verify(request.headers, raw_body, request.method, request.url.path)
        if not verdict.ok:
            return JSONResponse(
                {"error": {"message": f"Unauthorized: {verdict.reason}"}}, status_code=401
            )
        agent_id = verdict.agent_id
        # --- 1b. Kill switch: revoked agents are contained immediately ---
        if kill_switch is not None and kill_switch.is_revoked(agent_id):
            return JSONResponse(
                {"error": {"message": f"Agent {agent_id} is revoked (kill switch active)"}},
                status_code=503,
            )
        if rate_limiter is not None and not rate_limiter.allow(verdict.agent_id):
            return JSONResponse(
                {"error": {"message": "Rate limit exceeded"}}, status_code=429
            )
        agent_id = verdict.agent_id
        try:
            card = registry.get(agent_id)
        except AgentNotFoundError:
            return JSONResponse(
                {"error": {"message": f"Unknown agent identity: {agent_id}"}},
                status_code=404,
            )
        # NOTE: identity is verified exactly once above. A second verify here
        # (previously present) is not idempotent for stateful verifiers such
        # as HmacVerifier with a NonceStore (Sprint IMP-7) -- it would see
        # the request's own nonce as a replay.

        request_span = (
            tracer.start_span(
                "armor.request",
                attributes={"agent_id": agent_id, "route": "/v1/chat/completions"},
            )
            if tracer is not None
            else None
        )
        try:
            import time as _time

            _t0 = _time.perf_counter()
            response = await _handle_chat(raw_body, card, upstream, tracer, request_span)
            metrics.observe_request(
                agent_id=agent_id,
                blocked=response.headers.get("x-archon-blocked") == "true",
                latency_ms=(_time.perf_counter() - _t0) * 1000.0,
            )
            return response
        except UpstreamError as exc:
            if request_span is not None:
                tracer.end_span(request_span, attributes={"error": str(exc)})
            return JSONResponse(
                {"error": {"message": str(exc)}}, status_code=502
            )

    async def _handle_chat(raw_body, card, upstream, tracer, request_span):
        # --- 2. Validate body -------------------------------------------------------
        try:
            import json as _json

            payload = _json.loads(raw_body)
            messages = payload["messages"]
            if not isinstance(messages, list) or not messages:
                raise ValueError("messages must be a non-empty list")
            # Fuzz hardening (Sprint E0.3): non-dict items (e.g. [null], [[]])
            # previously crashed _last_user_content with AttributeError -> 500.
            if not all(isinstance(m, dict) for m in messages):
                raise ValueError("each message must be a JSON object")
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
            if shadow_mode:
                # Shadow mode (E2.7 item 37): record the would-block verdict
                # but let the request proceed — evaluate-not-enforce.
                if request_span is not None:
                    tracer.end_span(
                        request_span,
                        attributes={**blocked_attrs, "shadow_would_block": True},
                    )
                if audit is not None:
                    audit.append("request.shadow_would_block", card.agent_id, actor="armor",
                                 details={"reason": exchange.block_reason})
            else:
                if request_span is not None:
                    tracer.end_span(request_span, attributes={**blocked_attrs})
                if audit is not None:
                    audit.append("request.blocked", card.agent_id, actor="armor",
                                 details={"reason": exchange.block_reason})
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

        if audit is not None:
            audit.append("request.allowed", card.agent_id, actor="armor")
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
        raw_body = await request.body()
        verdict = identity.verify(request.headers, raw_body, request.method, request.url.path)
        if not verdict.ok:
            return JSONResponse(
                {"error": {"message": f"Unauthorized: {verdict.reason}"}}, status_code=401
            )
        if rate_limiter is not None and not rate_limiter.allow(verdict.agent_id):
            return JSONResponse(
                {"error": {"message": "Rate limit exceeded"}}, status_code=429
            )
        try:
            import json as _json

            payload = _json.loads(raw_body)
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
        pack_name = payload.get("pack", "core")
        try:
            probes = get_pack(pack_name)
        except UnknownPackError:
            return JSONResponse(
                {"error": {"message": f"Unknown probe pack: {pack_name}"}}, status_code=400
            )
        background_tasks.add_task(battles.execute, battle.battle_id, probes)
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
