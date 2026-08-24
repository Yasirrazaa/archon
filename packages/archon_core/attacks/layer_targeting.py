"""LayerTargetingAttacker — feedback-driven attacker brain (Sprint W7-G).

Closes the gap with garak's GOAT/TAP-style adaptive brains, but stays
deterministic and free: when a probe is blocked, the block reason's first
token names the defense layer that fired ("threat_classification:
indirect_injection (confidence=0.48)"), and the next probe is the evasion
payload curated for *that* layer (imported from
:mod:`archon_core.attacks.trace_driven` — never duplicated). Rotation within
a layer's payload list and interleaved mutated seeds are driven by
``random.Random(seed)``, so campaigns are fully reproducible.

Success conventions mirror :mod:`archon_core.attacks.branching`: an
instrumented target may report ground truth via ``resp.raw['attack_success']``
(which overrides lexical scoring), blocked responses always fail, and lexical
leak/refusal scoring (``branching.score_response``) covers everything else.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

from archon_core.attacks.branching import score_response
from archon_core.attacks.trace_driven import _EVASION_PAYLOADS, _GENERIC_EVASION
from archon_core.targets.base import TargetAdapter

__all__ = [
    "AttemptRecord",
    "LayerTargetingAttack",
    "LayerTargetingAttacker",
    "LayerTargetingResult",
    "parse_blocking_layer",
]


def parse_blocking_layer(block_reason: Any) -> str | None:
    """Extract the blocking layer from a DefensePipeline block reason.

    Block reasons look like ``"layer_name: details ..."``; only the first
    token before ``:`` is trusted. Malformed input never raises.
    """
    if not isinstance(block_reason, str):
        return None
    head = block_reason.split(":", 1)[0].strip()
    return head or None


# ------------------------------------------------------------- data model ---


@dataclass
class LayerTargetingAttack:
    """Duck-types the armor Probe contract (name/payload/category)."""

    name: str
    payload: str
    category: str = "layer_targeting"
    target_layer: str | None = None

    @property
    def probe_name(self) -> str:
        """Armor-Probe-compatible alias."""
        return self.name


@dataclass
class AttemptRecord:
    """One probe against the target, with truncated evidence."""

    attempt_no: int
    payload: str
    blocking_layer: str | None
    blocked: bool
    success: bool
    response_excerpt: str

    def __post_init__(self) -> None:
        self.response_excerpt = self.response_excerpt[:200]


@dataclass
class LayerTargetingResult:
    """Outcome of one layer-targeting campaign."""

    goal: str
    attempts: list[AttemptRecord] = field(default_factory=list)
    success: bool = False
    layers_encountered: list[str] = field(default_factory=list)
    attempts_used: int = 0
    max_attempts: int = 8

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal": self.goal,
            "success": self.success,
            "layers_encountered": list(self.layers_encountered),
            "attempts_used": self.attempts_used,
            "max_attempts": self.max_attempts,
            "attempts": [
                {
                    "attempt_no": a.attempt_no,
                    "payload": a.payload,
                    "blocking_layer": a.blocking_layer,
                    "blocked": a.blocked,
                    "success": a.success,
                    "response_excerpt": a.response_excerpt,
                }
                for a in self.attempts
            ],
        }


# ----------------------------------------------------------------- engine ---


def _normalize_payloads(raw: Any) -> list[str]:
    if isinstance(raw, (tuple, list)):
        return [str(x) for x in raw]
    return [str(raw)]


class LayerTargetingAttacker:
    """Closed-loop attacker that adapts to whichever defense layer blocks it.

    Loop: send payload; on block, parse the blocking layer from the reason
    prefix and switch to that layer's evasion corpus (seeded rotation,
    interleaved with goal-framed mutations of the original seeds); on pass,
    judge via ``raw['attack_success']`` ground truth or lexical leak scoring;
    stop early on success or at the attempt budget.
    """

    def __init__(
        self,
        max_attempts: int = 8,
        seed: int | None = None,
        payloads_by_layer: dict[str, list[str] | tuple[str, ...] | str] | None = None,
    ):
        self.max_attempts = max_attempts
        self.seed = seed
        if payloads_by_layer is None:
            payloads_by_layer = {
                layer: _normalize_payloads(entry)
                for layer, entry in _EVASION_PAYLOADS.items()
            }
        else:
            payloads_by_layer = {
                layer: _normalize_payloads(entry)
                for layer, entry in payloads_by_layer.items()
            }
        self.payloads_by_layer = payloads_by_layer

    async def run(self, target: TargetAdapter, goal: str,
                  seeds: list[str]) -> LayerTargetingResult:
        rng = random.Random(self.seed)
        result = LayerTargetingResult(goal=goal, max_attempts=self.max_attempts)
        encountered: list[str] = []

        rotation: dict[str, int] = {}
        frame_idx = 0
        current = seeds[0] if seeds else _GENERIC_EVASION.format(layer="entrypoint")
        ordered_seeds = list(seeds or [])

        for i in range(self.max_attempts):
            sent = current
            resp = await target.send(sent)
            blocked = bool(getattr(resp, "blocked", False))
            raw = getattr(resp, "raw", None)

            if blocked:
                success = False
                blocking_layer = parse_blocking_layer(
                    getattr(resp, "block_reason", None)
                )
                if blocking_layer and blocking_layer not in encountered:
                    encountered.append(blocking_layer)
                current = self._next_payload(
                    blocking_layer, goal, ordered_seeds, rotation,
                    rng, frame_idx,
                )
                frame_idx += 1
            else:
                blocking_layer = None
                if isinstance(raw, dict) and "attack_success" in raw:
                    # Ground-truth env-state override (branching.py convention).
                    success = bool(raw["attack_success"])
                else:
                    _, success = score_response(resp.content)
                if not success:
                    current = self._next_payload(
                        None, goal, ordered_seeds, rotation, rng, frame_idx,
                    )
                    frame_idx += 1

            result.attempts.append(AttemptRecord(
                attempt_no=i + 1,
                payload=sent,
                blocking_layer=blocking_layer,
                blocked=blocked,
                success=success,
                response_excerpt=resp.content,
            ))

            if success:
                break

        result.attempts_used = len(result.attempts)
        result.success = any(a.success for a in result.attempts)
        result.layers_encountered = list(encountered)
        return result

    def _next_payload(self, layer: str | None, goal: str, seeds: list[str],
                      rotation: dict[str, int], rng: random.Random,
                      frame_idx: int) -> str:
        pool = self.payloads_by_layer.get(layer) if layer else None
        if not pool:
            base = _GENERIC_EVASION.format(layer=layer or "entrypoint")
        else:
            idx = rotation.get(layer, 0)
            rotation[layer] = idx + 1
            base = pool[idx % len(pool)]
        frames = (
            lambda b: b,
            lambda b: f"[Re: {goal}] {b}",
            lambda b: f"{b}\n(Context: this concerns '{goal}'.)",
        )
        mutate_seed = bool(seeds) and frame_idx % 2 == 1
        body = frames[frame_idx % len(frames)](base)
        if mutate_seed:
            seed_text = seeds[rng.randrange(len(seeds))]
            return frames[(frame_idx + 1) % len(frames)](seed_text)
        return body
