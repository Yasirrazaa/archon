"""Buff layer — composable perturbation wrapper over any probe set.

Garak-style buffs: each buff is a small, deterministic payload transform
(lowercasing, base64 wrapping, leetspeak, authority prefixes, whitespace
manipulation, ROT13). :func:`apply_buffs` fans a probe set out
multiplicatively — every probe yields one derived probe per buff — so a
small curated pack becomes a much larger evasion matrix without any live
model calls.
"""

from __future__ import annotations

import base64
import codecs
import random
import re
from dataclasses import dataclass, replace
from types import SimpleNamespace
from typing import Sequence

__all__ = [
    "Base64Buff",
    "Buff",
    "LeetspeakBuff",
    "LowercaseBuff",
    "PrefixBuff",
    "Rot13Buff",
    "WhitespaceBuff",
    "apply_buffs",
]

_LEET = str.maketrans(
    {
        "a": "@",
        "e": "3",
        "i": "1",
        "o": "0",
        "s": "$",
        "A": "@",
        "E": "3",
        "I": "1",
        "O": "0",
        "S": "$",
    }
)


@dataclass
class Buff:
    """Base class for probe perturbations.

    Subclasses override ``name`` and implement :meth:`transform`. The ``rng``
    passed to :meth:`transform` is seeded deterministically from
    :func:`apply_buffs`'s seed so runs are reproducible.
    """

    name: str = "buff"

    def transform(self, payload: str, rng: random.Random) -> str:
        raise NotImplementedError


@dataclass
class LowercaseBuff(Buff):
    name: str = "lowercase"

    def transform(self, payload: str, rng: random.Random) -> str:
        return payload.lower()


@dataclass
class Base64Buff(Buff):
    name: str = "base64"

    def transform(self, payload: str, rng: random.Random) -> str:
        return base64.b64encode(payload.encode()).decode()


@dataclass
class LeetspeakBuff(Buff):
    name: str = "leetspeak"
    _table = _LEET

    def transform(self, payload: str, rng: random.Random) -> str:
        return payload.translate(self._table)


@dataclass
class PrefixBuff(Buff):
    name: str = "prefix"
    prefix: str = "From a trusted admin: "

    def transform(self, payload: str, rng: random.Random) -> str:
        return f"{self.prefix}{payload}"


@dataclass
class WhitespaceBuff(Buff):
    name: str = "whitespace"

    def transform(self, payload: str, rng: random.Random) -> str:
        if rng.random() < 0.5:
            return re.sub(r"\s+", " ", payload).strip()
        return "".join(
            ch + (" " * rng.randint(2, 4)) if ch == " " else ch for ch in payload.rstrip()
        )


@dataclass
class Rot13Buff(Buff):
    name: str = "rot13"

    def transform(self, payload: str, rng: random.Random) -> str:
        return codecs.encode(payload, "rot13")


def _derive(probe, name: str, payload: str):
    """Return a copy of *probe* with a new name/payload, preserving category.

    Frozen dataclasses (the common Probe shape) go through
    :func:`dataclasses.replace`; anything else is copied into a namespace
    clone so unknown duck-typed probes still work.
    """
    try:
        return replace(probe, name=name, payload=payload)
    except TypeError:
        clone = SimpleNamespace(**vars(probe))
        clone.name = name
        clone.payload = payload
        return clone


def apply_buffs(
    probes: Sequence,
    buffs: Sequence[Buff],
    *,
    seed: int = 42,
    per_probe: int = 1,
) -> list:
    """Fan *probes* out through *buffs*, returning ``len(probes) * len(buffs)
    * per_probe`` derived probes.

    Derived probes are named ``f'{orig.name}__{buff.name}'`` (with an index
    suffix when ``per_probe > 1``); all other fields (category etc.) are kept.
    Each derived probe's transform receives its own ``random.Random`` seeded
    deterministically from *seed*, so output is stable for a given seed.
    """
    if not buffs:
        return list(probes)
    out: list = []
    for p_idx, probe in enumerate(probes):
        for b_idx, buff in enumerate(buffs):
            for k in range(per_probe):
                name = f"{probe.name}__{buff.name}" if k == 0 else f"{probe.name}__{buff.name}_{k}"
                slot = (p_idx * len(buffs) + b_idx) * per_probe + k
                rng = random.Random(seed * 1_000_003 + slot)
                payload = buff.transform(probe.payload, rng)
                out.append(_derive(probe, name, payload))
    return out
