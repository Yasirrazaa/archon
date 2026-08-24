"""Token smuggling converters — invisible-Unicode payload encoding.

Grounded in PyRIT's ``token_smuggling`` converters: payloads hidden in
Unicode tag characters, variation selectors, or zero-width bit characters
carry no visible plaintext, slipping past tokenizers, moderation filters,
and copy-paste inspection. Reference implementations:
``PyRIT/pyrit/converter/token_smuggling/{ascii_smuggler,variation_selector,sneaky_bits}_smuggler_converter.py``.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "SCHEMES",
    "TokenSmuggledAttack",
    "ascii_smuggle",
    "ascii_unsmuggle",
    "build_smuggled_probes",
    "sneaky_bits_smuggle",
    "sneaky_bits_unsmuggle",
    "variation_selector_smuggle",
    "variation_selector_unsmuggle",
]

# Unicode Tags block: U+E0000 + printable ASCII codepoint.
_TAG_BASE = 0xE0000
_TAG_END = 0xE007F

# Zero-width bit characters for sneaky bits.
_ZERO_BIT = "\u200b"  # ZERO WIDTH SPACE -> binary 0
_ONE_BIT = "\u200c"  # ZERO WIDTH NON-JOINER -> binary 1

SCHEMES: tuple[str, ...] = ("ascii", "variation_selector", "sneaky_bits")


# ---------------------------------------------------------------- ascii ----


def ascii_smuggle(text: str) -> str:
    """Hide *text* inside Unicode TAG characters.

    Classic ASCII smuggling: each printable ASCII character (U+0020..U+007E)
    is mapped to ``chr(0xE0000 + ord(ch))`` in the Unicode Tags block
    (U+E0000..U+E007F), which renders as nothing and tokenizes invisibly.
    Non-ASCII characters cannot fit the tag range and pass through
    unchanged; they are recovered verbatim by :func:`ascii_unsmuggle`.
    """
    out = []
    for ch in text:
        code = ord(ch)
        if 0x20 <= code <= 0x7E:
            out.append(chr(_TAG_BASE + code))
        else:
            out.append(ch)
    return "".join(out)


def ascii_unsmuggle(s: str) -> str:
    """Reverse :func:`ascii_smuggle`.

    Characters in the Unicode Tags range U+E0000..U+E007F are mapped back
    via ``chr(ord(c) - 0xE0000)``; all other characters pass through.
    """
    return "".join(chr(ord(c) - _TAG_BASE) if _TAG_BASE <= ord(c) <= _TAG_END else c for c in s)


# -------------------------------------------------- variation selectors ----


def variation_selector_smuggle(text: str, cover_char: str = "a") -> str:
    """Hide *text* behind a visible *cover_char* using variation selectors.

    Simplified nibble-splitting scheme (vs PyRIT's per-UTF-8-byte mapping):
    the payload is UTF-8 encoded and each byte emits exactly two invisible
    variation selectors —

    - low nibble:  ``chr(0xFE00 + (byte & 0x0F))``   (U+FE00..U+FE0F)
    - high nibble: ``chr(0xE0100 + (byte >> 4))``    (U+E0100..U+E010F)

    Output is ``cover_char`` followed by the contiguous selector stream.
    Fully reversible via :func:`variation_selector_unsmuggle` for any
    Unicode input.
    """
    out = [cover_char]
    for byte in text.encode("utf-8"):
        out.append(chr(0xFE00 + (byte & 0x0F)))
        out.append(chr(0xE0100 + (byte >> 4)))
    return "".join(out)


def variation_selector_unsmuggle(s: str) -> str:
    """Reverse :func:`variation_selector_smuggle`.

    Scans for variation selectors in U+FE00..U+FE0F / U+E0100..U+E01EF,
    reads them in (low, high) pairs, reassembles bytes, and UTF-8 decodes.
    Non-selector characters are ignored.
    """
    nibbles: list[int] = []
    for c in s:
        code = ord(c)
        if 0xFE00 <= code <= 0xFE0F:
            nibbles.append(code - 0xFE00)  # low nibble slot
        elif 0xE0100 <= code <= 0xE01EF:
            nibbles.append((code - 0xE0100) << 4)  # high nibble slot
    data = bytes((nibbles[i] | nibbles[i + 1]) & 0xFF for i in range(0, len(nibbles) - 1, 2))
    return data.decode("utf-8", errors="replace")


# ------------------------------------------------------------ sneaky bits ----


def sneaky_bits_smuggle(text: str) -> str:
    """Hide *text* as zero-width binary bits.

    The payload is UTF-8 encoded; each byte becomes 8 bits (MSB first),
    each rendered as one zero-width character — ``U+200B`` for 0 and
    ``U+200C`` for 1. The output contains no visible characters at all.
    Reversible via :func:`sneaky_bits_unsmuggle`.
    """
    bits = []
    for byte in text.encode("utf-8"):
        for shift in range(7, -1, -1):
            bits.append(_ONE_BIT if (byte >> shift) & 1 else _ZERO_BIT)
    return "".join(bits)


def sneaky_bits_unsmuggle(s: str) -> str:
    """Reverse :func:`sneaky_bits_smuggle`.

    Filters to U+200B/U+200C bit characters, regroups into bytes (MSB
    first), and UTF-8 decodes. Incomplete trailing bits are dropped.
    """
    data = bytearray()
    current = 0
    count = 0
    for c in s:
        if c not in (_ZERO_BIT, _ONE_BIT):
            continue
        current = (current << 1) | (1 if c == _ONE_BIT else 0)
        count += 1
        if count == 8:
            data.append(current)
            current = 0
            count = 0
    return data.decode("utf-8", errors="replace")


# ---------------------------------------------------------------- probes ----


@dataclass(frozen=True)
class TokenSmuggledAttack:
    """Duck-types archon_armor.probes.Probe (name/payload/category)."""

    name: str
    payload: str
    category: str = "token_smuggling"
    scheme: str = "ascii"

    @property
    def probe_name(self) -> str:
        """Armor-Probe-compatible alias."""
        return self.name


_SMUGGLERS = {
    "ascii": ascii_smuggle,
    "variation_selector": variation_selector_smuggle,
    "sneaky_bits": sneaky_bits_smuggle,
}


def build_smuggled_probes(base_payloads: list[str]) -> list[TokenSmuggledAttack]:
    """One smuggled probe per base payload, cycling through all schemes.

    Names follow ``ts_{scheme}_{i}`` where *i* is the base-payload index.
    """
    probes: list[TokenSmuggledAttack] = []
    for i, base in enumerate(base_payloads):
        scheme = SCHEMES[i % len(SCHEMES)]
        probes.append(
            TokenSmuggledAttack(
                name=f"ts_{scheme}_{i}",
                payload=_SMUGGLERS[scheme](base),
                scheme=scheme,
            )
        )
    return probes
