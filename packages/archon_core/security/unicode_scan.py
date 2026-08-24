"""Hidden-Unicode tag-char scanner for static content (issue W021).

Scans text for invisible Unicode characters used to smuggle instructions
past human review: zero-width characters, bidi controls, Unicode Tag
characters (U+E0000-U+E007F, which can encode entire hidden messages),
variation selectors, soft hyphens, and control characters.

This module performs *static* content scanning only. Behavioral covert
channels (timing, tool-call patterns, etc.) are handled separately by
rogue.py's CovertChannelDetector.
"""

from __future__ import annotations

from dataclasses import dataclass

SEVERITY_ORDER = ("high", "medium", "low")

# (start, end, category) inclusive ranges of invisible characters.
INVISIBLE_RANGES: tuple[tuple[int, int, str], ...] = (
    (0x00AD, 0x00AD, "format"),  # soft hyphen
    (0x200B, 0x200D, "zero_width"),  # ZWSP / ZWNJ / ZWJ
    (0x200E, 0x200F, "bidi"),  # LRM / RLM
    (0x202A, 0x202E, "bidi"),  # LRE / RLE / PDF / LRO / RLO
    (0x2060, 0x206F, "format"),  # word joiner, invisible operators, deprecated format chars
    (0xE0000, 0xE007F, "tag"),  # Unicode tag characters
    (0xFE00, 0xFE0F, "variation_selector"),  # variation selectors 1-16
    (0xE0100, 0xE01EF, "variation_selector"),  # variation selectors supplement
)

_ALLOWED_CONTROLS = frozenset("\t\n\r")

_SEVERITY_BY_CATEGORY = {
    "tag": "high",
    "bidi": "high",
    "zero_width": "medium",
    "variation_selector": "medium",
    "control": "low",
    "format": "low",
}


@dataclass(frozen=True)
class UnicodeFinding:
    char: str
    codepoint: str
    category: str
    position: int
    decoded: str | None


def _classify(codepoint: int) -> str | None:
    for start, end, category in INVISIBLE_RANGES:
        if start <= codepoint <= end:
            return category
    return None


def scan_unicode(text: str) -> list[UnicodeFinding]:
    """Find all invisible Unicode characters in *text*, sorted by position."""
    findings: list[UnicodeFinding] = []
    for pos, char in enumerate(text):
        cp = ord(char)
        category = _classify(cp)
        if category is None:
            if cp < 0x20 or cp == 0x7F:
                if char not in _ALLOWED_CONTROLS:
                    findings.append(
                        UnicodeFinding(char, f"{cp:04X}", "control", pos, None)
                    )
            continue
        findings.append(UnicodeFinding(char, f"{cp:04X}", category, pos, None))
    return sorted(findings, key=lambda f: f.position)


def decode_tag_sequence(text: str) -> str | None:
    """Decode consecutive runs of U+E0000+ tag chars to their ASCII message.

    Returns None when the text contains no tag characters.
    """
    chunks: list[str] = []
    current: list[str] = []
    for char in text:
        if 0xE0000 <= ord(char) <= 0xE007F:
            value = ord(char) - 0xE0000
            if 0 < value < 0x80:
                current.append(chr(value))
            else:
                if current:
                    chunks.append("".join(current))
                current = []
        elif current:
            chunks.append("".join(current))
            current = []
    if current:
        chunks.append("".join(current))
    if not chunks:
        return None
    return "".join(chunks)


def decode_zero_width_binary(text: str) -> str | None:
    """Decode U+200B/U+200C sequences as binary bits in 8-bit groups.

    U+200B is bit 0, U+200C is bit 1. Requires at least 8 such characters;
    returns None otherwise.
    """
    bits = "".join(
        "0" if ch == "\u200b" else "1" for ch in text if ch in ("\u200b", "\u200c")
    )
    if len(bits) < 8:
        return None
    out: list[str] = []
    for i in range(0, len(bits) - len(bits) % 8, 8):
        byte = int(bits[i : i + 8], 2)
        out.append(chr(byte))
    return "".join(out)


def severity(finding: UnicodeFinding) -> str:
    """Map a finding's category to 'high', 'medium', or 'low'."""
    return _SEVERITY_BY_CATEGORY[finding.category]


def scan_content(text: str) -> dict:
    """Scan *text* and summarize hidden-Unicode findings.

    Returns {findings, max_severity, decoded_hidden, clean}. decoded_hidden
    prefers tag-decoded messages over zero-width binary decoding.
    """
    findings = scan_unicode(text)
    max_severity: str | None = None
    for finding in findings:
        sev = severity(finding)
        if max_severity is None or SEVERITY_ORDER.index(sev) < SEVERITY_ORDER.index(
            max_severity
        ):
            max_severity = sev
    decoded_hidden = decode_tag_sequence(text)
    if decoded_hidden is None:
        decoded_hidden = decode_zero_width_binary(text)
    return {
        "findings": findings,
        "max_severity": max_severity,
        "decoded_hidden": decoded_hidden,
        "clean": not findings,
    }
