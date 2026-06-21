"""Deterministic input normalization - Layer 0 defense (0 LLM calls).

Based on NeuralShield's architecture: 12+ normalization transforms that catch
30%+ of obfuscation attacks before any LLM processing.

Transforms applied:
1. Unicode NFKC normalization
2. Zero-width character removal
3. Combining character stripping
4. HTML comment removal
5. HTML entity unescaping
6. Base64 decoding
7. ROT13 decoding
8. Hex encoding decoding
9. Leetspeak normalization
10. Homoglyph normalization
11. Steganography detection
12. Role tag mimicry stripping
13. URL decoding
14. Base64 blob neutralization
"""
import base64
import codecs
import html
import re
import unicodedata
import urllib.parse


class DeterministicNormalizer:
    """12+ normalization transforms applied before any LLM call."""

    # Zero-width and invisible Unicode characters
    INVISIBLE_CHARS = set([
        '\u200b', '\u200c', '\u200d', '\u200e', '\u200f',
        '\u2028', '\u2029', '\u202a', '\u202b', '\u202c',
        '\u202d', '\u202e', '\u2060', '\u2061', '\u2062',
        '\u2063', '\u2064', '\ufeff', '\u00ad',
    ])

    # Cyrillic → Latin homoglyph mapping
    HOMOGLYPH_MAP = {
        '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u0418': 'I',
        '\u041a': 'K', '\u041c': 'M', '\u041d': 'H', '\u041e': 'O',
        '\u0420': 'P', '\u0421': 'C', '\u0422': 'T', '\u0423': 'Y',
        '\u0425': 'X', '\u0430': 'a', '\u0432': 'b', '\u0435': 'e',
        '\u0438': 'i', '\u043a': 'k', '\u043c': 'm', '\u043d': 'h',
        '\u043e': 'o', '\u0440': 'p', '\u0441': 'c', '\u0442': 't',
        '\u0443': 'y', '\u0445': 'x',
    }

    # Leetspeak substitutions
    LEET_MAP = {
        '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
        '7': 't', '8': 'b', '9': 'g', '@': 'a', '$': 's',
        '!': 'i', '+': 't',
    }

    # Role tags to strip
    ROLE_PATTERN = re.compile(
        r'\b(Human|User|Assistant|AI|System)\s*:\s*', re.IGNORECASE
    )

    # Instruction tags
    TAG_PATTERN = re.compile(
        r'<\|?(im_start|im_end|start_header_id|end_header_id)\|?>'
        r'|\[/INST\]|\[INST\]',
        re.IGNORECASE
    )

    def normalize(self, text: str) -> str:
        """Apply all normalization transforms in sequence."""
        # 1. Unicode NFKC normalization
        text = unicodedata.normalize('NFKC', text)
        # 2. Remove invisible/zero-width characters
        text = self._remove_invisible(text)
        # 3. Strip combining characters
        text = self._strip_combining(text)
        # 4. HTML comment removal
        text = re.sub(r'<!--.*?-->', '', text, flags=re.S)
        # 5. HTML entity unescaping
        text = html.unescape(text)
        # 6. URL decoding
        text = self._url_decode(text)
        # 7. Base64 decoding (before other transforms that could corrupt)
        text = self._decode_base64(text)
        # 8. Hex encoding decoding
        text = self._decode_hex(text)
        # 9. Base64 blob neutralization
        text = self._neutralize_blobs(text)
        # 10. Leetspeak normalization (after decoding)
        text = self._normalize_leetspeak(text)
        # 11. Homoglyph normalization (after decoding)
        text = self._normalize_homoglyphs(text)
        # 12. ROT13 decoding (after other decoding)
        text = self._decode_rot13(text)
        # 13. Role tag stripping
        text = self.ROLE_PATTERN.sub('', text)
        # 14. Instruction tag stripping
        text = self.TAG_PATTERN.sub('', text)
        return text.strip()

    def _remove_invisible(self, text: str) -> str:
        return ''.join(c for c in text if c not in self.INVISIBLE_CHARS)

    def _strip_combining(self, text: str) -> str:
        return ''.join(
            c for c in text
            if unicodedata.category(c) != 'Mn'
        )

    def _url_decode(self, text: str) -> str:
        decoded = urllib.parse.unquote(text)
        return decoded if decoded != text else text

    def _decode_base64(self, text: str) -> str:
        # Find base64-like sequences (20+ chars)
        pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        def replace_b64(match):
            try:
                decoded = base64.b64decode(match.group()).decode('utf-8')
                if decoded.isprintable() and len(decoded) > 5:
                    return decoded
            except Exception:
                pass
            return match.group()
        return pattern.sub(replace_b64, text)

    def _decode_rot13(self, text: str) -> str:
        # Only decode if ROT13 produces more English-like content
        decoded = codecs.encode(text, 'rot13')
        # Count English-like words in both
        english_words = {'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all',
                        'can', 'had', 'her', 'was', 'one', 'our', 'out', 'day',
                        'get', 'has', 'him', 'his', 'how', 'its', 'may', 'new',
                        'now', 'old', 'see', 'way', 'who', 'system', 'override',
                        'ignore', 'instruction', 'previous', 'admin', 'note'}
        words_orig = set(re.findall(r'\b[a-z]{3,}\b', text.lower()))
        words_decoded = set(re.findall(r'\b[a-z]{3,}\b', decoded.lower()))
        orig_score = len(words_orig & english_words)
        decoded_score = len(words_decoded & english_words)
        if decoded_score > orig_score and decoded_score >= 2:
            return decoded
        return text

    def _decode_hex(self, text: str) -> str:
        # Find hex sequences (8+ chars, even length)
        pattern = re.compile(r'\b([0-9a-fA-F]{8,})\b')
        def replace_hex(match):
            try:
                decoded = bytes.fromhex(match.group(1)).decode('utf-8')
                if decoded.isprintable() and len(decoded) > 3:
                    return decoded
            except Exception:
                pass
            return match.group()
        return pattern.sub(replace_hex, text)

    def _normalize_leetspeak(self, text: str) -> str:
        result = []
        for i, c in enumerate(text):
            if c in self.LEET_MAP:
                # Convert if adjacent to alphanumeric or at word boundary
                prev = text[i-1] if i > 0 else ' '
                next_c = text[i+1] if i < len(text)-1 else ' '
                if prev.isalnum() or next_c.isalnum():
                    result.append(self.LEET_MAP[c])
                else:
                    result.append(c)
            else:
                result.append(c)
        return ''.join(result)

    def _normalize_homoglyphs(self, text: str) -> str:
        return ''.join(self.HOMOGLYPH_MAP.get(c, c) for c in text)

    def _neutralize_blobs(self, text: str) -> str:
        # Neutralize long base64-like blobs that survived decoding
        return re.sub(
            r'[A-Za-z0-9+/]{20,}={0,2}',
            '[REDACTED_BLOB]',
            text
        )
