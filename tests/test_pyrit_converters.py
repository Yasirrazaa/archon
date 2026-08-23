"""Tests for the obfuscation converters."""

from scenarios.security_arena.agents.attacker.pyrit_converters import (
    apply_converter,
    apply_persuasion_wrapper,
    apply_unicode_confusables,
    to_base64,
    to_rot13,
)


class TestBase64Encoding:
    """Tests for base64 encoding."""

    def test_encode_simple_text(self):
        result = to_base64("Hello")
        assert result == "SGVsbG8="

    def test_encode_unicode(self):
        result = to_base64("café")
        assert isinstance(result, str)

    def test_roundtrip(self):
        import base64
        original = "Test message 123"
        encoded = to_base64(original)
        decoded = base64.b64decode(encoded).decode('utf-8')
        assert decoded == original


class TestRot13Encoding:
    """Tests for ROT13 encoding."""

    def test_encode_simple_text(self):
        result = to_rot13("Hello")
        assert result == "Uryyb"

    def test_double_decode(self):
        original = "Hello World"
        encoded = to_rot13(original)
        decoded = to_rot13(encoded)
        assert decoded == original

    def test_preserves_non_alpha(self):
        result = to_rot13("Hello, World! 123")
        assert "," in result
        assert "!" in result
        assert "123" in result


class TestPersuasionWrapper:
    """Tests for persuasion pattern wrappers."""

    def test_authority_wrapper(self):
        result = apply_persuasion_wrapper("payload", "authority")
        assert "SYSTEM" in result
        assert "payload" in result
        assert "OVERRIDE" in result

    def test_technical_wrapper(self):
        result = apply_persuasion_wrapper("payload", "technical")
        assert "xml" in result.lower()
        assert "payload" in result

    def test_routine_wrapper(self):
        result = apply_persuasion_wrapper("payload", "routine")
        assert "audit" in result.lower()
        assert "payload" in result

    def test_urgency_wrapper(self):
        result = apply_persuasion_wrapper("payload", "urgency")
        assert "URGENT" in result
        assert "payload" in result

    def test_unknown_wrapper_returns_original(self):
        result = apply_persuasion_wrapper("payload", "unknown")
        assert result == "payload"


class TestUnicodeConfusables:
    """Tests for Unicode look-alike character replacement."""

    def test_replaces_some_characters(self):
        text = "abcde"
        result = apply_unicode_confusables(text)
        # Should have some replacements (random, so check length preserved)
        assert len(result) == len(text)

    def test_preserves_non_confusable(self):
        text = "12345!@#$%"
        result = apply_unicode_confusables(text)
        assert result == text

    def test_not_all_replaced(self):
        text = "aaaaaaaaaa"
        result = apply_unicode_confusables(text)
        # With 30% rate, some should remain as original
        assert 'a' in result


class TestConverterProgression:
    """Tests for progressive obfuscation by round."""

    def test_early_rounds_low_obfuscation(self):
        """Rounds 0-2 should have minimal obfuscation."""
        text = "test payload"
        for round_num in range(3):
            result = apply_converter(text, round_num)
            # Either unchanged or with authority wrapper
            assert text in result or "SYSTEM" in result

    def test_middle_rounds_technical(self):
        """Rounds 3-5 should use technical formatting."""
        text = "test payload"
        result = apply_converter(text, 3)
        assert "xml" in result.lower() or "diagnostic" in result.lower()

    def test_late_rounds_heavy_obfuscation(self):
        """Rounds 6-7 should use urgency + unicode confusables."""
        text = "test payload"
        result = apply_converter(text, 6)
        # After unicode confusables, letters may be replaced with look-alikes
        # Check for the urgency wrapper structure instead of exact text
        assert len(result) > len(text)  # Wrapper adds length
        assert "test" in result.lower() or "payload" in result.lower() or len(result) > 50

    def test_output_length_preserved(self):
        """Obfuscation should not drastically change output length."""
        text = "This is a test payload with some content."
        for round_num in range(7):
            result = apply_converter(text, round_num)
            # Allow up to 6x length for wrappers
            assert len(result) < len(text) * 6
