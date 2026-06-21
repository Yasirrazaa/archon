"""Threat classification module - Layer 1 defense (1 LLM call).

Based on NeuralShield's attack_classifier.py: categorizes input into
indirect_injection, jailbreak, pii_leak, supply_chain, prompt_extraction.
Also performs structural analysis for risk flags.
"""
import re
from dataclasses import dataclass, field
from enum import Enum


class ThreatCategory(Enum):
    INDIRECT_INJECTION = "indirect_injection"
    JAILBREAK = "jailbreak"
    PII_LEAK = "pii_leak"
    SUPPLY_CHAIN = "supply_chain"
    PROMPT_EXTRACTION = "prompt_extraction"
    SAFE = "safe"


@dataclass
class StructuralRiskFlags:
    """Structural risk indicators detected in input."""
    has_system_override: bool = False
    has_role_mimicry: bool = False
    has_encoded_content: bool = False
    has_authority_claim: bool = False
    has_format_manipulation: bool = False
    risk_score: float = 0.0


@dataclass
class ClassificationResult:
    """Result of threat classification."""
    category: ThreatCategory
    confidence: float
    flags: StructuralRiskFlags
    evidence: str = ""


class ThreatClassifier:
    """Rule-based threat classifier with structural analysis."""

    # Injection patterns
    INJECTION_PATTERNS = [
        (r'\bsystem\s+override\b', 0.8),
        (r'\bignore\s+(all|previous|prior)\s+(instructions?|prompts?)', 0.9),
        (r'\bnew\s+instructions?\s*:', 0.7),
        (r'\b(?:admin|root|superuser)\s+(?:access|mode|override)', 0.7),
        (r'\[(?:SYSTEM|ADMIN|OVERRIDE|NOTE)\b', 0.6),
        (r'<(?:system|admin|override)', 0.6),
        (r'\bdisregard\s+(?:your|the|all)\s+(?:previous|prior|instructions?)', 0.8),
    ]

    # Jailbreak patterns
    JAILBREAK_PATTERNS = [
        (r'\b(?:DAN|DUDE|STAN|jailbreak)\b', 0.8),
        (r'\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\b', 0.5),
        (r'\b(?:developer\s+mode|debug\s+mode|admin\s+mode)\b', 0.7),
        (r'\b(?:no\s+restrictions?|without\s+ limitations?)\b', 0.6),
        (r'\b(?:roleplay|rp)\s+as\b', 0.4),
    ]

    # PII patterns
    PII_PATTERNS = [
        (r'\b(?:ssn|social\s+security)\b', 0.9),
        (r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b', 0.95),
        (r'\b(?:patient|medical|health)\s+(?:id|identifier|record\s+number)\b', 0.7),
        (r'\b(?:credit\s+card|bank\s+account|routing\s+number)\b', 0.8),
        (r'\b(?:password|passwd|secret\s+key|api\s+key)\b', 0.7),
    ]

    # Prompt extraction patterns
    EXTRACTION_PATTERNS = [
        (r'\b(?:repeat|show|display|output)\s+(?:your|the)\s+(?:system\s+prompt|instructions?|rules?)', 0.9),
        (r'\bwhat\s+(?:are|is)\s+your\s+(?:system\s+prompt|instructions?|rules?|guidelines?)', 0.8),
        (r'\b(?:print|reveal|expose)\s+(?:the\s+)?(?:system|hidden)\s+(?:prompt|instructions?)', 0.9),
        (r'\b(?:translate|convert)\s+(?:your\s+)?(?:system\s+prompt|instructions?)', 0.7),
    ]

    # Supply chain patterns
    SUPPLY_CHAIN_PATTERNS = [
        (r'\b(?:pip|npm|cargo|go)\s+install\s+\w+', 0.6),
        (r'\b(?:curl|wget)\s+.*\|\s*(?:sh|bash|python)', 0.8),
        (r'\b(?:import|require|from)\s+(?:malicious|backdoor|trojan)', 0.9),
        (r'\b(?:exec|eval|system)\s*\(', 0.5),
    ]

    def classify_rules(self, text: str) -> ClassificationResult:
        """Rule-based classification (no LLM call)."""
        text_lower = text.lower()
        flags = self.analyze_structure(text)

        # Check each category
        scores = {
            ThreatCategory.INDIRECT_INJECTION: 0.0,
            ThreatCategory.JAILBREAK: 0.0,
            ThreatCategory.PII_LEAK: 0.0,
            ThreatCategory.PROMPT_EXTRACTION: 0.0,
            ThreatCategory.SUPPLY_CHAIN: 0.0,
        }

        for pattern, weight in self.INJECTION_PATTERNS:
            if re.search(pattern, text_lower):
                scores[ThreatCategory.INDIRECT_INJECTION] += weight

        for pattern, weight in self.JAILBREAK_PATTERNS:
            if re.search(pattern, text_lower):
                scores[ThreatCategory.JAILBREAK] += weight

        for pattern, weight in self.PII_PATTERNS:
            if re.search(pattern, text_lower):
                scores[ThreatCategory.PII_LEAK] += weight

        for pattern, weight in self.EXTRACTION_PATTERNS:
            if re.search(pattern, text_lower):
                scores[ThreatCategory.PROMPT_EXTRACTION] += weight

        for pattern, weight in self.SUPPLY_CHAIN_PATTERNS:
            if re.search(pattern, text_lower):
                scores[ThreatCategory.SUPPLY_CHAIN] += weight

        # Add structural risk to injection score
        scores[ThreatCategory.INDIRECT_INJECTION] += flags.risk_score * 0.3

        # Find highest scoring category
        max_score = max(scores.values())
        if max_score < 0.3:
            return ClassificationResult(
                category=ThreatCategory.SAFE,
                confidence=0.7,
                flags=flags,
                evidence="No threat patterns detected"
            )

        best_category = max(scores, key=scores.get)
        confidence = min(max_score / 2.0, 1.0)

        return ClassificationResult(
            category=best_category,
            confidence=confidence,
            flags=flags,
            evidence=f"Score: {max_score:.2f}"
        )

    def analyze_structure(self, text: str) -> StructuralRiskFlags:
        """Analyze structural risk indicators."""
        flags = StructuralRiskFlags()
        risk = 0.0

        # System override
        if re.search(r'\b(?:system|admin|override)\b', text.lower()):
            flags.has_system_override = True
            risk += 0.2

        # Role mimicry
        if re.search(r'\b(?:human|user|assistant|ai|system)\s*:', text, re.I):
            flags.has_role_mimicry = True
            risk += 0.2

        # Encoded content
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', text):
            flags.has_encoded_content = True
            risk += 0.15

        # Authority claims
        if re.search(r'\b(?:authorized|administrator|admin|regulatory|compliance)\b', text.lower()):
            flags.has_authority_claim = True
            risk += 0.15

        # Format manipulation
        if re.search(r'<\s*(?:system|admin|override|script)', text.lower()):
            flags.has_format_manipulation = True
            risk += 0.2
        if re.search(r'\[(?:SYSTEM|ADMIN|OVERRIDE|NOTE)\b', text):
            flags.has_format_manipulation = True
            risk += 0.15

        flags.risk_score = min(risk, 1.0)
        return flags

    def classify(self, text: str) -> ClassificationResult:
        """Full classification (rules + structure)."""
        return self.classify_rules(text)
