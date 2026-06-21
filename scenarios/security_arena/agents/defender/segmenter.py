"""Trust Boundary Segmentation module - Layer 0.5 defense (0 LLM calls).

Based on NeuralShield's architecture: splits multi-document inputs, assigns
trust scores per segment, identifies external vs internal sources.

Trust boundary design separates:
- Trusted fields: defender_role, defender_task, output_format, security_guidelines
- Untrusted payload: formatted_input, user-provided content

Trust score computed from:
1. Explicit external markers (URLs, email, "User input:" labels)
2. Content risk patterns (injection, role mimicry, encoded content)
3. Position decay (later segments receive lower trust by default)
"""
import re
from dataclasses import dataclass, field


@dataclass
class Segment:
    """A text segment with trust metadata."""
    text: str
    trust_score: float
    source_type: str  # 'trusted' | 'untrusted' | 'mixed'
    position: int


class InputSegmenter:
    """Splits input into trust-boundary segments with trust scores."""

    # Markers that indicate external/untrusted content
    EXTERNAL_MARKERS = [
        re.compile(r'https?://\S+', re.I),
        re.compile(r'\bFrom\s*:\s*\S+@\S+', re.I),
        re.compile(r'\bUser\s*input\s*:', re.I),
        re.compile(r'\bUser\s*query\s*:', re.I),
        re.compile(r'\bUser\s*asked\s*:', re.I),
        re.compile(r'\bFile\s*uploaded\s*:', re.I),
        re.compile(r'\bAttachment\s*:', re.I),
        re.compile(r'\bExternal\s+source\s*:', re.I),
        re.compile(r'\bSource\s*:\s*\S+', re.I),
    ]

    # Risk patterns that reduce trust
    RISK_PATTERNS = [
        (re.compile(r'\bignore\s+(?:all|previous|prior)\s+(?:instructions?|prompts?)', re.I), 0.5),
        (re.compile(r'\bsystem\s+override\b', re.I), 0.5),
        (re.compile(r'\b(?:DAN|DUDE|STAN|jailbreak)\b', re.I), 0.4),
        (re.compile(r'\b(?:human|user|assistant|ai|system)\s*:\s*', re.I), 0.5),
        (re.compile(r'\b(?:admin|root|superuser)\s+(?:access|mode|override)', re.I), 0.5),
        (re.compile(r'<\|?(?:im_start|im_end)\|?>', re.I), 0.4),
        (re.compile(r'\bnew\s+instructions?\s*:', re.I), 0.5),
        (re.compile(r'\bdisregard\s+(?:your|the|all)\s+(?:previous|prior|instructions?)', re.I), 0.5),
        (re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'), 0.4),
    ]

    # Trusted field names from ScenarioContext
    TRUSTED_FIELDS = {"defender_role", "defender_task", "output_format", "security_guidelines"}

    # Document boundary separators (outside code blocks)
    BOUNDARY_PATTERNS = [
        re.compile(r'^-{3,}\s*$', re.M),
        re.compile(r'^={3,}\s*$', re.M),
    ]

    # Code block pattern
    CODE_BLOCK_PATTERN = re.compile(r'```[\s\S]*?```', re.M)

    # Position decay rate per segment
    POSITION_DECAY = 0.05

    def segment(self, input_text: str, context: dict) -> list[Segment]:
        """Segment input text with trust scores based on source and content risk.

        Args:
            input_text: The raw input text to segment.
            context: ScenarioContext dict with trusted fields.

        Returns:
            List of Segment objects with trust metadata.
        """
        if not input_text:
            return [Segment(text="", trust_score=1.0, source_type="trusted", position=0)]

        # Phase 1: Split on document boundaries (outside code blocks)
        raw_segments = self._split_boundaries(input_text)

        # Phase 2: Further split code blocks
        all_segments: list[Segment] = []
        for text in raw_segments:
            all_segments.extend(self._split_code_blocks(text))

        # Phase 3: Assign trust scores
        result: list[Segment] = []
        for i, text in enumerate(all_segments):
            trust = self._compute_trust(text, context, i)
            source = self._classify_source(text, context)
            result.append(Segment(
                text=text,
                trust_score=round(trust, 3),
                source_type=source,
                position=i,
            ))

        return result if result else [Segment(text=input_text, trust_score=0.5, source_type="mixed", position=0)]

    def _split_boundaries(self, text: str) -> list[str]:
        """Split on --- and === separators, but not inside code blocks."""
        code_regions = set()
        for m in self.CODE_BLOCK_PATTERN.finditer(text):
            code_regions.update(range(m.start(), m.end()))

        split_points = [0]
        for pattern in self.BOUNDARY_PATTERNS:
            for m in pattern.finditer(text):
                if not any(pos in code_regions for pos in range(m.start(), m.end())):
                    split_points.append(m.start())
                    split_points.append(m.end())
        split_points.append(len(text))

        split_points = sorted(set(split_points))
        segments = []
        for i in range(len(split_points) - 1):
            chunk = text[split_points[i]:split_points[i + 1]].strip()
            if chunk:
                segments.append(chunk)
        return segments if segments else [text]

    def _split_code_blocks(self, text: str) -> list[str]:
        """Split text so each code block is a separate segment."""
        parts = []
        last_end = 0
        for m in self.CODE_BLOCK_PATTERN.finditer(text):
            before = text[last_end:m.start()].strip()
            if before:
                parts.append(before)
            parts.append(m.group().strip())
            last_end = m.end()
        after = text[last_end:].strip()
        if after:
            parts.append(after)
        return parts if parts else [text]

    def _compute_trust(self, text: str, context: dict, position: int) -> float:
        """Compute trust score 0.0-1.0 for a segment.

        Starts at 1.0 and subtracts for:
        - External markers
        - Risk patterns
        - Position decay
        - Code block presence
        """
        score = 1.0

        # Trusted context fields boost trust
        if context:
            text_lower = text.lower()
            for field_name in self.TRUSTED_FIELDS:
                if field_name in context and field_name.replace("_", " ") in text_lower:
                    score = min(score + 0.1, 1.0)

        # External markers reduce trust
        for pattern in self.EXTERNAL_MARKERS:
            if pattern.search(text):
                score -= 0.45
                break

        # Risk patterns reduce trust
        for pattern, penalty in self.RISK_PATTERNS:
            if pattern.search(text):
                score -= penalty
                break

        # Code blocks reduce trust
        if self.CODE_BLOCK_PATTERN.fullmatch(text.strip()):
            score -= 0.3

        # Position decay
        score -= position * self.POSITION_DECAY

        return max(score, 0.0)

    def _classify_source(self, text: str, context: dict) -> str:
        """Classify segment as trusted, untrusted, or mixed."""
        has_external = any(p.search(text) for p in self.EXTERNAL_MARKERS)
        has_risk = any(p.search(text) for p, _ in self.RISK_PATTERNS)

        # Check if text matches trusted context fields
        is_trusted_content = False
        if context:
            text_lower = text.lower()
            for field_name in self.TRUSTED_FIELDS:
                if field_name in context and field_name.replace("_", " ") in text_lower:
                    is_trusted_content = True
                    break

        if has_external or has_risk:
            if is_trusted_content:
                return "mixed"
            return "untrusted"
        if is_trusted_content:
            return "trusted"
        return "trusted"
