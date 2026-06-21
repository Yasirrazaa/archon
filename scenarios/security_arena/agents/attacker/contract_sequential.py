"""Contract awareness and sequential chaining - attacker module.

Based on NeuralShield's attacker: parses output_format for attack surface
modeling and chains strategies with fallback.
"""
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class ContractModel:
    """Parsed output format contract."""
    expected_fields: list[str]
    is_numeric: bool
    is_constrained: bool
    task_type: str


class ContractAnalyzer:
    """Parse defender's output format to model attack surface."""

    NUMERIC_PATTERNS = [
        r'"score"', r'"rating"', r'"count"', r'"confidence"',
        r'"level"', r'"amount"', r'"total"', r'"percentage"',
        r'\d+%', r'"priority"',
    ]

    CONSTRAINED_PATTERNS = [
        r'"High"\s*\|\s*"Medium"\s*\|\s*"Low"',
        r'"high"\s*\|\s*"medium"\s*\|\s*"low"',
        r'"High\|Medium\|Low"',
        r'"high\|medium\|low"',
        r'true\s*\|\s*false',
        r'true\|false',
        r'"yes"\s*\|\s*"no"',
        r'"yes\|no"',
        r'"true"\s*\|\s*"false"',
        r'"true\|false"',
        r'"allowed"\s*\|\s*"denied"',
        r'"pass"\s*\|\s*"fail"',
        r'"safe"\s*\|\s*"unsafe"',
        r'"malicious"\s*\|\s*"benign"',
    ]

    CLASSIFICATION_FIELDS = [
        "category", "classification", "label", "type",
        "risk_level", "threat_type", "severity",
    ]

    SCORING_FIELDS = [
        "score", "rating", "confidence", "probability",
        "likelihood", "strength", "intensity",
    ]

    def analyze(self, output_format: str) -> ContractModel:
        """Analyze output format string to build contract model."""
        fields = self._extract_fields(output_format)
        is_numeric = self._detect_numeric(output_format, fields)
        is_constrained = self._detect_constrained(output_format)
        task_type = self._detect_task_type(fields)

        return ContractModel(
            expected_fields=fields,
            is_numeric=is_numeric,
            is_constrained=is_constrained,
            task_type=task_type,
        )

    def _extract_fields(self, output_format: str) -> list[str]:
        """Extract JSON field names from output format."""
        fields = []
        field_pattern = re.compile(r'"(\w+)"\s*:')

        for match in field_pattern.finditer(output_format):
            field_name = match.group(1)
            if field_name not in fields and len(field_name) > 1:
                fields.append(field_name)

        try:
            parsed = json.loads(output_format)
            if isinstance(parsed, dict):
                self._extract_from_dict(parsed, fields)
        except (json.JSONDecodeError, ValueError):
            pass

        return fields

    def _extract_from_dict(self, d: dict, fields: list[str]) -> None:
        """Recursively extract field names from dict."""
        for key, value in d.items():
            if key not in fields and len(key) > 1:
                fields.append(key)
            if isinstance(value, dict):
                self._extract_from_dict(value, fields)

    def _detect_numeric(self, output_format: str, fields: list[str]) -> bool:
        """Detect if output expects numeric values."""
        for pattern in self.NUMERIC_PATTERNS:
            if re.search(pattern, output_format, re.IGNORECASE):
                return True
        for field_name in fields:
            if field_name in self.SCORING_FIELDS:
                return True
        return False

    def _detect_constrained(self, output_format: str) -> bool:
        """Detect if output has constrained/enum values."""
        for pattern in self.CONSTRAINED_PATTERNS:
            if re.search(pattern, output_format, re.IGNORECASE):
                return True
        return False

    def _detect_task_type(self, fields: list[str]) -> str:
        """Infer task type from field names."""
        classification_hits = sum(1 for f in fields if f in self.CLASSIFICATION_FIELDS)
        scoring_hits = sum(1 for f in fields if f in self.SCORING_FIELDS)

        if classification_hits >= 2:
            return "classification"
        if scoring_hits >= 1:
            return "scoring"
        if fields:
            return "extraction"
        return "unknown"


class SequentialAttacker:
    """Chain attack strategies with fallback and failure tracking."""

    def __init__(self) -> None:
        self.failure_log: dict[str, int] = {}
        self._history: list[dict[str, Any]] = []

    def execute(
        self,
        strategies: list[tuple[str, int]],
        context: dict[str, Any],
        strategy_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Execute strategies in order with fallback.

        Args:
            strategies: List of (strategy_name, max_attempts) tuples.
            context: Context dict passed to each strategy call.
            strategy_fn: Callable that takes context and returns
                {'success': bool, ...}. If None, always returns failure.

        Returns:
            Dict with 'strategy' and 'result' keys.
        """
        if not strategies:
            return {
                "strategy": "fallback",
                "result": {"success": False, "reason": "no_strategies"},
            }

        if strategy_fn is None:
            strategy_fn = lambda ctx: {"success": False, "reason": "no_fn"}

        for strategy_name, max_attempts in strategies:
            for attempt in range(max_attempts):
                result = strategy_fn(context)
                self._history.append({
                    "strategy": strategy_name,
                    "attempt": attempt + 1,
                    "result": result,
                })

                if result.get("success"):
                    return {"strategy": strategy_name, "result": result}

                self.failure_log[strategy_name] = (
                    self.failure_log.get(strategy_name, 0) + 1
                )

        return {
            "strategy": "fallback",
            "result": {"success": False, "reason": "all_strategies_exhausted"},
        }

    def get_history(self) -> list[dict[str, Any]]:
        """Return full execution history."""
        return list(self._history)

    def reset(self) -> None:
        """Clear failure log and history."""
        self.failure_log.clear()
        self._history.clear()
