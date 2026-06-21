"""Output guardrails module - post-execution output sanitization.

Based on NeuralShield's output guardrails: detects PII leakage, unsafe code
patterns, unverified references, and sanitizes output accordingly. Applies
risk levels (none, low, medium, high) based on violation severity.
"""
import re
from dataclasses import dataclass, field


@dataclass
class OutputGuardrailResult:
    """Result of output guardrail processing."""
    sanitized_output: str
    was_modified: bool
    violations_found: list[str]
    risk_level: str


class OutputGuardrails:
    """Post-execution output sanitizer.

    Detects and sanitizes PII, unsafe code, and unverified references
    in model output before it reaches the user.
    """

    # PII patterns: (pattern, description)
    PII_PATTERNS = [
        (re.compile(r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b'), "SSN detected"),
        (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), "Email detected"),
        (re.compile(r'\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'), "Phone number detected"),
    ]

    # Unsafe code patterns: (pattern, description)
    UNSAFE_CODE_PATTERNS = [
        (re.compile(r'\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s+.*\b(?:FROM|INTO|WHERE)\b', re.I), "SQL injection pattern"),
        (re.compile(r'\b(?:cat|ls|pwd|rm|chmod|chown|wget|curl)\s+[/\w\-\.]+', re.I), "Shell command detected"),
        (re.compile(r'\beval\s*\(', re.I), "eval() usage detected"),
        (re.compile(r'\bexec\s*\(', re.I), "exec() usage detected"),
        (re.compile(r'\bpip\s+install\s+\w+', re.I), "Package install detected"),
        (re.compile(r'\b(?:curl|wget)\s+.*\|\s*(?:sh|bash)', re.I), "Remote code execution pattern"),
        (re.compile(r'\b(?:import|require)\s+os\b', re.I), "OS module import detected"),
    ]

    def detect_pii(self, output: str) -> list[str]:
        """Find PII patterns (SSN, emails, phones, etc.) in output."""
        violations = []
        for pattern, description in self.PII_PATTERNS:
            if pattern.search(output):
                violations.append(description)
        return violations

    def detect_unsafe_code(self, output: str) -> list[str]:
        """Find unsafe code patterns (SQL injection, shell commands, etc.)."""
        violations = []
        for pattern, description in self.UNSAFE_CODE_PATTERNS:
            if pattern.search(output):
                violations.append(description)
        return violations

    def detect_unverified_references(self, output: str, context: dict) -> list[str]:
        """Find package/module references not in trusted list."""
        violations = []
        trusted = set(context.get("trusted_packages", []))

        package_pattern = re.compile(r'\b(?:pip|npm|cargo|go)\s+install\s+(\S+)', re.I)
        for match in package_pattern.finditer(output):
            package = match.group(1)
            if package not in trusted:
                violations.append(f"Unverified package: {package}")

        return violations

    def _redact_pii(self, output: str) -> str:
        """Replace PII with redaction markers."""
        # SSN: xxx-xx-xxxx format
        output = re.sub(
            r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b',
            '[REDACTED_SSN]',
            output
        )
        # Email
        output = re.sub(
            r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}',
            '[REDACTED_EMAIL]',
            output
        )
        # Phone
        output = re.sub(
            r'\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
            '[REDACTED_PHONE]',
            output
        )
        return output

    def _redact_unsafe_code(self, output: str) -> str:
        """Replace unsafe code patterns with redaction markers."""
        # SQL injection
        output = re.sub(
            r'\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s+.*\b(?:FROM|INTO|WHERE)\b.*',
            '[REDACTED_SQL_QUERY]',
            output,
            flags=re.I
        )
        # Shell commands
        output = re.sub(
            r'\b(?:cat|ls|pwd|rm|chmod|chown|wget|curl)\s+[/\w\-\.]+',
            '[REDACTED_COMMAND]',
            output,
            flags=re.I
        )
        # eval/exec
        output = re.sub(r'\beval\s*\([^)]*\)', '[REDACTED_EVAL]', output, flags=re.I)
        output = re.sub(r'\bexec\s*\([^)]*\)', '[REDACTED_EXEC]', output, flags=re.I)
        # pip install
        output = re.sub(
            r'\bpip\s+install\s+\S+',
            '[REDACTED_INSTALL]',
            output,
            flags=re.I
        )
        # curl|wget pipe
        output = re.sub(
            r'\b(?:curl|wget)\s+.*\|\s*(?:sh|bash)',
            '[REDACTED_REMOTE_EXEC]',
            output,
            flags=re.I
        )
        return output

    def _compute_risk_level(self, violations: list[str]) -> str:
        """Compute risk level from violation list."""
        if not violations:
            return "none"

        has_code_injection = any(
            "sql" in v.lower() or "eval" in v.lower() or "exec" in v.lower()
            or "command" in v.lower() or "remote" in v.lower()
            for v in violations
        )
        has_pii = any(
            "ssn" in v.lower() or "email" in v.lower() or "phone" in v.lower()
            for v in violations
        )

        if has_code_injection:
            return "high"
        if has_pii:
            return "medium"
        return "low"

    def sanitize(self, output: str, context: dict) -> OutputGuardrailResult:
        """Sanitize output: redact PII and unsafe code, return result."""
        violations = []
        sanitized = output

        pii = self.detect_pii(output)
        if pii:
            violations.extend(pii)
            sanitized = self._redact_pii(sanitized)

        code = self.detect_unsafe_code(output)
        if code:
            violations.extend(code)
            sanitized = self._redact_unsafe_code(sanitized)

        was_modified = sanitized != output
        risk_level = self._compute_risk_level(violations)

        return OutputGuardrailResult(
            sanitized_output=sanitized,
            was_modified=was_modified,
            violations_found=violations,
            risk_level=risk_level,
        )

    def sanitize_all(self, output: str, context: dict) -> OutputGuardrailResult:
        """Full sanitization pipeline: PII + unsafe code + unverified refs."""
        violations = []
        sanitized = output

        pii = self.detect_pii(output)
        if pii:
            violations.extend(pii)
            sanitized = self._redact_pii(sanitized)

        code = self.detect_unsafe_code(output)
        if code:
            violations.extend(code)
            sanitized = self._redact_unsafe_code(sanitized)

        refs = self.detect_unverified_references(output, context)
        if refs:
            violations.extend(refs)

        was_modified = sanitized != output
        risk_level = self._compute_risk_level(violations)

        return OutputGuardrailResult(
            sanitized_output=sanitized,
            was_modified=was_modified,
            violations_found=violations,
            risk_level=risk_level,
        )
