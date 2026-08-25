"""Tests for prompt-as-rule LLM audit tier (Sprint E3-72, arXiv:2606.31227 §6.5)."""

import asyncio

import pytest
from archon_core.providers.base import Completion, LLMProvider
from archon_core.security.prompt_as_rule import (
    DEFAULT_RULES,
    AuditFinding,
    AuditRule,
    audit_all,
    audit_artifact,
    build_audit_prompt,
    network_reachable,
    parse_verdict,
)

EXPECTED_IDS = {
    "auth-bypass",
    "command-injection",
    "credential-theft",
    "hardcoded-secrets",
    "indirect-prompt-injection",
    "tool-name-confusion",
    "rug-pull",
    "tool-poisoning",
    "tool-shadowing",
    "skill-manifest-consistency",
}


class StubProvider(LLMProvider):
    def __init__(self, content: str = ""):
        self.content = content
        self.calls: list[list[dict]] = []

    async def generate(self, messages: list[dict], **kwargs) -> Completion:
        self.calls.append(messages)
        return Completion(content=self.content, model="stub")


class TestDefaultRules:
    def test_ten_rules_with_expected_ids(self):
        assert {r.id for r in DEFAULT_RULES} == EXPECTED_IDS

    def test_every_rule_has_exclusions_and_owasp_id(self):
        for rule in DEFAULT_RULES:
            assert rule.exclusions, rule.id
            assert rule.owasp_mcp_id.startswith("MCP")

    def test_every_rule_has_patterns_and_definition(self):
        for rule in DEFAULT_RULES:
            assert 1 <= len(rule.patterns) <= 2, rule.id
            assert len(rule.definition) > 20, rule.id

    def test_tool_shadowing_excludes_same_server_references(self):
        rule = next(r for r in DEFAULT_RULES if r.id == "tool-shadowing")
        assert any("SAME server" in e or "same server" in e.lower() for e in rule.exclusions)

    def test_hardcoded_secrets_excludes_placeholders(self):
        rule = next(r for r in DEFAULT_RULES if r.id == "hardcoded-secrets")
        joined = " ".join(rule.exclusions).lower()
        assert "test" in joined or "dummy" in joined or "example" in joined


class TestBuildAuditPrompt:
    def test_embeds_untrusted_delimiters(self):
        prompt = build_audit_prompt(DEFAULT_RULES[0], "artifact body here")
        assert "<untrusted_artifact>" in prompt
        assert "</untrusted_artifact>" in prompt
        assert "artifact body here" in prompt

    def test_embeds_definition_and_exclusions(self):
        rule = next(r for r in DEFAULT_RULES if r.id == "hardcoded-secrets")
        prompt = build_audit_prompt(rule, "text")
        assert rule.definition in prompt
        for exclusion in rule.exclusions:
            assert exclusion in prompt

    def test_requests_verdict_tags(self):
        prompt = build_audit_prompt(DEFAULT_RULES[0], "text")
        assert "<finding>" in prompt
        assert "<reason>" in prompt


class TestParseVerdict:
    def test_yes_verdict(self):
        finding, reason = parse_verdict("<finding>yes</finding><reason>bad auth</reason>")
        assert finding is True
        assert reason == "bad auth"

    def test_no_verdict(self):
        finding, reason = parse_verdict("<finding>no</finding><reason>clean</reason>")
        assert finding is False
        assert reason == "clean"

    def test_tolerates_surrounding_text(self):
        text = "Analysis done.\n<finding>YES</finding>\n<reason>injection found</reason>"
        finding, reason = parse_verdict(text)
        assert finding is True
        assert reason == "injection found"

    def test_garbage_is_unparseable(self):
        finding, reason = parse_verdict("total nonsense")
        assert finding is False
        assert reason == "unparseable"


class TestNetworkReachable:
    def test_stdio_not_reachable(self):
        assert network_reachable({"transport": "stdio"}) is False
        assert network_reachable({"transport": "local"}) is False

    def test_remote_transports_reachable(self):
        for transport in ("sse", "http", "streamable-http"):
            assert network_reachable({"transport": transport}) is True

    def test_host_or_url_fields(self):
        assert network_reachable({"host": "api.example.com"}) is True
        assert network_reachable({"url": "https://x.example.com/mcp"}) is True

    def test_empty_artifact_not_reachable(self):
        assert network_reachable({}) is False


class TestAuditArtifact:
    def _any_network_rule(self) -> AuditRule:
        rule = next((r for r in DEFAULT_RULES if r.requires_network), None)
        if rule is None:
            rule = AuditRule(
                id="rug-pull",
                title="t",
                definition="d" * 40,
                patterns=["p"],
                exclusions=["e"],
                owasp_mcp_id="MCP99",
                requires_network=True,
            )
        return rule

    def test_skips_when_requires_network_and_unreachable(self):
        rule = self._any_network_rule()
        provider = StubProvider("<finding>yes</finding><reason>x</reason>")
        result = asyncio.run(
            audit_artifact(rule, "artifact", provider, reachable=False)
        )
        assert result is None
        assert provider.calls == []

    def test_runs_when_reachable(self):
        rule = self._any_network_rule()
        provider = StubProvider("<finding>yes</finding><reason>found it</reason>")
        result = asyncio.run(audit_artifact(rule, "artifact", provider, reachable=True))
        assert result is not None
        assert result.finding is True

    def test_finding_captured_and_reason_preserved(self):
        provider = StubProvider(
            "<finding>no</finding><reason>no issue observed here</reason>"
        )
        result = asyncio.run(audit_artifact(DEFAULT_RULES[0], "artifact", provider))
        assert isinstance(result, AuditFinding)
        assert result.finding is False
        assert result.reason == "no issue observed here"
        assert result.rule_id == DEFAULT_RULES[0].id
        assert result.owasp_mcp_id == DEFAULT_RULES[0].owasp_mcp_id

    def test_provider_called_with_user_message_containing_prompt(self):
        rule = DEFAULT_RULES[0]
        provider = StubProvider("<finding>no</finding><reason>r</reason>")
        asyncio.run(audit_artifact(rule, "the artifact text", provider))
        assert len(provider.calls) == 1
        msg = provider.calls[0][0]
        assert msg["role"] == "user"
        assert "the artifact text" in msg["content"]


class TestAuditAll:
    def test_filters_negatives(self):
        provider = StubProvider("<finding>no</finding><reason>clean</reason>")
        findings = asyncio.run(
            audit_all(list(DEFAULT_RULES)[:3], ["artifact-a"], provider)
        )
        assert findings == []

    def test_keeps_positives(self):
        provider = StubProvider("<finding>yes</finding><reason>violation</reason>")
        findings = asyncio.run(
            audit_all(list(DEFAULT_RULES)[:2], ["artifact-a", "artifact-b"], provider)
        )
        assert all(f.finding for f in findings)
        assert len(findings) > 0

    def test_reachability_map_gates_rules(self):
        rule = next((r for r in DEFAULT_RULES if r.requires_network), None)
        if rule is None:
            pytest.skip("no default rule requires network")
        provider = StubProvider("<finding>yes</finding><reason>x</reason>")
        findings = asyncio.run(
            audit_all([rule], ["art"], provider, reachability={"art": False})
        )
        assert findings == []
