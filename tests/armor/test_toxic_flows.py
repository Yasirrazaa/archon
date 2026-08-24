"""Tests for toxic-flow capability graph and E002 cross-server tool shadowing."""

from archon_core.security.toxic_flows import (
    ShadowFinding,
    ToolCapability,
    classify_tool,
    cross_server_shadowing,
    toxic_flows,
)


class TestClassifyTool:
    def test_fetch_marks_untrusted(self):
        cap = classify_tool("Fetches content from a web URL")
        assert cap.touches_untrusted_content is True
        assert not cap.accesses_sensitive_data
        assert not cap.destructive
        assert not cap.network_egress

    def test_search_and_read_web_mark_untrusted(self):
        assert classify_tool("Web search engine").touches_untrusted_content
        assert classify_tool("Read web pages and extract text").touches_untrusted_content

    def test_password_marks_sensitive(self):
        cap = classify_tool("Retrieves stored passwords")
        assert cap.accesses_sensitive_data is True

    def test_token_pii_credential_mark_sensitive(self):
        assert classify_tool("Returns the current token").accesses_sensitive_data
        assert classify_tool("Look up customer PII records").accesses_sensitive_data
        assert classify_tool("Manage credentials").accesses_sensitive_data

    def test_destructive_keywords(self):
        for desc in ("Delete files", "Drop tables", "Purge cache", "Wipe disk",
                     "Send money to recipient", "Transfer funds"):
            assert classify_tool(desc).destructive, desc

    def test_egress_keywords(self):
        for desc in ("Makes http calls", "Post messages to chat", "Upload backups",
                     "Trigger a webhook"):
            assert classify_tool(desc).network_egress, desc

    def test_benign_description_all_defaults_false(self):
        cap = classify_tool("Adds two numbers together")
        assert not cap.touches_untrusted_content
        assert not cap.accesses_sensitive_data
        assert not cap.destructive
        assert not cap.network_egress

    def test_server_and_tool_are_carried_through(self):
        cap = classify_tool("Create an issue", server="github", tool="create_issue")
        assert cap.server == "github"
        assert cap.tool == "create_issue"


class TestToxicFlows:
    def test_untrusted_plus_destructive_is_high(self):
        caps = [
            classify_tool("Fetches content from a web page", server="web", tool="fetch_page"),
            classify_tool("Delete files from disk", server="fs", tool="delete_file"),
        ]
        flows = toxic_flows(caps)
        flow = next(f for f in flows if f.severity == "high"
                    and f.reason == "untrusted content can trigger destruction")
        assert set(flow.servers) == {"web", "fs"}

    def test_untrusted_sensitive_egress_exfil_path_is_high(self):
        caps = [
            classify_tool("Fetches content from a web page", server="web", tool="fetch_page"),
            classify_tool("Returns a stored password", server="vault", tool="get_secret"),
            classify_tool("Upload results via webhook", server="http", tool="report"),
        ]
        flows = toxic_flows(caps)
        exfil = [f for f in flows if f.severity == "high"
                 and f.reason.startswith("sensitive data")]
        assert len(exfil) == 1
        assert set(exfil[0].servers) == {"vault", "http"}

    def test_sensitive_plus_egress_is_medium(self):
        caps = [
            classify_tool("Returns a stored password", server="vault", tool="get_secret"),
            classify_tool("Post a message to a channel", server="slack", tool="notify"),
        ]
        flows = toxic_flows(caps)
        medium = [f for f in flows if f.severity == "medium"]
        assert len(medium) == 1
        assert set(medium[0].servers) == {"vault", "slack"}

    def test_destructive_alone_is_info(self):
        caps = [classify_tool("Delete files from disk", server="fs", tool="delete_file")]
        flows = toxic_flows(caps)
        info = [f for f in flows if f.severity == "info"]
        assert len(info) == 1
        assert info[0].servers == ["fs"]

    def test_single_capability_combination_flags_too(self):
        cap = ToolCapability("db", "purge_user", touches_untrusted_content=True,
                             accesses_sensitive_data=True, destructive=True,
                             network_egress=True)
        severities = {f.severity for f in toxic_flows([cap])}
        assert severities == {"high", "medium", "info"}

    def test_benign_caps_produce_no_flows(self):
        caps = [ToolCapability("math", "add"), ToolCapability("time", "now")]
        assert toxic_flows(caps) == []

    def test_identical_flows_are_deduped(self):
        caps = [
            classify_tool("Fetches remote content", server="web1", tool="fetch_a"),
            classify_tool("Retrieves remote pages", server="web2", tool="fetch_b"),
            classify_tool("Purge old records", server="fs", tool="delete_x"),
        ]
        flows = toxic_flows(caps)
        keys = [(f.severity, f.reason, tuple(f.servers)) for f in flows]
        assert len(keys) == len(set(keys))

    def test_empty_input_safe(self):
        assert toxic_flows([]) == []
        assert cross_server_shadowing([]) == []


class TestCrossServerShadowing:
    def test_cross_server_mention_flagged(self):
        caps = [
            ToolCapability("evil", "helper", description="Wrapper around github create_issue"),
            ToolCapability("github", "create_issue", description="Create an issue"),
        ]
        findings = cross_server_shadowing(caps)
        assert len(findings) == 1
        f = findings[0]
        assert isinstance(f, ShadowFinding)
        assert f.server == "evil"
        assert f.tool == "helper"
        assert f.shadowed_server == "github"
        assert f.shadowed_tool == "create_issue"

    def test_same_server_mention_not_flagged(self):
        caps = [
            ToolCapability("github", "list_prs",
                           description="Like create_issue but lists pull requests"),
            ToolCapability("github", "create_issue", description="Create an issue"),
        ]
        assert cross_server_shadowing(caps) == []

    def test_case_insensitive_matching(self):
        caps = [
            ToolCapability("a", "x", description="Use GITHUB CREATE_ISSUE internally"),
            ToolCapability("github", "create_issue", description="ok"),
        ]
        assert len(cross_server_shadowing(caps)) == 1

    def test_multiple_shadowed_tools_each_reported(self):
        caps = [
            ToolCapability("evil", "combo",
                           description="Combines vault read_secret and fs delete_file"),
            ToolCapability("vault", "read_secret", description="s"),
            ToolCapability("fs", "delete_file", description="d"),
        ]
        findings = cross_server_shadowing(caps)
        assert {(f.shadowed_server, f.shadowed_tool) for f in findings} == {
            ("vault", "read_secret"),
            ("fs", "delete_file"),
        }
