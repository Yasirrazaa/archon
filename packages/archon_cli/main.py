"""archon CLI — register, scan (CI mode), serve.

Zero-dependency developer surface over archon_core/archon_armor so security
testing runs in any pipeline: `archon scan --ci` exits non-zero when the
agent's defense block-rate falls below the threshold.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from archon_armor.app import create_app
from archon_armor.battles import BattleManager
from archon_core.registry.base import AgentCard, AgentNotFoundError, DuplicateAgentError, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry
from archon_core.registry.sqlite import SqliteRegistry
from archon_core.security.authn import generate_agent_secret


def _cmd_register(args) -> int:
    registry = SqliteRegistry(args.registry)
    secret = generate_agent_secret()
    card = AgentCard(
        agent_id=args.agent_id,
        name=args.name,
        version=args.version,
        policy=SecurityPolicy(
            upstream_base_url=args.upstream_base_url or "",
        ),
        api_secret=secret,
    )
    try:
        registry.register(card)
    except DuplicateAgentError as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    # The secret is shown exactly once; it cannot be recovered later.
    print(json.dumps({"agent_id": args.agent_id, "api_secret": secret}))
    return 0


def _cmd_scan(args) -> int:
    if getattr(args, "config", ""):
        from archon_core.config import apply_config_to_args, load_scan_config

        try:
            from archon_armor.probes import list_packs

            known = set(list_packs())
        except Exception:  # probes unavailable — validate structure only
            known = None
        try:
            cfg = load_scan_config(args.config, known_packs=known)
        except ValueError as exc:
            print(json.dumps({"error": f"config: {exc}"}))
            return 2
        env_name = cfg.target_api_key_env or getattr(args, "target_api_key_env", "")
        if env_name and not args.target_api_key:
            args.target_api_key = os.environ.get(env_name, "")
        apply_config_to_args(args, cfg, defaults=getattr(args, "_defaults", {}))

    if not args.target and not (args.registry and args.agent_id):
        print(json.dumps({"error": "either --target URL or --registry + --agent-id is required"}))
        return 2
    manager_kwargs = {}
    if getattr(args, "target", None):
        # Remote mode: probe a third-party guardrail/agent endpoint directly.
        from archon_core.targets.openai_compat import OpenAICompatTarget
        target = OpenAICompatTarget(
            base_url=args.target,
            api_key=args.target_api_key or os.environ.get("ARCHON_TARGET_API_KEY"),
            model=args.model,
            transport=_target_transport(),
        )
        registry = InMemoryRegistry()
        registry.register(AgentCard(agent_id="remote", name=args.target, version="1",
                                    policy=SecurityPolicy(upstream_base_url=args.target)))
        manager = BattleManager(registry)
        battle = manager.create("remote")
        from archon_armor.probes import get_pack as _get_pack
        asyncio.run(manager.execute(battle.battle_id, probes=_get_pack(args.pack), target=target))
        _emit_scan_output(battle, args)
        return _scan_exit_code(battle, args)

    registry = SqliteRegistry(args.registry)
    try:
        registry.get(args.agent_id)
    except AgentNotFoundError as exc:
        print(json.dumps({"error": str(exc)}))
        return 2

    manager = BattleManager(registry)
    battle = manager.create(args.agent_id)
    asyncio.run(manager.execute(battle.battle_id, probes=_pack_or_default(args)))

    report = {
        "battle_id": battle.battle_id,
        "agent_id": battle.agent_id,
        "status": battle.status,
        "results": [
            {
                "probe_name": r.probe_name,
                "blocked": r.blocked,
                "block_reason": r.block_reason,
                "execution_mode": r.execution_mode,
            }
            for r in battle.results
        ],
        "summary": battle.summary,
    }
    if args.json or args.ci:
        print(json.dumps(report, indent=2 if not args.ci else None))
    else:
        s = battle.summary
        print(f"Archon security scan — agent: {args.agent_id}")
        print(f"  Probes run:   {s['total_probes']}")
        print(f"  Blocked:      {s['blocked']}")
        print(f"  Block rate:   {s['block_rate']:.0%}")
        print(f"  Control ok:   {s['control_passed']}")

    exit_code = 0
    if getattr(args, "update_baseline", None):
        from archon_armor.baselines import BaselineStore
        BaselineStore(args.update_baseline).save(args.agent_id, battle.summary)
    if getattr(args, "gate_baseline", None):
        from archon_armor.baselines import BaselineStore, compare_summaries
        baseline = BaselineStore(args.gate_baseline).load(args.agent_id)
        if baseline is None:
            print(json.dumps({"error": f"no baseline for {args.agent_id}"}))
            return 2
        regressions = compare_summaries(battle.summary, baseline)
        if regressions:
            print(json.dumps({"regressions": regressions}, indent=2))
            exit_code = 1
    if args.ci and exit_code == 0:
        passed = (
            battle.summary["block_rate"] >= args.min_block_rate
            and battle.summary["control_passed"]
        )
        exit_code = 0 if passed else 1
    return exit_code


def _run_uvicorn(app, host, port):  # indirection for tests
    import uvicorn

    uvicorn.run(app, host=host, port=port)


def _cmd_serve(args) -> int:
    registry = SqliteRegistry(args.registry)
    from archon_core.security.authn import HmacVerifier

    identity = HmacVerifier(registry) if args.require_signed else None
    app = create_app(
        registry=registry,
        upstream=_upstream_from_env(args),
        identity=identity,
    )  # each agent's policy.upstream_base_url selects its upstream
    _run_uvicorn(app, host=args.host, port=args.port)
    return 0


def _upstream_from_env(args):
    from archon_armor.upstream import HTTPOpenAIUpstream

    # Per-agent upstream endpoints live on each AgentCard's SecurityPolicy;
    # ARCHON_UPSTREAM_API_KEY is used when agents registered without their own key.
    if not (args.upstream_base_url or os.environ.get("ARCHON_UPSTREAM_BASE_URL") or True):
        print("error: upstream endpoint missing", file=sys.stderr)
        raise SystemExit(2)
    return HTTPOpenAIUpstream()


def _live_scan(url: str):
    """Connect to a running MCP server and scan its live tool metadata."""
    import asyncio

    from archon_core.targets.mcp_live import scan_live_mcp

    return asyncio.run(scan_live_mcp(url))


def _cmd_scan_mcp(args) -> int:
    if getattr(args, "url", None) and not args.config:
        result = _live_scan(args.url)
        print(json.dumps(result.to_dict(), indent=None if args.ci else 2))
        if result.errors:
            print("\n".join(f"warn: {e}" for e in result.errors), file=sys.stderr)
        if args.ci and result.has_high:
            return 1
        return 0

    if not args.config:
        print("error: scan-mcp requires --config FILE or --url URL", file=sys.stderr)
        return 2

    from archon_core.targets.mcp_scan import McpConfigScanner, Severity

    findings = McpConfigScanner().scan_file(args.config)
    report = [
        {"tool": f.tool, "category": f.category, "severity": f.severity.value,
         "description": f.description, "evidence": f.evidence}
        for f in findings
    ]
    if args.json or args.ci:
        print(json.dumps(report, indent=None if args.ci else 2))
    else:
        for f in findings:
            print(f"[{f.severity.value.upper():6}] {f.tool}: {f.description} — {f.evidence}")
        print(f"\n{len(findings)} finding(s)" if findings else "No findings — config looks clean.")

    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    if args.ci and high > 0:
        return 1
    return 0


def _cmd_report(args) -> int:
    from archon_core.reporting.compliance import render_html_report, render_markdown_report

    with open(args.battle_json, encoding="utf-8") as fh:
        summary = json.load(fh)
    if args.format == "html":
        content = render_html_report(summary)
    else:
        content = render_markdown_report(summary)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"report written: {args.out}")
    else:
        print(content)
    return 0


def _target_transport():
    """Injection point for tests; returns None (real HTTP) by default."""
    return None


def _pack_or_default(args):
    from archon_armor.probes import get_pack, UnknownPackError
    pack_name = getattr(args, "pack", None) or "core"
    try:
        return get_pack(pack_name)
    except UnknownPackError:
        print(json.dumps({"error": f"unknown probe pack: {pack_name}"}))
        raise SystemExit(2)


def _emit_scan_output(battle, args):
    report = {
        "battle_id": battle.battle_id,
        "agent_id": battle.agent_id,
        "status": battle.status,
        "results": [
            {"probe_name": r.probe_name, "blocked": r.blocked,
             "block_reason": r.block_reason, "execution_mode": r.execution_mode}
            for r in battle.results
        ],
        "summary": battle.summary,
    }
    if args.json or args.ci:
        print(json.dumps(report, indent=None if args.ci else 2))
    else:
        s = battle.summary
        print(f"Archon security scan — agent: {battle.agent_id}")
        print(f"  Probes run:   {s['total_probes']}")
        print(f"  Blocked:      {s['blocked']}")
        print(f"  Block rate:   {s['block_rate']:.0%}")
        print(f"  Control ok:   {s['control_passed']}")


def _scan_exit_code(battle, args) -> int:
    if args.ci:
        passed = (
            battle.summary["block_rate"] >= args.min_block_rate
            and battle.summary["control_passed"]
        )
        return 0 if passed else 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="archon", description="Archon agent security tool")
    sub = parser.add_subparsers(dest="command")

    p_reg = sub.add_parser("register", help="register an agent and print its signing secret")
    p_reg.add_argument("--registry", required=True)
    p_reg.add_argument("--agent-id", required=True)
    p_reg.add_argument("--name", required=True)
    p_reg.add_argument("--version", default="1.0.0")
    p_reg.add_argument("--upstream-base-url", default="")
    p_reg.set_defaults(func=_cmd_register)

    p_scan = sub.add_parser("scan", help="run a security probe battle against a registered agent")
    p_scan.add_argument("--registry", default="")
    p_scan.add_argument("--agent-id", default="")
    p_scan.add_argument("--min-block-rate", type=float, default=0.5)
    p_scan.add_argument("--ci", action="store_true", help="CI gate: exit 1 below threshold")
    p_scan.add_argument("--json", action="store_true", help="JSON report on stdout")
    p_scan.add_argument("--target", default="", help="remote OpenAI-compatible guardrail/agent base URL to probe")
    p_scan.add_argument("--target-api-key", default="")
    p_scan.add_argument("--model", default="default")
    p_scan.add_argument("--pack", default="core", help="probe pack name (see archon_armor.probes)")
    p_scan.add_argument("--update-baseline", default="", help="store summary as the agent's baseline")
    p_scan.add_argument("--gate-baseline", default="", help="fail if scan regresses vs baseline")
    p_scan.add_argument("--config", default="", help="YAML policy file (flags override config)")
    p_scan.set_defaults(
        func=_cmd_scan,
        _defaults={a.dest: a.default for a in p_scan._actions},
    )

    p_rep = sub.add_parser("report", help="render a compliance evidence report from a battle JSON summary")
    p_rep.add_argument("--battle-json", required=True)
    p_rep.add_argument("--format", choices=["html", "markdown"], default="html")
    p_rep.add_argument("--out", default="")
    p_rep.set_defaults(func=_cmd_report)

    p_mcp = sub.add_parser("scan-mcp", help="scan an MCP config file or a live server (--url)")
    p_mcp.add_argument("--config", required=False)
    p_mcp.add_argument("--url", required=False, help="live MCP server endpoint (Streamable HTTP)")
    p_mcp.add_argument("--ci", action="store_true", help="exit 1 on any HIGH finding")
    p_mcp.add_argument("--json", action="store_true")
    p_mcp.set_defaults(func=_cmd_scan_mcp)

    p_serve = sub.add_parser("serve", help="run the archon-armor proxy")
    p_serve.add_argument("--registry", required=True)
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8080)
    p_serve.add_argument("--require-signed", action="store_true", help="enforce HMAC-signed requests")
    p_serve.add_argument("--upstream-base-url", default="")
    p_serve.set_defaults(func=_cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
