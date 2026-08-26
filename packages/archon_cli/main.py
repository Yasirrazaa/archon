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
from archon_core.registry.base import (
    AgentCard,
    AgentNotFoundError,
    DuplicateAgentError,
    SecurityPolicy,
)
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
    resume_state = None
    if getattr(args, "resume", ""):
        from archon_armor.checkpoints import load_checkpoint

        resume_state = load_checkpoint(args.resume)
        if resume_state is None:
            print(json.dumps({"error": f"no checkpoint at {args.resume}"}))
            return 2
    asyncio.run(manager.execute(
        battle.battle_id, probes=_pack_or_default(args),
        checkpoint_path=getattr(args, "checkpoint", "") or None,
        resume_state=resume_state,
    ))

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


def _cmd_ui(args) -> int:
    from archon_armor.ui import create_ui_app

    app = create_ui_app(SqliteRegistry(args.registry))
    _run_uvicorn(app, host=args.host, port=args.port)
    return 0


def _cmd_purple(args) -> int:
    """One-click purple run: attack two policy versions, emit delta verdict."""
    import json as _json

    from archon_armor.purple import (
        compare_to_baseline,
        load_baseline,
        render_baseline_md,
        render_purple_md,
        run_purple_sync,
        save_baseline,
    )

    report = run_purple_sync(
        args.registry,
        args.agent_a,
        args.agent_b,
        pack=args.pack,
    )
    comparison = None
    if getattr(args, "save_baseline", ""):
        save_baseline(report, args.save_baseline)
    if getattr(args, "baseline", ""):
        baseline = load_baseline(args.baseline)
        if baseline is not None:
            comparison = compare_to_baseline(report, baseline)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(render_purple_md(report))
            if comparison is not None:
                fh.write(render_baseline_md(comparison))
    if comparison is not None and args.json:
        print(_json.dumps(comparison, indent=2))
    elif args.json:
        print(_json.dumps(report, indent=2))
    else:
        print(render_purple_md(report))
        if comparison is not None:
            print(render_baseline_md(comparison))
    if args.ci:
        if comparison is not None:
            return 1 if comparison.get("regressed") else 0
        if report.get("verdict") == "regressed":
            return 1
    return 0


def _cmd_bot(args) -> int:
    """Autonomous red bot: continuous unattended probing of a running target."""

    from archon_core.bots import RedBot, RedBotConfig, summarize_bot_run

    config = RedBotConfig(
        interval=args.interval,
        packs=tuple(args.packs),
        max_rounds=args.max_rounds,
        target_url=args.target,
    )
    bot = RedBot(config)
    findings = bot.run()
    summary = summarize_bot_run(findings)
    import json as _json

    print(_json.dumps(summary, indent=2))
    return 0


def _cmd_kill_switch(args) -> int:
    """Kill-switch drill: atomic revocation with measured MTTC."""
    import json as _json

    from archon_core.audit import SqliteAuditTrail
    from archon_core.security.killswitch import KillSwitch

    audit = SqliteAuditTrail(args.store.replace(".db", "-audit.db"))
    ks = KillSwitch(store_path=args.store, audit=audit)
    if args.restore:
        removed = ks.restore(args.agent)
        print(_json.dumps({"agent_id": args.agent, "restored": removed}, indent=2))
        return 0
    result = ks.trigger(args.agent)
    print(_json.dumps(result.to_dict(), indent=2))
    return 0


def _upstream_from_env(args):
    from archon_armor.upstream import HTTPOpenAIUpstream

    # Per-agent upstream endpoints live on each AgentCard's SecurityPolicy;
    # ARCHON_UPSTREAM_API_KEY is used when agents registered without their own key.
    if not (args.upstream_base_url or os.environ.get("ARCHON_UPSTREAM_BASE_URL") or True):
        print("error: upstream endpoint missing", file=sys.stderr)
        raise SystemExit(2)
    return HTTPOpenAIUpstream()


def _live_scan(url: str, probe_tools: list[str] | None = None):
    """Connect to a running MCP server and scan its live tool metadata."""
    import asyncio

    from archon_core.targets.mcp_live import scan_live_mcp

    return asyncio.run(scan_live_mcp(url, probe_tools=probe_tools))


def _cmd_scan_mcp(args) -> int:
    if getattr(args, "url", None) and not args.config:
        result = _live_scan(args.url, probe_tools=getattr(args, "probe_tool", None))
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


def _cmd_compare(args) -> int:
    from archon_armor.compare import compare_battles, render_compare_md

    with open(args.a, encoding="utf-8") as fh:
        report_a = json.load(fh)
    with open(args.b, encoding="utf-8") as fh:
        report_b = json.load(fh)
    comparison = compare_battles(report_a, report_b)
    if args.format == "json":
        print(json.dumps(comparison, indent=2))
    else:
        print(render_compare_md(comparison, label_a=args.label_a, label_b=args.label_b))
    if args.ci and comparison["verdict"] == "regressed":
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
    from archon_armor.probes import UnknownPackError, get_pack
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
    p_scan.add_argument("--checkpoint", default="", help="persist verdicts to this file after every probe (crash-safe long scans)")
    p_scan.add_argument("--resume", default="", help="resume an interrupted scan from a checkpoint file")
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

    p_cmp = sub.add_parser(
        "compare", help="compare two battle/scan JSON reports (A = reference, B = candidate)"
    )
    p_cmp.add_argument("--a", required=True, help="reference report JSON (e.g. baseline run)")
    p_cmp.add_argument("--b", required=True, help="candidate report JSON (e.g. new policy)")
    p_cmp.add_argument("--label-a", default="A")
    p_cmp.add_argument("--label-b", default="B")
    p_cmp.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p_cmp.add_argument("--ci", action="store_true", help="exit 1 if B regressed vs A")
    p_cmp.set_defaults(func=_cmd_compare)

    p_mcp = sub.add_parser("scan-mcp", help="scan an MCP config file or a live server (--url)")
    p_mcp.add_argument("--config", required=False)
    p_mcp.add_argument("--url", required=False, help="live MCP server endpoint (Streamable HTTP)")
    p_mcp.add_argument("--probe-tool", action="append", default=None,
                       help="behaviorally invoke this tool with injection probes (repeatable)")
    p_mcp.add_argument("--ci", action="store_true", help="exit 1 on any HIGH finding")
    p_mcp.add_argument("--json", action="store_true")
    p_mcp.set_defaults(func=_cmd_scan_mcp)

    p_battle = sub.add_parser(
        "battle", help="multi-turn adaptive battle against a remote guardrail/agent"
    )
    p_battle.add_argument("--target", required=True)
    p_battle.add_argument("--goal", required=True, help="attack goal, e.g. 'exfiltrate system prompt'")
    p_battle.add_argument("--seed", action="append", default=[],
                          help="seed probe payload (repeatable)")
    p_battle.add_argument("--width", type=int, default=2, help="branching factor")
    p_battle.add_argument("--max-rounds", type=int, default=3)
    p_battle.add_argument("--target-api-key", default="")
    p_battle.add_argument("--model", default="default")
    p_battle.add_argument("--ci", action="store_true",
                          help="exit 1 if the attack SUCCEEDS (defense failed)")
    p_battle.set_defaults(func=_cmd_battle)

    p_plugins = sub.add_parser("plugins", help="list extension seams (packs, layers, targets, providers)")
    p_plugins.add_argument("--ci", action="store_true")
    p_plugins.set_defaults(func=_cmd_plugins)

    p_results = sub.add_parser("results", help="list stored battle results from the results DB")
    p_results.add_argument("--db", required=True, help="path to the results SQLite database")
    p_results.add_argument("--agent-id", default=None, help="filter by agent id")
    p_results.add_argument("--limit", type=int, default=50)
    p_results.add_argument("--share", default="", help="battle id: print its share URL fragment")
    p_results.add_argument("--sarif", default="", help="battle id: write SARIF 2.1.0 to this path (GitHub Code Scanning)")
    p_results.add_argument("--html", default="", help="battle id: write self-contained HTML report to this path")
    p_results.set_defaults(func=_cmd_results)
    p_disc = sub.add_parser("discover", help="discover local agent configs (Claude/Cursor/VSCode/Gemini CLI...)")
    p_disc.add_argument("--root", default=None, help="override home dir for discovery")
    p_disc.add_argument("--json", action="store_true")
    p_disc.add_argument(
        "--scan-skills",
        action="store_true",
        help="run SKILL.md supply-chain checks on each found client's skills dirs",
    )
    p_disc.set_defaults(func=_cmd_discover)

    p_fleet = sub.add_parser("fleet", help="fleet overview from baselines (dashboard primitive)")
    p_fleet.add_argument("--registry", required=True)
    p_fleet.add_argument("--baselines", required=True, help="JSON baseline store path")
    p_fleet.add_argument("--min-block-rate", type=float, default=0.75)
    p_fleet.add_argument("--ci", action="store_true",
                         help="exit 1 if any agent is below the fleet minimum")
    p_fleet.add_argument("--json", action="store_true")
    p_fleet.set_defaults(func=_cmd_fleet)

    p_serve = sub.add_parser("serve", help="run the archon-armor proxy")
    p_serve.add_argument("--registry", required=True)
    p_serve.add_argument("--host", default="0.0.0.0")
    p_serve.add_argument("--port", type=int, default=8080)
    p_serve.add_argument("--require-signed", action="store_true", help="enforce HMAC-signed requests")
    p_serve.add_argument("--upstream-base-url", default="")
    p_serve.set_defaults(func=_cmd_serve)

    p_ui = sub.add_parser("ui", help="fleet dashboard web UI")
    p_ui.add_argument("--registry", required=True)
    p_ui.add_argument("--host", default="0.0.0.0")
    p_ui.add_argument("--port", type=int, default=8081)
    p_ui.set_defaults(func=_cmd_ui)

    p_purple = sub.add_parser(
        "purple", help="one-click purple run: attack two policy versions, emit delta verdict"
    )
    p_purple.add_argument("--registry", required=True)
    p_purple.add_argument("--agent-a", required=True)
    p_purple.add_argument("--agent-b", required=True)
    p_purple.add_argument("--pack", default="core")
    p_purple.add_argument("--out", default="", help="write markdown report to file")
    p_purple.add_argument("--json", action="store_true")
    p_purple.add_argument("--ci", action="store_true", help="exit 1 if policy B regressed")
    p_purple.add_argument(
        "--save-baseline",
        default="",
        help="persist the measured agent's results as a Policy-CI baseline JSON file",
    )
    p_purple.add_argument(
        "--baseline",
        default="",
        help="compare the measured agent's fresh run against a saved baseline JSON file",
    )
    p_purple.set_defaults(func=_cmd_purple)

    p_bot = sub.add_parser("bot", help="autonomous red bot: continuous unattended probing")
    p_bot.add_argument("--target", default="", help="target URL for the bot")
    p_bot.add_argument("--packs", nargs="+", default=["core"], help="probe packs to cycle")
    p_bot.add_argument("--interval", type=float, default=300.0)
    p_bot.add_argument("--max-rounds", type=int, default=None)
    p_bot.set_defaults(func=_cmd_bot)

    p_kill = sub.add_parser(
        "kill-switch", help="atomic agent revocation drill with measured MTTC"
    )
    p_kill.add_argument("--store", required=True, help="kill-switch SQLite store path")
    p_kill.add_argument("--agent", required=True)
    p_kill.add_argument("--restore", action="store_true", help="re-enable a revoked agent")
    p_kill.set_defaults(func=_cmd_kill_switch)

    return parser


def _run_battle(args) -> dict:
    """Run one multi_turn branching battle against a remote target.

    Provider comes from the environment (never CLI flags):
        ARCHON_ATTACK_PROVIDER_KIND      'anthropic' (native Claude) | 'openai' (default)
        ARCHON_ATTACK_PROVIDER_BASE_URL  e.g. Gemini OpenAI-compat endpoint (openai kind)
        ARCHON_ATTACK_PROVIDER_API_KEY
        ARCHON_ATTACK_PROVIDER_MODEL     default: gemini-2.5-flash / claude-sonnet-4-5
    Returns the attack-tree summary dict.
    """
    from archon_armor.battles import BattleManager
    from archon_core.providers import provider_from_env
    from archon_core.targets.openai_compat import OpenAICompatTarget

    provider = provider_from_env(transport=_target_transport())
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
    result = manager.execute_sync(
        battle.battle_id, target=target, mode="multi_turn",
        goal=args.goal, seeds=list(args.seed), provider=provider,
        width=args.width, max_rounds=args.max_rounds,
    )
    return result.summary["attack_tree"]


def _cmd_battle(args) -> int:
    tree = _run_battle(args)
    print(json.dumps(tree, indent=None if args.ci else 2))
    if args.ci and tree["success"]:
        print("battle: attack succeeded — gate FAILED", file=sys.stderr)
        return 1
    return 0


def _contrib_packs() -> list[str]:
    """Load community packs from ARCHON_CONTRIB_DIR (best-effort)."""
    from archon_armor.probes import load_pack_file

    d = os.environ.get("ARCHON_CONTRIB_DIR", "")
    loaded: list[str] = []
    if d and os.path.isdir(d):
        for f in sorted(os.listdir(d)):
            if f.endswith(".py") and not f.startswith("_"):
                try:
                    loaded.append(load_pack_file(os.path.join(d, f)))
                except Exception as exc:
                    print(f"warn: contrib pack {f}: {exc}", file=sys.stderr)
    return loaded


def _provider_names() -> list[str]:
    """Seam inventory: every LLMProvider implementation archon ships."""
    from archon_core.providers.anthropic import ClaudeNativeProvider
    from archon_core.providers.openai_compat import (
        GeminiOpenAICompatProvider,
        OpenAICompatProvider,
    )

    return [
        OpenAICompatProvider.__name__,
        GeminiOpenAICompatProvider.__name__,
        ClaudeNativeProvider.__name__,
    ]


def _cmd_plugins(args) -> int:
    from archon_armor.probes import PROBE_PACKS
    from archon_core.defenses import layers as defense_layers
    from archon_core.defenses.external import ExternalGuardrailLayer
    from archon_core.targets.mcp_live import probe_tool, scan_live_mcp
    from archon_core.targets.openai_compat import OpenAICompatTarget

    inventory = {
        "probe_packs": {name: len(probes) for name, probes in sorted(PROBE_PACKS.items())},
        "contrib_packs": _contrib_packs(),
        "defense_layers": [
            cls.name
            for cls in vars(defense_layers).values()
            if isinstance(cls, type) and hasattr(cls, "process") and hasattr(cls, "name")
            and cls.__module__.endswith("layers")
        ] + [ExternalGuardrailLayer.name],
        "targets": [OpenAICompatTarget.__name__],
        "providers": _provider_names(),
        "mcp": ["scan_live_mcp", "probe_tool", "McpConfigScanner"],
    }
    # include seam functions imported above so the names survive linting
    inventory["mcp"].append(scan_live_mcp.__name__)
    inventory["mcp"].append(probe_tool.__name__)
    print(json.dumps(inventory, indent=None if args.ci else 2))
    return 0


def _cmd_results(args) -> int:
    from archon_armor.results_store import ResultsStore

    store = ResultsStore(args.db)
    if args.share:
        battle = store.get_battle(args.share)
        if battle is None:
            print(json.dumps({"error": f"unknown battle: {args.share}"}))
            return 2
        token = store.share_token(args.share)
        print(json.dumps({
            "battle_id": args.share,
            "share_token": token,
            "url_fragment": f"?share={token}",
        }, indent=None if getattr(args, "json", False) else 2))
        return 0
    if getattr(args, "sarif", "") or getattr(args, "html", ""):
        battle = store.get_battle(args.sarif or args.html)
        if battle is None:
            print(json.dumps({"error": f"unknown battle: {args.sarif or args.html}"}))
            return 2
        out = {}
        if args.sarif:
            from archon_core.reporting.sarif import render_sarif

            render_sarif(battle, args.sarif)
            out["sarif"] = args.sarif
        if args.html:
            from archon_armor.html_report import write_battle_html

            write_battle_html(battle, args.html)
            out["html"] = args.html
        print(json.dumps(out, indent=2))
        return 0
    rows = store.list_battles(agent_id=args.agent_id, limit=args.limit)
    print(json.dumps(rows, indent=None if getattr(args, "json", False) else 2))
    return 0


def _skill_roots_for(base: str) -> list:
    """Skills dirs to probe for one discovered client path.

    File-style config paths (e.g. ~/.claude/settings.json) map to a sibling
    ``skills/`` directory; directory-style paths are searched directly.
    """
    from pathlib import Path

    p = Path(base)
    if p.is_file():
        return [p.parent / "skills"]
    return [p]


def _scan_client_skills(client_name: str, paths: list[str]) -> list[dict]:
    """Run skill_scan checks on every SKILL.md under a client's paths.

    Never raises: missing dirs and unreadable files degrade gracefully.
    """
    from archon_core.security.skill_scan import Finding, SkillDefinition, scan_skill

    seen: set[str] = set()
    records: list[dict] = []
    for base in paths:
        for root in _skill_roots_for(base):
            try:
                candidates = sorted(root.rglob("SKILL.md"))
            except OSError:
                continue
            for md in candidates:
                if not md.is_file() or str(md) in seen:
                    continue
                seen.add(str(md))
                try:
                    body = md.read_text(encoding="utf-8")
                    findings = scan_skill(
                        SkillDefinition(name=md.stem, body=body, source_path=str(md))
                    )
                except (OSError, UnicodeDecodeError, ValueError):
                    findings = [Finding("W000", "low", f"unreadable skill file: {md.name}")]
                records.append({
                    "client": client_name,
                    "skill_path": str(md),
                    "findings": [
                        {"code": f.code, "severity": f.severity, "message": f.message}
                        for f in findings
                    ],
                })
    return records


def _cmd_discover(args) -> int:
    from archon_core.discovery.clients import discover_clients, summarize_discovery

    found = discover_clients(root=getattr(args, "root", None))
    summary = summarize_discovery(found)
    print(json.dumps(summary, indent=None if getattr(args, "json", False) else 2))
    if getattr(args, "scan_skills", False):
        for client in found:
            for record in _scan_client_skills(client.name, client.found_paths):
                print(json.dumps(record))
    return 0


def _cmd_fleet(args) -> int:
    from archon_armor.baselines import BaselineStore
    from archon_armor.fleet import FleetSummary
    from archon_core.registry.sqlite import SqliteRegistry

    registry = SqliteRegistry(args.registry)
    try:
        metrics = FleetSummary(
            registry=registry,
            baselines=BaselineStore(args.baselines),
            min_block_rate=args.min_block_rate,
        ).metrics()
    except FileNotFoundError as exc:
        print(json.dumps({"error": f"baselines not found: {exc}"}))
        return 2
    print(json.dumps(metrics, indent=None if args.json else 2))
    if args.ci and metrics["degraded"]:
        print(
            f"fleet: degraded agents under min block rate: "
            f"{', '.join(metrics['degraded'])}",
            file=sys.stderr,
        )
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
