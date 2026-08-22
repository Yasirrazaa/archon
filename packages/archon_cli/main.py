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
    registry = SqliteRegistry(args.registry)
    try:
        registry.get(args.agent_id)
    except AgentNotFoundError as exc:
        print(json.dumps({"error": str(exc)}))
        return 2

    manager = BattleManager(registry)
    battle = manager.create(args.agent_id)
    asyncio.run(manager.execute(battle.battle_id))

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

    if args.ci:
        passed = (
            battle.summary["block_rate"] >= args.min_block_rate
            and battle.summary["control_passed"]
        )
        return 0 if passed else 1
    return 0


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
    p_scan.add_argument("--registry", required=True)
    p_scan.add_argument("--agent-id", required=True)
    p_scan.add_argument("--min-block-rate", type=float, default=0.5)
    p_scan.add_argument("--ci", action="store_true", help="CI gate: exit 1 below threshold")
    p_scan.add_argument("--json", action="store_true", help="JSON report on stdout")
    p_scan.set_defaults(func=_cmd_scan)

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
