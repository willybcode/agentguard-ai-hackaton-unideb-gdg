"""AgentGuard command line.

    python -m ag check plan.json        vet a plan, execute nothing (CI-friendly)
    python -m ag check -                read the plan from stdin
    python -m ag run "task"             plan with a model, then vet and simulate
    python -m ag suite                  the OWASP ASI01..ASI10 attack suite
    python -m ag serve                  the demo web UI
    python -m ag policy                 print the active policy as JSON
    python -m ag doctor                 check the endpoint, models and policy

Exit codes: 0 clean, 1 something was refused or leaked, 2 usage or config error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from . import owl
from .audit import AuditLog
from .config import config_from_env, load_dotenv
from .guard import AgentGuard, dump_policy, load_policy
from .policy import ApprovalBudget, default_policy

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _colour(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


class Out:
    def __init__(self, stream=None) -> None:
        # Resolve at construction, not at definition: a default argument would
        # bind the original sys.stdout and break redirect_stdout.
        self.stream = stream if stream is not None else sys.stdout
        self.on = _colour(self.stream) and not os.environ.get("NO_COLOR")

    def __call__(self, text: str = "") -> None:
        self.stream.write(text + "\n")

    def paint(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self.on else text


def _load_plan(source: str) -> list[dict[str, Any]]:
    text = sys.stdin.read() if source == "-" else open(source, encoding="utf-8").read()
    parsed = json.loads(text)
    if isinstance(parsed, dict):
        parsed = parsed.get("steps", [parsed])
    if not isinstance(parsed, list):
        raise ValueError("plan must be a JSON array of {tool, args} objects")
    return [step for step in parsed if isinstance(step, dict)]


def cmd_check(args, out: Out) -> int:
    """Vet a plan offline. Nothing is executed, so this is safe in CI."""
    policy = load_policy(args.policy) if args.policy else default_policy()
    guard = AgentGuard(policy, audit=AuditLog(), budget=ApprovalBudget())

    try:
        plan = _load_plan(args.plan)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        out(out.paint(RED, f"cannot read plan: {exc}"))
        return 2

    refused = 0
    for call in guard.vet_all(plan, task=args.task or ""):
        if call.refused:
            refused += 1
            mark = out.paint(RED, "REFUSE")
        elif call.needs_human:
            mark = out.paint(YELLOW, "HUMAN ")
        else:
            mark = out.paint(GREEN, "ALLOW ")
        detail = f"{call.tool}({json.dumps(call.args, default=str)[:70]})"
        out(f"  {mark} {detail}")
        if call.refused or call.needs_human:
            out(f"        {out.paint(DIM, call.rule + ' — ' + call.decision.reason)}")
            if call.asi_label:
                out(f"        {out.paint(DIM, call.asi_label)}")

    report = guard.report()
    out()
    out(f"  {len(plan)} calls, {refused} refused, audit {report['entries']} entries "
        f"{'(intact)' if report['intact'] else '(TAMPERED)'}")
    return 1 if refused else 0


def cmd_run(args, out: Out) -> int:
    """Plan with the configured model, then vet and simulate."""
    from .demo import main as demo_main

    if args.task:
        return demo_main(["--task", args.task])
    out(out.paint(RED, "usage: python -m ag run \"<task>\""))
    return 2


def cmd_suite(args, out: Out) -> int:
    from .demo import main as demo_main

    extra = []
    if args.json:
        extra.append("--json")
    if args.save:
        extra += ["--save", args.save]
    return demo_main(extra)


def cmd_serve(args, out: Out) -> int:
    from .server import serve

    serve(port=args.port)
    return 0


def cmd_policy(args, out: Out) -> int:
    policy = load_policy(args.policy) if args.policy else default_policy()
    out(json.dumps(dump_policy(policy), indent=2))
    return 0


def cmd_doctor(args, out: Out) -> int:
    """Check everything the demo needs, before you are on stage."""
    load_dotenv()
    cfg = config_from_env()
    problems = 0

    out(out.paint(BOLD, "AgentGuard doctor"))
    out()

    out(f"  endpoint        {cfg.api_url}")
    out(f"  planner         {cfg.model} ({cfg.model_type})")
    out(f"  adjudicator     {cfg.adjudicator_model or 'off'}")
    out(f"  max tokens      {cfg.max_tokens}")
    out(f"  fallback        {'mock' if cfg.fallback_to_mock else 'off'}")

    if not cfg.configured:
        out(f"\n  {out.paint(YELLOW, 'endpoint not configured')} — running on the built-in mock")
        out(out.paint(DIM, "  set AG_API_URL in .env to use a real model"))

    from .llm import build_provider, probe

    provider = build_provider(cfg)
    result = probe(provider)
    if result.get("ok"):
        out(f"\n  planner probe   {out.paint(GREEN, 'ok')} ({provider.name})")
    else:
        problems += 1
        out(f"\n  planner probe   {out.paint(RED, 'failed')} — {result.get('error', '')[:90]}")
    if result.get("fell_back"):
        out(f"  {out.paint(YELLOW, 'fell back to the mock planner')}")

    if cfg.adjudicator_model:
        from .adjudicate import probe_adjudicator

        verdict = probe_adjudicator(cfg)
        if verdict.get("ok"):
            out(f"  adjudicator     {out.paint(GREEN, 'ok')} "
                f"(p={verdict['confidence']}, {verdict['reason']})")
        else:
            problems += 1
            out(f"  adjudicator     {out.paint(RED, 'failed')} — {verdict.get('error', '')}")

    policy = default_policy()
    out(f"  policy          {len(policy.tools)} tools, "
        f"{len(policy.forbidden_tokens)} forbidden tokens")

    out()
    if problems:
        out(out.paint(YELLOW, f" {problems} problem(s) — the mock planner will be used"))
        return 1
    out(out.paint(GREEN, " all checks passed"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ag", description="AgentGuard — policy gate for LLM tool calls"
    )
    sub = parser.add_subparsers(dest="command")

    p_check = sub.add_parser("check", help="vet a plan without executing it")
    p_check.add_argument("plan", help="path to a JSON plan, or - for stdin")
    p_check.add_argument("--policy", help="path to a policy JSON file")
    p_check.add_argument("--task", help="the user request the plan answers")
    p_check.set_defaults(func=cmd_check)

    p_run = sub.add_parser("run", help="plan a task with the model, then vet it")
    p_run.add_argument("task", nargs="?", help="the task to plan")
    p_run.set_defaults(func=cmd_run)

    p_suite = sub.add_parser("suite", help="run the OWASP ASI01..ASI10 attack suite")
    p_suite.add_argument("--json", action="store_true")
    p_suite.add_argument("--save", metavar="PATH")
    p_suite.set_defaults(func=cmd_suite)

    p_serve = sub.add_parser("serve", help="start the demo web UI")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.set_defaults(func=cmd_serve)

    p_policy = sub.add_parser("policy", help="print the active policy")
    p_policy.add_argument("--policy", help="path to a policy JSON file")
    p_policy.set_defaults(func=cmd_policy)

    p_doctor = sub.add_parser("doctor", help="check endpoint, models and policy")
    p_doctor.set_defaults(func=cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    out = Out()

    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    load_dotenv()
    return args.func(args, out)


if __name__ == "__main__":
    raise SystemExit(main())
