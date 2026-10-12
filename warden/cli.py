"""
warden/cli.py

    warden run "read notes.txt"              one request
    warden shell                             interactive session
    warden log [-n 10]                       recent runs from the audit log
    warden verify                            check the audit hash chain
    warden actions                           list the action vocabulary

Planner selection:
    --planner mock                           (default) no model needed
    --planner ollama --model warden-primary  local model via Ollama
    --validator-model warden-validator       second, independent model for risky plans
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from warden import __version__, actions
from warden.audit import AuditLog
from warden.executor import Executor
from warden.pipeline import Runtime
from warden.planner import MockPlanner, OllamaPlanner

BOLD, DIM, RED, GREEN, YELLOW, RESET = ("\033[1m", "\033[2m", "\033[31m",
                                         "\033[32m", "\033[33m", "\033[0m")
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    BOLD = DIM = RED = GREEN = YELLOW = RESET = ""


def render_dry_run(dry: dict) -> None:
    v = dry["verdict"]
    color = GREEN if v["verdict"] == "proceed" else YELLOW
    print(f"\n{BOLD}── dry run ─────────────────────────────────────────{RESET}")
    print(f"intent:  {dry['intent']}")
    print(f"verdict: {color}{v['verdict']}{RESET}  {DIM}({v['rule']}: {v['reason']}){RESET}")
    for s in dry["steps"]:
        mark = f"{GREEN}✓{RESET}" if s["ok"] else f"{RED}✗{RESET}"
        target = s["args"].get("path", "")
        print(f"  {mark} {s['id']:<8} {s['action']:<12} {target:<24} [{s['risk']}] {DIM}{s['note']}{RESET}")
    print(f"{BOLD}────────────────────────────────────────────────────{RESET}")


def interactive_approver(dry: dict) -> bool:
    render_dry_run(dry)
    try:
        answer = input("approve? [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes", "approve")


def build_runtime(args) -> Runtime:
    if args.planner == "ollama":
        planner = OllamaPlanner(args.model, temperature=0.2, url=args.ollama_url)
        validator = (OllamaPlanner(args.validator_model, temperature=0.4, url=args.ollama_url)
                     if args.validator_model else None)
    else:
        planner = MockPlanner("mock-primary")
        validator = MockPlanner("mock-validator")
    home = Path(args.home)
    return Runtime(
        planner=planner,
        validator=validator,
        executor=Executor(args.workspace),
        audit=AuditLog(home / "audit.db"),
        approver=interactive_approver,
        auto_approve_read_only=args.auto_read,
    )


def print_result(res) -> None:
    color = {"executed": GREEN, "declined": YELLOW}.get(res.status, RED)
    if res.dry_run and res.stage in ("preflight", "execute") and res.status != "executed":
        render_dry_run(res.dry_run)
    for o in res.outputs:
        print(f"\n{DIM}[{o['id']}]{RESET}\n{o['output']}")
    print(f"\n{color}{res.status}{RESET} at {res.stage}: {res.message}  {DIM}run {res.run_id[:8]}{RESET}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="warden", description="Gated AI execution runtime.")
    p.add_argument("--version", action="version", version=f"warden {__version__}")
    p.add_argument("--workspace", default=os.environ.get("WARDEN_WORKSPACE", "./workspace"),
                   help="sandbox directory all actions are confined to")
    p.add_argument("--home", default=os.environ.get("WARDEN_HOME", "./.warden"),
                   help="where the audit log lives")
    p.add_argument("--planner", choices=["mock", "ollama"], default="mock")
    p.add_argument("--model", default="warden-primary")
    p.add_argument("--validator-model", default=None)
    p.add_argument("--ollama-url", default="http://localhost:11434/api/chat")
    p.add_argument("--auto-read", action="store_true",
                   help="run read-only plans without asking (writes/deletes always ask)")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run one request")
    r.add_argument("request", nargs="+")
    sub.add_parser("shell", help="interactive session")
    lg = sub.add_parser("log", help="show recent runs")
    lg.add_argument("-n", type=int, default=10)
    lg.add_argument("--json", action="store_true")
    sub.add_parser("verify", help="verify the audit hash chain")
    sub.add_parser("actions", help="list known actions")

    args = p.parse_args(argv)

    if args.cmd == "actions":
        for spec in actions.REGISTRY.values():
            rev = "reversible" if spec.reversible else "IRREVERSIBLE"
            print(f"{spec.name:<12} {spec.category:<7} {rev:<13} {spec.description}")
        return 0

    audit = AuditLog(Path(args.home) / "audit.db")

    if args.cmd == "verify":
        problems = audit.verify()
        if problems:
            print(f"{RED}audit chain BROKEN{RESET}")
            for prob in problems:
                print(f"  {prob}")
            return 1
        print(f"{GREEN}audit chain intact{RESET}")
        return 0

    if args.cmd == "log":
        rows = audit.recent(args.n)
        if args.json:
            print(json.dumps(rows, indent=2))
            return 0
        for row in rows:
            rec = row["record"]
            print(f"{row['seq']:>4}  {row['started_at'][:19]}  {rec.get('status', '?'):<9} "
                  f"{rec.get('stage', '?'):<10} {rec.get('input', '')[:50]}")
        return 0

    runtime = build_runtime(args)

    if args.cmd == "run":
        res = runtime.run(" ".join(args.request))
        print_result(res)
        return 0 if res.status in ("executed", "declined") else 1

    print(f"{BOLD}warden {__version__}{RESET} — workspace: {runtime.executor.root}  (ctrl-d to quit)")
    while True:
        try:
            line = input(f"{BOLD}warden>{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if line in ("exit", "quit"):
            return 0
        if line:
            print_result(runtime.run(line))


if __name__ == "__main__":
    sys.exit(main())
