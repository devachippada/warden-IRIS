"""
warden/pipeline.py

Sequencing only — no decisions live here.

    input
      → guard                    reject bad / injected input before any model sees it
      → primary planner (+retry) natural language → JSON plan
      → analysis pass 1          facts
      → validator planner        only if the plan changes state; gets the ORIGINAL input
      → comparator               disagreement → hard stop, human decides
      → analysis pass 2          signals
      → policy                   proceed | require_confirmation | reject
      → dry run + preflight      what exactly would happen, checked against the real disk
      → approval                 approve | reject (human, or auto for read-only if allowed)
      → executor                 sandboxed, step by step, stops at first failure
      → audit seal               hash-chained record of everything above
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from warden import analysis, policy
from warden.audit import AuditLog
from warden.comparator import compare
from warden.executor import Executor, SandboxError
from warden.guard import guard
from warden.planner import Planner, plan_with_retry

# approver(dry_run) -> True to approve, False to reject
Approver = Callable[[dict], bool]


@dataclass
class RunResult:
    run_id: str
    status: str                      # rejected | declined | executed | failed
    stage: str                       # last stage reached
    message: str
    plan: dict | None = None
    verdict: dict | None = None
    dry_run: dict | None = None
    outputs: list[dict] = field(default_factory=list)


class Runtime:
    def __init__(self, planner: Planner, executor: Executor, audit: AuditLog,
                 validator: Planner | None = None, approver: Approver | None = None,
                 auto_approve_read_only: bool = False):
        self.planner = planner
        self.validator = validator
        self.executor = executor
        self.audit = audit
        self.approver = approver or (lambda _dry: False)
        self.auto_approve_read_only = auto_approve_read_only

    def run(self, user_input: str) -> RunResult:
        run_id = self.audit.start()
        record: dict = {"input": user_input, "planner": self.planner.name}
        try:
            result = self._run(run_id, user_input, record)
        except Exception as e:  # never let one bad run crash the host
            result = RunResult(run_id, "failed", "internal", f"internal error: {e}")
        record.update(status=result.status, stage=result.stage, message=result.message)
        self.audit.seal(run_id, record)
        return result

    def _run(self, run_id: str, user_input: str, rec: dict) -> RunResult:
        # 1. guard
        g = guard(user_input)
        rec["guard"] = {"passed": g.passed, "reason": g.reason}
        if not g.passed:
            return RunResult(run_id, "rejected", "guard", f"input rejected: {g.reason}")

        # 2. primary plan
        primary = plan_with_retry(self.planner, g.content)
        rec["primary"] = {k: primary.get(k) for k in ("valid", "error", "detail", "attempts", "raw_output")}
        if not primary["valid"]:
            if primary["error"] == "cannot_plan":
                msg = f"could not plan — {primary['detail']}. Please rephrase."
            else:
                msg = f"planner failed after {primary['attempts']} attempt(s): {primary['error']} — {primary.get('detail')}"
            return RunResult(run_id, "rejected", "plan", msg)
        plan = primary["plan"]
        rec["plan"] = plan

        # 3. pass 1
        f = analysis.facts(plan)

        # 4. independent validation for state-changing plans
        if f["state_change"]:
            if self.validator is None:
                rec["validator"] = "not configured"
            else:
                second = plan_with_retry(self.validator, g.content)  # original input, never plan
                if not second["valid"]:
                    rec["validator"] = {"valid": False, "error": second["error"]}
                    return RunResult(run_id, "rejected", "validator",
                                     f"validator could not confirm a state-changing plan ({second['error']})",
                                     plan=plan)
                cmp = compare(plan, second["plan"])
                rec["validator"] = {"valid": True, "comparison": cmp}
                if not cmp["match"]:
                    return RunResult(run_id, "rejected", "comparator",
                                     "primary and validator disagree: "
                                     f"{cmp['only_in_primary']} vs {cmp['only_in_validator']}. "
                                     "Not resolving automatically — please clarify.",
                                     plan=plan)

        # 5. pass 2 + policy
        a = analysis.signals(f)
        v = policy.decide(a)
        verdict = {"verdict": v.verdict, "rule": v.rule, "reason": v.reason}
        rec["signals"], rec["verdict"] = a["signals"], verdict
        if v.verdict == policy.REJECT:
            return RunResult(run_id, "rejected", "policy", f"rejected by policy: {v.reason}",
                             plan=plan, verdict=verdict)

        # 6. dry run with filesystem preflight
        planned: set = set()
        steps = []
        for s in plan["steps"]:
            pf = self.executor.preflight(s, planned)
            steps.append({"id": s["id"], "action": s["action"], "args": s["args"],
                          "risk": s["risk"], **pf})
        dry = {"intent": plan["intent"], "verdict": verdict, "steps": steps}
        rec["dry_run"] = dry
        bad = [st for st in steps if not st["ok"]]
        if bad:
            return RunResult(run_id, "rejected", "preflight",
                             "preflight failed: " + "; ".join(f"{b['id']}: {b['note']}" for b in bad),
                             plan=plan, verdict=verdict, dry_run=dry)

        # 7. approval
        if v.verdict == policy.PROCEED and self.auto_approve_read_only:
            approved, how = True, "auto (read-only)"
        else:
            approved, how = bool(self.approver(dry)), "human"
        rec["approval"] = {"approved": approved, "by": how}
        if not approved:
            return RunResult(run_id, "declined", "approval", "not approved — nothing was executed",
                             plan=plan, verdict=verdict, dry_run=dry)

        # 8. execute
        outputs = []
        for s in plan["steps"]:
            try:
                out = self.executor.run_step(s)
                outputs.append({"id": s["id"], "ok": True, "output": out})
            except (SandboxError, OSError) as e:
                outputs.append({"id": s["id"], "ok": False, "output": str(e)})
                rec["outputs"] = _trim(outputs)
                return RunResult(run_id, "failed", "execute",
                                 f"{s['id']} failed: {e} — remaining steps skipped",
                                 plan=plan, verdict=verdict, dry_run=dry, outputs=outputs)
        rec["outputs"] = _trim(outputs)
        return RunResult(run_id, "executed", "execute", f"executed {len(outputs)} step(s)",
                         plan=plan, verdict=verdict, dry_run=dry, outputs=outputs)


def _trim(outputs: list[dict], limit: int = 2000) -> list[dict]:
    """Keep the audit log small: store at most `limit` chars of each output."""
    return [{**o, "output": o["output"][:limit]} for o in outputs]
