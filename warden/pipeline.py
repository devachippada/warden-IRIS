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
    status: str                      # rejected | awaiting_approval | declined | executed | failed
    stage: str                       # last stage reached
    message: str
    plan: dict | None = None
    verdict: dict | None = None
    dry_run: dict | None = None
    outputs: list[dict] = field(default_factory=list)
    _record: dict = field(default_factory=dict, repr=False, compare=False)

    def public(self) -> dict:
        """JSON-safe view for APIs."""
        return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}


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
        """Full pipeline in one call, using the synchronous approver."""
        pending = self.prepare(user_input)
        if pending.status != "awaiting_approval":
            return pending
        if pending.verdict["verdict"] == policy.PROCEED and self.auto_approve_read_only:
            return self.commit(pending, approved=True, by="auto (read-only)")
        return self.commit(pending, approved=bool(self.approver(pending.dry_run)), by="human")

    def prepare(self, user_input: str) -> RunResult:
        """
        Run every gate up to (not including) approval.
        Returns status "awaiting_approval" with a dry run, or a final result.
        Final results are sealed in the audit log; pending ones are sealed by commit().
        """
        run_id = self.audit.start()
        record: dict = {"input": user_input, "planner": self.planner.name}
        try:
            result = self._run(run_id, user_input, record)
        except Exception as e:  # never let one bad run crash the host
            result = RunResult(run_id, "failed", "internal", f"internal error: {e}")
        result._record = record
        if result.status != "awaiting_approval":
            self._seal(result)
        return result

    def commit(self, pending: "RunResult", approved: bool, by: str = "human") -> RunResult:
        """Approve or reject a prepared run. Executes only if approved."""
        if pending.status != "awaiting_approval":
            raise ValueError("run is not awaiting approval")
        rec = pending._record
        rec["approval"] = {"approved": approved, "by": by}
        base = dict(run_id=pending.run_id, plan=pending.plan,
                    verdict=pending.verdict, dry_run=pending.dry_run)
        if not approved:
            result = RunResult(status="declined", stage="approval",
                               message="not approved — nothing was executed", **base)
        else:
            result = self._execute(pending.plan, rec, base)
        result._record = rec
        pending.status = "committed"  # a pending run can only be committed once
        self._seal(result)
        return result

    def _seal(self, result: "RunResult") -> None:
        rec = result._record
        rec.update(status=result.status, stage=result.stage, message=result.message)
        self.audit.seal(result.run_id, rec)

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

        return RunResult(run_id, "awaiting_approval", "approval", "waiting for approval",
                         plan=plan, verdict=verdict, dry_run=dry)

    def _execute(self, plan: dict, rec: dict, base: dict) -> RunResult:
        outputs = []
        for s in plan["steps"]:
            try:
                out = self.executor.run_step(s)
                outputs.append({"id": s["id"], "ok": True, "output": out})
            except (SandboxError, OSError) as e:
                outputs.append({"id": s["id"], "ok": False, "output": str(e)})
                rec["outputs"] = _trim(outputs)
                return RunResult(status="failed", stage="execute",
                                 message=f"{s['id']} failed: {e} — remaining steps skipped",
                                 outputs=outputs, **base)
        rec["outputs"] = _trim(outputs)
        return RunResult(status="executed", stage="execute",
                         message=f"executed {len(outputs)} step(s)", outputs=outputs, **base)


def _trim(outputs: list[dict], limit: int = 2000) -> list[dict]:
    """Keep the audit log small: store at most `limit` chars of each output."""
    return [{**o, "output": o["output"][:limit]} for o in outputs]
