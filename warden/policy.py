"""
warden/policy.py

The decision engine. Final authority. No model touches this layer.

Rules are evaluated in order; the first rule that fires decides.
Loss aversion: asking when unnecessary is always cheaper than acting when wrong.

Verdicts:
    proceed               safe to run after the dry run is shown
    require_confirmation  human must explicitly approve
    reject                will not run, regardless of approval
"""

from __future__ import annotations

from dataclasses import dataclass

PROCEED = "proceed"
CONFIRM = "require_confirmation"
REJECT = "reject"


@dataclass(frozen=True)
class Verdict:
    verdict: str
    rule: str
    reason: str


def decide(analysis: dict) -> Verdict:
    f = analysis["facts"]
    s = analysis["signals"]

    if f["unknown_actions"]:
        return Verdict(REJECT, "unknown_action",
                       f"unknown action(s) {f['unknown_actions']} — cannot assess safety")

    if not f["all_steps_have_args"]:
        return Verdict(REJECT, "unbounded_step", "a step has no arguments — scope is unbounded")

    if s["intent_mismatch"]:
        return Verdict(CONFIRM, "intent_mismatch",
                       f"declared intent {f['declared_intent']!r} does not match the actions")

    if f["irreversible_actions"]:
        return Verdict(CONFIRM, "irreversible",
                       f"irreversible action(s): {f['irreversible_actions']}")

    if s["explicit_destructive"]:
        return Verdict(CONFIRM, "explicit_destructive", "plan is declared destructive")

    if s["implicit_destructive"]:
        return Verdict(CONFIRM, "implicit_destructive",
                       f"destructive wording {s['implicit_terms']} on a state-changing plan")

    if f["multi_step"] and f["state_change"]:
        return Verdict(CONFIRM, "multi_step_state_change",
                       "multi-step plan that changes state")

    if f["state_change"]:
        return Verdict(CONFIRM, "state_change", "plan changes state")

    return Verdict(PROCEED, "read_only", "read-only plan, no blocking rules fired")
