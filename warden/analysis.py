"""
warden/analysis.py

Two-pass plan analysis.

Pass 1 — facts()   Deterministic facts only. No interpretation.
Pass 2 — signals() Interpretation only. Consumes pass-1 facts and may not
                   modify them (they are returned as a frozen copy).

If something misfires, you know which pass broke.
"""

from __future__ import annotations

import copy
from types import MappingProxyType

from warden import actions

IMPLICIT_DESTRUCTIVE_TERMS = frozenset({
    "clean", "clear", "remove", "prune", "reset", "purge", "wipe", "flush",
    "truncate", "erase", "nuke", "zero", "trim",
})


def facts(plan: dict) -> dict:
    """Pass 1: what the plan literally contains."""
    steps = plan["steps"]
    cats = [actions.category(s["action"]) for s in steps]
    unknown = [s["action"] for s, c in zip(steps, cats) if c == actions.UNKNOWN]
    irreversible = sorted({
        actions.canonical(s["action"]) for s, c in zip(steps, cats)
        if c != actions.UNKNOWN and not actions.is_reversible(s["action"])
    })

    terms: list[str] = []
    for s in steps:
        terms.append(s["action"].lower())
        for k, v in s["args"].items():
            terms.append(str(k).lower())
            if isinstance(v, str):
                terms.extend(v.lower().replace("/", " ").replace("_", " ").split())

    return {
        "step_count": len(steps),
        "categories": cats,
        "reads": cats.count("read"),
        "writes": cats.count("write"),
        "deletes": cats.count("delete"),
        "unknown_actions": unknown,
        "irreversible_actions": irreversible,
        "state_change": "write" in cats or "delete" in cats,
        "multi_step": len(steps) > 1,
        "all_steps_have_args": all(bool(s["args"]) for s in steps),
        "declared_intent": plan["intent"],
        "terms": sorted(set(terms)),
    }


def signals(pass1: dict) -> dict:
    """
    Pass 2: interpretation. Returns {"facts": <frozen pass1>, "signals": {...}}.

    implicit_destructive uses a two-step gate:
        1. a destructive-sounding term appears in the plan's actions/args
        2. the plan actually changes state (write or delete)
    Both must hold — "explain clearly" alone never trips it.
    """
    frozen = MappingProxyType(copy.deepcopy(pass1))

    matched = sorted(IMPLICIT_DESTRUCTIVE_TERMS & set(frozen["terms"]))
    implicit = bool(matched) and frozen["state_change"]

    declared = frozen["declared_intent"]
    # The model's declared intent should agree with the facts. Disagreement is
    # a signal on its own: the model either misunderstood or is being steered.
    intent_mismatch = (
        (declared == "read_only" and frozen["state_change"])
        or (declared != "destructive" and frozen["deletes"] > 0)
    )

    return {
        "facts": frozen,
        "signals": {
            "implicit_destructive": implicit,
            "implicit_terms": matched if implicit else [],
            "explicit_destructive": declared == "destructive",
            "intent_mismatch": intent_mismatch,
        },
    }
