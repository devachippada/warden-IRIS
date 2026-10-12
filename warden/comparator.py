"""
warden/comparator.py

Compares the primary plan against the independent validator plan.

Actions are normalised to canonical names (so `rm` and `delete_file` agree),
then compared as sorted lists together with each step's primary target.
No fuzzy matching, no auto-resolution: a mismatch is a hard stop and the
human decides.
"""

from __future__ import annotations

from warden import actions


def _signature(plan: dict) -> list[tuple[str, str]]:
    sig = []
    for s in plan["steps"]:
        name = actions.canonical(s["action"]) or f"?{s['action']}"
        target = str(s["args"].get("path", ""))
        sig.append((name, target))
    return sorted(sig)


def compare(primary: dict, validator: dict) -> dict:
    a, b = _signature(primary), _signature(validator)
    match = a == b
    return {
        "match": match,
        "primary": a,
        "validator": b,
        "only_in_primary": sorted(set(a) - set(b)),
        "only_in_validator": sorted(set(b) - set(a)),
    }
