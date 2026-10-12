"""
warden/schema.py

Plan schema and validator. Never raises.

A plan is strict JSON produced by the planning model:

    {
      "intent": "read_only" | "single_action" | "multi_step" | "destructive",
      "steps": [
        {"id": "step_1", "action": "read_file", "args": {"path": "notes.txt"}, "risk": "low"}
      ]
    }

A model may also refuse explicitly with:
    {"error": "cannot_plan", "reason": "..."}
"""

from __future__ import annotations

import json
import re

import jsonschema

PLAN_SCHEMA: dict = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["intent", "steps"],
    "additionalProperties": False,
    "properties": {
        "intent": {
            "type": "string",
            "enum": ["read_only", "single_action", "multi_step", "destructive"],
        },
        "steps": {
            "type": "array",
            "minItems": 1,
            "maxItems": 20,
            "items": {
                "type": "object",
                "required": ["id", "action", "args", "risk"],
                "additionalProperties": False,
                "properties": {
                    "id": {"type": "string", "pattern": "^step_[a-z0-9_]+$"},
                    "action": {"type": "string", "minLength": 1},
                    "args": {"type": "object"},
                    "risk": {"type": "string", "enum": ["low", "medium", "high"]},
                },
            },
        },
    },
}

_FENCE_RE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.DOTALL)


def _strip_fences(raw: str) -> str:
    """Models love markdown fences. Remove one wrapping fence if present — nothing more."""
    m = _FENCE_RE.match(raw.strip())
    return m.group(1) if m else raw.strip()


def validate(raw: str) -> dict:
    """
    Returns one of:
        {"valid": True,  "plan": dict}
        {"valid": False, "error": "invalid_json",     "detail": str}
        {"valid": False, "error": "cannot_plan",      "detail": str}
        {"valid": False, "error": "schema_violation", "detail": str}
    """
    try:
        parsed = json.loads(_strip_fences(raw or ""))
    except (json.JSONDecodeError, TypeError) as e:
        return {"valid": False, "error": "invalid_json", "detail": str(e)}

    if isinstance(parsed, dict) and parsed.get("error") == "cannot_plan":
        return {"valid": False, "error": "cannot_plan",
                "detail": str(parsed.get("reason", "no reason given"))}

    try:
        jsonschema.validate(instance=parsed, schema=PLAN_SCHEMA)
    except jsonschema.ValidationError as e:
        return {"valid": False, "error": "schema_violation", "detail": e.message}

    ids = [s["id"] for s in parsed["steps"]]
    if len(ids) != len(set(ids)):
        return {"valid": False, "error": "schema_violation", "detail": "duplicate step ids"}

    return {"valid": True, "plan": parsed}
