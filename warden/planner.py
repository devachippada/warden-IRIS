"""
warden/planner.py

Planning backends + retry. The planner turns natural language into a plan.
It has no authority — its output is only a suggestion that every later gate
can reject.

Backends
--------
OllamaPlanner  calls a local model through Ollama's /api/chat endpoint.
MockPlanner    deterministic keyword planner. No model needed — used for
               tests, CI and trying the runtime out.

Retry policy (plan_with_retry)
------------------------------
invalid_json, schema_violation  -> retry (a different sample may succeed)
cannot_plan                     -> no retry (input is ambiguous; ask the human)
backend_error                   -> no retry (infrastructure problem, surface it)
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Protocol

from warden.schema import validate

PROMPT_PATH = Path(__file__).parent / "prompts" / "planner.txt"
MAX_RETRIES = 2
RETRYABLE = {"invalid_json", "schema_violation"}


class Planner(Protocol):
    name: str

    def generate(self, user_input: str) -> str:
        """Return the raw model output (expected to be JSON)."""
        ...


class OllamaPlanner:
    def __init__(self, model: str, temperature: float = 0.2,
                 url: str = "http://localhost:11434/api/chat", timeout: float = 120.0):
        self.name = f"ollama:{model}"
        self.model = model
        self.temperature = temperature
        self.url = url
        self.timeout = timeout

    def generate(self, user_input: str) -> str:
        payload = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "options": {"temperature": self.temperature},
            "messages": [
                {"role": "system", "content": PROMPT_PATH.read_text()},
                {"role": "user", "content": user_input},
            ],
        }
        req = urllib.request.Request(
            self.url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read())["message"]["content"]


class MockPlanner:
    """
    A tiny rule-based planner so the runtime is usable without a GPU.
    Understands requests like:
        read notes.txt / show me notes.txt
        list docs
        search for TODO in src
        write "hello" to greeting.txt
        append "more" to log.txt
        make folder archive
        delete old.txt
    Multiple requests can be joined with "then" / "and then".
    """

    def __init__(self, name: str = "mock", variant: int = 0):
        self.name = name
        self.variant = variant  # lets tests simulate a disagreeing second slot

    _RULES = [
        (re.compile(r'^(?:write|save)\s+"(.*)"\s+(?:to|into)\s+(\S+)$', re.I),
         lambda m: ("write_file", {"path": m[2], "content": m[1]}, "medium")),
        (re.compile(r'^append\s+"(.*)"\s+to\s+(\S+)$', re.I),
         lambda m: ("append_file", {"path": m[2], "content": m[1]}, "low")),
        (re.compile(r'^(?:delete|remove)\s+(?:the\s+file\s+)?(\S+)$', re.I),
         lambda m: ("delete_file", {"path": m[1]}, "high")),
        (re.compile(r'^(?:make|create)\s+(?:a\s+)?(?:folder|directory|dir)\s+(\S+)$', re.I),
         lambda m: ("make_dir", {"path": m[1]}, "low")),
        (re.compile(r'^(?:search|find)\s+(?:for\s+)?"?([^"]+?)"?\s+in\s+(\S+)$', re.I),
         lambda m: ("search_text", {"query": m[1], "path": m[2]}, "low")),
        (re.compile(r'^(?:list|ls)\s+(?:the\s+)?(?:files\s+in\s+)?(\S+)$', re.I),
         lambda m: ("list_dir", {"path": m[1]}, "low")),
        (re.compile(r'^(?:read|show(?:\s+me)?|open|cat)\s+(?:the\s+file\s+)?(\S+)$', re.I),
         lambda m: ("read_file", {"path": m[1]}, "low")),
    ]

    def generate(self, user_input: str) -> str:
        # drop a sentence-ending period ("read a.txt.") but keep a bare "." path
        parts = [re.sub(r"(?<=\w)\.$", "", p.strip())
                 for p in re.split(r"\s*(?:,\s*)?(?:and\s+)?then\s+", user_input) if p.strip()]
        steps = []
        for i, part in enumerate(parts, 1):
            for pattern, build in self._RULES:
                m = pattern.match(part)
                if m:
                    action, args, risk = build(m)
                    if self.variant and action == "delete_file":
                        action = "write_file"  # simulated disagreement
                    steps.append({"id": f"step_{i}", "action": action, "args": args, "risk": risk})
                    break
            else:
                return json.dumps({"error": "cannot_plan",
                                   "reason": f"could not interpret: {part!r}"})

        cats = {s["action"] for s in steps}
        if "delete_file" in cats:
            intent = "destructive"
        elif len(steps) > 1:
            intent = "multi_step"
        elif cats <= {"read_file", "list_dir", "search_text"}:
            intent = "read_only"
        else:
            intent = "single_action"
        return json.dumps({"intent": intent, "steps": steps})


def plan_with_retry(planner: Planner, user_input: str, max_retries: int = MAX_RETRIES) -> dict:
    """
    Generate and validate a plan. Returns the validation dict enriched with
    `attempts` and `raw_output`. Never raises.
    """
    result: dict = {}
    raw = None
    for attempt in range(1, max_retries + 2):
        try:
            raw = planner.generate(user_input)
        except (urllib.error.URLError, OSError, KeyError, ValueError) as e:
            return {"valid": False, "error": "backend_error",
                    "detail": f"{planner.name}: {e}", "attempts": attempt, "raw_output": raw}
        result = validate(raw)
        result.update(attempts=attempt, raw_output=raw)
        if result["valid"] or result["error"] not in RETRYABLE:
            return result
    return result
