"""
warden/guard.py

Input guard — the first gate. Runs before any model sees the input.

Checks, in order:
    1. type / emptiness
    2. max length
    3. encoding (control characters, invalid unicode)
    4. prompt-injection patterns
    5. shell / command-injection patterns

Contract:
    guard(raw) -> GuardResult(passed, content, reason)
    reason codes: empty_input, max_length_exceeded, encoding_invalid,
                  injection_pattern_detected, command_injection_detected
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

MAX_LENGTH = 2000

_INJECTION_PATTERNS = [
    r"ignore (all |any )?(previous|prior|above) (instructions|rules|prompts)",
    r"disregard (the |your )?(system|previous) (prompt|instructions)",
    r"you are now (?!able)",
    r"\bsystem prompt\b",
    r"\bjailbreak\b",
    r"output (the )?(following|this) (json|plan) exactly",
    r"</?(system|assistant|instructions)>",
]

_COMMAND_PATTERNS = [
    r"\$\([^)]*\)",          # $(subshell)
    r"`[^`]+`",              # `backticks`
    r";\s*(rm|curl|wget|bash|sh|python|nc)\b",
    r"&&\s*(rm|curl|wget|bash|sh|python|nc)\b",
    r"\|\s*(sh|bash)\b",
    r"\brm\s+-rf\b",
]

_INJECTION_RE = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]
_COMMAND_RE = [re.compile(p, re.IGNORECASE) for p in _COMMAND_PATTERNS]


@dataclass
class GuardResult:
    passed: bool
    content: str | None
    reason: str | None = None


def _has_bad_encoding(text: str) -> bool:
    for ch in text:
        cat = unicodedata.category(ch)
        # Cc = control chars (allow tab/newline), Cs = surrogates, Co = private use
        if cat == "Cc" and ch not in "\t\n\r":
            return True
        if cat in ("Cs", "Co"):
            return True
    return False


def guard(raw: object) -> GuardResult:
    if not isinstance(raw, str) or not raw.strip():
        return GuardResult(False, None, "empty_input")

    text = unicodedata.normalize("NFKC", raw).strip()

    if len(text) > MAX_LENGTH:
        return GuardResult(False, None, "max_length_exceeded")
    if _has_bad_encoding(text):
        return GuardResult(False, None, "encoding_invalid")
    if any(r.search(text) for r in _INJECTION_RE):
        return GuardResult(False, None, "injection_pattern_detected")
    if any(r.search(text) for r in _COMMAND_RE):
        return GuardResult(False, None, "command_injection_detected")

    return GuardResult(True, text)
