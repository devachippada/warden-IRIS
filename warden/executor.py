"""
warden/executor.py

Sandboxed execution. Only reached after policy + human approval.

Every path is resolved against a single workspace root; anything that
escapes it (absolute paths, "..", symlinks pointing outside) is refused.
Deletes are soft: files are moved to <workspace>/.warden/trash/ so a
mistaken approval can still be recovered by hand.

preflight() inspects the real filesystem *without changing it* so the
dry run can say things like "will OVERWRITE existing file (312 bytes)".
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path

from warden import actions

MAX_READ_BYTES = 64_000
MAX_SEARCH_HITS = 50
TRASH_DIR = ".warden/trash"


class SandboxError(Exception):
    pass


class Executor:
    def __init__(self, workspace: str | Path):
        self.root = Path(workspace).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    # ── path safety ─────────────────────────────────────────────────────────
    def resolve(self, rel: str) -> Path:
        if not isinstance(rel, str) or not rel.strip():
            raise SandboxError("missing path")
        p = Path(rel)
        if p.is_absolute():
            raise SandboxError(f"absolute paths are not allowed: {rel}")
        full = (self.root / p).resolve()
        if full != self.root and self.root not in full.parents:
            raise SandboxError(f"path escapes the workspace: {rel}")
        if ".warden" in full.relative_to(self.root).parts:
            raise SandboxError("the .warden directory is off limits")
        return full

    # ── dry-run inspection ─────────────────────────────────────────────────
    def preflight(self, step: dict, planned: set | None = None) -> dict:
        """
        Return {"ok": bool, "note": str} describing what this step would do.

        `planned` carries paths that earlier steps in the same plan will create,
        so "write a.txt then read a.txt" passes preflight. It is updated in place.
        """
        planned = planned if planned is not None else set()
        name = actions.canonical(step["action"])
        try:
            path = self.resolve(step["args"].get("path", ""))
        except SandboxError as e:
            return {"ok": False, "note": str(e)}

        if path in planned and not path.exists():
            note = "acts on a path created earlier in this plan"
            return {"ok": True, "note": note}
        if name in ("write_file", "append_file", "make_dir"):
            planned.add(path)

        exists = path.exists()
        size = path.stat().st_size if exists and path.is_file() else None

        if name in ("read_file", "delete_file"):
            if not exists or not path.is_file():
                return {"ok": False, "note": "file does not exist"}
            verb = "read" if name == "read_file" else "move to trash"
            return {"ok": True, "note": f"will {verb} ({size} bytes)"}
        if name in ("list_dir", "search_text"):
            if not exists or not path.is_dir():
                return {"ok": False, "note": "directory does not exist"}
            return {"ok": True, "note": "will scan directory"}
        if name == "write_file":
            n = len(str(step["args"].get("content", "")))
            if exists and path.is_dir():
                return {"ok": False, "note": "target is a directory"}
            if exists:
                return {"ok": True, "note": f"will OVERWRITE existing file ({size} bytes) with {n} chars"}
            return {"ok": True, "note": f"will create new file with {n} chars"}
        if name == "append_file":
            n = len(str(step["args"].get("content", "")))
            return {"ok": True, "note": f"will append {n} chars" + ("" if exists else " (new file)")}
        if name == "make_dir":
            return {"ok": True, "note": "already exists" if exists else "will create directory"}
        return {"ok": False, "note": "no executor for this action"}

    # ── execution ───────────────────────────────────────────────────────────
    def run_step(self, step: dict) -> str:
        name = actions.canonical(step["action"])
        args = step["args"]
        path = self.resolve(args.get("path", ""))

        if name == "read_file":
            data = path.read_bytes()[:MAX_READ_BYTES]
            return data.decode("utf-8", errors="replace")

        if name == "list_dir":
            entries = sorted(
                (p.name + ("/" if p.is_dir() else "")) for p in path.iterdir()
                if p.name != ".warden"
            )
            return "\n".join(entries) or "(empty)"

        if name == "search_text":
            query = str(args.get("query", ""))
            if not query:
                raise SandboxError("search_text needs a query")
            hits = []
            for f in sorted(path.rglob("*")):
                if not f.is_file() or ".warden" in f.relative_to(self.root).parts:
                    continue
                try:
                    for n, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
                        if query in line:
                            hits.append(f"{f.relative_to(self.root)}:{n}: {line.strip()}")
                            if len(hits) >= MAX_SEARCH_HITS:
                                return "\n".join(hits + ["(truncated)"])
                except OSError:
                    continue
            return "\n".join(hits) or "(no matches)"

        if name == "write_file":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(str(args.get("content", "")))
            return f"wrote {path.relative_to(self.root)}"

        if name == "append_file":
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a") as fh:
                fh.write(str(args.get("content", "")))
            return f"appended to {path.relative_to(self.root)}"

        if name == "make_dir":
            path.mkdir(parents=True, exist_ok=True)
            return f"created {path.relative_to(self.root)}/"

        if name == "delete_file":
            if not path.is_file():
                raise SandboxError("file does not exist")
            trash = self.root / TRASH_DIR
            trash.mkdir(parents=True, exist_ok=True)
            dest = trash / f"{int(time.time())}_{path.name}"
            shutil.move(str(path), dest)
            return f"moved {path.relative_to(self.root)} to {dest.relative_to(self.root)}"

        raise SandboxError(f"no executor for action {step['action']!r}")
