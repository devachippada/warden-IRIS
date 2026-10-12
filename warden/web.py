"""
warden/web.py

A small web front-end for the runtime. Standard library only.

    python -m warden.web            # listens on $PORT (default 8000)

Every visitor gets their own throwaway sandbox (a workspace folder and an
audit log), keyed by a random cookie. Sandboxes are seeded with sample files,
deleted after WARDEN_SESSION_TTL seconds of inactivity, and capped in number
and size, so a public demo cannot be used to fill the disk.

API (JSON):
    GET  /api/state                 workspace tree + audit log + chain status
    GET  /api/file?path=...         read one workspace file (preview)
    POST /api/request {input}       run every gate up to approval
    POST /api/decide  {run_id, approve}
    POST /api/reset                 restore the sample workspace
    GET  /healthz
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import threading
import time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from warden import __version__
from warden.audit import AuditLog
from warden.executor import Executor, SandboxError
from warden.pipeline import Runtime
from warden.planner import MockPlanner, OllamaPlanner

DATA_DIR = Path(os.environ.get("WARDEN_DATA_DIR", "/tmp/warden-web"))
SESSION_TTL = int(os.environ.get("WARDEN_SESSION_TTL", "3600"))
MAX_SESSIONS = int(os.environ.get("WARDEN_MAX_SESSIONS", "300"))
MAX_WORKSPACE_BYTES = 256_000
MAX_BODY = 8_000
PENDING_TTL = 600
STATIC = Path(__file__).parent / "static"
COOKIE = "warden_sid"

SAMPLE_FILES = {
    "notes.txt": "Meeting notes\n- ship the demo on Friday\nTODO: call the bank\n",
    "todo.md": "# Todo\n- [ ] write README\n- [ ] TODO: add tests for the guard\n- [x] set up CI\n",
    "docs/guide.md": "# Guide\nwarden only touches files inside this sandbox.\nTODO: add screenshots\n",
    "logs/app.log": "2026-10-12 09:00 started\n2026-10-12 09:05 request ok\n2026-10-12 09:07 request ok\n",
    "old_backup.txt": "an old backup nobody needs anymore\n",
}


def _planners():
    if os.environ.get("WARDEN_PLANNER") == "ollama":
        url = os.environ.get("WARDEN_OLLAMA_URL", "http://localhost:11434/api/chat")
        primary = OllamaPlanner(os.environ.get("WARDEN_MODEL", "warden-primary"), 0.2, url)
        vm = os.environ.get("WARDEN_VALIDATOR_MODEL")
        return primary, (OllamaPlanner(vm, 0.4, url) if vm else None)
    return MockPlanner("mock-primary"), MockPlanner("mock-validator")


# ── sessions ──────────────────────────────────────────────────────────────────
class Session:
    def __init__(self, sid: str):
        self.sid = sid
        self.dir = DATA_DIR / "sessions" / sid
        self.workspace = self.dir / "workspace"
        self.lock = threading.Lock()
        self.last_seen = time.time()
        self.pending: dict = {}  # run_id -> (RunResult, created_at)
        fresh = not self.workspace.exists()
        self.workspace.mkdir(parents=True, exist_ok=True)
        if fresh:
            self.seed()
        primary, validator = _planners()
        self.runtime = Runtime(
            planner=primary, validator=validator,
            executor=Executor(self.workspace),
            audit=AuditLog(self.dir / "audit.db"),
            auto_approve_read_only=False,
        )

    def seed(self) -> None:
        if self.workspace.exists():
            shutil.rmtree(self.workspace)
        for rel, text in SAMPLE_FILES.items():
            p = self.workspace / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        self.pending.clear()

    def workspace_bytes(self) -> int:
        return sum(f.stat().st_size for f in self.workspace.rglob("*") if f.is_file())

    def tree(self) -> list[dict]:
        out = []
        for p in sorted(self.workspace.rglob("*")):
            rel = p.relative_to(self.workspace)
            if rel.parts[0] == ".warden":
                if rel.parts[:2] == (".warden", "trash") and p.is_file():
                    out.append({"path": str(rel), "dir": False, "size": p.stat().st_size, "trash": True})
                continue
            out.append({"path": str(rel), "dir": p.is_dir(),
                        "size": None if p.is_dir() else p.stat().st_size, "trash": False})
        return out


class SessionStore:
    def __init__(self):
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        (DATA_DIR / "sessions").mkdir(parents=True, exist_ok=True)

    def get(self, sid: str | None) -> tuple[Session, bool]:
        """Return (session, is_new)."""
        with self._lock:
            if sid and len(sid) == 32 and sid.isalnum() and sid in self._sessions:
                s = self._sessions[sid]
                s.last_seen = time.time()
                return s, False
            if len(self._sessions) >= MAX_SESSIONS:
                oldest = min(self._sessions.values(), key=lambda x: x.last_seen)
                self._drop(oldest.sid)
            s = Session(secrets.token_hex(16))
            self._sessions[s.sid] = s
            return s, True

    def _drop(self, sid: str) -> None:
        s = self._sessions.pop(sid, None)
        if s:
            shutil.rmtree(s.dir, ignore_errors=True)

    def sweep(self) -> None:
        now = time.time()
        with self._lock:
            for sid in [k for k, s in self._sessions.items() if now - s.last_seen > SESSION_TTL]:
                self._drop(sid)
            for s in self._sessions.values():
                for rid in [r for r, (_, t) in s.pending.items() if now - t > PENDING_TTL]:
                    s.pending.pop(rid, None)


STORE: SessionStore | None = None


def _trace(result) -> dict:
    """Summarise what each gate did, for the UI."""
    rec = result._record
    v = rec.get("validator")
    if v is None:
        validator = "skipped (read-only)" if rec.get("plan") else "not reached"
    elif v == "not configured":
        validator = "not configured"
    elif not v.get("valid"):
        validator = f"failed ({v.get('error')})"
    else:
        validator = "agreed" if v["comparison"]["match"] else "disagreed"
    return {
        "guard": rec.get("guard"),
        "attempts": (rec.get("primary") or {}).get("attempts"),
        "validator": validator,
        "signals": rec.get("signals"),
        "approval": rec.get("approval"),
    }


def _payload(result) -> dict:
    return {**result.public(), "trace": _trace(result)}


# ── HTTP ────────────────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    server_version = f"warden/{__version__}"

    def log_message(self, fmt, *args):  # quieter logs, no request bodies
        print(f"[web] {self.address_string()} {fmt % args}")

    # helpers
    def _session(self) -> tuple[Session, bool]:
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        sid = jar[COOKIE].value if COOKIE in jar else None
        return STORE.get(sid)

    def _send(self, code: int, body: bytes, ctype: str, session: Session | None = None, new=False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                         "font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; "
                         "frame-ancestors 'none'")
        if session and new:
            secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
            self.send_header("Set-Cookie",
                             f"{COOKIE}={session.sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}{secure}")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code: int, obj, session=None, new=False):
        self._send(code, json.dumps(obj, default=str).encode(), "application/json", session, new)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError("request too large")
        try:
            data = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            raise ValueError("invalid JSON")
        if not isinstance(data, dict):
            raise ValueError("expected a JSON object")
        return data

    def _state(self, s: Session) -> dict:
        rt = s.runtime
        log = [{"seq": r["seq"], "at": r["started_at"], "input": r["record"].get("input"),
                "status": r["record"].get("status", "pending"), "stage": r["record"].get("stage"),
                "hash": (r["entry_hash"] or "")[:12]} for r in rt.audit.recent(30)]
        return {"files": s.tree(), "log": log, "chain_ok": rt.audit.verify() == [],
                "planner": rt.planner.name, "bytes": s.workspace_bytes(),
                "quota": MAX_WORKSPACE_BYTES, "version": __version__}

    # routes
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/healthz":
            return self._json(200, {"ok": True})
        if url.path in ("/", "/index.html"):
            s, new = self._session()
            return self._send(200, (STATIC / "index.html").read_bytes(),
                              "text/html; charset=utf-8", s, new)
        if url.path == "/api/state":
            s, new = self._session()
            with s.lock:
                return self._json(200, self._state(s), s, new)
        if url.path == "/api/file":
            s, new = self._session()
            rel = (parse_qs(url.query).get("path") or [""])[0]
            with s.lock:
                try:
                    p = (s.workspace / rel).resolve()
                    if s.workspace.resolve() not in p.parents or not p.is_file():
                        raise SandboxError("not a file in this sandbox")
                    text = p.read_bytes()[:20_000].decode("utf-8", errors="replace")
                    return self._json(200, {"path": rel, "content": text}, s, new)
                except (SandboxError, OSError) as e:
                    return self._json(404, {"error": str(e)}, s, new)
        self._json(404, {"error": "not found"})

    def do_POST(self):
        url = urlparse(self.path)
        s, new = self._session()
        try:
            body = self._body()
        except ValueError as e:
            return self._json(400, {"error": str(e)}, s, new)

        with s.lock:
            if url.path == "/api/request":
                text = body.get("input")
                if not isinstance(text, str):
                    return self._json(400, {"error": "input must be a string"}, s, new)
                result = s.runtime.prepare(text)
                if result.status == "awaiting_approval":
                    s.pending[result.run_id] = (result, time.time())
                return self._json(200, {"result": _payload(result), "state": self._state(s)}, s, new)

            if url.path == "/api/decide":
                entry = s.pending.pop(str(body.get("run_id")), None)
                if entry is None:
                    return self._json(404, {"error": "no pending run with that id (expired?)"}, s, new)
                pending = entry[0]
                approve = body.get("approve") is True
                if approve and s.workspace_bytes() > MAX_WORKSPACE_BYTES:
                    approve = False
                    pending._record["quota"] = "sandbox full — reset it to continue"
                result = s.runtime.commit(pending, approved=approve, by="web user")
                return self._json(200, {"result": _payload(result), "state": self._state(s)}, s, new)

            if url.path == "/api/reset":
                s.seed()
                return self._json(200, {"state": self._state(s)}, s, new)

        self._json(404, {"error": "not found"}, s, new)


def _sweeper():
    while True:
        time.sleep(60)
        try:
            STORE.sweep()
        except Exception as e:  # keep sweeping no matter what
            print(f"[web] sweep failed: {e}")


def main() -> None:
    global STORE
    STORE = SessionStore()
    threading.Thread(target=_sweeper, daemon=True).start()
    port = int(os.environ.get("PORT", "8000"))
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"[web] warden {__version__} listening on :{port} (data: {DATA_DIR})")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
