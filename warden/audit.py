"""
warden/audit.py

Append-only, tamper-evident audit log (SQLite + SHA-256 hash chain).

Every pipeline run becomes one row. When a run finishes it is sealed:

    entry_hash = sha256(previous_hash + canonical_json(row_content))

where previous_hash is the entry_hash of the previous sealed row
("GENESIS" for the first). Editing or deleting any sealed row breaks every
hash after it, and verify() reports exactly where.

Logging must never take the pipeline down: every public call swallows its
own errors and reports them on stderr.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "GENESIS"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT NOT NULL UNIQUE,
    started_at    TEXT NOT NULL,
    record        TEXT NOT NULL DEFAULT '{}',
    previous_hash TEXT,
    entry_hash    TEXT
);
"""


def _canonical(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _hash(previous: str, run_id: str, started_at: str, record: str) -> str:
    payload = "|".join([previous, run_id, started_at, record])
    return hashlib.sha256(payload.encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.executescript(_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    # ── writing ────────────────────────────────────────────────────────────
    def start(self) -> str:
        run_id = uuid.uuid4().hex
        try:
            with self._conn() as c:
                c.execute("INSERT INTO runs (run_id, started_at) VALUES (?, ?)",
                          (run_id, datetime.now(timezone.utc).isoformat()))
        except sqlite3.Error as e:
            print(f"[audit] start failed: {e}", file=sys.stderr)
        return run_id

    def seal(self, run_id: str, record: dict) -> None:
        """Write the final record for a run and chain it. Idempotent per run."""
        try:
            with self._conn() as c:
                row = c.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
                if row is None or row["entry_hash"]:
                    return
                prev = c.execute(
                    "SELECT entry_hash FROM runs WHERE entry_hash IS NOT NULL "
                    "ORDER BY seq DESC LIMIT 1").fetchone()
                previous = prev["entry_hash"] if prev else GENESIS
                body = _canonical(record)
                c.execute(
                    "UPDATE runs SET record = ?, previous_hash = ?, entry_hash = ? WHERE run_id = ?",
                    (body, previous, _hash(previous, run_id, row["started_at"], body), run_id))
        except sqlite3.Error as e:
            print(f"[audit] seal failed for {run_id}: {e}", file=sys.stderr)

    # ── reading ────────────────────────────────────────────────────────────
    def recent(self, limit: int = 10) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM runs ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
        return [{**dict(r), "record": json.loads(r["record"])} for r in rows]

    def verify(self) -> list[str]:
        """Return a list of problems. Empty list means the chain is intact."""
        problems = []
        expected_prev = GENESIS
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM runs WHERE entry_hash IS NOT NULL ORDER BY seq").fetchall()
        for r in rows:
            if r["previous_hash"] != expected_prev:
                problems.append(f"seq {r['seq']}: chain broken (previous_hash mismatch)")
            recomputed = _hash(r["previous_hash"], r["run_id"], r["started_at"], r["record"])
            if recomputed != r["entry_hash"]:
                problems.append(f"seq {r['seq']}: content altered (entry_hash mismatch)")
            expected_prev = r["entry_hash"]
        return problems
