import json

import pytest

from warden.audit import AuditLog
from warden.executor import Executor
from warden.pipeline import Runtime
from warden.planner import MockPlanner


class ScriptedPlanner:
    """Returns pre-written raw outputs in order — for testing retry and odd model output."""

    def __init__(self, *outputs):
        self.name = "scripted"
        self.outputs = list(outputs)
        self.calls = 0

    def generate(self, user_input):
        out = self.outputs[min(self.calls, len(self.outputs) - 1)]
        self.calls += 1
        return out if isinstance(out, str) else json.dumps(out)


@pytest.fixture
def ws(tmp_path):
    w = tmp_path / "ws"
    w.mkdir()
    (w / "notes.txt").write_text("hello\nTODO: ship it\n")
    (w / "docs").mkdir()
    (w / "docs" / "a.md").write_text("# A\nTODO later\n")
    return w


@pytest.fixture
def make_runtime(ws, tmp_path):
    def _make(planner=None, validator="default", approve=True, auto_read=False):
        if validator == "default":
            validator = MockPlanner("v")
        return Runtime(
            planner=planner or MockPlanner("p"),
            validator=validator,
            executor=Executor(ws),
            audit=AuditLog(tmp_path / "audit.db"),
            approver=lambda dry: approve,
            auto_approve_read_only=auto_read,
        )
    return _make
