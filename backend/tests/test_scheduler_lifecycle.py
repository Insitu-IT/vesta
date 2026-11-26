"""Import remains inert; the application lifespan owns the real scheduler clock."""

import ast
import asyncio
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.base import STATE_STOPPED
import pytest

BACKEND = Path(__file__).resolve().parents[1]


def startup_tree():
    return next(
        node
        for node in ast.parse((BACKEND / "app.py").read_text()).body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "startup_event"
    )


def start_clock(clock):
    # Execute the actual application block, with real APScheduler lifecycle and
    # executors. Other application owners/database are outside this clock test.
    node = next(
        node
        for node in startup_tree().body
        if isinstance(node, ast.If)
        and ast.unparse(node.test) == "not scheduler.running"
    )
    exec(
        compile(
            ast.Module(body=[node], type_ignores=[]), str(BACKEND / "app.py"), "exec"
        ),
        {"scheduler": clock},
    )


def test_actual_scheduler_import_never_starts_work_or_connects():
    # Fresh interpreter prevents collection order from hiding import side effects.
    program = r"""
import importlib.util
from pathlib import Path
import socket,sys,threading
from unittest.mock import patch
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.engine import Engine

def forbidden(*args, **kwargs):
    raise AssertionError("Import must not connect, start a scheduler or start a thread")

sys.path.insert(0,sys.argv[1])
with (
    patch.object(BackgroundScheduler,'start',forbidden),
    patch.object(Engine,'connect',forbidden),
    patch.object(socket.socket,'connect',forbidden),
    patch.object(socket,'getaddrinfo',forbidden),
    patch.object(threading.Thread,'start',forbidden),
):
    spec=importlib.util.spec_from_file_location('isolated_scheduler',Path(sys.argv[1])/'scheduler.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert not module.scheduler.running
    assert module.scheduler.get_jobs()==[]
    assert callable(module.load_schedules) and callable(module.add_schedule_to_scheduler)
"""
    result = subprocess.run(
        [sys.executable, "-c", program, str(BACKEND)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_real_first_start_and_restart_refresh_executor_without_clock_thread(
    monkeypatch,
):
    thread = MagicMock()
    monkeypatch.setattr("apscheduler.schedulers.background.Thread", thread)
    clock = BackgroundScheduler()
    callback = MagicMock()
    assert clock.state == STATE_STOPPED
    with pytest.raises(KeyError):
        clock.remove_executor("default", shutdown=False)
    clock.add_job(callback, "date", run_date="2099-01-01", id="first")
    try:
        start_clock(clock)
        first = clock._lookup_executor("default")
        assert clock.running and clock.get_job("first") is not None
        assert thread.return_value.start.call_count == 1
        # A duplicate lifespan start must leave the current executor intact.
        start_clock(clock)
        assert clock._lookup_executor("default") is first
        assert thread.return_value.start.call_count == 1
        clock.shutdown(wait=True)
        assert clock.state == STATE_STOPPED and first._pool._shutdown
        clock.add_job(callback, "date", run_date="2099-01-01", id="second")
        start_clock(clock)
        second = clock._lookup_executor("default")
        assert clock.running and second is not first and not second._pool._shutdown
        assert clock.get_job("second") is not None
        assert thread.return_value.start.call_count == 2
        callback.assert_not_called()
    finally:
        if clock.running:
            clock.shutdown(wait=True)


def test_database_validation_failure_precedes_all_scheduler_start(monkeypatch):
    node = startup_tree()
    node.decorator_list = []
    started = MagicMock()

    def invalid_database():
        raise RuntimeError("schema/role validation refused")

    scope = {
        "settings": SimpleNamespace(demo_mode=True),
        "init_database": invalid_database,
        "scheduler": SimpleNamespace(start=started),
        "scheduler_work": SimpleNamespace(start=started),
    }
    exec(
        compile(
            ast.Module(body=[node], type_ignores=[]), str(BACKEND / "app.py"), "exec"
        ),
        scope,
    )
    with pytest.raises(RuntimeError, match="schema/role validation refused"):
        asyncio.run(scope["startup_event"]())
    started.assert_not_called()
