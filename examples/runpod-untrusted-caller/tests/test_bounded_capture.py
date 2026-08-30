"""Deterministic output, deadline, and process-group bounds."""

from __future__ import annotations

import json
import signal
import stat
import sys
import time
from pathlib import Path

import bounded_capture
import pytest
from bounded_capture import EXIT_LIMIT, EXIT_TIMEOUT, capture_command


def _capture(
    tmp_path: Path,
    command: list[str],
    *,
    stdout_limit: int = 64,
    stderr_limit: int = 64,
    timeout: float = 2,
    append: bool = False,
) -> tuple[int, Path, Path, dict[str, object]]:
    stdout = tmp_path / "stdout.raw"
    stderr = tmp_path / "stderr.raw"
    result = tmp_path / f"result-{time.monotonic_ns()}.json"
    status = capture_command(
        command,
        stdout_path=stdout,
        stderr_path=stderr,
        result_path=result,
        stdout_limit=stdout_limit,
        stderr_limit=stderr_limit,
        timeout_seconds=timeout,
        append=append,
    )
    parsed = json.loads(result.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict)
    return status, stdout, stderr, parsed


def test_stdout_is_truncated_at_cap_and_reported_unambiguously(tmp_path: Path) -> None:
    status, stdout, stderr, result = _capture(
        tmp_path,
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 10000)"],
        stdout_limit=97,
    )

    assert status == EXIT_LIMIT
    assert stdout.stat().st_size == 97
    assert stderr.stat().st_size == 0
    assert result["outcome"] == "stdout_limit"
    assert result["stdout_total_bytes"] == 97
    assert stat.S_IMODE(stdout.stat().st_mode) == 0o600


def test_stderr_is_truncated_at_cap_and_reported_unambiguously(tmp_path: Path) -> None:
    status, stdout, stderr, result = _capture(
        tmp_path,
        [sys.executable, "-c", "import sys; sys.stderr.write('y' * 10000)"],
        stderr_limit=83,
    )

    assert status == EXIT_LIMIT
    assert stdout.stat().st_size == 0
    assert stderr.stat().st_size == 83
    assert result["outcome"] == "stderr_limit"


def test_timeout_terminates_silent_child(tmp_path: Path) -> None:
    started = time.monotonic()
    status, _stdout, _stderr, result = _capture(
        tmp_path,
        [sys.executable, "-c", "import time; time.sleep(30)"],
        timeout=0.1,
    )

    assert status == EXIT_TIMEOUT
    assert time.monotonic() - started < 2
    assert result["outcome"] == "timed_out"


def test_limit_terminates_descendant_process_group(tmp_path: Path) -> None:
    marker = tmp_path / "descendant-survived"
    child_code = (
        "import pathlib,time; time.sleep(0.8); "
        f"pathlib.Path({str(marker)!r}).write_text('survived')"
    )
    parent_code = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
        "sys.stdout.write('z' * 10000); sys.stdout.flush(); time.sleep(30)"
    )
    status, _stdout, _stderr, result = _capture(
        tmp_path,
        [sys.executable, "-c", parent_code],
        stdout_limit=32,
    )
    time.sleep(1)

    assert status == EXIT_LIMIT
    assert result["outcome"] == "stdout_limit"
    assert not marker.exists()


def test_child_nonzero_exit_is_preserved(tmp_path: Path) -> None:
    status, _stdout, _stderr, result = _capture(
        tmp_path,
        [sys.executable, "-c", "raise SystemExit(37)"],
    )

    assert status == 37
    assert result["outcome"] == "child_exit"
    assert result["child_returncode"] == 37


def test_append_enforces_total_file_cap(tmp_path: Path) -> None:
    first_status, stdout, _stderr, first = _capture(
        tmp_path,
        [sys.executable, "-c", "print('abcd', end='')"],
        stdout_limit=7,
        append=True,
    )
    second_status, _stdout, _stderr, second = _capture(
        tmp_path,
        [sys.executable, "-c", "print('efgh', end='')"],
        stdout_limit=7,
        append=True,
    )

    assert first_status == 0
    assert first["stdout_total_bytes"] == 4
    assert second_status == EXIT_LIMIT
    assert second["outcome"] == "stdout_limit"
    assert stdout.read_bytes() == b"abcdefg"


def test_signal_received_before_spawn_prevents_child_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_signal = bounded_capture.signal.signal
    delivered = False

    def deliver_once(signum: signal.Signals, handler: object) -> object:
        nonlocal delivered
        previous = original_signal(signum, handler)
        if not delivered and callable(handler):
            delivered = True
            handler(signal.SIGTERM, None)
        return previous

    def forbidden_spawn(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("child must not be spawned after a remembered signal")

    monkeypatch.setattr(bounded_capture.signal, "signal", deliver_once)
    monkeypatch.setattr(bounded_capture.subprocess, "Popen", forbidden_spawn)
    status, _stdout, _stderr, result = _capture(
        tmp_path,
        [sys.executable, "-c", "raise SystemExit(99)"],
    )

    assert status == 128 + signal.SIGTERM
    assert result["outcome"] == "interrupted"
    assert result["child_signal"] == signal.SIGTERM
