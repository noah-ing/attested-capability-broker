"""Hard-deadline and signal-forwarding tests for the live process supervisor."""

from __future__ import annotations

import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import deadline_supervisor
import pytest
from deadline_supervisor import supervise


def _cleanup_child_command(marker: Path) -> list[str]:
    code = (
        "import pathlib,signal,time\n"
        f"marker=pathlib.Path({str(marker)!r})\n"
        "def stop(_signum,_frame):\n"
        " marker.write_text('cleanup-ran', encoding='utf-8')\n"
        " raise SystemExit(0)\n"
        "signal.signal(signal.SIGTERM, stop)\n"
        "while True: time.sleep(0.05)\n"
    )
    return [sys.executable, "-c", code]


def test_supervisor_deadline_terminates_group_and_allows_cleanup(tmp_path: Path) -> None:
    marker = tmp_path / "deadline-cleanup"

    status = supervise(
        _cleanup_child_command(marker),
        limit_seconds=0.25,
        cleanup_grace_seconds=2,
    )

    assert status == 124
    assert marker.read_text(encoding="utf-8") == "cleanup-ran"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group semantics")
def test_supervisor_forwards_external_term_and_preserves_signal_status(tmp_path: Path) -> None:
    marker = tmp_path / "signal-cleanup"
    supervisor = Path(__file__).resolve().parents[1] / "deadline_supervisor.py"
    process = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            str(supervisor),
            "--limit-seconds",
            "10",
            "--cleanup-grace-seconds",
            "2",
            "--",
            *_cleanup_child_command(marker),
        ]
    )
    time.sleep(0.25)
    process.send_signal(signal.SIGTERM)

    assert process.wait(timeout=5) == 128 + signal.SIGTERM
    assert marker.read_text(encoding="utf-8") == "cleanup-ran"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX process-group semantics")
def test_signal_delivered_during_spawn_is_forwarded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ready = tmp_path / "child-ready"
    cleaned = tmp_path / "spawn-race-cleanup"
    code = (
        "import pathlib,signal,time\n"
        f"ready=pathlib.Path({str(ready)!r})\n"
        f"cleaned=pathlib.Path({str(cleaned)!r})\n"
        "def stop(_signum,_frame):\n"
        " cleaned.write_text('cleanup-ran', encoding='utf-8')\n"
        " raise SystemExit(0)\n"
        "signal.signal(signal.SIGTERM, stop)\n"
        "ready.write_text('ready', encoding='utf-8')\n"
        "while True: time.sleep(0.05)\n"
    )
    original_popen = subprocess.Popen

    def signalling_popen(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        child = original_popen(*args, **kwargs)  # nosec B603
        wait_until = time.monotonic() + 2
        while not ready.exists() and time.monotonic() < wait_until:
            if child.poll() is not None:
                break
            time.sleep(0.01)
        assert ready.exists()
        signal.raise_signal(signal.SIGTERM)
        return child

    monkeypatch.setattr(deadline_supervisor.subprocess, "Popen", signalling_popen)

    status = supervise(
        [sys.executable, "-c", code],
        limit_seconds=10,
        cleanup_grace_seconds=2,
    )

    assert status == 128 + signal.SIGTERM
    assert cleaned.read_text(encoding="utf-8") == "cleanup-ran"
