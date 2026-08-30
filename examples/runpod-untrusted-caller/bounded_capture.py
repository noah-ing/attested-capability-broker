"""Run an untrusted command with bounded private stdout and stderr captures."""

from __future__ import annotations

import argparse
import json
import os
import selectors
import signal
import stat
import subprocess  # nosec B404
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import BinaryIO, Literal, TypedDict

EXIT_TIMEOUT = 124
EXIT_LIMIT = 125
EXIT_WRAPPER_ERROR = 126
READ_CHUNK_BYTES = 65_536
TERMINATION_GRACE_SECONDS = 0.5

CaptureOutcome = Literal[
    "child_exit",
    "child_signal",
    "interrupted",
    "stdout_limit",
    "stderr_limit",
    "timed_out",
    "wrapper_error",
]


class CaptureResult(TypedDict):
    schema_version: Literal["atcap-bounded-capture/v1"]
    outcome: CaptureOutcome
    child_returncode: int | None
    child_signal: int | None
    stdout_bytes_written: int
    stdout_total_bytes: int
    stderr_bytes_written: int
    stderr_total_bytes: int


class CaptureError(RuntimeError):
    """The local capture wrapper could not safely run or record a command."""


def _open_capture(path: Path, *, append: bool, limit: int) -> tuple[BinaryIO, int]:
    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_APPEND if append else os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise CaptureError("capture destination is not a regular file")
        if metadata.st_size > limit:
            raise CaptureError("capture destination already exceeds its limit")
        os.fchmod(descriptor, 0o600)
        destination = os.fdopen(descriptor, "wb", buffering=0)
        descriptor = None
        return destination, metadata.st_size
    except OSError as exc:
        raise CaptureError("capture destination could not be opened") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_result(path: Path, result: CaptureResult) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    encoded = (
        json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise CaptureError("capture result destination is not a regular file")
        os.fchmod(descriptor, 0o600)
        destination = os.fdopen(descriptor, "wb")
        descriptor = None
        with destination:
            destination.write(encoded)
    except OSError as exc:
        raise CaptureError("capture result could not be written") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _kill_process_group(child: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=TERMINATION_GRACE_SECONDS)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.wait()


def _result(
    *,
    outcome: CaptureOutcome,
    child_returncode: int | None,
    child_signal: int | None,
    stdout_written: int,
    stdout_initial: int,
    stderr_written: int,
    stderr_initial: int,
) -> CaptureResult:
    return {
        "schema_version": "atcap-bounded-capture/v1",
        "outcome": outcome,
        "child_returncode": child_returncode,
        "child_signal": child_signal,
        "stdout_bytes_written": stdout_written,
        "stdout_total_bytes": stdout_initial + stdout_written,
        "stderr_bytes_written": stderr_written,
        "stderr_total_bytes": stderr_initial + stderr_written,
    }


def capture_command(
    command: Sequence[str],
    *,
    stdout_path: Path,
    stderr_path: Path,
    result_path: Path,
    stdout_limit: int,
    stderr_limit: int,
    timeout_seconds: float,
    append: bool = False,
) -> int:
    """Capture one command without allowing output, descendants, or time to escape bounds."""

    if not command:
        raise ValueError("command must not be empty")
    if stdout_limit < 0 or stderr_limit < 0 or timeout_seconds <= 0:
        raise ValueError("capture limits must be nonnegative and timeout must be positive")
    resolved_paths = {
        os.path.abspath(stdout_path),
        os.path.abspath(stderr_path),
        os.path.abspath(result_path),
    }
    if len(resolved_paths) != 3:
        raise ValueError("stdout, stderr, and result paths must be distinct")

    stdout_destination, stdout_initial = _open_capture(
        stdout_path, append=append, limit=stdout_limit
    )
    try:
        stderr_destination, stderr_initial = _open_capture(
            stderr_path, append=append, limit=stderr_limit
        )
    except BaseException:
        stdout_destination.close()
        raise

    stdout_written = 0
    stderr_written = 0
    child: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    received_signal: int | None = None

    def remember_signal(signum: int, _frame: object) -> None:
        nonlocal received_signal
        received_signal = received_signal or signum

    handled = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    previous = {signum: signal.signal(signum, remember_signal) for signum in handled}
    outcome: CaptureOutcome = "wrapper_error"
    exit_status = EXIT_WRAPPER_ERROR
    child_returncode: int | None = None
    child_signal: int | None = None
    try:
        if received_signal is not None:
            outcome = "interrupted"
            child_signal = received_signal
            exit_status = 128 + received_signal
        else:
            try:
                child = subprocess.Popen(  # noqa: S603  # nosec B603
                    list(command),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
            except OSError:
                outcome = "wrapper_error"
            else:
                if child.stdout is None or child.stderr is None:
                    raise CaptureError("capture pipes were not created")
                streams = {
                    child.stdout.fileno(): ("stdout", child.stdout, stdout_destination),
                    child.stderr.fileno(): ("stderr", child.stderr, stderr_destination),
                }
                for descriptor, stream_spec in streams.items():
                    os.set_blocking(descriptor, False)
                    selector.register(stream_spec[1], selectors.EVENT_READ, data=descriptor)

                deadline = time.monotonic() + timeout_seconds
                stop_reason: CaptureOutcome | None = None
                while stop_reason is None:
                    if received_signal is not None:
                        stop_reason = "interrupted"
                        break
                    remaining_time = deadline - time.monotonic()
                    if remaining_time <= 0:
                        stop_reason = "timed_out"
                        break
                    if selector.get_map():
                        events = selector.select(timeout=min(0.1, remaining_time))
                    else:
                        time.sleep(min(0.05, remaining_time))
                        events = []
                    for key, _mask in events:
                        descriptor = key.data
                        stream_name, pipe_stream, destination = streams[descriptor]
                        try:
                            chunk = os.read(descriptor, READ_CHUNK_BYTES)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(pipe_stream)
                            pipe_stream.close()
                            continue
                        if stream_name == "stdout":
                            available = stdout_limit - stdout_initial - stdout_written
                            if len(chunk) > available:
                                if available > 0:
                                    destination.write(chunk[:available])
                                    stdout_written += available
                                stop_reason = "stdout_limit"
                                break
                            destination.write(chunk)
                            stdout_written += len(chunk)
                        else:
                            available = stderr_limit - stderr_initial - stderr_written
                            if len(chunk) > available:
                                if available > 0:
                                    destination.write(chunk[:available])
                                    stderr_written += available
                                stop_reason = "stderr_limit"
                                break
                            destination.write(chunk)
                            stderr_written += len(chunk)
                    if child.poll() is not None and not selector.get_map():
                        break

                if stop_reason is not None:
                    outcome = stop_reason
                    _kill_process_group(child)
                    if stop_reason == "timed_out":
                        exit_status = EXIT_TIMEOUT
                    elif stop_reason in ("stdout_limit", "stderr_limit"):
                        exit_status = EXIT_LIMIT
                    else:
                        if received_signal is None:
                            outcome = "wrapper_error"
                            exit_status = EXIT_WRAPPER_ERROR
                        else:
                            child_signal = received_signal
                            exit_status = 128 + received_signal
                else:
                    returncode = child.wait()
                    if returncode < 0:
                        outcome = "child_signal"
                        child_signal = -returncode
                        exit_status = 128 + child_signal
                    else:
                        outcome = "child_exit"
                        child_returncode = returncode
                        exit_status = returncode
    except (CaptureError, OSError):
        outcome = "wrapper_error"
        exit_status = EXIT_WRAPPER_ERROR
        if child is not None and child.poll() is None:
            _kill_process_group(child)
    finally:
        selector.close()
        if child is not None:
            for child_stream in (child.stdout, child.stderr):
                if child_stream is not None and not child_stream.closed:
                    child_stream.close()
        stdout_destination.close()
        stderr_destination.close()
        for signum, old_handler in previous.items():
            signal.signal(signum, old_handler)

    result = _result(
        outcome=outcome,
        child_returncode=child_returncode,
        child_signal=child_signal,
        stdout_written=stdout_written,
        stdout_initial=stdout_initial,
        stderr_written=stderr_written,
        stderr_initial=stderr_initial,
    )
    try:
        _write_result(result_path, result)
    except CaptureError:
        print("bounded capture: local result write failed", file=sys.stderr)
        return EXIT_WRAPPER_ERROR
    diagnostics = {
        "interrupted": "bounded capture: interrupted",
        "stderr_limit": "bounded capture: stderr limit exceeded",
        "stdout_limit": "bounded capture: stdout limit exceeded",
        "timed_out": "bounded capture: execution timed out",
        "wrapper_error": "bounded capture: local wrapper error",
    }
    if outcome in diagnostics:
        print(diagnostics[outcome], file=sys.stderr)
    return exit_status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stdout", type=Path, required=True)
    parser.add_argument("--stderr", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--stdout-limit-bytes", type=int, required=True)
    parser.add_argument("--stderr-limit-bytes", type=int, required=True)
    parser.add_argument("--timeout-seconds", type=float, required=True)
    parser.add_argument("--append", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args(argv)
    command = arguments.command
    if command and command[0] == "--":
        command = command[1:]
    try:
        return capture_command(
            command,
            stdout_path=arguments.stdout,
            stderr_path=arguments.stderr,
            result_path=arguments.result,
            stdout_limit=arguments.stdout_limit_bytes,
            stderr_limit=arguments.stderr_limit_bytes,
            timeout_seconds=arguments.timeout_seconds,
            append=arguments.append,
        )
    except (CaptureError, ValueError):
        print("bounded capture: invalid local capture configuration", file=sys.stderr)
        return EXIT_WRAPPER_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
