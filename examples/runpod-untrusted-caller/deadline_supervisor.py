"""Hard execution deadline and signal forwarding for the opt-in live runner."""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import signal
import subprocess  # nosec B404
import sys
import time
from collections.abc import Sequence


def supervise(
    command: Sequence[str],
    *,
    limit_seconds: float,
    cleanup_grace_seconds: float = 120,
    append_handshake: bool = False,
) -> int:
    """Run a new process group, bound execution, and allow bounded cleanup."""

    if not command or limit_seconds <= 0 or cleanup_grace_seconds <= 0:
        raise ValueError("supervisor arguments must be nonempty and positive")
    received_signal: int | None = None

    def remember_signal(signum: int, _frame: object) -> None:
        nonlocal received_signal
        received_signal = received_signal or signum

    handled = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    previous = {signum: signal.signal(signum, remember_signal) for signum in handled}
    environment = dict(os.environ)
    child_command = list(command)
    read_fd: int | None = None
    write_fd: int | None = None
    pass_fds: tuple[int, ...] = ()
    child: subprocess.Popen[bytes] | None = None
    try:
        if append_handshake:
            token = secrets.token_bytes(32)
            read_fd, write_fd = os.pipe()
            os.set_inheritable(read_fd, True)
            child_command.extend(("--supervised-fd", str(read_fd)))
            token_text = token.hex().encode("ascii")
            environment["ATCAP_RUNPOD_SUPERVISION_SHA256"] = hashlib.sha256(token_text).hexdigest()
            os.write(write_fd, token_text + b"\n")
            os.close(write_fd)
            write_fd = None
            pass_fds = (read_fd,)
        if received_signal is not None:
            return 128 + received_signal
        try:
            child = subprocess.Popen(  # noqa: S603  # nosec B603
                child_command,
                env=environment,
                start_new_session=True,
                pass_fds=pass_fds,
            )
        finally:
            if write_fd is not None:
                os.close(write_fd)
                write_fd = None
            if read_fd is not None:
                os.close(read_fd)
                read_fd = None

        deadline = time.monotonic() + limit_seconds
        exit_status: int | None = None
        while exit_status is None:
            if received_signal is not None:
                exit_status = 128 + received_signal
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                print(
                    f"Execution deadline of {limit_seconds:g} seconds reached; initiating cleanup.",
                    file=sys.stderr,
                )
                exit_status = 124
                break
            try:
                return child.wait(timeout=min(0.25, remaining))
            except subprocess.TimeoutExpired:
                pass

        # The handlers are installed before Popen so a signal delivered while the
        # child is being spawned is remembered and reaches this termination path.
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=cleanup_grace_seconds)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
        return exit_status
    finally:
        if write_fd is not None:
            os.close(write_fd)
        if read_fd is not None:
            os.close(read_fd)
        for signum, old_handler in previous.items():
            signal.signal(signum, old_handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit-seconds", required=True, type=float)
    parser.add_argument("--cleanup-grace-seconds", default=120, type=float)
    parser.add_argument("--append-handshake", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args(argv)
    command = arguments.command
    if command and command[0] == "--":
        command = command[1:]
    return supervise(
        command,
        limit_seconds=arguments.limit_seconds,
        cleanup_grace_seconds=arguments.cleanup_grace_seconds,
        append_handshake=arguments.append_handshake,
    )


if __name__ == "__main__":
    raise SystemExit(main())
