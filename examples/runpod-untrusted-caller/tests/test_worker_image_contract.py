"""Static regressions for the disposable worker image build contract."""

from __future__ import annotations

import re
from pathlib import Path

EXAMPLE = Path(__file__).resolve().parents[1]
DOCKERFILE = EXAMPLE / "Dockerfile"


def _dockerfile() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def test_worker_dockerfile_rejects_an_empty_lock_before_installing() -> None:
    source = _dockerfile()
    nonempty_guard = re.search(r"\btest\s+-s\s+(?:\./)?requirements\.lock\b", source)
    hashed_install = re.search(
        r"python\s+-m\s+pip\s+install\b[^\n]*(?:\\\n[^\n]*)*"
        r"--require-hashes\b[^\n]*(?:\\\n[^\n]*)*"
        r"--requirement\s+(?:\./)?requirements\.lock\b",
        source,
    )

    assert nonempty_guard is not None, "an empty requirements.lock must fail the build"
    assert hashed_install is not None, "worker dependencies must remain hash locked"
    assert nonempty_guard.start() < hashed_install.start()


def test_worker_dockerfile_checks_installed_dependencies_and_imports() -> None:
    source = _dockerfile()
    install_at = source.index("python -m pip install")
    pip_check_at = source.index("python -m pip check")
    copied_code_at = source.index("COPY --chown=worker:worker handler.py")
    import_guard_at = source.index("python -c", copied_code_at)

    assert install_at < pip_check_at
    assert copied_code_at < import_guard_at
    dependency_guard = source[pip_check_at:copied_code_at]
    for required_dependency in ("ca2a_runtime", "runpod", "rfc8785"):
        assert required_dependency in dependency_guard
    copied_module_guard = source[import_guard_at:]
    for required_module in ("handler", "lab.worker", "lab.worker_wire"):
        assert required_module in copied_module_guard
