"""Shared isolated-deployment fixture."""

from __future__ import annotations

import itertools
from collections.abc import Callable
from pathlib import Path

import pytest

from atcap.tpm import TpmAppraiser

from .support import Harness


@pytest.fixture
def harness_factory(tmp_path: Path) -> Callable[..., Harness]:
    counter = itertools.count()

    def create(*, tpm_appraiser: TpmAppraiser | None = None) -> Harness:
        return Harness.create(
            tmp_path / f"deployment-{next(counter)}.sqlite3",
            tpm_appraiser=tpm_appraiser,
        )

    return create


@pytest.fixture
def harness(harness_factory: Callable[..., Harness]) -> Harness:
    return harness_factory()
