"""Regression tests for fail-closed distribution verification."""

from __future__ import annotations

import base64
import copy
import csv
import hashlib
import importlib.util
import io
import shutil
import sys
import tarfile
import tomllib
import warnings
from collections.abc import Callable
from email.parser import BytesParser
from pathlib import Path
from types import ModuleType
from zipfile import ZipFile, ZipInfo

import pytest
from build import ProjectBuilder

ROOT = Path(__file__).resolve().parent.parent


def _load_verifier() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "atcap_verify_package", ROOT / "scripts" / "verify-package.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


VERIFIER = _load_verifier()


@pytest.fixture(scope="module")
def built_distributions(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, object]]:
    output = tmp_path_factory.mktemp("verified-distributions")
    builder = ProjectBuilder(ROOT)
    builder.build("sdist", output)
    builder.build("wheel", output)
    with (ROOT / "pyproject.toml").open("rb") as pyproject_file:
        project = tomllib.load(pyproject_file)["project"]
    return output, project


def _artifact_copy(source: Path, destination: Path, pattern: str) -> Path:
    artifact = next(source.glob(pattern))
    copied = destination / artifact.name
    shutil.copy2(artifact, copied)
    return copied


def _rewrite_wheel(
    wheel: Path,
    transform: Callable[[list[ZipInfo], dict[str, bytes]], None],
) -> None:
    rewritten = wheel.with_suffix(".rewritten")
    with ZipFile(wheel) as archive:
        members = archive.infolist()
        contents = {member.filename: archive.read(member) for member in members}
    transform(members, contents)
    with ZipFile(rewritten, mode="w") as archive:
        for member in members:
            archive.writestr(member, contents[member.filename])
    rewritten.replace(wheel)


def _refresh_wheel_record(contents: dict[str, bytes]) -> None:
    record = next(name for name in contents if name.endswith("/RECORD"))
    rows = list(csv.reader(io.StringIO(contents[record].decode("utf-8"))))
    refreshed: list[list[str]] = []
    for path, encoded_hash, encoded_size in rows:
        if path == record:
            refreshed.append([path, encoded_hash, encoded_size])
            continue
        payload = contents[path]
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
        refreshed.append([path, f"sha256={digest.decode('ascii')}", str(len(payload))])
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerows(refreshed)
    contents[record] = output.getvalue().encode("utf-8")


def _rewrite_sdist(
    sdist: Path,
    transform: Callable[[tarfile.TarInfo, bytes | None], tuple[tarfile.TarInfo, bytes | None]],
    *,
    duplicate_suffix: str | None = None,
) -> None:
    rewritten = sdist.with_suffix(".rewritten")
    duplicate: tuple[tarfile.TarInfo, bytes] | None = None
    with tarfile.open(sdist, mode="r:gz") as source, tarfile.open(rewritten, mode="w:gz") as target:
        for source_member in source.getmembers():
            member = copy.copy(source_member)
            extracted = source.extractfile(source_member) if source_member.isfile() else None
            contents = extracted.read() if extracted is not None else None
            member, contents = transform(member, contents)
            target.addfile(member, io.BytesIO(contents) if contents is not None else None)
            if duplicate_suffix is not None and member.name.endswith(duplicate_suffix):
                assert contents is not None
                duplicate = (copy.copy(member), contents)
        if duplicate is not None:
            member, contents = duplicate
            target.addfile(member, io.BytesIO(contents))
    rewritten.replace(sdist)


def test_wheel_duplicate_member_is_rejected(
    built_distributions: tuple[Path, dict[str, object]], tmp_path: Path
) -> None:
    source, project = built_distributions
    wheel = _artifact_copy(source, tmp_path, "*.whl")
    with ZipFile(wheel, mode="a") as archive:
        member = archive.getinfo("atcap/__init__.py")
        contents = archive.read(member)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            archive.writestr(member, contents)

    with pytest.raises(VERIFIER.VerificationError, match="duplicate member"):
        VERIFIER._verify_wheel(wheel, ROOT, project)


def test_sdist_duplicate_member_is_rejected(
    built_distributions: tuple[Path, dict[str, object]], tmp_path: Path
) -> None:
    source, project = built_distributions
    sdist = _artifact_copy(source, tmp_path, "*.tar.gz")
    _rewrite_sdist(
        sdist, lambda member, contents: (member, contents), duplicate_suffix="/README.md"
    )

    with pytest.raises(VERIFIER.VerificationError, match="duplicate member"):
        VERIFIER._verify_sdist(sdist, ROOT, project)


def test_duplicate_wheel_record_path_is_rejected(
    built_distributions: tuple[Path, dict[str, object]], tmp_path: Path
) -> None:
    source, project = built_distributions
    wheel = _artifact_copy(source, tmp_path, "*.whl")

    def duplicate_record_path(_members: list[ZipInfo], contents: dict[str, bytes]) -> None:
        record = next(name for name in contents if name.endswith("/RECORD"))
        rows = list(csv.reader(io.StringIO(contents[record].decode("utf-8"))))
        rows.append(rows[-1])
        output = io.StringIO(newline="")
        csv.writer(output, lineterminator="\n").writerows(rows)
        contents[record] = output.getvalue().encode("utf-8")

    _rewrite_wheel(wheel, duplicate_record_path)
    with pytest.raises(VERIFIER.VerificationError, match="RECORD contains duplicate"):
        VERIFIER._verify_wheel(wheel, ROOT, project)


def test_sdist_script_without_executable_mode_is_rejected(
    built_distributions: tuple[Path, dict[str, object]], tmp_path: Path
) -> None:
    source, project = built_distributions
    sdist = _artifact_copy(source, tmp_path, "*.tar.gz")

    def strip_executable_mode(
        member: tarfile.TarInfo, contents: bytes | None
    ) -> tuple[tarfile.TarInfo, bytes | None]:
        if member.name.endswith("/scripts/verify-coverage.sh"):
            member.mode = 0o644
        return member, contents

    _rewrite_sdist(sdist, strip_executable_mode)
    with pytest.raises(VERIFIER.VerificationError, match="expected 0o755"):
        VERIFIER._verify_sdist(sdist, ROOT, project)


def test_wheel_executable_mode_is_rejected(
    built_distributions: tuple[Path, dict[str, object]], tmp_path: Path
) -> None:
    source, project = built_distributions
    wheel = _artifact_copy(source, tmp_path, "*.whl")

    def add_executable_mode(members: list[ZipInfo], _contents: dict[str, bytes]) -> None:
        member = next(item for item in members if item.filename == "atcap/__init__.py")
        member.external_attr = 0o100755 << 16

    _rewrite_wheel(wheel, add_executable_mode)
    with pytest.raises(VERIFIER.VerificationError, match="expected 0o644"):
        VERIFIER._verify_wheel(wheel, ROOT, project)


def test_author_metadata_mutation_is_rejected(
    built_distributions: tuple[Path, dict[str, object]],
) -> None:
    source, project = built_distributions
    wheel = next(source.glob("*.whl"))
    with ZipFile(wheel) as archive:
        metadata_name = next(name for name in archive.namelist() if name.endswith("/METADATA"))
        raw_metadata = archive.read(metadata_name).replace(
            b"Author: Noah Ingwers\n", b"Author: Mallory Example\n"
        )
    metadata = BytesParser().parsebytes(raw_metadata)

    with pytest.raises(VERIFIER.VerificationError, match="incorrect Author"):
        VERIFIER._verify_metadata(metadata, project, label="wheel")


def test_repeated_root_is_purelib_is_rejected_after_record_rehash(
    built_distributions: tuple[Path, dict[str, object]], tmp_path: Path
) -> None:
    source, project = built_distributions
    wheel = _artifact_copy(source, tmp_path, "*.whl")

    def repeat_root_is_purelib(_members: list[ZipInfo], contents: dict[str, bytes]) -> None:
        wheel_metadata = next(name for name in contents if name.endswith("/WHEEL"))
        contents[wheel_metadata] += b"Root-Is-Purelib: false\n"
        _refresh_wheel_record(contents)

    _rewrite_wheel(wheel, repeat_root_is_purelib)
    with pytest.raises(VERIFIER.VerificationError, match="repeated Root-Is-Purelib"):
        VERIFIER._verify_wheel(wheel, ROOT, project)
