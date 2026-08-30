#!/usr/bin/env python3
"""Fail-closed checks for the built wheel and source distribution."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import os
import shutil
import stat

# Required for argument-array invocations of absolute uv and Python paths; no shell is used.
import subprocess  # nosec B404
import sys
import tarfile
import tempfile
import tomllib
from collections import Counter
from email.message import Message
from email.parser import BytesParser
from email.utils import formataddr
from pathlib import Path, PurePosixPath
from zipfile import ZipFile, ZipInfo

ROOT_SDIST_FILES = {
    ".dockerignore",
    ".gitignore",
    "Dockerfile",
    "LICENSE",
    "PKG-INFO",
    "README.md",
    "SECURITY.md",
    "compose.yaml",
    "pyproject.toml",
    "uv.lock",
}
DOC_SDIST_FILES = {"docs/audit-guide.md", "docs/threat-model.md"}
SCRIPT_SDIST_FILES = {
    "examples/runpod-untrusted-caller/scripts/run-live.sh",
    "scripts/container-smoke.sh",
    "scripts/run-swtpm.sh",
    "scripts/verify-coverage.sh",
    "scripts/verify-package.py",
}
EXAMPLE_ROOT_FILES = {
    ".dockerignore",
    "Dockerfile",
    "README.md",
    "billing_observation.py",
    "bounded_capture.py",
    "deadline_supervisor.py",
    "evidence_manifest.py",
    "handler.py",
    "handler_self_test.py",
    "lab_test_support.py",
    "provider_readback.py",
    "requirements.in",
    "requirements.lock",
    "self_test.py",
}
EXAMPLE_LAB_FILES = {
    "__init__.py",
    "controller.py",
    "errors.py",
    "live_cli.py",
    "record.py",
    "swtpm.py",
    "transport.py",
    "wire.py",
    "worker.py",
    "worker_wire.py",
}
EXAMPLE_TEST_FILES = {
    "conftest.py",
    "test_billing_observation.py",
    "test_bounded_capture.py",
    "test_controller.py",
    "test_deadline_supervisor.py",
    "test_evidence_manifest.py",
    "test_live_cli.py",
    "test_provider_readback.py",
    "test_real_swtpm_lab.py",
    "test_record.py",
    "test_run_live_script.py",
}
EXAMPLE_FIXTURE_FILES = {
    "runpodctl-2.12-endpoint-create.json",
    "runpodctl-2.12-endpoint-get.json",
    "runpodctl-2.12-template-get.json",
}
EXAMPLE_PREFIX = "examples/runpod-untrusted-caller"
EXAMPLE_SDIST_FILES = (
    {f"{EXAMPLE_PREFIX}/{name}" for name in EXAMPLE_ROOT_FILES}
    | {f"{EXAMPLE_PREFIX}/lab/{name}" for name in EXAMPLE_LAB_FILES}
    | {f"{EXAMPLE_PREFIX}/tests/{name}" for name in EXAMPLE_TEST_FILES}
    | {f"{EXAMPLE_PREFIX}/tests/fixtures/{name}" for name in EXAMPLE_FIXTURE_FILES}
    | {f"{EXAMPLE_PREFIX}/scripts/run-live.sh"}
)
FORBIDDEN_PARTS = {
    ".git",
    ".github",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "artifacts",
    "build",
    "dist",
    "evidence",
    "htmlcov",
    "logs",
    "private",
    "run",
}
FORBIDDEN_NAMES = {
    ".coverage",
    ".env",
    ".secrets.baseline",
    "coverage.xml",
    "pytest.xml",
}
FORBIDDEN_SUFFIXES = {".db", ".log", ".sqlite", ".sqlite3"}
REGULAR_FILE_MODE = 0o644
SCRIPT_FILE_MODE = 0o755
DIRECTORY_MODE = 0o755


class VerificationError(RuntimeError):
    """A built distribution violated an asserted package invariant."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _one_artifact(dist_dir: Path, pattern: str, label: str) -> Path:
    matches = sorted(dist_dir.glob(pattern))
    _require(len(matches) == 1, f"expected exactly one {label}, found {len(matches)}")
    return matches[0]


def _metadata_from_bytes(raw: bytes, *, label: str) -> Message:
    metadata = BytesParser().parsebytes(raw)
    _require(not metadata.defects, f"{label} metadata is malformed")
    _require(
        metadata.get_all("Metadata-Version") == ["2.5"],
        f"{label} has unsupported or repeated Metadata-Version",
    )
    return metadata


def _expected_author_metadata(project: dict[str, object]) -> tuple[list[str], list[str]]:
    authors = project.get("authors")
    _require(isinstance(authors, list) and authors, "pyproject project.authors is malformed")
    names: list[str] = []
    addresses: list[str] = []
    for author in authors:
        _require(isinstance(author, dict), "pyproject project.authors is malformed")
        _require(
            set(author).issubset({"name", "email"}),
            "pyproject project.authors has unsupported fields",
        )
        name = author.get("name")
        email = author.get("email")
        _require(name is None or isinstance(name, str), "project author name is malformed")
        _require(email is None or isinstance(email, str), "project author email is malformed")
        _require(bool(name or email), "project author must have a name or email")
        if email:
            addresses.append(formataddr((name or "", email)))
        elif name:
            names.append(name)
    return ([", ".join(names)] if names else [], [", ".join(addresses)] if addresses else [])


def _expected_description_content_type(project: dict[str, object]) -> str:
    readme = project.get("readme")
    _require(isinstance(readme, str), "verify-package.py requires a string project.readme")
    suffix = PurePosixPath(readme).suffix.lower()
    content_types = {".md": "text/markdown", ".rst": "text/x-rst", ".txt": "text/plain"}
    _require(suffix in content_types, "verify-package.py does not recognize project.readme")
    return content_types[suffix]


def _expected_requirements(project: dict[str, object]) -> list[str]:
    dependencies = project.get("dependencies")
    _require(isinstance(dependencies, list), "pyproject project.dependencies is malformed")
    expected = [str(item) for item in dependencies]

    optional = project.get("optional-dependencies")
    _require(isinstance(optional, dict), "pyproject optional-dependencies is malformed")
    for extra, requirements in optional.items():
        _require(
            isinstance(requirements, list), f"optional dependency group {extra!r} is malformed"
        )
        for requirement in requirements:
            requirement_text = str(requirement)
            _require(
                ";" not in requirement_text,
                "verify-package.py needs an explicit marker rule for optional dependencies",
            )
            expected.append(f"{requirement_text}; extra == '{extra}'")
    _require(len(expected) == len(set(expected)), "pyproject contains duplicate requirements")
    return expected


def _specifier_parts(value: str) -> set[str]:
    return {part.strip() for part in value.split(",") if part.strip()}


def _verify_metadata(metadata: Message, project: dict[str, object], *, label: str) -> None:
    scalar_fields = {
        "Name": project["name"],
        "Version": project["version"],
        "Summary": project["description"],
        "License-Expression": project["license"],
    }
    for field, expected in scalar_fields.items():
        _require(metadata.get_all(field) == [expected], f"{label} has incorrect {field}")

    expected_authors, expected_author_emails = _expected_author_metadata(project)
    _require(metadata.get_all("Author", []) == expected_authors, f"{label} has incorrect Author")
    _require(
        metadata.get_all("Author-email", []) == expected_author_emails,
        f"{label} has incorrect Author-email",
    )

    keywords = project.get("keywords")
    classifiers = project.get("classifiers")
    _require(isinstance(keywords, list), "pyproject project.keywords is malformed")
    _require(isinstance(classifiers, list), "pyproject project.classifiers is malformed")
    _require(
        metadata.get_all("Keywords", []) == [",".join(str(item) for item in keywords)],
        f"{label} has incorrect Keywords",
    )
    _require(
        metadata.get_all("Classifier", []) == [str(item) for item in classifiers],
        f"{label} has incorrect Classifier metadata",
    )
    _require(
        metadata.get_all("Description-Content-Type", [])
        == [_expected_description_content_type(project)],
        f"{label} has incorrect Description-Content-Type",
    )

    requires_python_values = metadata.get_all("Requires-Python", [])
    _require(len(requires_python_values) == 1, f"{label} lacks exact Requires-Python metadata")
    _require(
        _specifier_parts(requires_python_values[0])
        == _specifier_parts(str(project["requires-python"])),
        f"{label} has incorrect Requires-Python",
    )
    _require(metadata.get_all("License-File") == ["LICENSE"], f"{label} lacks LICENSE metadata")
    optional = project.get("optional-dependencies")
    _require(isinstance(optional, dict), "pyproject optional-dependencies is malformed")
    _require(
        metadata.get_all("Provides-Extra", []) == [str(extra) for extra in optional],
        f"{label} has incorrect Provides-Extra metadata",
    )
    _require(
        Counter(metadata.get_all("Requires-Dist", [])) == Counter(_expected_requirements(project)),
        f"{label} dependency metadata does not match pyproject.toml",
    )

    expected_urls = project.get("urls")
    _require(isinstance(expected_urls, dict), "pyproject project.urls is malformed")
    actual_urls = {}
    for value in metadata.get_all("Project-URL", []):
        name, separator, url = value.partition(", ")
        _require(bool(separator), f"{label} has malformed Project-URL")
        _require(name not in actual_urls, f"{label} has duplicate Project-URL names")
        actual_urls[name] = url
    _require(actual_urls == expected_urls, f"{label} project URLs do not match pyproject.toml")


def _expected_sdist_directories(expected_files: set[str]) -> set[str]:
    directories = {"."}
    for filename in expected_files:
        parent = PurePosixPath(filename).parent
        while parent != PurePosixPath("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    return directories


def _require_sdist_mode(member: tarfile.TarInfo, relative: PurePosixPath) -> None:
    actual_mode = stat.S_IMODE(member.mode)
    if member.isdir():
        expected_mode = DIRECTORY_MODE
    elif relative.as_posix() in SCRIPT_SDIST_FILES:
        expected_mode = SCRIPT_FILE_MODE
    else:
        expected_mode = REGULAR_FILE_MODE
    _require(
        actual_mode == expected_mode,
        f"sdist member {relative} has mode {actual_mode:#05o}, expected {expected_mode:#05o}",
    )


def _require_wheel_mode(info: ZipInfo) -> None:
    # ZIP mode metadata is portable only for members created on Unix. Hatchling
    # supplies it for this wheel; archives without Unix mode metadata are not
    # rejected solely for omitting a non-portable field.
    if info.create_system != 3:
        return
    raw_mode = info.external_attr >> 16
    if raw_mode == 0:
        return
    file_type = stat.S_IFMT(raw_mode)
    _require(
        file_type in {0, stat.S_IFREG},
        f"wheel has a non-regular member mode: {info.filename}",
    )
    actual_mode = stat.S_IMODE(raw_mode)
    _require(
        actual_mode == REGULAR_FILE_MODE,
        f"wheel member {info.filename} has mode {actual_mode:#05o}, "
        f"expected {REGULAR_FILE_MODE:#05o}",
    )


def _source_distribution_allowlist(root: Path) -> set[str]:
    source_files = {
        path.relative_to(root).as_posix()
        for path in (root / "src" / "atcap").iterdir()
        if path.is_file() and (path.suffix == ".py" or path.name == "py.typed")
    }
    test_files = {
        path.relative_to(root).as_posix()
        for path in (root / "tests").iterdir()
        if path.is_file() and path.suffix == ".py"
    }
    _require(source_files, "source allowlist is unexpectedly empty")
    _require(test_files, "test allowlist is unexpectedly empty")
    return (
        ROOT_SDIST_FILES
        | DOC_SDIST_FILES
        | SCRIPT_SDIST_FILES
        | EXAMPLE_SDIST_FILES
        | source_files
        | test_files
    )


def _is_forbidden(path: PurePosixPath) -> bool:
    name = path.name
    return (
        any(part in FORBIDDEN_PARTS for part in path.parts)
        or name in FORBIDDEN_NAMES
        or name.startswith((".coverage.", ".env."))
        or name.endswith(tuple(FORBIDDEN_SUFFIXES))
        or name.startswith("junit")
        or name.endswith("-pytest.xml")
        or ".db-" in name
        or ".sqlite-" in name
        or ".sqlite3-" in name
    )


def _verify_sdist(sdist: Path, root: Path, project: dict[str, object]) -> None:
    expected_prefix = f"{str(project['name']).replace('-', '_')}-{project['version']}"
    _require(sdist.name == f"{expected_prefix}.tar.gz", f"unexpected sdist filename: {sdist.name}")
    expected_files = _source_distribution_allowlist(root)
    expected_directories = _expected_sdist_directories(expected_files)
    actual_files: set[str] = set()
    seen_member_paths: set[str] = set()
    pkg_info: bytes | None = None

    with tarfile.open(sdist, mode="r:gz") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            _require(not path.is_absolute() and ".." not in path.parts, "sdist has unsafe path")
            normalized_path = path.as_posix()
            _require(
                normalized_path not in seen_member_paths,
                f"sdist has duplicate member path: {normalized_path}",
            )
            seen_member_paths.add(normalized_path)
            _require(path.parts and path.parts[0] == expected_prefix, "sdist root is unexpected")
            _require(
                member.isdir() or member.isfile(), f"sdist has non-regular member: {member.name}"
            )
            relative = PurePosixPath(*path.parts[1:])
            if member.isdir():
                _require(
                    relative.as_posix() in expected_directories,
                    f"sdist contains unexpected directory: {relative}",
                )
                _require_sdist_mode(member, relative)
                continue
            _require(not _is_forbidden(relative), f"sdist contains forbidden file: {relative}")
            _require_sdist_mode(member, relative)
            actual_files.add(relative.as_posix())
            if relative.as_posix() == "PKG-INFO":
                extracted = archive.extractfile(member)
                _require(extracted is not None, "could not read sdist PKG-INFO")
                pkg_info = extracted.read()

    unexpected = actual_files - expected_files
    missing = expected_files - actual_files
    _require(not unexpected, f"sdist contains files outside allowlist: {sorted(unexpected)}")
    _require(not missing, f"sdist is missing allowlisted files: {sorted(missing)}")
    _require(pkg_info is not None, "sdist lacks PKG-INFO")
    _verify_metadata(_metadata_from_bytes(pkg_info, label="sdist"), project, label="sdist")
    print(f"sdist allowlist: PASS ({len(actual_files)} files)")


def _verify_wheel(wheel: Path, root: Path, project: dict[str, object]) -> None:
    distribution = str(project["name"]).replace("-", "_")
    version = str(project["version"])
    expected_filename = f"{distribution}-{version}-py3-none-any.whl"
    _require(wheel.name == expected_filename, f"unexpected wheel filename: {wheel.name}")
    dist_info = f"{distribution}-{version}.dist-info"
    source_files = {
        f"atcap/{path.name}"
        for path in (root / "src" / "atcap").iterdir()
        if path.is_file() and (path.suffix == ".py" or path.name == "py.typed")
    }
    expected_files = source_files | {
        f"{dist_info}/METADATA",
        f"{dist_info}/RECORD",
        f"{dist_info}/WHEEL",
        f"{dist_info}/licenses/LICENSE",
    }

    with ZipFile(wheel) as archive:
        members = archive.infolist()
        member_names = [info.filename for info in members]
        _require(
            len(member_names) == len(set(member_names)),
            "wheel contains duplicate member names",
        )
        _require(not any(info.is_dir() for info in members), "wheel contains directory members")
        for info in members:
            _require_wheel_mode(info)
        actual_files = set(member_names)
        _require(actual_files == expected_files, "wheel contents differ from strict allowlist")
        metadata = _metadata_from_bytes(archive.read(f"{dist_info}/METADATA"), label="wheel")
        wheel_metadata = BytesParser().parsebytes(archive.read(f"{dist_info}/WHEEL"))
        _require(not wheel_metadata.defects, "wheel WHEEL metadata is malformed")
        record_path = f"{dist_info}/RECORD"
        record_rows = list(csv.reader(io.StringIO(archive.read(record_path).decode("utf-8"))))
        _require(all(len(row) == 3 for row in record_rows), "wheel RECORD has malformed rows")
        record_paths = [row[0] for row in record_rows]
        _require(
            len(record_paths) == len(set(record_paths)),
            "wheel RECORD contains duplicate paths",
        )
        _require(
            set(record_paths) == actual_files,
            "wheel RECORD does not cover the exact archive contents",
        )
        for path, encoded_hash, encoded_size in record_rows:
            if path == record_path:
                _require(
                    not encoded_hash and not encoded_size,
                    "wheel RECORD self-entry must omit hash and size",
                )
                continue
            contents = archive.read(path)
            algorithm, separator, digest = encoded_hash.partition("=")
            _require(separator == "=" and algorithm == "sha256", f"invalid RECORD hash: {path}")
            actual_digest = base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).rstrip(b"=")
            _require(digest.encode("ascii") == actual_digest, f"wheel RECORD hash mismatch: {path}")
            _require(encoded_size == str(len(contents)), f"wheel RECORD size mismatch: {path}")

    _verify_metadata(metadata, project, label="wheel")
    _require(
        wheel_metadata.get_all("Wheel-Version") == ["1.0"],
        "wheel has unsupported or repeated Wheel-Version",
    )
    _require(
        wheel_metadata.get_all("Root-Is-Purelib") == ["true"],
        "wheel has unsupported or repeated Root-Is-Purelib",
    )
    _require(wheel_metadata.get_all("Tag") == ["py3-none-any"], "wheel tag is not py3-none-any")
    print(f"wheel metadata and contents: PASS ({len(actual_files)} files)")


def _verify_isolated_wheel_install(wheel: Path, root: Path, project: dict[str, object]) -> None:
    with tempfile.TemporaryDirectory(prefix="atcap-wheel-smoke-") as temp_dir:
        environment = Path(temp_dir) / "venv"
        uv = shutil.which("uv")
        _require(uv is not None, "uv is required for the isolated wheel smoke")
        # uv is an absolute executable path and no shell is used.
        subprocess.run(  # noqa: S603  # nosec B603
            [uv, "venv", "--python", sys.executable, str(environment)], check=True
        )
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        sync_environment = os.environ.copy()
        sync_environment["VIRTUAL_ENV"] = str(environment)
        # uv is an absolute executable path and no shell is used.
        subprocess.run(  # noqa: S603  # nosec B603
            [
                uv,
                "sync",
                "--offline",
                "--frozen",
                "--no-install-project",
                "--active",
            ],
            check=True,
            cwd=root,
            env=sync_environment,
        )
        # uv is an absolute executable path and no shell is used.
        subprocess.run(  # noqa: S603  # nosec B603
            [
                uv,
                "pip",
                "install",
                "--offline",
                "--python",
                str(python),
                "--no-deps",
                str(wheel.resolve()),
            ],
            check=True,
        )
        smoke = (
            "import atcap, importlib.metadata as metadata; "
            "from atcap.broker import CapabilityBroker; "
            "from atcap.inventory import InventoryApplication; "
            "from atcap.tpm import ReleasedTpmAppraiser; "
            f"assert atcap.__version__ == {project['version']!r}; "
            f"assert metadata.version({project['name']!r}) == {project['version']!r}; "
            "assert all((CapabilityBroker, InventoryApplication, ReleasedTpmAppraiser))"
        )
        # python is this fresh venv's absolute interpreter path and no shell is used.
        subprocess.run(  # noqa: S603  # nosec B603
            [str(python), "-I", "-c", smoke], check=True
        )
    print("isolated offline wheel install/import: PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    with (root / "pyproject.toml").open("rb") as pyproject_file:
        configuration = tomllib.load(pyproject_file)
    project = configuration.get("project")
    _require(isinstance(project, dict), "pyproject.toml lacks [project]")

    dist_dir = (
        (root / args.dist_dir).resolve() if not args.dist_dir.is_absolute() else args.dist_dir
    )
    _require(dist_dir.is_dir(), f"distribution directory does not exist: {dist_dir}")
    wheel = _one_artifact(dist_dir, "*.whl", "wheel")
    sdist = _one_artifact(dist_dir, "*.tar.gz", "source distribution")

    _verify_wheel(wheel, root, project)
    _verify_sdist(sdist, root, project)
    _verify_isolated_wheel_install(wheel, root, project)
    print("package verification: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"package verification: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1) from error
