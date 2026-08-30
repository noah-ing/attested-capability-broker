"""Create checksums and a closed summary for one dedicated live evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


def write_manifest(
    *,
    root: Path,
    worker_image: str,
    endpoint_id_sha256: str | None,
    template_id_sha256: str | None,
    cleanup_complete: bool,
) -> None:
    if not root.is_dir():
        raise ValueError("evidence root must be an existing directory")
    for digest in (endpoint_id_sha256, template_id_sha256):
        if digest is not None and re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("resource identifier digest must be lowercase SHA-256")
    files: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name not in {"SHA256SUMS", "verification-manifest.json"}:
            relative = path.relative_to(root).as_posix()
            files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    (root / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in files.items()),
        encoding="utf-8",
    )
    manifest = {
        "schema_version": "atcap-runpod-live-evidence-manifest/v1",
        "worker_image": worker_image,
        "endpoint_id_sha256": endpoint_id_sha256,
        "template_id_sha256": template_id_sha256,
        "cleanup_complete": cleanup_complete,
        "files": files,
    }
    (root / "verification-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--worker-image", required=True)
    parser.add_argument("--endpoint-id-sha256", default="")
    parser.add_argument("--template-id-sha256", default="")
    parser.add_argument("--cleanup-complete", choices=["true", "false"], required=True)
    arguments = parser.parse_args(argv)
    write_manifest(
        root=arguments.root,
        worker_image=arguments.worker_image,
        endpoint_id_sha256=arguments.endpoint_id_sha256 or None,
        template_id_sha256=arguments.template_id_sha256 or None,
        cleanup_complete=arguments.cleanup_complete == "true",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
