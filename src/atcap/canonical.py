"""Canonical encodings and digests used at protocol boundaries."""

from __future__ import annotations

import hashlib
from typing import Any

import rfc8785


def canonical_json(value: Any) -> bytes:
    """Return RFC 8785 canonical JSON bytes."""

    return rfc8785.dumps(value)


def sha256_hex(data: bytes) -> str:
    """Return a lowercase SHA-256 digest without an algorithm prefix."""

    return hashlib.sha256(data).hexdigest()


def canonical_digest(value: Any) -> str:
    """Return the SHA-256 digest of an RFC 8785 value."""

    return sha256_hex(canonical_json(value))


def challenge_token_hash(token: str) -> str:
    """Hash a bearer challenge before persisting it."""

    return sha256_hex(token.encode("utf-8"))
