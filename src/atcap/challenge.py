"""Clock-injected issuer for cA2A 0.2.0's documented challenge wire format."""

from __future__ import annotations

import hmac
import secrets
from hashlib import sha256

from ca2a_runtime.challenge import verify_challenge


def issue_ca2a_challenge_at(secret: bytes, *, now: int, ttl_seconds: int) -> tuple[str, int]:
    """Issue ``v1.<expiry>.<random>.<HMAC-SHA256>`` at an explicit time.

    cA2A 0.2.0's public issuer always reads the process wall clock, while its
    public verifier accepts an explicit ``now``. This compatibility adapter
    reproduces the documented 0.2.0 wire format so one injected clock governs
    issuance, persistence, and verification. The released verifier self-checks
    every token before it is returned.
    """

    if ttl_seconds <= 0:
        raise ValueError("challenge TTL must be positive")
    if now < 0:
        raise ValueError("challenge time must be non-negative")
    expiry = now + ttl_seconds
    random_hex = secrets.token_hex(16)
    authenticated = f"v1.{expiry}.{random_hex}"
    mac = hmac.new(secret, authenticated.encode("ascii"), sha256).hexdigest()
    token = f"{authenticated}.{mac}"
    verify_challenge(secret, token, now=now)
    return token, expiry
