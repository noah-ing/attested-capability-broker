"""Compatibility tests for clock-injected cA2A 0.2.0 challenge issuance."""

from __future__ import annotations

import pytest
from ca2a_runtime.challenge import verify_challenge
from ca2a_runtime.errors import AttestationFailed

from atcap.challenge import issue_ca2a_challenge_at


def test_clock_injected_challenge_has_exact_ca2a_shape_and_expiry() -> None:
    secret = b"c" * 32
    now = 1_800_000_000

    token, expiry = issue_ca2a_challenge_at(secret, now=now, ttl_seconds=45)

    prefix, wire_expiry, random_hex, mac_hex = token.split(".")
    assert (prefix, int(wire_expiry), expiry) == ("v1", now + 45, now + 45)
    assert len(random_hex) == 32
    assert len(mac_hex) == 64
    verify_challenge(secret, token, now=now)
    with pytest.raises(AttestationFailed, match="expired"):
        verify_challenge(secret, token, now=expiry)
