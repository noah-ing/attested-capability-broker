"""Uniquely named shared helpers for the isolated lab tests."""

from __future__ import annotations

from ca2a_runtime.delegation import DelegationCredential
from lab.controller import CapabilityGrant

from atcap.canonical import canonical_digest, challenge_token_hash
from atcap.errors import Reason
from tests.support import Harness

WORKER_IMAGE = "example.invalid/atcap-worker@sha256:" + "1" * 64
WORKER_DIGEST = "2" * 64


def issue_grant(harness: Harness) -> CapabilityGrant:
    challenge = harness.broker.new_challenge()
    request = harness.endorsed_request(challenge)
    decision = harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=harness.accepted_evidence,
    )
    if not decision.allowed or decision.reason != Reason.ALLOW or decision.result is None:
        raise AssertionError(f"fixture issuance failed: {decision.reason}")
    return CapabilityGrant(
        credential=DelegationCredential.from_dict(decision.result["credential"]),
        broker_receipt=decision.receipt,
        expected_manifest_digest=harness.policy.manifest.expected_digest,
        expected_broker_policy_sha256=canonical_digest(harness.policy.public_dict()),
        expected_broker_challenge_token_hash=challenge_token_hash(challenge),
        expected_tpm_attest_sha256=harness.accepted_evidence.digestable()["tpm_attest_sha256"],
        expected_tpm_signature_sha256=harness.accepted_evidence.digestable()[
            "tpm_signature_sha256"
        ],
        expected_tpm_ak_chain_sha256=harness.accepted_evidence.digestable()["tpm_ak_chain_sha256"],
        expected_issuance_request_sha256=canonical_digest(request.to_dict()),
    )
