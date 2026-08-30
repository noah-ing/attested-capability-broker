"""Broker issuance invariants and negative decisions."""

from __future__ import annotations

import copy
import json
import sqlite3
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import atcap.broker as broker_module
from atcap.canonical import canonical_digest, challenge_token_hash
from atcap.errors import DecisionError, Reason
from atcap.manifest_verifier import signed_manifest_digest, verify_signed_manifest
from atcap.models import IssuanceRequest, TpmEvidence
from atcap.policy import TpmPolicy
from atcap.tpm import TestTpmAppraiser as AcceptedTpmAppraiser

from .support import Harness


def test_allow_uses_real_manifest_verification_and_signed_receipt(harness: Harness) -> None:
    normalized = verify_signed_manifest(harness.manifest, harness.policy.manifest)
    assert normalized == harness.manifest

    credential, decision = harness.issue_credential()

    assert decision.allowed is True
    assert decision.reason == Reason.ALLOW
    assert credential.issuer == harness.broker_issuer_public
    assert credential.subject == harness.holder_public
    assert credential.scope == frozenset({harness.policy.qualified_scope})
    assert len(credential.credential_id) == 64
    assert int(credential.credential_id, 16) >= 0
    payload = harness.broker_receipts.verify(decision.receipt)
    assert payload.deciding_service == "broker"
    assert payload.decision == "allow"
    assert payload.reason == Reason.ALLOW
    assert payload.credential_id == credential.credential_id
    assert payload.manifest_digest == harness.policy.manifest.expected_digest
    assert payload.artifact_hashes["broker_policy_sha256"] == canonical_digest(
        harness.policy.public_dict()
    )
    assert payload.handler_invoked is False
    assert payload.business_result == "not_applicable"


def test_credential_ids_have_256_bits_of_randomness_and_do_not_repeat(
    harness: Harness,
) -> None:
    first, _ = harness.issue_credential()
    second, _ = harness.issue_credential()

    assert len(first.credential_id) == 64
    assert len(second.credential_id) == 64
    assert first.credential_id != second.credential_id


def test_broker_persists_only_challenge_token_hash(harness: Harness) -> None:
    challenge = harness.broker.new_challenge()

    with sqlite3.connect(harness.store.path) as connection:
        row = connection.execute("SELECT token_hash FROM broker_challenges").fetchone()

    assert row is not None
    assert row[0] == challenge_token_hash(challenge)
    assert challenge not in row[0]


def test_untrusted_tpm_evidence_is_denied_and_receipted(harness: Harness) -> None:
    request = harness.endorsed_request(harness.broker.new_challenge())
    untrusted = TpmEvidence(
        attest=harness.accepted_evidence.attest + b"substitution",
        signature=harness.accepted_evidence.signature,
        ak_chain_pem=harness.accepted_evidence.ak_chain_pem,
    )

    decision = harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=untrusted,
    )

    assert decision.allowed is False
    assert decision.reason == Reason.TPM_UNTRUSTED
    payload = harness.broker_receipts.verify(decision.receipt)
    assert payload.decision == "deny"
    assert payload.reason == Reason.TPM_UNTRUSTED


def test_failed_appraisal_does_not_burn_broker_challenge(harness: Harness) -> None:
    request = harness.endorsed_request(harness.broker.new_challenge())
    untrusted = TpmEvidence(
        attest=harness.accepted_evidence.attest + b"substitution",
        signature=harness.accepted_evidence.signature,
        ak_chain_pem=harness.accepted_evidence.ak_chain_pem,
    )
    denied = harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=untrusted,
    )

    allowed = harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=harness.accepted_evidence,
    )

    assert denied.reason == Reason.TPM_UNTRUSTED
    assert allowed.allowed is True
    assert allowed.reason == Reason.ALLOW


@dataclass(frozen=True)
class PcrRejectingAppraiser:
    """A host-side appraisal result for a quote over an unapproved selection."""

    def appraise(
        self,
        evidence: TpmEvidence,
        *,
        expected_qualifying_data: bytes,
        policy: TpmPolicy,
    ) -> None:
        del evidence, expected_qualifying_data, policy
        raise DecisionError(Reason.PCR_POLICY, "signed PCR selection is unapproved")


@dataclass
class RecordingAppraiser:
    """Record whether issuance reached appraisal without inspecting evidence."""

    called: bool = False

    def appraise(
        self,
        evidence: TpmEvidence,
        *,
        expected_qualifying_data: bytes,
        policy: TpmPolicy,
    ) -> None:
        del evidence, expected_qualifying_data, policy
        self.called = True


@dataclass(frozen=True)
class UnexpectedFailureAppraiser:
    """Raise an unexpected dependency failure carrying a leak-detection marker."""

    marker: str

    def appraise(
        self,
        evidence: TpmEvidence,
        *,
        expected_qualifying_data: bytes,
        policy: TpmPolicy,
    ) -> None:
        del evidence, expected_qualifying_data, policy
        raise RuntimeError(self.marker)


@dataclass(frozen=True)
class RuntimeLeakMarker:
    """Malformed public-boundary value whose rendering must never escape."""

    marker: str

    def __str__(self) -> str:
        return self.marker

    def __repr__(self) -> str:
        return self.marker


@pytest.mark.parametrize(
    "field_name",
    [
        "version",
        "broker_id",
        "challenge",
        "manifest_digest",
        "identity_key",
        "holder_key",
        "resource_issuer_kid",
        "resource_issuer_key",
        "requested_scope",
        "identity_signature",
    ],
)
def test_malformed_issuance_request_field_is_signed_without_consuming_challenge(
    field_name: str,
    harness: Harness,
) -> None:
    challenge = harness.broker.new_challenge()
    valid_request = harness.endorsed_request(challenge)
    malformed_request = replace(valid_request)
    marker = f"RUNTIME_REQUEST_VALUE_MUST_NOT_ESCAPE_{field_name}"
    object.__setattr__(malformed_request, field_name, RuntimeLeakMarker(marker))

    denied = harness.broker.issue(
        malformed_request,
        manifest=harness.manifest,
        tpm_evidence=harness.accepted_evidence,
    )

    assert denied.allowed is False
    assert denied.reason == Reason.REQUEST_BINDING
    assert denied.result is None
    payload = harness.broker_receipts.verify(denied.receipt)
    assert payload.decision == "deny"
    assert payload.reason == Reason.REQUEST_BINDING
    assert payload.challenge_token_hash is None
    assert payload.manifest_digest is None
    exposed = json.dumps(denied.to_dict(), sort_keys=True) + payload.model_dump_json()
    assert marker not in exposed

    # Runtime model rejection happens before the one-time challenge spend.
    allowed = harness.broker.issue(
        valid_request,
        manifest=harness.manifest,
        tpm_evidence=harness.accepted_evidence,
    )
    assert allowed.allowed is True


def test_non_request_runtime_object_is_signed_without_consuming_challenge(
    harness: Harness,
) -> None:
    challenge = harness.broker.new_challenge()
    valid_request = harness.endorsed_request(challenge)
    marker = "NON_REQUEST_RUNTIME_OBJECT_MUST_NOT_ESCAPE"

    denied = harness.broker.issue(
        cast(IssuanceRequest, RuntimeLeakMarker(marker)),
        manifest=harness.manifest,
        tpm_evidence=harness.accepted_evidence,
    )

    assert denied.allowed is False
    assert denied.reason == Reason.REQUEST_BINDING
    payload = harness.broker_receipts.verify(denied.receipt)
    assert payload.reason == Reason.REQUEST_BINDING
    assert payload.challenge_token_hash is None
    assert marker not in (json.dumps(denied.to_dict()) + payload.model_dump_json())
    assert harness.broker.issue(
        valid_request,
        manifest=harness.manifest,
        tpm_evidence=harness.accepted_evidence,
    ).allowed


@pytest.mark.parametrize("field_name", ["attest", "signature", "ak_chain_pem"])
def test_malformed_tpm_evidence_field_is_signed_without_consuming_challenge(
    field_name: str,
    harness: Harness,
) -> None:
    challenge = harness.broker.new_challenge()
    request = harness.endorsed_request(challenge)
    malformed_evidence = replace(harness.accepted_evidence)
    marker = f"RUNTIME_TPM_VALUE_MUST_NOT_ESCAPE_{field_name}"
    object.__setattr__(malformed_evidence, field_name, RuntimeLeakMarker(marker))

    denied = harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=malformed_evidence,
    )

    assert denied.allowed is False
    assert denied.reason == Reason.TPM_INVALID
    assert denied.result is None
    payload = harness.broker_receipts.verify(denied.receipt)
    assert payload.decision == "deny"
    assert payload.reason == Reason.TPM_INVALID
    assert payload.challenge_token_hash == challenge_token_hash(challenge)
    assert payload.manifest_digest == request.manifest_digest
    exposed = json.dumps(denied.to_dict(), sort_keys=True) + payload.model_dump_json()
    assert marker not in exposed

    # Invalid evidence is rejected before appraisal and the challenge spend.
    allowed = harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=harness.accepted_evidence,
    )
    assert allowed.allowed is True


def test_non_evidence_runtime_object_is_signed_without_consuming_challenge(
    harness: Harness,
) -> None:
    challenge = harness.broker.new_challenge()
    request = harness.endorsed_request(challenge)
    marker = "NON_EVIDENCE_RUNTIME_OBJECT_MUST_NOT_ESCAPE"

    denied = harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=cast(TpmEvidence, RuntimeLeakMarker(marker)),
    )

    assert denied.allowed is False
    assert denied.reason == Reason.TPM_INVALID
    payload = harness.broker_receipts.verify(denied.receipt)
    assert payload.reason == Reason.TPM_INVALID
    assert payload.challenge_token_hash == challenge_token_hash(challenge)
    assert marker not in (json.dumps(denied.to_dict()) + payload.model_dump_json())
    assert harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=harness.accepted_evidence,
    ).allowed


def test_unexpected_manifest_verifier_failure_is_signed_and_does_not_leak(
    harness_factory: Callable[..., Harness],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appraiser = RecordingAppraiser()
    harness = harness_factory(tpm_appraiser=appraiser)
    challenge = harness.broker.new_challenge()
    request = harness.endorsed_request(challenge)
    manifest_marker = "RAW_MANIFEST_MATERIAL_MUST_NOT_ESCAPE"
    exception_marker = "manifest verifier dependency exposed private material"
    marked_manifest = {"private_manifest_material": manifest_marker}
    marked_evidence = TpmEvidence(
        attest=b"RAW_TPM_ATTEST_MUST_NOT_ESCAPE",
        signature=b"RAW_TPM_SIGNATURE_MUST_NOT_ESCAPE",
        ak_chain_pem=b"RAW_AK_CHAIN_MUST_NOT_ESCAPE",
    )

    def fail_manifest_verification(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError(exception_marker)

    with monkeypatch.context() as patch:
        patch.setattr(broker_module, "verify_signed_manifest", fail_manifest_verification)
        decision = harness.broker.issue(
            request,
            manifest=marked_manifest,
            tpm_evidence=marked_evidence,
        )

    assert decision.allowed is False
    assert decision.reason == Reason.INTERNAL_ERROR
    assert decision.result is None
    assert appraiser.called is False
    payload = harness.broker_receipts.verify(decision.receipt)
    assert payload.decision == "deny"
    assert payload.reason == Reason.INTERNAL_ERROR
    assert payload.handler_invoked is False
    assert payload.business_result == "not_applicable"
    exposed = json.dumps(decision.to_dict(), sort_keys=True) + payload.model_dump_json()
    private_markers = (
        exception_marker,
        manifest_marker,
        challenge,
        request.identity_signature,
        request.identity_key,
        request.holder_key,
        request.resource_issuer_key,
        harness.broker.challenge_secret.hex(),
        harness.identity_private.private_bytes_raw().hex(),
        harness.broker_issuer_private.private_bytes_raw().hex(),
        *(item.decode() for item in marked_evidence.__dict__.values()),
    )
    assert all(marker not in exposed for marker in private_markers)

    # The unexpected pre-appraisal failure did not consume the bearer challenge.
    allowed = harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=marked_evidence,
    )
    assert allowed.allowed is True
    assert appraiser.called is True


def test_unexpected_tpm_appraiser_failure_is_signed_and_does_not_leak(
    harness_factory: Callable[..., Harness],
) -> None:
    exception_marker = "TPM dependency failure included secret key material"
    harness = harness_factory(tpm_appraiser=UnexpectedFailureAppraiser(exception_marker))
    challenge = harness.broker.new_challenge()
    request = harness.endorsed_request(challenge)
    marked_evidence = TpmEvidence(
        attest=b"RAW_TPM_ATTEST_ON_FAILURE",
        signature=b"RAW_TPM_SIGNATURE_ON_FAILURE",
        ak_chain_pem=b"RAW_AK_CHAIN_ON_FAILURE",
    )

    decision = harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=marked_evidence,
    )

    assert decision.allowed is False
    assert decision.reason == Reason.INTERNAL_ERROR
    assert decision.result is None
    payload = harness.broker_receipts.verify(decision.receipt)
    assert payload.decision == "deny"
    assert payload.reason == Reason.INTERNAL_ERROR
    assert payload.credential_id is None
    exposed = json.dumps(decision.to_dict(), sort_keys=True) + payload.model_dump_json()
    private_markers = (
        exception_marker,
        challenge,
        request.identity_signature,
        request.identity_key,
        request.holder_key,
        request.resource_issuer_key,
        str(harness.manifest["manifest_id"]),
        harness.broker.challenge_secret.hex(),
        harness.identity_private.private_bytes_raw().hex(),
        harness.broker_issuer_private.private_bytes_raw().hex(),
        *(item.decode() for item in marked_evidence.__dict__.values()),
    )
    assert all(marker not in exposed for marker in private_markers)

    # An unexpected appraisal failure is still non-mutating.
    harness.broker.tpm_appraiser = AcceptedTpmAppraiser(marked_evidence)
    allowed = harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=marked_evidence,
    )
    assert allowed.allowed is True


def test_wrong_pcr_state_is_denied(
    harness_factory: Callable[..., Harness],
) -> None:
    harness = harness_factory(tpm_appraiser=PcrRejectingAppraiser())
    request = harness.endorsed_request(harness.broker.new_challenge())

    decision = harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=harness.accepted_evidence,
    )

    assert decision.allowed is False
    assert decision.reason == Reason.PCR_POLICY
    assert harness.broker_receipts.verify(decision.receipt).reason == Reason.PCR_POLICY


def test_consumed_broker_challenge_cannot_be_reused(harness: Harness) -> None:
    request = harness.endorsed_request(harness.broker.new_challenge())
    first = harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=harness.accepted_evidence,
    )
    second = harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=harness.accepted_evidence,
    )

    assert first.allowed is True
    assert second.allowed is False
    assert second.reason == Reason.CHALLENGE_CONSUMED
    assert harness.broker_receipts.verify(second.receipt).reason == Reason.CHALLENGE_CONSUMED


@dataclass(frozen=True)
class BarrierAppraiser:
    """Make two independently verified issuance requests reach the spend race."""

    barrier: threading.Barrier

    def appraise(
        self,
        evidence: TpmEvidence,
        *,
        expected_qualifying_data: bytes,
        policy: TpmPolicy,
    ) -> None:
        del evidence, expected_qualifying_data, policy
        self.barrier.wait(timeout=10)


def test_two_issuances_racing_one_broker_challenge_mint_exactly_one_credential(
    harness_factory: Callable[..., Harness],
) -> None:
    appraisal_barrier = threading.Barrier(2)
    harness = harness_factory(tpm_appraiser=BarrierAppraiser(appraisal_barrier))
    request = harness.endorsed_request(harness.broker.new_challenge())

    def issue():
        return harness.broker.issue(
            request,
            manifest=harness.manifest,
            tpm_evidence=harness.accepted_evidence,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        decisions = [
            future.result(timeout=15) for future in (executor.submit(issue), executor.submit(issue))
        ]

    assert sum(decision.allowed for decision in decisions) == 1
    assert sorted(decision.reason for decision in decisions) == [
        Reason.ALLOW,
        Reason.CHALLENGE_CONSUMED,
    ]
    allowed = next(decision for decision in decisions if decision.allowed)
    assert allowed.result is not None
    assert len(allowed.result["credential"]["credential_id"]) == 64


def test_stale_broker_challenge_is_denied(harness: Harness) -> None:
    challenge = harness.broker.new_challenge()
    request = harness.endorsed_request(challenge)
    harness.clock.set(int(challenge.split(".")[1]) + 1)

    decision = harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=harness.accepted_evidence,
    )

    assert decision.allowed is False
    assert decision.reason == Reason.CHALLENGE_STALE
    assert harness.broker_receipts.verify(decision.receipt).reason == Reason.CHALLENGE_STALE


def test_broker_challenge_expiring_while_waiting_for_sqlite_lock_is_not_used(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    challenge = harness.broker.new_challenge()
    request = harness.endorsed_request(challenge)
    original_consume = harness.store.consume_broker_challenge
    reached_transaction = threading.Event()

    def observed_consume(**kwargs):
        reached_transaction.set()
        return original_consume(**kwargs)

    monkeypatch.setattr(harness.store, "consume_broker_challenge", observed_consume)
    lock_connection = sqlite3.connect(harness.store.path, isolation_level=None)
    lock_connection.execute("BEGIN IMMEDIATE")
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                harness.broker.issue,
                request,
                manifest=harness.manifest,
                tpm_evidence=harness.accepted_evidence,
            )
            assert reached_transaction.wait(timeout=10)
            harness.clock.set(int(challenge.split(".")[1]) + 1)
            lock_connection.rollback()
            decision = future.result(timeout=15)
    finally:
        if lock_connection.in_transaction:
            lock_connection.rollback()
        lock_connection.close()

    assert decision.allowed is False
    assert decision.reason == Reason.CHALLENGE_STALE


def test_identity_not_bound_to_manifest_is_denied(harness: Harness) -> None:
    unauthorized_identity = Ed25519PrivateKey.generate()
    request = harness.endorsed_request(
        harness.broker.new_challenge(),
        identity_private=unauthorized_identity,
    )

    decision = harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=harness.accepted_evidence,
    )

    assert decision.allowed is False
    assert decision.reason == Reason.IDENTITY_UNAUTHORIZED
    assert harness.broker_receipts.verify(decision.receipt).reason == Reason.IDENTITY_UNAUTHORIZED


def test_substituted_resource_issuer_is_denied_even_when_identity_endorses_it(
    harness: Harness,
) -> None:
    attacker_issuer = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    request = harness.endorsed_request(
        harness.broker.new_challenge(),
        resource_issuer_key=attacker_issuer,
    )

    decision = harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=harness.accepted_evidence,
    )

    assert decision.allowed is False
    assert decision.reason == Reason.REQUEST_BINDING
    assert harness.broker_receipts.verify(decision.receipt).reason == Reason.REQUEST_BINDING


def test_substituted_resource_issuer_kid_is_denied_even_when_identity_endorses_it(
    harness: Harness,
) -> None:
    request = harness.endorsed_request(
        harness.broker.new_challenge(),
        resource_issuer_kid="substituted-inventoryd-key",
    )

    decision = harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=harness.accepted_evidence,
    )

    assert decision.allowed is False
    assert decision.reason == Reason.REQUEST_BINDING


def test_broker_policy_hash_commits_every_security_root_and_ttl(harness: Harness) -> None:
    baseline = canonical_digest(harness.policy.public_dict())
    substitutions = [
        replace(
            harness.policy,
            tpm=replace(harness.policy.tpm, trusted_roots_pem=b"other-tpm-root"),
        ),
        replace(harness.policy, resource_issuer_public_hex="00" * 32),
        replace(harness.policy, challenge_ttl_seconds=61),
        replace(
            harness.policy,
            manifest=replace(
                harness.policy.manifest,
                signing_public_b64url="substituted-manifest-signing-key",
            ),
        ),
    ]

    assert all(canonical_digest(item.public_dict()) != baseline for item in substitutions)


def test_holder_substitution_breaks_complete_request_endorsement(harness: Harness) -> None:
    request = harness.endorsed_request(harness.broker.new_challenge())
    substituted_holder = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    substituted = replace(request, holder_key=substituted_holder)

    decision = harness.broker.issue(
        substituted,
        manifest=harness.manifest,
        tpm_evidence=harness.accepted_evidence,
    )

    assert decision.allowed is False
    assert decision.reason == Reason.IDENTITY_SIGNATURE
    assert harness.broker_receipts.verify(decision.receipt).reason == Reason.IDENTITY_SIGNATURE


def test_unsupported_issuance_request_version_is_denied(harness: Harness) -> None:
    request = replace(
        harness.endorsed_request(harness.broker.new_challenge()),
        version="atcap-issuance/v2",
    )
    request = replace(
        request,
        identity_signature=harness.identity_private.sign(request.signing_bytes()).hex(),
    )

    decision = harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=harness.accepted_evidence,
    )

    assert decision.allowed is False
    assert decision.reason == Reason.REQUEST_BINDING


def test_identity_endorsed_malformed_holder_key_is_denied(harness: Harness) -> None:
    request = harness.endorsed_request(
        harness.broker.new_challenge(),
        holder_public="not-an-ed25519-public-key",
    )

    decision = harness.broker.issue(
        request,
        manifest=harness.manifest,
        tpm_evidence=harness.accepted_evidence,
    )

    assert decision.allowed is False
    assert decision.reason == Reason.REQUEST_BINDING


def test_substituted_manifest_is_not_authorized(harness: Harness) -> None:
    request = harness.endorsed_request(harness.broker.new_challenge())
    substituted_manifest = copy.deepcopy(harness.manifest)
    substituted_manifest["agent_id"] = "spiffe://attested-capability.test/agent/other"

    decision = harness.broker.issue(
        request,
        manifest=substituted_manifest,
        tpm_evidence=harness.accepted_evidence,
    )

    assert decision.allowed is False
    assert decision.reason == Reason.MANIFEST_POLICY
    assert harness.broker_receipts.verify(decision.receipt).reason == Reason.MANIFEST_POLICY


def test_manifest_with_policy_matching_digest_but_invalid_signature_is_denied(
    harness: Harness,
) -> None:
    tampered_manifest = copy.deepcopy(harness.manifest)
    tampered_manifest["agent_id"] = "spiffe://attested-capability.test/agent/tampered"
    tampered_policy = replace(
        harness.policy.manifest,
        expected_digest=signed_manifest_digest(tampered_manifest),
    )

    with pytest.raises(DecisionError) as caught:
        verify_signed_manifest(tampered_manifest, tampered_policy)

    assert caught.value.reason == Reason.MANIFEST_INVALID
