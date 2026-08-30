"""Resource-native verification, binding, and atomic redemption tests."""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any

import pytest
from ca2a_runtime.canonical import canonicalize
from ca2a_runtime.delegation import (
    DelegationCredential,
    HolderProof,
    build_holder_proof,
)
from ca2a_runtime.delegation.holder import proof_body
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import atcap.inventory as inventory_module
from atcap.broker import credential_to_dict
from atcap.canonical import canonical_digest, canonical_json, challenge_token_hash
from atcap.errors import PostInvocationError, Reason
from atcap.inventory import LookupInput
from atcap.receipt import DecisionReceiptPayload
from atcap.storage import CredentialSpendResult

from .support import AUDIENCE, METHOD, SCOPE, Harness


def _unverified_request(credential: dict[str, Any]) -> LookupInput:
    return LookupInput(
        sku="widget-42",
        credential=credential,
        holder_proof={"challenge": "not-evaluated", "signature": "not-evaluated"},
        record_id=secrets.token_hex(16),
    )


def test_allow_redeems_inside_inventoryd_and_signs_canonical_receipt(
    harness: Harness,
) -> None:
    credential, _ = harness.issue_credential()
    challenge, request = harness.lookup_request(credential)

    decision = harness.inventory.redeem(request)

    assert decision.allowed is True
    assert decision.reason == Reason.ALLOW
    assert decision.result == {
        "sku": "widget-42",
        "quantity": 7,
        "invocation_number": 1,
    }
    assert harness.inventory.invocation_count == 1
    assert harness.store.redemption_count(credential.credential_id) == 1
    payload = harness.inventory_receipts.verify(decision.receipt)
    assert payload.deciding_service == "inventoryd"
    assert payload.decision == "allow"
    assert payload.reason == Reason.ALLOW
    assert payload.credential_id == credential.credential_id
    assert payload.method == METHOD
    assert payload.audience == AUDIENCE
    assert payload.qualified_scope == SCOPE
    assert payload.challenge_token_hash == challenge_token_hash(challenge.token)
    assert payload.arguments_digest == challenge.arguments_digest
    assert payload.record_id == challenge.record_id
    assert payload.invocation_id == decision.result["invocation_number"]
    assert payload.handler_count_snapshot == 1
    assert payload.handler_invoked is True
    assert payload.business_result == "completed"


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("audience", "another-resource"),
        ("method", "inventory.other"),
        ("qualified_scope", "mcp://inventoryd/tool/inventory.other"),
        ("trusted_broker_public_hex", "00" * 32),
        ("challenge_ttl_seconds", 61),
        ("max_credential_lifetime_seconds", 301),
    ],
)
def test_resource_receipt_policy_hash_commits_every_security_input(
    harness: Harness,
    field: str,
    replacement: object,
) -> None:
    credential, _ = harness.issue_credential()
    _, request = harness.lookup_request(credential)

    decision = harness.inventory.redeem(request)

    payload = harness.inventory_receipts.verify(decision.receipt)
    expected = canonical_digest(harness.resource_policy.public_dict())
    assert payload.artifact_hashes["resource_policy_sha256"] == expected
    mutated = replace(harness.resource_policy, **{field: replacement})
    assert canonical_digest(mutated.public_dict()) != expected


def test_resource_challenge_hash_and_full_context_are_persisted(harness: Harness) -> None:
    credential, _ = harness.issue_credential()
    challenge, _ = harness.lookup_request(credential, record_id="record-context-test")

    stored = harness.store.get_resource_challenge(challenge_token_hash(challenge.token))

    assert stored is not None
    assert stored.token_hash == challenge_token_hash(challenge.token)
    assert challenge.token not in stored.token_hash
    assert stored.credential_id == credential.credential_id
    assert stored.method == METHOD
    assert stored.arguments_digest == challenge.arguments_digest
    assert stored.record_id == "record-context-test"
    assert stored.audience == AUDIENCE
    assert stored.expires_at == challenge.expires_at


def test_untrusted_resource_specific_broker_root_is_denied(harness: Harness) -> None:
    attacker_issuer = Ed25519PrivateKey.generate()
    attacker_credential = harness.signed_credential(issuer_private=attacker_issuer)
    request = _unverified_request(credential_to_dict(attacker_credential))

    decision = harness.inventory.redeem(request)

    assert decision.allowed is False
    assert decision.reason == Reason.CREDENTIAL_INVALID
    assert harness.inventory.invocation_count == 0
    payload = harness.inventory_receipts.verify(decision.receipt)
    assert payload.decision == "deny"
    assert payload.handler_invoked is False
    assert payload.business_result == "not_invoked"


def test_wrong_resource_scope_is_denied(harness: Harness) -> None:
    credential = harness.signed_credential(scope="mcp://inventoryd/tool/inventory.admin")
    request = _unverified_request(credential_to_dict(credential))

    decision = harness.inventory.redeem(request)

    assert decision.allowed is False
    assert decision.reason == Reason.SCOPE_DENIED
    assert harness.inventory.invocation_count == 0
    assert harness.inventory_receipts.verify(decision.receipt).reason == Reason.SCOPE_DENIED


def test_expired_credential_is_denied(harness: Harness) -> None:
    credential = harness.signed_credential(
        not_before=harness.clock() - 300,
        not_after=harness.clock() - 1,
    )
    request = _unverified_request(credential_to_dict(credential))

    decision = harness.inventory.redeem(request)

    assert decision.allowed is False
    assert decision.reason == Reason.CREDENTIAL_EXPIRED
    assert harness.inventory.invocation_count == 0
    assert harness.inventory_receipts.verify(decision.receipt).reason == Reason.CREDENTIAL_EXPIRED


@pytest.mark.parametrize(
    ("not_before", "not_after"),
    [
        (None, 1_900_000_000),
        (1_700_000_000, None),
        (None, None),
    ],
)
def test_credential_with_missing_validity_bound_is_denied(
    harness: Harness,
    not_before: int | None,
    not_after: int | None,
) -> None:
    credential = DelegationCredential(
        credential_id=secrets.token_hex(32),
        issuer=harness.broker_issuer_public,
        subject=harness.holder_public,
        scope=frozenset({SCOPE}),
        depth=0,
        parent_id=None,
        not_before=not_before,
        not_after=not_after,
    ).sign(harness.broker_issuer_private)

    decision = harness.inventory.redeem(_unverified_request(credential_to_dict(credential)))

    assert decision.allowed is False
    assert decision.reason == Reason.CREDENTIAL_INVALID
    assert harness.inventory.invocation_count == 0


def test_overlong_credential_lifetime_is_denied(harness: Harness) -> None:
    credential = harness.signed_credential(
        not_before=harness.clock(),
        not_after=harness.clock() + harness.resource_policy.max_credential_lifetime_seconds + 1,
    )

    decision = harness.inventory.redeem(_unverified_request(credential_to_dict(credential)))

    assert decision.allowed is False
    assert decision.reason == Reason.CREDENTIAL_INVALID
    assert harness.inventory.invocation_count == 0


def test_holder_key_substitution_is_denied(harness: Harness) -> None:
    credential, _ = harness.issue_credential()
    challenge, request = harness.lookup_request(credential)
    wrong_holder = Ed25519PrivateKey.generate()
    signed_body = proof_body(
        audience=AUDIENCE,
        challenge=challenge.token,
        credential_id=credential.credential_id,
        subject=credential.subject,
        requested_capability=SCOPE,
        record_id=request.record_id,
        sealed_payload=canonical_json({"sku": request.sku}),
        caller_channel_key=None,
        parent_record_hash=None,
    )
    substituted_proof = HolderProof(
        challenge=challenge.token,
        signature=wrong_holder.sign(canonicalize(signed_body)).hex(),
    )
    substituted = request.model_copy(update={"holder_proof": substituted_proof.to_dict()})

    decision = harness.inventory.redeem(substituted)

    assert decision.allowed is False
    assert decision.reason == Reason.HOLDER_PROOF_INVALID
    assert harness.inventory.invocation_count == 0
    assert harness.store.redemption_count(credential.credential_id) == 0


def test_resource_challenge_cannot_be_moved_to_another_credential(
    harness: Harness,
) -> None:
    first_credential, _ = harness.issue_credential()
    second_credential, _ = harness.issue_credential()
    challenge, first_request = harness.lookup_request(first_credential)
    # Re-sign for credential two over credential one's issued challenge. The
    # holder has both grants, but inventoryd still rejects the context swap.
    second_proof = build_holder_proof(
        harness.holder_private,
        second_credential,
        audience=AUDIENCE,
        challenge=challenge.token,
        requested_capability=SCOPE,
        record_id=first_request.record_id,
        sealed_payload=canonical_json({"sku": first_request.sku}),
        caller_channel_key=None,
        parent_record_hash=None,
    )
    substituted = first_request.model_copy(
        update={
            "credential": credential_to_dict(second_credential),
            "holder_proof": second_proof.to_dict(),
        }
    )

    decision = harness.inventory.redeem(substituted)

    assert decision.allowed is False
    assert decision.reason == Reason.HOLDER_PROOF_INVALID
    assert harness.inventory.invocation_count == 0


@pytest.mark.parametrize(
    ("audience", "capability"),
    [
        ("other-resource", SCOPE),
        (AUDIENCE, "mcp://inventoryd/tool/other"),
    ],
)
def test_holder_proof_is_bound_to_audience_and_qualified_capability(
    harness: Harness,
    audience: str,
    capability: str,
) -> None:
    credential, _ = harness.issue_credential()
    challenge, request = harness.lookup_request(credential)
    wrong_context_proof = build_holder_proof(
        harness.holder_private,
        credential,
        audience=audience,
        challenge=challenge.token,
        requested_capability=capability,
        record_id=request.record_id,
        sealed_payload=canonical_json({"sku": request.sku}),
        caller_channel_key=None,
        parent_record_hash=None,
    )
    substituted = request.model_copy(update={"holder_proof": wrong_context_proof.to_dict()})

    decision = harness.inventory.redeem(substituted)

    assert decision.allowed is False
    assert decision.reason == Reason.HOLDER_PROOF_INVALID
    assert harness.inventory.invocation_count == 0


@pytest.mark.parametrize(
    ("field", "substitution"),
    [
        ("sku", "widget-99"),
        ("record_id", "record-substitution"),
    ],
)
def test_resource_challenge_rejects_argument_or_record_substitution(
    harness: Harness,
    field: str,
    substitution: str,
) -> None:
    credential, _ = harness.issue_credential()
    _, request = harness.lookup_request(credential)
    tampered = request.model_copy(update={field: substitution})

    decision = harness.inventory.redeem(tampered)

    assert decision.allowed is False
    assert decision.reason == Reason.HOLDER_PROOF_INVALID
    assert harness.inventory.invocation_count == 0
    assert harness.store.redemption_count(credential.credential_id) == 0


@pytest.mark.parametrize("failure_stage", ["holder-proof-verifier", "atomic-spend"])
def test_unexpected_authorization_failure_is_signed_fail_closed_and_does_not_leak(
    failure_stage: str,
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential, _ = harness.issue_credential()
    challenge, request = harness.lookup_request(
        credential,
        record_id=f"internal-error-{failure_stage}",
    )
    exception_marker = "authorization dependency exposed raw secrets"
    handler_called = False

    def fail_authorization(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError(exception_marker)

    def forbidden_handler(_arguments: object) -> dict[str, Any]:
        nonlocal handler_called
        handler_called = True
        return {"should": "not execute"}

    monkeypatch.setattr(harness.inventory, "_inventory_lookup", forbidden_handler)
    if failure_stage == "holder-proof-verifier":
        monkeypatch.setattr(inventory_module, "verify_holder_proof", fail_authorization)
    else:
        monkeypatch.setattr(
            harness.store,
            "consume_challenge_and_spend_credential",
            fail_authorization,
        )

    decision = harness.inventory.redeem(request)

    assert decision.allowed is False
    assert decision.reason == Reason.INTERNAL_ERROR
    assert decision.result is None
    assert handler_called is False
    assert harness.inventory.invocation_count == 0
    assert harness.store.redemption_count(credential.credential_id) == 0
    stored = harness.store.get_resource_challenge(challenge_token_hash(challenge.token))
    assert stored is not None
    assert stored.consumed_at is None
    payload = harness.inventory_receipts.verify(decision.receipt)
    assert payload.decision == "deny"
    assert payload.reason == Reason.INTERNAL_ERROR
    assert payload.credential_id == credential.credential_id
    assert payload.challenge_token_hash == challenge_token_hash(challenge.token)
    assert payload.invocation_id is None
    assert payload.handler_count_snapshot == 0
    assert payload.handler_invoked is False
    assert payload.business_result == "not_invoked"

    exposed = json.dumps(decision.to_dict(), sort_keys=True) + payload.model_dump_json()
    private_markers = (
        exception_marker,
        challenge.token,
        request.holder_proof["signature"],
        request.credential["signature"],
        credential.subject,
        credential.issuer,
        harness.inventory.challenge_secret.hex(),
        harness.holder_private.private_bytes_raw().hex(),
        harness.broker_issuer_private.private_bytes_raw().hex(),
        str(harness.manifest["manifest_id"]),
        harness.accepted_evidence.attest.hex(),
        harness.accepted_evidence.signature.hex(),
        harness.accepted_evidence.ak_chain_pem.decode(),
    )
    assert all(marker not in exposed for marker in private_markers)


def test_stale_resource_challenge_is_denied(harness: Harness) -> None:
    credential, _ = harness.issue_credential()
    challenge, request = harness.lookup_request(credential)
    harness.clock.set(challenge.expires_at + 1)

    decision = harness.inventory.redeem(request)

    assert decision.allowed is False
    assert decision.reason == Reason.CHALLENGE_STALE
    assert harness.inventory.invocation_count == 0
    assert harness.store.redemption_count(credential.credential_id) == 0


def test_spent_credential_is_denied_with_a_fresh_valid_holder_proof(
    harness: Harness,
) -> None:
    credential, _ = harness.issue_credential()
    first_challenge, first_request = harness.lookup_request(credential)
    first = harness.inventory.redeem(first_request)
    second_challenge, second_request = harness.lookup_request(credential)

    second = harness.inventory.redeem(second_request)

    assert first.allowed is True
    assert second.allowed is False
    assert second.reason == Reason.CREDENTIAL_SPENT
    assert first_challenge.token != second_challenge.token
    assert first_request.holder_proof != second_request.holder_proof
    assert harness.inventory.invocation_count == 1
    assert harness.store.redemption_count(credential.credential_id) == 1
    assert harness.inventory_receipts.verify(second.receipt).reason == Reason.CREDENTIAL_SPENT


def test_consumed_resource_challenge_cannot_be_replayed(harness: Harness) -> None:
    credential, _ = harness.issue_credential()
    _, request = harness.lookup_request(credential)
    first = harness.inventory.redeem(request)

    replay = harness.inventory.redeem(request)

    assert first.allowed is True
    assert replay.allowed is False
    assert replay.reason == Reason.CHALLENGE_CONSUMED
    assert harness.inventory.invocation_count == 1


def test_two_fresh_proofs_racing_one_credential_invoke_exactly_once(
    harness: Harness,
) -> None:
    credential, _ = harness.issue_credential()
    first_challenge, first_request = harness.lookup_request(credential)
    second_challenge, second_request = harness.lookup_request(credential)
    barrier = threading.Barrier(3)

    def redeem_after_barrier(request: LookupInput):
        barrier.wait(timeout=10)
        return harness.inventory.redeem(request)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(redeem_after_barrier, first_request)
        second_future = executor.submit(redeem_after_barrier, second_request)
        barrier.wait(timeout=10)
        decisions = [first_future.result(timeout=10), second_future.result(timeout=10)]

    assert first_challenge.token != second_challenge.token
    assert first_request.holder_proof != second_request.holder_proof
    assert sum(decision.allowed for decision in decisions) == 1
    assert sorted(decision.reason for decision in decisions) == [
        Reason.ALLOW,
        Reason.CREDENTIAL_SPENT,
    ]
    assert harness.inventory.invocation_count == 1
    assert harness.store.redemption_count(credential.credential_id) == 1


def test_parallel_valid_calls_sign_their_own_invocation_ids(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_credential, _ = harness.issue_credential()
    second_credential, _ = harness.issue_credential()
    _, first_request = harness.lookup_request(first_credential, record_id="parallel-first")
    _, second_request = harness.lookup_request(second_credential, record_id="parallel-second")
    original_lookup = harness.inventory._inventory_lookup
    both_invoked = threading.Barrier(2)

    def synchronized_lookup(arguments: Any) -> dict[str, Any]:
        both_invoked.wait(timeout=10)
        return original_lookup(arguments)

    monkeypatch.setattr(harness.inventory, "_inventory_lookup", synchronized_lookup)
    with ThreadPoolExecutor(max_workers=2) as executor:
        decisions = [
            future.result(timeout=15)
            for future in (
                executor.submit(harness.inventory.redeem, first_request),
                executor.submit(harness.inventory.redeem, second_request),
            )
        ]

    assert all(decision.allowed for decision in decisions)
    assert all(decision.result is not None for decision in decisions)
    invocation_ids = {
        decision.result["invocation_number"]  # type: ignore[index]
        for decision in decisions
    }
    assert invocation_ids == {1, 2}
    for decision in decisions:
        assert decision.result is not None
        payload = harness.inventory_receipts.verify(decision.receipt)
        assert payload.invocation_id == decision.result["invocation_number"]
        assert payload.handler_count_snapshot == 2


def test_challenge_expiring_while_waiting_for_sqlite_lock_is_not_spent(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential, _ = harness.issue_credential()
    challenge, request = harness.lookup_request(credential)
    original_consume = harness.store.consume_challenge_and_spend_credential
    reached_transaction = threading.Event()

    def observed_consume(**kwargs: Any) -> CredentialSpendResult:
        reached_transaction.set()
        return original_consume(**kwargs)

    monkeypatch.setattr(
        harness.store,
        "consume_challenge_and_spend_credential",
        observed_consume,
    )
    lock_connection = sqlite3.connect(
        harness.store.path,
        isolation_level=None,
    )
    lock_connection.execute("BEGIN IMMEDIATE")
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(harness.inventory.redeem, request)
            assert reached_transaction.wait(timeout=10)
            harness.clock.set(challenge.expires_at + 1)
            lock_connection.rollback()
            decision = future.result(timeout=15)
    finally:
        if lock_connection.in_transaction:
            lock_connection.rollback()
        lock_connection.close()

    assert decision.allowed is False
    assert decision.reason == Reason.CHALLENGE_STALE
    assert harness.inventory.invocation_count == 0
    assert harness.store.redemption_count(credential.credential_id) == 0


def test_credential_expiring_while_waiting_for_sqlite_lock_is_not_spent(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential = harness.signed_credential(
        not_before=harness.clock(),
        not_after=harness.clock() + 1,
    )
    _, request = harness.lookup_request(credential)
    original_consume = harness.store.consume_challenge_and_spend_credential
    reached_transaction = threading.Event()

    def observed_consume(**kwargs: Any) -> CredentialSpendResult:
        reached_transaction.set()
        return original_consume(**kwargs)

    monkeypatch.setattr(
        harness.store,
        "consume_challenge_and_spend_credential",
        observed_consume,
    )
    lock_connection = sqlite3.connect(harness.store.path, isolation_level=None)
    lock_connection.execute("BEGIN IMMEDIATE")
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(harness.inventory.redeem, request)
            assert reached_transaction.wait(timeout=10)
            harness.clock.set(credential.not_after + 1)
            lock_connection.rollback()
            decision = future.result(timeout=15)
    finally:
        if lock_connection.in_transaction:
            lock_connection.rollback()
        lock_connection.close()

    assert decision.allowed is False
    assert decision.reason == Reason.CREDENTIAL_EXPIRED
    assert harness.inventory.invocation_count == 0
    assert harness.store.redemption_count(credential.credential_id) == 0


def test_handler_failure_after_spend_is_an_authorized_failed_execution(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential, _ = harness.issue_credential()
    _, first_request = harness.lookup_request(credential)

    def fail_after_commit(_arguments: Any) -> dict[str, Any]:
        raise RuntimeError("simulated handler failure after spend commit")

    monkeypatch.setattr(harness.inventory, "_inventory_lookup", fail_after_commit)
    failed = harness.inventory.redeem(first_request)
    _, fresh_request = harness.lookup_request(credential)
    spent = harness.inventory.redeem(fresh_request)

    assert failed.allowed is True
    assert failed.reason == Reason.HANDLER_FAILED
    failure_receipt = harness.inventory_receipts.verify(failed.receipt)
    assert failure_receipt.decision == "allow"
    assert failure_receipt.handler_invoked is True
    assert failure_receipt.business_result == "failed"
    assert failed.result is not None
    assert failure_receipt.invocation_id == failed.result["invocation_number"] == 1
    assert failure_receipt.handler_count_snapshot == 1
    assert spent.allowed is False
    assert spent.reason == Reason.CREDENTIAL_SPENT
    assert harness.inventory.invocation_count == 1
    assert harness.store.redemption_count(credential.credential_id) == 1


def test_receipt_failure_after_successful_handler_is_never_reclassified_as_denial(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential, _ = harness.issue_credential()
    _, request = harness.lookup_request(credential)
    original_sign = harness.inventory.receipt_signer.sign

    def fail_allow_receipt(payload: DecisionReceiptPayload):
        if payload.decision == "allow":
            raise RuntimeError("simulated receipt signer outage after handler")
        return original_sign(payload)

    monkeypatch.setattr(
        harness.inventory.receipt_signer,
        "sign",
        fail_allow_receipt,
    )

    with pytest.raises(
        PostInvocationError,
        match="handler completed but no signed receipt could be produced",
    ) as caught:
        harness.inventory.redeem(request)

    assert caught.value.completed is True
    assert caught.value.invocation_id == 1
    assert harness.inventory.invocation_count == 1
    assert harness.store.redemption_count(credential.credential_id) == 1
