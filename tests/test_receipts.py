"""Standards-based Ed25519 JWS receipt verification tests."""

from __future__ import annotations

import json
import secrets

import pytest
from joserfc import jws
from joserfc.jwk import OKPKey

from atcap.canonical import canonical_json
from atcap.errors import DecisionError, Reason
from atcap.models import SignedDecisionReceipt
from atcap.receipt import (
    JWS_ALGORITHM,
    JWS_TYPE,
    DecisionReceiptPayload,
    ReceiptSigner,
    ReceiptVerifier,
)


def _payload() -> DecisionReceiptPayload:
    return DecisionReceiptPayload(
        schema_version="atcap-decision-receipt/v1",
        receipt_id=secrets.token_hex(16),
        deciding_service="inventoryd",
        decision="allow",
        reason=Reason.ALLOW,
        decided_at=1_800_000_000,
        credential_id=secrets.token_hex(32),
        qualified_scope="mcp://inventoryd/tool/inventory.lookup",
        challenge_token_hash=secrets.token_hex(32),
        manifest_digest=None,
        method="inventory.lookup",
        audience="inventoryd",
        arguments_digest=secrets.token_hex(32),
        record_id=secrets.token_hex(16),
        invocation_id=1,
        handler_count_snapshot=1,
        handler_invoked=True,
        business_result="completed",
        artifact_hashes={"resource_policy_sha256": secrets.token_hex(32)},
    )


def _sign_raw(payload: dict[str, object]) -> tuple[SignedDecisionReceipt, ReceiptVerifier]:
    key = OKPKey.generate_key(
        "Ed25519",
        parameters={"alg": JWS_ALGORITHM, "kid": "inventory-receipt-v1", "use": "sig"},
    )
    compact = jws.serialize_compact(
        {
            "alg": JWS_ALGORITHM,
            "kid": "inventory-receipt-v1",
            "typ": JWS_TYPE,
        },
        canonical_json(payload),
        key,
        algorithms=[JWS_ALGORITHM],
    )
    public = OKPKey.import_key(key.as_dict(private=False))
    return (
        SignedDecisionReceipt(compact_jws=compact),
        ReceiptVerifier(public, key_id="inventory-receipt-v1"),
    )


def test_receipt_round_trip_requires_configured_trusted_key() -> None:
    signer = ReceiptSigner.generate(key_id="inventory-receipt-v1")
    verifier = ReceiptVerifier(
        signer.public_key(),
        key_id="inventory-receipt-v1",
    )
    payload = _payload()

    verified = verifier.verify(signer.sign(payload))

    assert verified == payload


def test_tampered_receipt_is_rejected() -> None:
    signer = ReceiptSigner.generate(key_id="inventory-receipt-v1")
    verifier = ReceiptVerifier(
        signer.public_key(),
        key_id="inventory-receipt-v1",
    )
    compact = signer.sign(_payload()).compact_jws
    protected, encoded_payload, signature = compact.split(".")
    replacement = "A" if encoded_payload[0] != "A" else "B"
    tampered = SignedDecisionReceipt(
        compact_jws=".".join((protected, replacement + encoded_payload[1:], signature))
    )

    with pytest.raises(DecisionError) as caught:
        verifier.verify(tampered)

    assert caught.value.reason == Reason.RECEIPT_INVALID


def test_receipt_from_wrong_signing_key_is_rejected() -> None:
    trusted = ReceiptSigner.generate(key_id="inventory-receipt-v1")
    attacker = ReceiptSigner.generate(key_id="inventory-receipt-v1")
    verifier = ReceiptVerifier(
        trusted.public_key(),
        key_id="inventory-receipt-v1",
    )

    with pytest.raises(DecisionError) as caught:
        verifier.verify(attacker.sign(_payload()))

    assert caught.value.reason == Reason.RECEIPT_INVALID


@pytest.mark.parametrize(
    "protected",
    [
        {
            "alg": JWS_ALGORITHM,
            "kid": "inventory-receipt-v1",
            "typ": "unexpected+jws",
        },
        {
            "alg": JWS_ALGORITHM,
            "kid": "attacker-selected-kid",
            "typ": JWS_TYPE,
        },
    ],
)
def test_correctly_signed_receipt_with_wrong_protected_header_is_rejected(
    protected: dict[str, str],
) -> None:
    key = OKPKey.generate_key(
        "Ed25519",
        parameters={"alg": JWS_ALGORITHM, "kid": "inventory-receipt-v1", "use": "sig"},
    )
    public = OKPKey.import_key(key.as_dict(private=False))
    compact = jws.serialize_compact(
        protected,
        canonical_json(_payload().model_dump(mode="json")),
        key,
        algorithms=[JWS_ALGORITHM],
    )
    verifier = ReceiptVerifier(public, key_id="inventory-receipt-v1")

    with pytest.raises(DecisionError) as caught:
        verifier.verify(SignedDecisionReceipt(compact_jws=compact))

    assert caught.value.reason == Reason.RECEIPT_INVALID


def test_correctly_signed_noncanonical_json_receipt_is_rejected() -> None:
    key = OKPKey.generate_key(
        "Ed25519",
        parameters={"alg": JWS_ALGORITHM, "kid": "inventory-receipt-v1", "use": "sig"},
    )
    public = OKPKey.import_key(key.as_dict(private=False))
    payload = _payload().model_dump(mode="json")
    noncanonical = json.dumps(payload, indent=2).encode()
    compact = jws.serialize_compact(
        {
            "alg": JWS_ALGORITHM,
            "kid": "inventory-receipt-v1",
            "typ": JWS_TYPE,
        },
        noncanonical,
        key,
        algorithms=[JWS_ALGORITHM],
    )
    verifier = ReceiptVerifier(public, key_id="inventory-receipt-v1")

    with pytest.raises(DecisionError) as caught:
        verifier.verify(SignedDecisionReceipt(compact_jws=compact))

    assert caught.value.reason == Reason.RECEIPT_INVALID


@pytest.mark.parametrize(
    ("claim", "wrong_value"),
    [
        ("decided_at", "1800000000"),
        ("invocation_id", "1"),
        ("handler_count_snapshot", "0"),
        ("handler_invoked", "false"),
    ],
)
def test_correctly_signed_receipt_with_wrong_claim_type_is_rejected(
    claim: str,
    wrong_value: object,
) -> None:
    payload = _payload().model_dump(mode="json")
    payload[claim] = wrong_value
    receipt, verifier = _sign_raw(payload)

    with pytest.raises(DecisionError) as caught:
        verifier.verify(receipt)

    assert caught.value.reason == Reason.RECEIPT_INVALID


def test_correctly_signed_receipt_with_unknown_claim_is_rejected() -> None:
    payload = _payload().model_dump(mode="json")
    payload["unsigned_interpretation_hint"] = "ignore-me"
    receipt, verifier = _sign_raw(payload)

    with pytest.raises(DecisionError) as caught:
        verifier.verify(receipt)

    assert caught.value.reason == Reason.RECEIPT_INVALID


@pytest.mark.parametrize(
    "missing",
    [
        "schema_version",
        "invocation_id",
        "handler_count_snapshot",
        "handler_invoked",
        "business_result",
        "artifact_hashes",
    ],
)
def test_correctly_signed_receipt_missing_core_claim_is_rejected(missing: str) -> None:
    payload = _payload().model_dump(mode="json")
    del payload[missing]
    receipt, verifier = _sign_raw(payload)

    with pytest.raises(DecisionError) as caught:
        verifier.verify(receipt)

    assert caught.value.reason == Reason.RECEIPT_INVALID


@pytest.mark.parametrize(
    "missing",
    ["challenge_token_hash", "record_id", "resource_policy_sha256"],
)
def test_correctly_signed_inventory_allow_missing_security_binding_is_rejected(
    missing: str,
) -> None:
    payload = _payload().model_dump(mode="json")
    if missing == "resource_policy_sha256":
        del payload["artifact_hashes"][missing]
    else:
        del payload[missing]
    receipt, verifier = _sign_raw(payload)

    with pytest.raises(DecisionError) as caught:
        verifier.verify(receipt)

    assert caught.value.reason == Reason.RECEIPT_INVALID


@pytest.mark.parametrize(
    "missing",
    [
        "manifest_digest",
        "challenge_token_hash",
        "qualified_scope",
        "broker_policy_sha256",
    ],
)
def test_correctly_signed_broker_allow_missing_security_binding_is_rejected(
    missing: str,
) -> None:
    payload: dict[str, object] = {
        "schema_version": "atcap-decision-receipt/v1",
        "receipt_id": secrets.token_hex(16),
        "deciding_service": "broker",
        "decision": "allow",
        "reason": Reason.ALLOW,
        "decided_at": 1_800_000_000,
        "credential_id": secrets.token_hex(32),
        "qualified_scope": "mcp://inventoryd/tool/inventory.lookup",
        "challenge_token_hash": secrets.token_hex(32),
        "manifest_digest": secrets.token_hex(32),
        "method": None,
        "audience": None,
        "arguments_digest": None,
        "record_id": None,
        "invocation_id": None,
        "handler_count_snapshot": 0,
        "handler_invoked": False,
        "business_result": "not_applicable",
        "artifact_hashes": {"broker_policy_sha256": secrets.token_hex(32)},
    }
    if missing == "broker_policy_sha256":
        del payload["artifact_hashes"][missing]
    else:
        del payload[missing]
    receipt, verifier = _sign_raw(payload)

    with pytest.raises(DecisionError) as caught:
        verifier.verify(receipt)

    assert caught.value.reason == Reason.RECEIPT_INVALID


def test_correctly_signed_broker_denial_cannot_claim_handler_failure() -> None:
    payload: dict[str, object] = {
        "schema_version": "atcap-decision-receipt/v1",
        "receipt_id": secrets.token_hex(16),
        "deciding_service": "broker",
        "decision": "deny",
        "reason": Reason.HANDLER_FAILED,
        "decided_at": 1_800_000_000,
        "qualified_scope": "mcp://inventoryd/tool/inventory.lookup",
        "challenge_token_hash": secrets.token_hex(32),
        "manifest_digest": secrets.token_hex(32),
        "credential_id": None,
        "method": None,
        "audience": None,
        "arguments_digest": None,
        "record_id": None,
        "invocation_id": None,
        "handler_count_snapshot": 0,
        "handler_invoked": False,
        "business_result": "not_applicable",
        "artifact_hashes": {"broker_policy_sha256": secrets.token_hex(32)},
    }
    receipt, verifier = _sign_raw(payload)

    with pytest.raises(DecisionError) as caught:
        verifier.verify(receipt)

    assert caught.value.reason == Reason.RECEIPT_INVALID


@pytest.mark.parametrize(
    "changes",
    [
        {"handler_invoked": False},
        {"decision": "deny", "business_result": "not_invoked"},
        {"reason": Reason.HANDLER_FAILED, "business_result": "completed"},
    ],
)
def test_correctly_signed_receipt_with_inconsistent_semantics_is_rejected(
    changes: dict[str, object],
) -> None:
    payload = _payload().model_dump(mode="json")
    payload.update(changes)
    receipt, verifier = _sign_raw(payload)

    with pytest.raises(DecisionError) as caught:
        verifier.verify(receipt)

    assert caught.value.reason == Reason.RECEIPT_INVALID
