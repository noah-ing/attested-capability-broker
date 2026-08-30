"""Fail-closed tests for the released Agent Manifest TPM adapter."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from agent_manifest import TpmVerificationError
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

import atcap.tpm as tpm_module
from atcap.errors import DecisionError, Reason
from atcap.tpm import (
    ReleasedTpmAppraiser,
    TestTpmAppraiser,
    enforce_synthetic_ak_certificate_policy,
    issuance_qualifying_data,
)

from .support import Harness

_EVALUATION_TIME = datetime(2026, 8, 29, 12, tzinfo=UTC)


def test_test_tpm_appraiser_is_not_a_pytest_test_class() -> None:
    assert TestTpmAppraiser.__test__ is False


def _key_usage(*, digital_signature: bool, key_cert_sign: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=digital_signature,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=key_cert_sign,
        crl_sign=key_cert_sign,
        encipher_only=None,
        decipher_only=None,
    )


def _certificate(
    *,
    common_name: str,
    public_key: Any,
    issuer: x509.Name,
    signer: Ed25519PrivateKey,
    not_valid_before: datetime,
    not_valid_after: datetime,
    basic_constraints: x509.BasicConstraints | None,
    key_usage: x509.KeyUsage | None,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
    )
    if basic_constraints is not None:
        builder = builder.add_extension(basic_constraints, critical=True)
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    return builder.sign(signer, algorithm=None)


def _root(
    common_name: str = "Synthetic test root",
    *,
    ca: bool = True,
    path_length: int | None = 2,
    key_cert_sign: bool = True,
    include_basic_constraints: bool = True,
    include_key_usage: bool = True,
    not_valid_before: datetime | None = None,
    not_valid_after: datetime | None = None,
) -> tuple[Ed25519PrivateKey, x509.Certificate]:
    key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    return key, _certificate(
        common_name=common_name,
        public_key=key.public_key(),
        issuer=name,
        signer=key,
        not_valid_before=not_valid_before or _EVALUATION_TIME - timedelta(days=1),
        not_valid_after=not_valid_after or _EVALUATION_TIME + timedelta(days=1),
        basic_constraints=(
            x509.BasicConstraints(ca=ca, path_length=path_length if ca else None)
            if include_basic_constraints
            else None
        ),
        key_usage=(
            _key_usage(digital_signature=False, key_cert_sign=key_cert_sign)
            if include_key_usage
            else None
        ),
    )


def _issued_certificate(
    *,
    common_name: str,
    issuer: x509.Certificate,
    issuer_key: Ed25519PrivateKey,
    subject_signer: Ed25519PrivateKey | None = None,
    ca: bool,
    path_length: int | None,
    digital_signature: bool,
    key_cert_sign: bool,
    not_valid_before: datetime | None = None,
    not_valid_after: datetime | None = None,
    include_basic_constraints: bool = True,
    include_key_usage: bool = True,
) -> tuple[Ed25519PrivateKey, x509.Certificate]:
    subject_key = subject_signer or Ed25519PrivateKey.generate()
    return subject_key, _certificate(
        common_name=common_name,
        public_key=subject_key.public_key(),
        issuer=issuer.subject,
        signer=issuer_key,
        not_valid_before=not_valid_before or _EVALUATION_TIME - timedelta(hours=1),
        not_valid_after=not_valid_after or _EVALUATION_TIME + timedelta(hours=1),
        basic_constraints=(
            x509.BasicConstraints(ca=ca, path_length=path_length)
            if include_basic_constraints
            else None
        ),
        key_usage=(
            _key_usage(
                digital_signature=digital_signature,
                key_cert_sign=key_cert_sign,
            )
            if include_key_usage
            else None
        ),
    )


def _pem(*certificates: x509.Certificate) -> bytes:
    return b"".join(
        certificate.public_bytes(serialization.Encoding.PEM) for certificate in certificates
    )


def _valid_ak_material() -> tuple[bytes, bytes]:
    root_key, root = _root()
    _, leaf = _issued_certificate(
        common_name="Synthetic AK leaf",
        issuer=root,
        issuer_key=root_key,
        ca=False,
        path_length=None,
        digital_signature=True,
        key_cert_sign=False,
    )
    return _pem(leaf, root), _pem(root)


def _tamper_certificate_signature(certificate: x509.Certificate) -> x509.Certificate:
    der = bytearray(certificate.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 1
    return x509.load_der_x509_certificate(bytes(der))


def test_released_adapter_passes_all_policy_bindings_and_requires_true(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def accept(
        attest: bytes,
        signature: bytes,
        ak_chain_pem: bytes,
        **kwargs: Any,
    ) -> bool:
        captured.update(
            attest=attest,
            signature=signature,
            ak_chain_pem=ak_chain_pem,
            **kwargs,
        )
        return True

    chain_pem, root_pem = _valid_ak_material()
    evidence = replace(harness.accepted_evidence, ak_chain_pem=chain_pem)
    policy = replace(harness.policy.tpm, trusted_roots_pem=root_pem)
    monkeypatch.setattr(tpm_module, "verify_tpm_quote", accept)
    appraiser = ReleasedTpmAppraiser(
        selection_reader=lambda _attest: policy.selection,
        evaluation_time=lambda: _EVALUATION_TIME,
    )
    qualifying_data = b"qualifying-data"

    appraiser.appraise(
        evidence,
        expected_qualifying_data=qualifying_data,
        policy=policy,
    )

    assert captured == {
        "attest": harness.accepted_evidence.attest,
        "signature": harness.accepted_evidence.signature,
        "ak_chain_pem": chain_pem,
        "trusted_roots_pem": root_pem,
        "expected_qualifying_data": qualifying_data,
        "expected_pcr_digest": harness.policy.tpm.expected_pcr_digest,
    }


def test_truthy_non_boolean_tpm_result_fails_closed(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    chain_pem, root_pem = _valid_ak_material()
    evidence = replace(harness.accepted_evidence, ak_chain_pem=chain_pem)
    policy = replace(harness.policy.tpm, trusted_roots_pem=root_pem)
    monkeypatch.setattr(tpm_module, "verify_tpm_quote", lambda *args, **kwargs: 1)
    appraiser = ReleasedTpmAppraiser(
        selection_reader=lambda _attest: policy.selection,
        evaluation_time=lambda: _EVALUATION_TIME,
    )

    with pytest.raises(DecisionError) as caught:
        appraiser.appraise(
            evidence,
            expected_qualifying_data=b"qualifying-data",
            policy=policy,
        )

    assert caught.value.reason == Reason.TPM_INVALID


def test_wrong_signed_pcr_selection_fails_before_quote_acceptance(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def should_not_run(*args: Any, **kwargs: Any) -> bool:
        nonlocal called
        del args, kwargs
        called = True
        return True

    monkeypatch.setattr(tpm_module, "verify_tpm_quote", should_not_run)
    appraiser = ReleasedTpmAppraiser(selection_reader=lambda _attest: (("sha256", (0,)),))

    with pytest.raises(DecisionError) as caught:
        appraiser.appraise(
            harness.accepted_evidence,
            expected_qualifying_data=b"qualifying-data",
            policy=harness.policy.tpm,
        )

    assert caught.value.reason == Reason.PCR_POLICY
    assert called is False


def _invalid_ak_material(case: str) -> tuple[bytes, bytes]:
    if case == "expired-leaf":
        root_key, root = _root()
        _, leaf = _issued_certificate(
            common_name="Expired AK",
            issuer=root,
            issuer_key=root_key,
            ca=False,
            path_length=None,
            digital_signature=True,
            key_cert_sign=False,
            not_valid_before=_EVALUATION_TIME - timedelta(hours=2),
            not_valid_after=_EVALUATION_TIME - timedelta(hours=1),
        )
        return _pem(leaf, root), _pem(root)
    if case == "not-yet-valid-leaf":
        root_key, root = _root()
        _, leaf = _issued_certificate(
            common_name="Future AK",
            issuer=root,
            issuer_key=root_key,
            ca=False,
            path_length=None,
            digital_signature=True,
            key_cert_sign=False,
            not_valid_before=_EVALUATION_TIME + timedelta(hours=1),
            not_valid_after=_EVALUATION_TIME + timedelta(hours=2),
        )
        return _pem(leaf, root), _pem(root)
    if case == "non-ca-issuer-root":
        root_key, root = _root(ca=False, path_length=None)
        _, leaf = _issued_certificate(
            common_name="AK under non-CA",
            issuer=root,
            issuer_key=root_key,
            ca=False,
            path_length=None,
            digital_signature=True,
            key_cert_sign=False,
        )
        return _pem(leaf, root), _pem(root)
    if case in {
        "expired-intermediate",
        "not-yet-valid-intermediate",
        "intermediate-key-usage",
    }:
        root_key, root = _root(path_length=2)
        intermediate_not_before = _EVALUATION_TIME - timedelta(hours=1)
        intermediate_not_after = _EVALUATION_TIME + timedelta(hours=1)
        if case == "expired-intermediate":
            intermediate_not_before = _EVALUATION_TIME - timedelta(hours=2)
            intermediate_not_after = _EVALUATION_TIME - timedelta(hours=1)
        elif case == "not-yet-valid-intermediate":
            intermediate_not_before = _EVALUATION_TIME + timedelta(hours=1)
            intermediate_not_after = _EVALUATION_TIME + timedelta(hours=2)
        intermediate_key, intermediate = _issued_certificate(
            common_name="Profile-negative AK intermediate",
            issuer=root,
            issuer_key=root_key,
            ca=True,
            path_length=0,
            digital_signature=False,
            key_cert_sign=case != "intermediate-key-usage",
            not_valid_before=intermediate_not_before,
            not_valid_after=intermediate_not_after,
        )
        _, leaf = _issued_certificate(
            common_name="AK below profile-negative intermediate",
            issuer=intermediate,
            issuer_key=intermediate_key,
            ca=False,
            path_length=None,
            digital_signature=True,
            key_cert_sign=False,
        )
        return _pem(leaf, intermediate, root), _pem(root)
    if case == "intermediate-path-length":
        root_key, root = _root(path_length=3)
        issuing_key, issuing = _issued_certificate(
            common_name="Path-length-zero issuer",
            issuer=root,
            issuer_key=root_key,
            ca=True,
            path_length=0,
            digital_signature=False,
            key_cert_sign=True,
        )
        subordinate_key, subordinate = _issued_certificate(
            common_name="Subordinate issuer",
            issuer=issuing,
            issuer_key=issuing_key,
            ca=True,
            path_length=0,
            digital_signature=False,
            key_cert_sign=True,
        )
        _, leaf = _issued_certificate(
            common_name="AK below excess issuer",
            issuer=subordinate,
            issuer_key=subordinate_key,
            ca=False,
            path_length=None,
            digital_signature=True,
            key_cert_sign=False,
        )
        return _pem(leaf, subordinate, issuing, root), _pem(root)
    if case == "leaf-key-usage":
        root_key, root = _root()
        _, leaf = _issued_certificate(
            common_name="AK without digitalSignature",
            issuer=root,
            issuer_key=root_key,
            ca=False,
            path_length=None,
            digital_signature=False,
            key_cert_sign=False,
        )
        return _pem(leaf, root), _pem(root)
    if case == "leaf-key-cert-sign":
        root_key, root = _root()
        _, leaf = _issued_certificate(
            common_name="AK with incompatible keyCertSign",
            issuer=root,
            issuer_key=root_key,
            ca=False,
            path_length=None,
            digital_signature=True,
            key_cert_sign=True,
        )
        return _pem(leaf, root), _pem(root)
    if case == "ca-leaf":
        root_key, root = _root()
        _, leaf = _issued_certificate(
            common_name="CA-marked AK leaf",
            issuer=root,
            issuer_key=root_key,
            ca=True,
            path_length=0,
            digital_signature=True,
            key_cert_sign=False,
        )
        return _pem(leaf, root), _pem(root)
    if case == "ca-key-usage":
        root_key, root = _root(key_cert_sign=False)
        _, leaf = _issued_certificate(
            common_name="AK below incompatible CA",
            issuer=root,
            issuer_key=root_key,
            ca=False,
            path_length=None,
            digital_signature=True,
            key_cert_sign=False,
        )
        return _pem(leaf, root), _pem(root)
    raise AssertionError(f"unknown invalid AK material case: {case}")


@pytest.mark.parametrize(
    "case",
    [
        "expired-leaf",
        "not-yet-valid-leaf",
        "non-ca-issuer-root",
        "expired-intermediate",
        "not-yet-valid-intermediate",
        "intermediate-key-usage",
        "intermediate-path-length",
        "ca-leaf",
        "leaf-key-usage",
        "leaf-key-cert-sign",
        "ca-key-usage",
    ],
)
def test_local_ak_policy_rejects_before_released_quote_verification(
    case: str,
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    chain_pem, root_pem = _invalid_ak_material(case)
    evidence = replace(harness.accepted_evidence, ak_chain_pem=chain_pem)
    policy = replace(harness.policy.tpm, trusted_roots_pem=root_pem)
    released_verifier_called = False

    def should_not_run(*args: Any, **kwargs: Any) -> bool:
        nonlocal released_verifier_called
        del args, kwargs
        released_verifier_called = True
        return True

    monkeypatch.setattr(tpm_module, "verify_tpm_quote", should_not_run)
    appraiser = ReleasedTpmAppraiser(
        selection_reader=lambda _attest: policy.selection,
        evaluation_time=lambda: _EVALUATION_TIME,
    )

    with pytest.raises(DecisionError) as caught:
        appraiser.appraise(
            evidence,
            expected_qualifying_data=b"qualifying-data",
            policy=policy,
        )

    assert caught.value.reason == Reason.TPM_UNTRUSTED
    assert released_verifier_called is False


@pytest.mark.parametrize(
    ("chain_pem", "roots_pem"),
    [
        (b"", b"not reached"),
        (b"not a certificate", b"not reached"),
        (_valid_ak_material()[0], b""),
        (_valid_ak_material()[0], b"not a certificate"),
    ],
)
def test_local_ak_policy_fails_closed_on_missing_or_malformed_pem(
    chain_pem: bytes,
    roots_pem: bytes,
) -> None:
    with pytest.raises(ValueError):
        enforce_synthetic_ak_certificate_policy(
            ak_chain_pem=chain_pem,
            trusted_roots_pem=roots_pem,
            evaluation_time=_EVALUATION_TIME,
        )


@pytest.mark.parametrize("missing", ["leaf-basic", "leaf-usage", "ca-basic", "ca-usage"])
def test_local_ak_policy_requires_role_extensions(missing: str) -> None:
    root_key, root = _root(
        include_basic_constraints=missing != "ca-basic",
        include_key_usage=missing != "ca-usage",
    )
    _, leaf = _issued_certificate(
        common_name="AK with a missing required extension",
        issuer=root,
        issuer_key=root_key,
        ca=False,
        path_length=None,
        digital_signature=True,
        key_cert_sign=False,
        include_basic_constraints=missing != "leaf-basic",
        include_key_usage=missing != "leaf-usage",
    )

    with pytest.raises(ValueError):
        enforce_synthetic_ak_certificate_policy(
            ak_chain_pem=_pem(leaf, root),
            trusted_roots_pem=_pem(root),
            evaluation_time=_EVALUATION_TIME,
        )


def test_local_ak_policy_rejects_naive_evaluation_time() -> None:
    chain_pem, root_pem = _valid_ak_material()

    with pytest.raises(ValueError):
        enforce_synthetic_ak_certificate_policy(
            ak_chain_pem=chain_pem,
            trusted_roots_pem=root_pem,
            evaluation_time=_EVALUATION_TIME.replace(tzinfo=None),
        )


def test_local_ak_policy_does_not_apply_validity_to_trust_anchors() -> None:
    expired_root_key, expired_root = _root(
        common_name="Expired synthetic trust anchor",
        not_valid_before=_EVALUATION_TIME - timedelta(days=2),
        not_valid_after=_EVALUATION_TIME - timedelta(days=1),
    )
    _, leaf = _issued_certificate(
        common_name="Current AK below expired trust anchor",
        issuer=expired_root,
        issuer_key=expired_root_key,
        ca=False,
        path_length=None,
        digital_signature=True,
        key_cert_sign=False,
    )
    _, additional_expired_root = _root(
        common_name="Additional expired configured anchor",
        not_valid_before=_EVALUATION_TIME - timedelta(days=2),
        not_valid_after=_EVALUATION_TIME - timedelta(days=1),
    )

    enforce_synthetic_ak_certificate_policy(
        ak_chain_pem=_pem(leaf, expired_root),
        trusted_roots_pem=_pem(expired_root, additional_expired_root),
        evaluation_time=_EVALUATION_TIME,
    )


def test_parseable_tampered_chain_signature_reaches_released_verifier(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root_key, root = _root()
    _, leaf = _issued_certificate(
        common_name="AK with tampered certificate signature",
        issuer=root,
        issuer_key=root_key,
        ca=False,
        path_length=None,
        digital_signature=True,
        key_cert_sign=False,
    )
    tampered_leaf = _tamper_certificate_signature(leaf)
    evidence = replace(harness.accepted_evidence, ak_chain_pem=_pem(tampered_leaf, root))
    policy = replace(harness.policy.tpm, trusted_roots_pem=_pem(root))
    released_verifier_called = False

    def reject_broken_chain(*args: Any, **kwargs: Any) -> bool:
        nonlocal released_verifier_called
        del args, kwargs
        released_verifier_called = True
        raise TpmVerificationError("AK chain certificate signature is invalid")

    monkeypatch.setattr(tpm_module, "verify_tpm_quote", reject_broken_chain)
    appraiser = ReleasedTpmAppraiser(
        selection_reader=lambda _attest: policy.selection,
        evaluation_time=lambda: _EVALUATION_TIME,
    )

    with pytest.raises(DecisionError) as caught:
        appraiser.appraise(
            evidence,
            expected_qualifying_data=b"qualifying-data",
            policy=policy,
        )

    assert caught.value.reason == Reason.TPM_UNTRUSTED
    assert released_verifier_called is True


def test_quote_qualifying_data_commits_to_every_issuance_field(harness: Harness) -> None:
    request = harness.endorsed_request(harness.broker.new_challenge())
    baseline = issuance_qualifying_data(request)
    substitutions = [
        replace(request, holder_key="00" * 32),
        replace(request, resource_issuer_kid="other-kid"),
        replace(request, resource_issuer_key="11" * 32),
        replace(request, requested_scope="mcp://inventoryd/tool/other"),
        replace(request, identity_signature="00" * 64),
    ]

    assert all(issuance_qualifying_data(item) != baseline for item in substitutions)
