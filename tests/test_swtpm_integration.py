"""Real swtpm appraisal through the production released-verifier adapter."""

from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import subprocess
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path
from typing import Any

import pytest
from agent_manifest import Ed25519Signer, Manifest, generate_ed25519
from ca2a_runtime.delegation import new_keypair
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from atcap.broker import CapabilityBroker
from atcap.errors import Reason
from atcap.identity import endorse_request, public_key_hex
from atcap.manifest_verifier import signed_manifest_digest
from atcap.models import IssuanceRequest, TpmEvidence
from atcap.policy import BrokerPolicy, ManifestPolicy, TpmPolicy
from atcap.receipt import ReceiptSigner, ReceiptVerifier
from atcap.storage import SQLiteStore
from atcap.tpm import (
    ReleasedTpmAppraiser,
    enforce_synthetic_ak_certificate_policy,
    issuance_qualifying_data,
    tpm2_pytss_selection_reader,
)

_EVENT_DIGEST = hashlib.sha256(b"attested-capability-broker:swtpm-profile:v1").hexdigest()
_EXPECTED_PCR_VALUE = bytes.fromhex(
    "1e5545acda784ccc7ddb39597a58d3d416b269e22aa16f3360cb1663d0a9cda7"  # pragma: allowlist secret
)
_EXPECTED_COMPOSITE_DIGEST = bytes.fromhex(
    "d01da9398dafb3b978b02af56ef39fd50c84546cb9e5271bcce508eb75fff3bf"  # pragma: allowlist secret
)
_SELECTION = (("sha256", (16,)),)
_SCOPE = "mcp://inventoryd/tool/inventory.lookup"
_BROKER_ID = "spiffe://attested-capability.test/broker/inventoryd"
_RESOURCE_ISSUER_KID = "inventoryd-ca2a-v1"
_MANIFEST_ISSUER = "spiffe://attested-capability.test/manifest-authority"
_SYSTEM_PROMPT_HASH = "sha256:" + "a" * 64
_POLICY_BUNDLE_HASH = "sha256:" + "b" * 64
_MODEL_HASH = "sha256:" + "c" * 64
_CERTIFICATE_EVALUATION_TIME = datetime(2030, 1, 1, 12, tzinfo=UTC)


def _tool(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise AssertionError(f"required swtpm integration command is missing: {name}")
    return resolved


def _run_tpm(
    tcti: str,
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment["TPM2TOOLS_TCTI"] = tcti
    return subprocess.run(  # noqa: S603 - executable is resolved from a fixed test list.
        [_tool(arguments[0]), *arguments[1:]],
        check=check,
        capture_output=True,
        env=environment,
    )


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


def _test_root(
    common_name: str,
    *,
    ca: bool = True,
    path_length: int | None = 3,
    key_cert_sign: bool = True,
) -> tuple[Ed25519PrivateKey, x509.Certificate]:
    private_key = Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_CERTIFICATE_EVALUATION_TIME - timedelta(days=1))
        .not_valid_after(_CERTIFICATE_EVALUATION_TIME + timedelta(days=1))
        .add_extension(
            x509.BasicConstraints(ca=ca, path_length=path_length if ca else None),
            critical=True,
        )
        .add_extension(
            _key_usage(digital_signature=False, key_cert_sign=key_cert_sign),
            critical=True,
        )
        .sign(private_key, algorithm=None)
    )
    return private_key, certificate


def _issue_certificate(
    *,
    common_name: str,
    public_key: Any,
    issuer: x509.Certificate,
    issuer_key: Ed25519PrivateKey,
    ca: bool,
    path_length: int | None,
    digital_signature: bool,
    key_cert_sign: bool,
    not_valid_before: datetime | None = None,
    not_valid_after: datetime | None = None,
) -> x509.Certificate:
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(issuer.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before or _CERTIFICATE_EVALUATION_TIME - timedelta(hours=1))
        .not_valid_after(not_valid_after or _CERTIFICATE_EVALUATION_TIME + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
        .add_extension(
            _key_usage(
                digital_signature=digital_signature,
                key_cert_sign=key_cert_sign,
            ),
            critical=True,
        )
        .sign(issuer_key, algorithm=None)
    )


def _pem(*certificates: x509.Certificate) -> bytes:
    return b"".join(
        certificate.public_bytes(serialization.Encoding.PEM) for certificate in certificates
    )


def _tamper_certificate_signature(certificate: x509.Certificate) -> x509.Certificate:
    der = bytearray(certificate.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 1
    return x509.load_der_x509_certificate(bytes(der))


def _issue_ak_chain(
    ak_public_pem: bytes,
    *,
    profile: str = "valid",
) -> tuple[bytes, bytes, bytes]:
    root_key, root = _test_root("Attested Capability Broker swtpm Test Root")
    _, untrusted_root = _test_root("Untrusted swtpm Test Root")
    ak_public = serialization.load_pem_public_key(ak_public_pem)
    leaf_issuer = root
    leaf_issuer_key = root_key
    chain_issuers: list[x509.Certificate] = []

    if profile == "non-ca-issuer":
        issuer_key = Ed25519PrivateKey.generate()
        issuer = _issue_certificate(
            common_name="Non-CA AK issuer",
            public_key=issuer_key.public_key(),
            issuer=root,
            issuer_key=root_key,
            ca=False,
            path_length=None,
            digital_signature=False,
            key_cert_sign=True,
        )
        leaf_issuer = issuer
        leaf_issuer_key = issuer_key
        chain_issuers.append(issuer)
    elif profile in {
        "expired-intermediate",
        "not-yet-valid-intermediate",
        "intermediate-key-usage",
    }:
        intermediate_not_before = _CERTIFICATE_EVALUATION_TIME - timedelta(hours=1)
        intermediate_not_after = _CERTIFICATE_EVALUATION_TIME + timedelta(hours=1)
        if profile == "expired-intermediate":
            intermediate_not_before = _CERTIFICATE_EVALUATION_TIME - timedelta(hours=2)
            intermediate_not_after = _CERTIFICATE_EVALUATION_TIME - timedelta(hours=1)
        elif profile == "not-yet-valid-intermediate":
            intermediate_not_before = _CERTIFICATE_EVALUATION_TIME + timedelta(hours=1)
            intermediate_not_after = _CERTIFICATE_EVALUATION_TIME + timedelta(hours=2)
        intermediate_key = Ed25519PrivateKey.generate()
        intermediate = _issue_certificate(
            common_name="Profile-negative AK intermediate",
            public_key=intermediate_key.public_key(),
            issuer=root,
            issuer_key=root_key,
            ca=True,
            path_length=0,
            digital_signature=False,
            key_cert_sign=profile != "intermediate-key-usage",
            not_valid_before=intermediate_not_before,
            not_valid_after=intermediate_not_after,
        )
        leaf_issuer = intermediate
        leaf_issuer_key = intermediate_key
        chain_issuers.append(intermediate)
    elif profile == "intermediate-path-length":
        constrained_key = Ed25519PrivateKey.generate()
        constrained = _issue_certificate(
            common_name="Path-length-zero AK issuer",
            public_key=constrained_key.public_key(),
            issuer=root,
            issuer_key=root_key,
            ca=True,
            path_length=0,
            digital_signature=False,
            key_cert_sign=True,
        )
        subordinate_key = Ed25519PrivateKey.generate()
        subordinate = _issue_certificate(
            common_name="Excess subordinate AK issuer",
            public_key=subordinate_key.public_key(),
            issuer=constrained,
            issuer_key=constrained_key,
            ca=True,
            path_length=0,
            digital_signature=False,
            key_cert_sign=True,
        )
        leaf_issuer = subordinate
        leaf_issuer_key = subordinate_key
        chain_issuers.extend((subordinate, constrained))
    elif profile == "non-ca-root":
        root_key, root = _test_root(
            "Non-CA swtpm configured root",
            ca=False,
            path_length=None,
        )
        leaf_issuer = root
        leaf_issuer_key = root_key
    elif profile == "ca-key-usage":
        root_key, root = _test_root(
            "swtpm root without keyCertSign",
            key_cert_sign=False,
        )
        leaf_issuer = root
        leaf_issuer_key = root_key

    not_valid_before = _CERTIFICATE_EVALUATION_TIME - timedelta(hours=1)
    not_valid_after = _CERTIFICATE_EVALUATION_TIME + timedelta(hours=1)
    if profile == "expired-leaf":
        not_valid_before = _CERTIFICATE_EVALUATION_TIME - timedelta(hours=2)
        not_valid_after = _CERTIFICATE_EVALUATION_TIME - timedelta(hours=1)
    elif profile == "not-yet-valid-leaf":
        not_valid_before = _CERTIFICATE_EVALUATION_TIME + timedelta(hours=1)
        not_valid_after = _CERTIFICATE_EVALUATION_TIME + timedelta(hours=2)

    leaf = _issue_certificate(
        common_name="swtpm Test AK",
        public_key=ak_public,
        issuer=leaf_issuer,
        issuer_key=leaf_issuer_key,
        ca=profile == "ca-leaf",
        path_length=0 if profile == "ca-leaf" else None,
        digital_signature=profile != "leaf-key-usage",
        key_cert_sign=profile == "leaf-key-cert-sign",
        not_valid_before=not_valid_before,
        not_valid_after=not_valid_after,
    )
    if profile == "tampered-chain-signature":
        leaf = _tamper_certificate_signature(leaf)

    chain = [leaf, *chain_issuers, root]
    trusted_root_pem = _pem(root)
    return _pem(*chain), trusted_root_pem, _pem(untrusted_root)


def _signed_manifest(
    identity_private: Ed25519PrivateKey,
) -> tuple[dict[str, Any], ManifestPolicy]:
    now = datetime.now(UTC).replace(microsecond=0)
    unsigned = Manifest.model_validate(
        {
            "@context": "https://manifest.agentrust-io.com/v0.2/context.json",
            "@type": "AgentManifest",
            "manifest_id": "01918e20-49c0-7b71-a6dd-0123456789ab",
            "agent_id": "spiffe://attested-capability.test/agent/inventory-reader",
            "version": "0.1",
            "issued_at": now,
            "expires_at": now + timedelta(hours=1),
            "issuer": _MANIFEST_ISSUER,
            "artifacts": {
                "system_prompt": {
                    "hash": _SYSTEM_PROMPT_HASH,
                    "version": "1",
                    "classification": "internal",
                    "bound_at": now,
                },
                "policy_bundle": {
                    "hash": _POLICY_BUNDLE_HASH,
                    "policy_language": "cedar",
                    "version": "1",
                    "enforcement_mode": "enforce",
                    "scope": [_SCOPE],
                    "bound_at": now,
                },
                "model_identity": {
                    "provider": "local-test",
                    "model_id": "deterministic-fixture",
                    "version": "1",
                    "deployment_type": "local",
                    "model_hash": _MODEL_HASH,
                    "model_attestation_type": "hash-bound",
                    "bound_at": now,
                },
            },
        }
    )
    document = unsigned.model_dump(mode="json", by_alias=True, exclude_none=True)
    signing_key = generate_ed25519()
    document["signature"] = Ed25519Signer(signing_key).sign(document)
    manifest = Manifest.model_validate(document).model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    manifest_policy = ManifestPolicy(
        expected_digest=signed_manifest_digest(manifest),
        issuer=_MANIFEST_ISSUER,
        signing_key_id=signing_key.key_id,
        signing_public_b64url=signing_key.public_b64url(),
        identity_public_hex=public_key_hex(identity_private),
        system_prompt_hash=_SYSTEM_PROMPT_HASH,
        policy_bundle_hash=_POLICY_BUNDLE_HASH,
        model_hash=_MODEL_HASH,
    )
    return manifest, manifest_policy


def _make_broker(
    directory: Path,
    *,
    name: str,
    manifest_policy: ManifestPolicy,
    tpm_policy: TpmPolicy,
    issuer_private: Ed25519PrivateKey,
    certificate_evaluation_time: datetime = _CERTIFICATE_EVALUATION_TIME,
) -> tuple[CapabilityBroker, ReceiptVerifier]:
    issuer_public = issuer_private.public_key().public_bytes_raw().hex()
    policy = BrokerPolicy(
        broker_id=_BROKER_ID,
        qualified_scope=_SCOPE,
        resource_issuer_kid=_RESOURCE_ISSUER_KID,
        resource_issuer_public_hex=issuer_public,
        challenge_ttl_seconds=60,
        credential_ttl_seconds=300,
        manifest=manifest_policy,
        tpm=tpm_policy,
    )
    receipt_signer = ReceiptSigner.generate(key_id=f"{name}-receipt")
    broker = CapabilityBroker(
        policy=policy,
        store=SQLiteStore(directory / f"{name}.sqlite3"),
        challenge_secret=secrets.token_bytes(32),
        issuer_private_key=issuer_private,
        receipt_signer=receipt_signer,
        tpm_appraiser=ReleasedTpmAppraiser(
            selection_reader=tpm2_pytss_selection_reader,
            evaluation_time=lambda: certificate_evaluation_time,
        ),
    )
    verifier = ReceiptVerifier(receipt_signer.public_key(), key_id=f"{name}-receipt")
    return broker, verifier


def _endorsed_request(
    broker: CapabilityBroker,
    *,
    identity_private: Ed25519PrivateKey,
    holder_public: str,
    manifest_policy: ManifestPolicy,
) -> IssuanceRequest:
    request = IssuanceRequest(
        version="atcap-issuance/v1",
        broker_id=_BROKER_ID,
        challenge=broker.new_challenge(),
        manifest_digest=manifest_policy.expected_digest,
        identity_key=public_key_hex(identity_private),
        holder_key=holder_public,
        resource_issuer_kid=_RESOURCE_ISSUER_KID,
        resource_issuer_key=broker.issuer_public,
        requested_scope=_SCOPE,
    )
    return endorse_request(request, identity_private)


def _quote(
    tcti: str,
    directory: Path,
    *,
    label: str,
    ak_context: Path,
    ak_public: Path,
    qualifying_data: bytes,
    chain_pem: bytes,
) -> TpmEvidence:
    qualifying_path = directory / f"{label}.qualifying.bin"
    attest_path = directory / f"{label}.quote.attest"
    signature_path = directory / f"{label}.quote.sig"
    quote_pcr_path = directory / f"{label}.quote.pcr"
    qualifying_path.write_bytes(qualifying_data)

    _run_tpm(tcti, "tpm2_flushcontext", "-t", check=False)
    _run_tpm(
        tcti,
        "tpm2_quote",
        "-Q",
        "-c",
        str(ak_context),
        "-l",
        "sha256:16",
        "-q",
        str(qualifying_path),
        "-g",
        "sha256",
        "-f",
        "tss",
        "-m",
        str(attest_path),
        "-s",
        str(signature_path),
        "-o",
        str(quote_pcr_path),
        "-F",
        "values",
    )
    _run_tpm(
        tcti,
        "tpm2_checkquote",
        "-u",
        str(ak_public),
        "-m",
        str(attest_path),
        "-s",
        str(signature_path),
        "-f",
        str(quote_pcr_path),
        "-g",
        "sha256",
        "-q",
        str(qualifying_path),
        "-l",
        "sha256:16",
    )
    pcr_values = quote_pcr_path.read_bytes()
    assert pcr_values == _EXPECTED_PCR_VALUE
    assert hashlib.sha256(pcr_values).digest() == _EXPECTED_COMPOSITE_DIGEST
    return TpmEvidence(
        attest=attest_path.read_bytes(),
        signature=signature_path.read_bytes(),
        ak_chain_pem=chain_pem,
    )


def _require_swtpm_tcti() -> str:
    tcti = os.environ.get("ATCAP_SWTPM_TCTI")
    if tcti is None:
        pytest.skip("ATCAP_SWTPM_TCTI is not configured")
    for command in (
        "tpm2_checkquote",
        "tpm2_createak",
        "tpm2_createek",
        "tpm2_flushcontext",
        "tpm2_pcrextend",
        "tpm2_pcrread",
        "tpm2_pcrreset",
        "tpm2_quote",
    ):
        _tool(command)
    return tcti


def _prepare_swtpm_ak(tcti: str, directory: Path) -> tuple[Path, Path]:
    ek_context = directory / "ek.ctx"
    ek_public = directory / "ek.pub"
    ak_context = directory / "ak.ctx"
    ak_public = directory / "ak.pem"
    ak_name = directory / "ak.name"

    _run_tpm(tcti, "tpm2_flushcontext", "-t", check=False)
    _run_tpm(tcti, "tpm2_pcrreset", "16")
    _run_tpm(tcti, "tpm2_pcrextend", f"16:sha256={_EVENT_DIGEST}")
    _run_tpm(tcti, "tpm2_pcrread", "sha256:16", "-o", str(directory / "pcr.bin"))
    _run_tpm(
        tcti,
        "tpm2_createek",
        "-G",
        "rsa",
        "-c",
        str(ek_context),
        "-u",
        str(ek_public),
    )
    _run_tpm(
        tcti,
        "tpm2_createak",
        "-C",
        str(ek_context),
        "-G",
        "rsa",
        "-g",
        "sha256",
        "-s",
        "rsassa",
        "-c",
        str(ak_context),
        "-u",
        str(ak_public),
        "-f",
        "pem",
        "-n",
        str(ak_name),
    )
    # swtpm may expose only three transient slots. The saved AK context can be
    # restored after this flush, avoiding TPM_RC_OBJECT_MEMORY on quote.
    _run_tpm(tcti, "tpm2_flushcontext", "-t")
    return ak_context, ak_public


@pytest.mark.swtpm
def test_real_swtpm_quote_drives_broker_allow_and_rejects_bad_policy(
    tmp_path: Path,
) -> None:
    tcti = _require_swtpm_tcti()
    try:
        ak_context, ak_public = _prepare_swtpm_ak(tcti, tmp_path)

        chain_pem, trusted_root_pem, untrusted_root_pem = _issue_ak_chain(ak_public.read_bytes())
        tpm_policy = TpmPolicy(
            selection=_SELECTION,
            expected_pcr_digest=_EXPECTED_COMPOSITE_DIGEST,
            trusted_roots_pem=trusted_root_pem,
        )

        identity_private = Ed25519PrivateKey.generate()
        _, holder_public = new_keypair()
        issuer_private, _ = new_keypair()
        manifest, manifest_policy = _signed_manifest(identity_private)

        allow_broker, allow_receipts = _make_broker(
            tmp_path,
            name="allow",
            manifest_policy=manifest_policy,
            tpm_policy=tpm_policy,
            issuer_private=issuer_private,
        )
        allow_request = _endorsed_request(
            allow_broker,
            identity_private=identity_private,
            holder_public=holder_public,
            manifest_policy=manifest_policy,
        )
        allow_qualifying_data = issuance_qualifying_data(allow_request)
        assert len(allow_qualifying_data) == 32
        allow_evidence = _quote(
            tcti,
            tmp_path,
            label="allow",
            ak_context=ak_context,
            ak_public=ak_public,
            qualifying_data=allow_qualifying_data,
            chain_pem=chain_pem,
        )
        assert tpm2_pytss_selection_reader(allow_evidence.attest) == _SELECTION

        allow = allow_broker.issue(
            allow_request,
            manifest=manifest,
            tpm_evidence=allow_evidence,
        )
        assert allow.allowed is True
        assert allow.reason == Reason.ALLOW
        assert allow.result is not None
        assert allow.result["credential"]["scope"] == [_SCOPE]
        assert allow_receipts.verify(allow.receipt).reason == Reason.ALLOW

        # A new, valid broker challenge changes the complete issuance
        # transcript. Replaying the previously valid quote must therefore fail.
        replay_request = _endorsed_request(
            allow_broker,
            identity_private=identity_private,
            holder_public=holder_public,
            manifest_policy=manifest_policy,
        )
        assert issuance_qualifying_data(replay_request) != allow_qualifying_data
        replay = allow_broker.issue(
            replay_request,
            manifest=manifest,
            tpm_evidence=allow_evidence,
        )
        assert replay.allowed is False
        assert replay.reason == Reason.TPM_INVALID
        assert allow_receipts.verify(replay.receipt).reason == Reason.TPM_INVALID

        wrong_pcr_broker, wrong_pcr_receipts = _make_broker(
            tmp_path,
            name="wrong-pcr",
            manifest_policy=manifest_policy,
            tpm_policy=replace(tpm_policy, expected_pcr_digest=b"\xff" * 32),
            issuer_private=issuer_private,
        )
        wrong_pcr_request = _endorsed_request(
            wrong_pcr_broker,
            identity_private=identity_private,
            holder_public=holder_public,
            manifest_policy=manifest_policy,
        )
        wrong_pcr_evidence = _quote(
            tcti,
            tmp_path,
            label="wrong-pcr",
            ak_context=ak_context,
            ak_public=ak_public,
            qualifying_data=issuance_qualifying_data(wrong_pcr_request),
            chain_pem=chain_pem,
        )
        wrong_pcr = wrong_pcr_broker.issue(
            wrong_pcr_request,
            manifest=manifest,
            tpm_evidence=wrong_pcr_evidence,
        )
        assert wrong_pcr.allowed is False
        assert wrong_pcr.reason == Reason.TPM_INVALID
        assert wrong_pcr_receipts.verify(wrong_pcr.receipt).reason == Reason.TPM_INVALID

        untrusted_broker, untrusted_receipts = _make_broker(
            tmp_path,
            name="untrusted-root",
            manifest_policy=manifest_policy,
            tpm_policy=replace(tpm_policy, trusted_roots_pem=untrusted_root_pem),
            issuer_private=issuer_private,
        )
        untrusted_request = _endorsed_request(
            untrusted_broker,
            identity_private=identity_private,
            holder_public=holder_public,
            manifest_policy=manifest_policy,
        )
        untrusted_evidence = _quote(
            tcti,
            tmp_path,
            label="untrusted-root",
            ak_context=ak_context,
            ak_public=ak_public,
            qualifying_data=issuance_qualifying_data(untrusted_request),
            chain_pem=chain_pem,
        )
        untrusted = untrusted_broker.issue(
            untrusted_request,
            manifest=manifest,
            tpm_evidence=untrusted_evidence,
        )
        assert untrusted.allowed is False
        assert untrusted.reason == Reason.TPM_UNTRUSTED
        assert untrusted_receipts.verify(untrusted.receipt).reason == Reason.TPM_UNTRUSTED
    finally:
        _run_tpm(tcti, "tpm2_flushcontext", "-t", check=False)


@pytest.mark.swtpm
@pytest.mark.parametrize(
    ("profile", "expected_reason"),
    [
        ("expired-leaf", Reason.TPM_UNTRUSTED),
        ("not-yet-valid-leaf", Reason.TPM_UNTRUSTED),
        ("non-ca-issuer", Reason.TPM_UNTRUSTED),
        ("non-ca-root", Reason.TPM_UNTRUSTED),
        ("expired-intermediate", Reason.TPM_UNTRUSTED),
        ("not-yet-valid-intermediate", Reason.TPM_UNTRUSTED),
        ("intermediate-key-usage", Reason.TPM_UNTRUSTED),
        ("intermediate-path-length", Reason.TPM_UNTRUSTED),
        ("ca-leaf", Reason.TPM_UNTRUSTED),
        ("leaf-key-usage", Reason.TPM_UNTRUSTED),
        ("leaf-key-cert-sign", Reason.TPM_UNTRUSTED),
        ("ca-key-usage", Reason.TPM_UNTRUSTED),
        ("tampered-chain-signature", Reason.TPM_UNTRUSTED),
        ("tampered-quote-signature", Reason.TPM_INVALID),
    ],
)
def test_real_swtpm_ak_certificate_and_signature_denials(
    profile: str,
    expected_reason: str,
    tmp_path: Path,
) -> None:
    """Use a real AK and fresh quote for every certificate/signature denial."""

    tcti = _require_swtpm_tcti()
    try:
        ak_context, ak_public = _prepare_swtpm_ak(tcti, tmp_path)
        chain_profile = "valid" if profile == "tampered-quote-signature" else profile
        chain_pem, trusted_root_pem, _ = _issue_ak_chain(
            ak_public.read_bytes(),
            profile=chain_profile,
        )

        # Except for the intentionally tampered certificate signature, every
        # profile-negative chain remains cryptographically adjacent-valid. That
        # keeps the genuine denial attributable to the named local policy rule.
        if profile != "tampered-chain-signature":
            certificates = x509.load_pem_x509_certificates(chain_pem)
            for child, issuer in pairwise(certificates):
                child.verify_directly_issued_by(issuer)

        if profile == "tampered-chain-signature":
            # Signature authentication is intentionally not duplicated in the
            # local profile guard; the released verifier must reject this.
            enforce_synthetic_ak_certificate_policy(
                ak_chain_pem=chain_pem,
                trusted_roots_pem=trusted_root_pem,
                evaluation_time=_CERTIFICATE_EVALUATION_TIME,
            )

        identity_private = Ed25519PrivateKey.generate()
        _, holder_public = new_keypair()
        issuer_private, _ = new_keypair()
        manifest, manifest_policy = _signed_manifest(identity_private)
        tpm_policy = TpmPolicy(
            selection=_SELECTION,
            expected_pcr_digest=_EXPECTED_COMPOSITE_DIGEST,
            trusted_roots_pem=trusted_root_pem,
        )
        broker, receipts = _make_broker(
            tmp_path,
            name=profile,
            manifest_policy=manifest_policy,
            tpm_policy=tpm_policy,
            issuer_private=issuer_private,
        )
        request = _endorsed_request(
            broker,
            identity_private=identity_private,
            holder_public=holder_public,
            manifest_policy=manifest_policy,
        )
        evidence = _quote(
            tcti,
            tmp_path,
            label=profile,
            ak_context=ak_context,
            ak_public=ak_public,
            qualifying_data=issuance_qualifying_data(request),
            chain_pem=chain_pem,
        )
        if profile == "tampered-quote-signature":
            tampered_signature = bytearray(evidence.signature)
            tampered_signature[-1] ^= 1
            evidence = replace(evidence, signature=bytes(tampered_signature))

        decision = broker.issue(request, manifest=manifest, tpm_evidence=evidence)

        assert decision.allowed is False
        assert decision.reason == expected_reason
        assert receipts.verify(decision.receipt).reason == expected_reason
    finally:
        _run_tpm(tcti, "tpm2_flushcontext", "-t", check=False)
