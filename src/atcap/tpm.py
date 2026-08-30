"""TPM appraisal composed from the released Agent Manifest verifier."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import ClassVar, Protocol

from agent_manifest import TpmVerificationError, parse_tpm_attest, verify_tpm_quote
from cryptography import x509

from .canonical import canonical_json
from .errors import DecisionError, Reason
from .models import IssuanceRequest, TpmEvidence
from .policy import TpmPolicy


def issuance_qualifying_data(request: IssuanceRequest) -> bytes:
    """Bind a quote to the complete, identity-endorsed issuance request."""

    transcript = b"atcap-issuance-v1\x00" + canonical_json(request.to_dict())
    return hashlib.sha256(transcript).digest()


class TpmAppraiser(Protocol):
    def appraise(
        self,
        evidence: TpmEvidence,
        *,
        expected_qualifying_data: bytes,
        policy: TpmPolicy,
    ) -> None: ...


PcrSelectionReader = Callable[[bytes], tuple[tuple[str, tuple[int, ...]], ...]]
EvaluationTime = Callable[[], datetime]


class AkCertificatePolicyError(ValueError):
    """The AK chain cannot satisfy this experiment's narrow certificate profile."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _load_certificates(pem: bytes, *, label: str) -> list[x509.Certificate]:
    if not isinstance(pem, bytes) or not pem:
        raise AkCertificatePolicyError(f"{label} is missing")
    try:
        certificates = x509.load_pem_x509_certificates(pem)
    except (TypeError, ValueError) as exc:
        raise AkCertificatePolicyError(f"{label} is malformed") from exc
    if not certificates:
        raise AkCertificatePolicyError(f"{label} contains no certificates")
    return certificates


def _required_basic_constraints(
    certificate: x509.Certificate,
    *,
    role: str,
) -> x509.BasicConstraints:
    try:
        return certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
    except (x509.DuplicateExtension, x509.ExtensionNotFound, ValueError) as exc:
        raise AkCertificatePolicyError(f"{role} certificate lacks valid BasicConstraints") from exc


def _required_key_usage(
    certificate: x509.Certificate,
    *,
    role: str,
) -> x509.KeyUsage:
    try:
        return certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except (x509.DuplicateExtension, x509.ExtensionNotFound, ValueError) as exc:
        raise AkCertificatePolicyError(f"{role} certificate lacks valid KeyUsage") from exc


def _require_current(
    certificate: x509.Certificate,
    *,
    role: str,
    evaluation_time: datetime,
) -> None:
    if (
        evaluation_time < certificate.not_valid_before_utc
        or evaluation_time > certificate.not_valid_after_utc
    ):
        raise AkCertificatePolicyError(f"{role} certificate is outside its validity window")


def enforce_synthetic_ak_certificate_policy(
    *,
    ak_chain_pem: bytes,
    trusted_roots_pem: bytes,
    evaluation_time: datetime,
) -> None:
    """Enforce the experiment's deliberately small synthetic AK X.509 profile.

    This is not a general PKIX validator. It parses the leaf-first chain and
    configured roots with ``cryptography`` and checks only leaf/intermediate
    validity and role constraints needed by the synthetic test profile. It does
    not apply validity windows to the terminal or configured trust anchors, and
    it does not authenticate certificate signatures or select/match a configured
    trust anchor. Those checks, plus AK quote verification, remain in the released
    Agent Manifest ``verify_tpm_quote`` path invoked after this guard.
    """

    if not isinstance(evaluation_time, datetime):
        raise AkCertificatePolicyError("certificate evaluation time is malformed")
    if evaluation_time.tzinfo is None or evaluation_time.utcoffset() is None:
        raise AkCertificatePolicyError("certificate evaluation time must be timezone-aware")
    now = evaluation_time.astimezone(UTC)

    chain = _load_certificates(ak_chain_pem, label="AK certificate chain")
    roots = _load_certificates(trusted_roots_pem, label="trusted TPM roots")
    if len(chain) < 2:
        raise AkCertificatePolicyError(
            "AK certificate chain must contain a leaf and at least one issuer"
        )

    leaf = chain[0]
    _require_current(leaf, role="AK leaf", evaluation_time=now)
    leaf_constraints = _required_basic_constraints(leaf, role="AK leaf")
    if leaf_constraints.ca:
        raise AkCertificatePolicyError("AK leaf certificate must not be a CA")
    leaf_usage = _required_key_usage(leaf, role="AK leaf")
    if not leaf_usage.digital_signature or leaf_usage.key_cert_sign:
        raise AkCertificatePolicyError(
            "AK leaf KeyUsage must allow digitalSignature and forbid keyCertSign"
        )

    # The input contract is leaf first. For a CA at index N, all CA
    # certificates at indices 1..N-1 are subordinate CAs. This narrow profile
    # counts every such certificate; it does not implement PKIX self-issued
    # path-length exceptions.
    for index, issuer in enumerate(chain[1:], start=1):
        role = "AK chain root" if index == len(chain) - 1 else f"AK issuer {index}"
        if index < len(chain) - 1:
            _require_current(issuer, role=role, evaluation_time=now)
        constraints = _required_basic_constraints(issuer, role=role)
        if not constraints.ca:
            raise AkCertificatePolicyError(f"{role} certificate must be a CA")
        usage = _required_key_usage(issuer, role=role)
        if not usage.key_cert_sign:
            raise AkCertificatePolicyError(f"{role} KeyUsage must allow keyCertSign")
        subordinate_ca_count = index - 1
        if constraints.path_length is not None and subordinate_ca_count > constraints.path_length:
            raise AkCertificatePolicyError(f"{role} path-length constraint is exceeded")

    # Configured roots are independently required policy inputs. Anchor
    # selection/fingerprint equality is intentionally left to Agent Manifest.
    for index, root in enumerate(roots):
        role = f"configured TPM root {index}"
        constraints = _required_basic_constraints(root, role=role)
        if not constraints.ca:
            raise AkCertificatePolicyError(f"{role} certificate must be a CA")
        usage = _required_key_usage(root, role=role)
        if not usage.key_cert_sign:
            raise AkCertificatePolicyError(f"{role} KeyUsage must allow keyCertSign")


def tpm2_pytss_selection_reader(
    attest: bytes,
) -> tuple[tuple[str, tuple[int, ...]], ...]:
    """Read the signed TPML_PCR_SELECTION with tpm2-pytss's TSS parser.

    Agent Manifest normalizes bare and TPM2B-wrapped attestation framing. The
    TSS parser then handles the TPM union and selection structures; this module
    deliberately contains no hand-written TPM offsets.
    """

    from tpm2_pytss import TPMS_ATTEST

    raw = parse_tpm_attest(attest).raw
    parsed, consumed = TPMS_ATTEST.unmarshal(raw)
    if consumed != len(raw):
        raise ValueError("TPMS_ATTEST parser did not consume the complete structure")

    result: list[tuple[str, tuple[int, ...]]] = []
    for selection in parsed.attested.quote.pcrSelect.pcrSelections:
        indices: list[int] = []
        for byte_index in range(int(selection.sizeofSelect)):
            selected = int(selection.pcrSelect[byte_index])
            for bit_index in range(8):
                if selected & (1 << bit_index):
                    indices.append(byte_index * 8 + bit_index)
        result.append((str(selection.hash), tuple(indices)))
    return tuple(result)


@dataclass(frozen=True)
class ReleasedTpmAppraiser:
    """Fail-closed adapter around Agent Manifest 0.11.2's TPM API.

    The released verifier authenticates the quote, AK chain, qualifying data,
    and composite PCR digest. It does not expose the signed PCR selection, so a
    standards-backed reader is supplied separately and must match policy exactly.
    """

    selection_reader: PcrSelectionReader
    evaluation_time: EvaluationTime = _utc_now

    def appraise(
        self,
        evidence: TpmEvidence,
        *,
        expected_qualifying_data: bytes,
        policy: TpmPolicy,
    ) -> None:
        try:
            selection = self.selection_reader(evidence.attest)
        except Exception as exc:
            raise DecisionError(
                Reason.TPM_INVALID, "TPM PCR selection could not be parsed"
            ) from exc
        if selection != policy.selection:
            raise DecisionError(Reason.PCR_POLICY, "signed TPM PCR selection is not approved")
        try:
            enforce_synthetic_ak_certificate_policy(
                ak_chain_pem=evidence.ak_chain_pem,
                trusted_roots_pem=policy.trusted_roots_pem,
                evaluation_time=self.evaluation_time(),
            )
        except Exception as exc:
            raise DecisionError(
                Reason.TPM_UNTRUSTED,
                "AK certificate chain does not satisfy the configured synthetic profile",
            ) from exc
        try:
            verified = verify_tpm_quote(
                evidence.attest,
                evidence.signature,
                evidence.ak_chain_pem,
                trusted_roots_pem=policy.trusted_roots_pem,
                expected_qualifying_data=expected_qualifying_data,
                expected_pcr_digest=policy.expected_pcr_digest,
            )
        except TpmVerificationError as exc:
            message = str(exc).lower()
            reason = (
                Reason.TPM_UNTRUSTED
                if "chain" in message or "root" in message
                else Reason.TPM_INVALID
            )
            raise DecisionError(reason, "TPM quote or AK trust path was rejected") from exc
        if verified is not True:
            raise DecisionError(Reason.TPM_INVALID, "TPM quote verification did not return True")


@dataclass(frozen=True)
class TestTpmAppraiser:
    """Explicit test double; never selected by production/demo construction."""

    __test__: ClassVar[bool] = False
    accepted_evidence: TpmEvidence

    def appraise(
        self,
        evidence: TpmEvidence,
        *,
        expected_qualifying_data: bytes,
        policy: TpmPolicy,
    ) -> None:
        del expected_qualifying_data, policy
        if evidence != self.accepted_evidence:
            raise DecisionError(Reason.TPM_UNTRUSTED, "test evidence is not trusted")
