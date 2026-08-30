"""Genuine local software-TPM issuance profile for the optional lab.

This module creates a synthetic AK certificate chain and quotes one fixed PCR
profile with a real ``swtpm``.  Runpod never receives the quote, chain, root, or
policy.  The profile is intentionally the same narrow synthetic trust model as
the core verification harness; it is not hardware provenance or production TPM
enrollment.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess  # nosec B404
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from atcap.models import IssuanceRequest, TpmEvidence
from atcap.policy import TpmPolicy
from atcap.tpm import (
    ReleasedTpmAppraiser,
    issuance_qualifying_data,
    tpm2_pytss_selection_reader,
)

from .errors import LabProtocolError

EVENT_DIGEST = hashlib.sha256(b"attested-capability-broker:swtpm-profile:v1").hexdigest()
EXPECTED_PCR_VALUE = bytes.fromhex(
    "1e5545acda784ccc7ddb39597a58d3d416b269e22aa16f3360cb1663d0a9cda7"  # pragma: allowlist secret
)
EXPECTED_COMPOSITE_DIGEST = bytes.fromhex(
    "d01da9398dafb3b978b02af56ef39fd50c84546cb9e5271bcce508eb75fff3bf"  # pragma: allowlist secret
)
SELECTION = (("sha256", (16,)),)


def _tool(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise LabProtocolError(f"required software-TPM integration tool is missing: {name}")
    return resolved


def _run_tpm(
    tcti: str,
    *arguments: str,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment["TPM2TOOLS_TCTI"] = tcti
    try:
        # The executable is resolved from the fixed tpm2 integration tool list.
        return subprocess.run(  # noqa: S603  # nosec B603
            [_tool(arguments[0]), *arguments[1:]],
            check=check,
            capture_output=True,
            env=environment,
        )
    except subprocess.CalledProcessError as exc:
        raise LabProtocolError("local software-TPM command failed") from exc


def _key_usage(*, digital_signature: bool, key_cert_sign: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=digital_signature,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=key_cert_sign,
        crl_sign=key_cert_sign,
        encipher_only=False,
        decipher_only=False,
    )


def _synthetic_ak_chain(
    ak_public_pem: bytes,
    *,
    evaluation_time: datetime,
) -> tuple[bytes, bytes]:
    root_private = Ed25519PrivateKey.generate()
    root_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Runpod Lab Synthetic swtpm Root")]
    )
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(evaluation_time - timedelta(days=1))
        .not_valid_after(evaluation_time + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            _key_usage(digital_signature=False, key_cert_sign=True),
            critical=True,
        )
        .sign(root_private, algorithm=None)
    )
    try:
        ak_public = serialization.load_pem_public_key(ak_public_pem)
    except ValueError as exc:
        raise LabProtocolError("software-TPM AK public key is malformed") from exc
    if not isinstance(ak_public, rsa.RSAPublicKey):
        raise LabProtocolError("software-TPM AK public key is not the required RSA profile")
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Runpod Lab swtpm AK")]))
        .issuer_name(root.subject)
        .public_key(ak_public)
        .serial_number(x509.random_serial_number())
        .not_valid_before(evaluation_time - timedelta(hours=1))
        .not_valid_after(evaluation_time + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            _key_usage(digital_signature=True, key_cert_sign=False),
            critical=True,
        )
        .sign(root_private, algorithm=None)
    )
    root_pem = root.public_bytes(serialization.Encoding.PEM)
    return leaf.public_bytes(serialization.Encoding.PEM) + root_pem, root_pem


def _prepare_ak(tcti: str, directory: Path) -> tuple[Path, Path]:
    ek_context = directory / "ek.ctx"
    ek_public = directory / "ek.pub"
    ak_context = directory / "ak.ctx"
    ak_public = directory / "ak.pem"
    ak_name = directory / "ak.name"

    _run_tpm(tcti, "tpm2_flushcontext", "-t", check=False)
    _run_tpm(tcti, "tpm2_pcrreset", "16")
    _run_tpm(tcti, "tpm2_pcrextend", f"16:sha256={EVENT_DIGEST}")
    pcr_output = directory / "pcr.bin"
    _run_tpm(tcti, "tpm2_pcrread", "sha256:16", "-o", str(pcr_output))
    if pcr_output.read_bytes() != EXPECTED_PCR_VALUE:
        raise LabProtocolError("software-TPM PCR 16 does not match the approved fixture state")
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
    # Restore the saved AK context on each quote rather than retaining a
    # transient object in the simulator's deliberately small object table.
    _run_tpm(tcti, "tpm2_flushcontext", "-t")
    return ak_context, ak_public


@dataclass
class RealSwtpmProfile:
    """One real local AK, fixed PCR policy, and released appraisal adapter."""

    tcti: str
    directory: Path
    ak_context: Path
    ak_public: Path
    chain_pem: bytes
    policy: TpmPolicy
    appraiser: ReleasedTpmAppraiser
    quote_index: int = 0

    def evidence_for(self, request: IssuanceRequest) -> TpmEvidence:
        self.quote_index += 1
        label = f"issuance-{self.quote_index:02d}"
        qualifying_path = self.directory / f"{label}.qualifying.bin"
        attest_path = self.directory / f"{label}.quote.attest"
        signature_path = self.directory / f"{label}.quote.sig"
        pcr_values_path = self.directory / f"{label}.quote.pcr"
        qualifying_data = issuance_qualifying_data(request)
        qualifying_path.write_bytes(qualifying_data)

        _run_tpm(self.tcti, "tpm2_flushcontext", "-t", check=False)
        _run_tpm(
            self.tcti,
            "tpm2_quote",
            "-Q",
            "-c",
            str(self.ak_context),
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
            str(pcr_values_path),
            "-F",
            "values",
        )
        _run_tpm(
            self.tcti,
            "tpm2_checkquote",
            "-u",
            str(self.ak_public),
            "-m",
            str(attest_path),
            "-s",
            str(signature_path),
            "-f",
            str(pcr_values_path),
            "-g",
            "sha256",
            "-q",
            str(qualifying_path),
            "-l",
            "sha256:16",
        )
        pcr_values = pcr_values_path.read_bytes()
        if (
            pcr_values != EXPECTED_PCR_VALUE
            or hashlib.sha256(pcr_values).digest() != EXPECTED_COMPOSITE_DIGEST
        ):
            raise LabProtocolError("quoted software-TPM PCR values do not match policy")
        return TpmEvidence(
            attest=attest_path.read_bytes(),
            signature=signature_path.read_bytes(),
            ak_chain_pem=self.chain_pem,
        )


@contextmanager
def real_swtpm_profile(tcti: str) -> Iterator[RealSwtpmProfile]:
    """Create and always flush a short-lived real software-TPM AK profile."""

    if not isinstance(tcti, str) or not tcti:
        raise LabProtocolError("ATCAP_SWTPM_TCTI must name the local software TPM")
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
    evaluation_time = datetime.now(UTC).replace(microsecond=0)
    with TemporaryDirectory(prefix="atcap-runpod-swtpm-") as raw_directory:
        directory = Path(raw_directory)
        ak_context, ak_public = _prepare_ak(tcti, directory)
        chain_pem, trusted_root_pem = _synthetic_ak_chain(
            ak_public.read_bytes(),
            evaluation_time=evaluation_time,
        )
        policy = TpmPolicy(
            selection=SELECTION,
            expected_pcr_digest=EXPECTED_COMPOSITE_DIGEST,
            trusted_roots_pem=trusted_root_pem,
        )
        profile = RealSwtpmProfile(
            tcti=tcti,
            directory=directory,
            ak_context=ak_context,
            ak_public=ak_public,
            chain_pem=chain_pem,
            policy=policy,
            appraiser=ReleasedTpmAppraiser(
                selection_reader=tpm2_pytss_selection_reader,
                evaluation_time=lambda: evaluation_time,
            ),
        )
        try:
            yield profile
        finally:
            _run_tpm(tcti, "tpm2_flushcontext", "-t", check=False)
