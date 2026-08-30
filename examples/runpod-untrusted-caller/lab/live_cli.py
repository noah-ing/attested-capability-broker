"""Two-phase local controller CLI for one disposable remote worker job."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import secrets
import shutil
import stat
import subprocess  # nosec B404
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast

from agent_manifest import Ed25519Signer, Manifest, generate_ed25519
from ca2a_runtime.delegation import DelegationCredential
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from joserfc.jwk import OKPKey
from pydantic import JsonValue

from atcap.broker import CapabilityBroker
from atcap.canonical import canonical_digest, canonical_json, challenge_token_hash, sha256_hex
from atcap.errors import Reason
from atcap.identity import endorse_request, public_key_hex
from atcap.inventory import InventoryApplication
from atcap.manifest_verifier import signed_manifest_digest
from atcap.models import IssuanceRequest, TpmEvidence
from atcap.policy import BrokerPolicy, ManifestPolicy, ResourcePolicy, TpmPolicy
from atcap.receipt import ReceiptSigner, ReceiptVerifier
from atcap.storage import SQLiteStore
from atcap.tpm import TestTpmAppraiser, TpmAppraiser

from .controller import CapabilityGrant, TrustedController
from .errors import LabError, LabProtocolError
from .record import ExperimentRecordSigner, ExperimentRecordVerifier
from .swtpm import real_swtpm_profile
from .wire import (
    CaseSpec,
    Ed25519PublicJwk,
    PublicExperimentVerifier,
    ResourcePolicyState,
    RunpodJobEnvelope,
    SignedExperimentRecord,
    TrustedLabState,
    UntrustedRunpodObservation,
    WorkerPayload,
    strict_json_object,
)
from .worker import DisposableHolderWorker

SCOPE = "mcp://inventoryd/tool/inventory.lookup"
AUDIENCE = "inventoryd"
METHOD = "inventory.lookup"
BROKER_ID = "spiffe://attested-capability.test/runpod-lab/broker/inventoryd"
MANIFEST_ISSUER = "spiffe://attested-capability.test/runpod-lab/manifest-authority"
SYSTEM_PROMPT_HASH = "sha256:" + "a" * 64
POLICY_BUNDLE_HASH = "sha256:" + "b" * 64
MODEL_HASH = "sha256:" + "c" * 64
STATE_FILENAME = "trusted-state.json"
DATABASE_FILENAME = "lab.sqlite3"
MAX_RUNPOD_ENVELOPE_BYTES = 2_097_152
MAX_EXPERIMENT_RECORD_BYTES = 4_194_304
MAX_EXPERIMENT_VERIFIER_BYTES = 16_384
WORKER_SOURCE_FILES = (
    "handler.py",
    "lab/__init__.py",
    "lab/errors.py",
    "lab/worker.py",
    "lab/worker_wire.py",
    "requirements.lock",
)


def _read_bounded_regular_file(path: Path, *, limit: int) -> bytes:
    """Read at most *limit* bytes without following a final symlink."""

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ValueError("evidence file exceeds its verification bound")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise ValueError("evidence file exceeds its verification bound")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _new_okp_signer(key_id: str) -> tuple[ReceiptSigner, dict[str, Any]]:
    key = OKPKey.generate_key("Ed25519", parameters={"alg": "Ed25519", "kid": key_id, "use": "sig"})
    return ReceiptSigner(key, key_id=key_id), key.as_dict(private=True)


def _signed_manifest(
    identity_private: Ed25519PrivateKey,
) -> tuple[dict[str, Any], ManifestPolicy]:
    now = datetime.now(UTC).replace(microsecond=0)
    unsigned = Manifest.model_validate(
        {
            "@context": "https://manifest.agentrust-io.com/v0.2/context.json",
            "@type": "AgentManifest",
            "manifest_id": "01918e20-49c0-7b71-a6dd-0123456789ab",
            "agent_id": "spiffe://attested-capability.test/runpod-lab/agent",
            "version": "0.1",
            "issued_at": now,
            "expires_at": now + timedelta(hours=1),
            "issuer": MANIFEST_ISSUER,
            "artifacts": {
                "system_prompt": {
                    "hash": SYSTEM_PROMPT_HASH,
                    "version": "1",
                    "classification": "internal",
                    "bound_at": now,
                },
                "policy_bundle": {
                    "hash": POLICY_BUNDLE_HASH,
                    "policy_language": "cedar",
                    "version": "1",
                    "enforcement_mode": "enforce",
                    "scope": [SCOPE],
                    "bound_at": now,
                },
                "model_identity": {
                    "provider": "local-test",
                    "model_id": "runpod-untrusted-caller-fixture",
                    "version": "1",
                    "deployment_type": "local",
                    "model_hash": MODEL_HASH,
                    "model_attestation_type": "hash-bound",
                    "bound_at": now,
                },
            },
        }
    )
    document = unsigned.model_dump(mode="json", by_alias=True, exclude_none=True)
    manifest_keypair = generate_ed25519()
    document["signature"] = Ed25519Signer(manifest_keypair).sign(document)
    signed = Manifest.model_validate(document).model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    return signed, ManifestPolicy(
        expected_digest=signed_manifest_digest(signed),
        issuer=MANIFEST_ISSUER,
        signing_key_id=manifest_keypair.key_id,
        signing_public_b64url=manifest_keypair.public_b64url(),
        identity_public_hex=public_key_hex(identity_private),
        system_prompt_hash=SYSTEM_PROMPT_HASH,
        policy_bundle_hash=POLICY_BUNDLE_HASH,
        model_hash=MODEL_HASH,
    )


def _repository_bindings() -> tuple[str, str]:
    root = Path(__file__).resolve().parents[3]
    supplied_commit = os.environ.get("ATCAP_LAB_COMMIT_SHA")
    if supplied_commit is not None:
        if re.fullmatch(r"[0-9a-f]{40}", supplied_commit) is None:
            raise LabProtocolError("ATCAP_LAB_COMMIT_SHA is not a lowercase Git commit ID")
        commit_sha = supplied_commit
    else:
        git = shutil.which("git")
        if git is None:
            raise LabProtocolError(
                "git or an explicit ATCAP_LAB_COMMIT_SHA is required for source binding"
            )
        result = subprocess.run(  # noqa: S603  # nosec B603
            [git, "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            cwd=root,
        )
        commit_sha = result.stdout.strip()
    uv_lock_sha256 = sha256_hex((root / "uv.lock").read_bytes())
    return commit_sha, uv_lock_sha256


def _worker_source_digest() -> str:
    """Hash the reviewed proof-generator files copied into the worker image."""

    example_root = Path(__file__).resolve().parents[1]
    digest = hashlib.sha256(b"atcap-runpod-worker-source/v1\x00")
    for relative in WORKER_SOURCE_FILES:
        contents = (example_root / relative).read_bytes()
        encoded_name = relative.encode("utf-8")
        digest.update(len(encoded_name).to_bytes(4, "big"))
        digest.update(encoded_name)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    return digest.hexdigest()


def _case_specs(concurrency: int = 8) -> list[CaseSpec]:
    variants: list[
        Literal[
            "valid",
            "replay",
            "argument-substitution",
            "record-substitution",
            "wrong-holder",
            "malformed",
        ]
    ] = [
        "valid",
        "replay",
        "argument-substitution",
        "record-substitution",
        "wrong-holder",
        "malformed",
    ]
    result = [
        CaseSpec(
            case_id=f"case-{variant}",
            variant=variant,
            record_id=f"record-{variant}",
        )
        for variant in variants
    ]
    result.append(
        CaseSpec(
            case_id="case-concurrent",
            variant="concurrent",
            record_id="record-concurrent",
            concurrency=concurrency,
        )
    )
    return result


def prepare_capability_cases(
    *,
    controller: TrustedController,
    grants: list[CapabilityGrant],
    specs: list[CaseSpec],
    disposable_holder_private: Ed25519PrivateKey,
) -> tuple[list[Any], WorkerPayload]:
    """Dependency-injected preparation API for test-double or real issuance."""

    if len(grants) != len(specs):
        raise ValueError("one independently issued capability is required per case")
    derived_public = disposable_holder_private.public_key().public_bytes_raw().hex()
    if derived_public != controller.expected_worker_public_key:
        raise ValueError("disposable holder key does not match controller expectation")
    prepared = [
        controller.prepare_case(grant, spec) for grant, spec in zip(grants, specs, strict=True)
    ]
    payload = WorkerPayload(
        schema_version="atcap-runpod-worker-payload/v1",
        disposable_holder_private_key=disposable_holder_private.private_bytes_raw().hex(),
        worker_image=controller.worker_image,
        worker_code_digest=controller.worker_code_digest,
        requests=[request for case in prepared for request in case.requests],
    )
    return prepared, payload


def _require_private_directory(path: Path) -> None:
    if not path.is_dir() or stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise LabProtocolError("trusted state directory must exist with mode 0700")


def _write_new_file(path: Path, contents: bytes, *, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as output:
        output.write(contents)


def _read_canonical_state(path: Path) -> TrustedLabState:
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise LabProtocolError("trusted state file permissions are too broad")
    try:
        raw = path.read_bytes()
        decoded = strict_json_object(raw)
        if canonical_json(decoded) != raw:
            raise ValueError("trusted state is not canonical")
        return TrustedLabState.model_validate(decoded)
    except Exception as exc:
        raise LabProtocolError("trusted state failed strict validation") from exc


def _prepare_capabilities(
    *,
    worker_image: str,
    state_dir: Path,
    payload_path: Path,
    concurrency: int,
    capability_ttl_seconds: int,
    tpm_policy: TpmPolicy,
    tpm_appraiser: TpmAppraiser,
    evidence_for: Callable[[IssuanceRequest], TpmEvidence],
    tpm_mode: Literal["test-double", "real-swtpm"],
    tpm_evidence_verified: bool,
) -> WorkerPayload:
    """Issue, locally prepare, and persist one capability per adversarial case."""

    _require_private_directory(state_dir)
    if any(state_dir.iterdir()):
        raise LabProtocolError("trusted state directory must be empty before prepare")
    if not 60 <= capability_ttl_seconds <= 3600:
        raise LabProtocolError("capability TTL must be between 60 and 3600 seconds")
    commit_sha, uv_lock_sha256 = _repository_bindings()
    worker_code_digest = _worker_source_digest()
    holder_private = Ed25519PrivateKey.generate()
    holder_public = public_key_hex(holder_private)
    identity_private = Ed25519PrivateKey.generate()
    issuer_private = Ed25519PrivateKey.generate()
    issuer_public = public_key_hex(issuer_private)
    manifest, manifest_policy = _signed_manifest(identity_private)
    broker_policy = BrokerPolicy(
        broker_id=BROKER_ID,
        qualified_scope=SCOPE,
        resource_issuer_kid="runpod-lab-inventoryd-ca2a-v1",
        resource_issuer_public_hex=issuer_public,
        challenge_ttl_seconds=60,
        credential_ttl_seconds=capability_ttl_seconds,
        manifest=manifest_policy,
        tpm=tpm_policy,
    )
    resource_policy = ResourcePolicy(
        audience=AUDIENCE,
        method=METHOD,
        qualified_scope=SCOPE,
        trusted_broker_public_hex=issuer_public,
        challenge_ttl_seconds=capability_ttl_seconds,
        max_credential_lifetime_seconds=capability_ttl_seconds,
    )
    store = SQLiteStore(state_dir / DATABASE_FILENAME)
    broker_signer, _ = _new_okp_signer("runpod-lab-broker-receipt-v1")
    inventory_signer, inventory_private_jwk = _new_okp_signer("runpod-lab-inventory-receipt-v1")
    experiment_signer = ExperimentRecordSigner.generate(key_id="runpod-lab-experiment-v1")
    broker = CapabilityBroker(
        policy=broker_policy,
        store=store,
        challenge_secret=secrets.token_bytes(32),
        issuer_private_key=issuer_private,
        receipt_signer=broker_signer,
        tpm_appraiser=tpm_appraiser,
    )
    resource_secret = secrets.token_bytes(32)
    inventory = InventoryApplication(
        policy=resource_policy,
        store=store,
        challenge_secret=resource_secret,
        receipt_signer=inventory_signer,
    )
    broker_verifier = ReceiptVerifier(
        broker_signer.public_key(), key_id="runpod-lab-broker-receipt-v1"
    )
    inventory_verifier = ReceiptVerifier(
        inventory_signer.public_key(), key_id="runpod-lab-inventory-receipt-v1"
    )
    controller = TrustedController(
        inventory=inventory,
        store=store,
        broker_receipt_verifier=broker_verifier,
        resource_receipt_verifier=inventory_verifier,
        experiment_signer=experiment_signer,
        expected_worker_public_key=holder_public,
        worker_image=worker_image,
        worker_code_digest=worker_code_digest,
    )

    specs = _case_specs(concurrency)
    grants: list[CapabilityGrant] = []
    for _spec in specs:
        challenge = broker.new_challenge()
        request = IssuanceRequest(
            version="atcap-issuance/v1",
            broker_id=BROKER_ID,
            challenge=challenge,
            manifest_digest=manifest_policy.expected_digest,
            identity_key=public_key_hex(identity_private),
            holder_key=holder_public,
            resource_issuer_kid=broker_policy.resource_issuer_kid,
            resource_issuer_key=issuer_public,
            requested_scope=SCOPE,
        )
        endorsed = endorse_request(request, identity_private)
        evidence = evidence_for(endorsed)
        decision = broker.issue(
            endorsed,
            manifest=manifest,
            tpm_evidence=evidence,
        )
        if not decision.allowed or decision.reason != Reason.ALLOW or decision.result is None:
            raise LabProtocolError(f"{tpm_mode} broker issuance failed: {decision.reason}")
        grants.append(
            CapabilityGrant(
                credential=DelegationCredential.from_dict(decision.result["credential"]),
                broker_receipt=decision.receipt,
                expected_manifest_digest=manifest_policy.expected_digest,
                expected_broker_policy_sha256=canonical_digest(broker_policy.public_dict()),
                expected_broker_challenge_token_hash=challenge_token_hash(challenge),
                expected_tpm_attest_sha256=evidence.digestable()["tpm_attest_sha256"],
                expected_tpm_signature_sha256=evidence.digestable()["tpm_signature_sha256"],
                expected_tpm_ak_chain_sha256=evidence.digestable()["tpm_ak_chain_sha256"],
                expected_issuance_request_sha256=canonical_digest(endorsed.to_dict()),
            )
        )

    prepared, payload = prepare_capability_cases(
        controller=controller,
        grants=grants,
        specs=specs,
        disposable_holder_private=holder_private,
    )
    state = TrustedLabState(
        schema_version="atcap-runpod-trusted-state/v1",
        experiment_id=f"runpod-lab-{secrets.token_hex(8)}",
        commit_sha=commit_sha,
        uv_lock_sha256=uv_lock_sha256,
        tpm_mode=tpm_mode,
        tpm_evidence_verified=tpm_evidence_verified,
        database_filename="lab.sqlite3",
        resource_policy=ResourcePolicyState(
            audience=resource_policy.audience,
            method=resource_policy.method,
            qualified_scope=resource_policy.qualified_scope,
            trusted_broker_public_hex=resource_policy.trusted_broker_public_hex,
            challenge_ttl_seconds=resource_policy.challenge_ttl_seconds,
            max_credential_lifetime_seconds=(resource_policy.max_credential_lifetime_seconds),
        ),
        resource_challenge_secret=resource_secret.hex(),
        inventory_receipt_key_id="runpod-lab-inventory-receipt-v1",
        inventory_receipt_private_jwk=inventory_private_jwk,
        broker_receipt_key_id="runpod-lab-broker-receipt-v1",
        broker_receipt_public_jwk=cast(
            dict[str, JsonValue], broker_signer.public_key().as_dict(private=False)
        ),
        experiment_key_id=experiment_signer.key_id,
        experiment_private_jwk=experiment_signer.private_jwk(),
        expected_worker_public_key=holder_public,
        worker_image=worker_image,
        worker_code_digest=worker_code_digest,
        prepared_cases=prepared,
    )
    _write_new_file(
        state_dir / STATE_FILENAME,
        canonical_json(state.model_dump(mode="json")),
        mode=0o600,
    )
    os.chmod(state_dir / DATABASE_FILENAME, 0o600)
    _write_new_file(
        payload_path,
        canonical_json(payload.model_dump(mode="json")),
        mode=0o600,
    )
    return payload


def prepare_test_double(
    *,
    worker_image: str,
    state_dir: Path,
    payload_path: Path,
    concurrency: int = 8,
    capability_ttl_seconds: int = 300,
) -> WorkerPayload:
    """Issue capabilities through the broker with an explicit TPM test double."""

    accepted_evidence = TpmEvidence(
        attest=secrets.token_bytes(96),
        signature=secrets.token_bytes(64),
        ak_chain_pem=b"explicit-test-double-ak-chain",
    )
    return _prepare_capabilities(
        worker_image=worker_image,
        state_dir=state_dir,
        payload_path=payload_path,
        concurrency=concurrency,
        capability_ttl_seconds=capability_ttl_seconds,
        tpm_policy=TpmPolicy(
            selection=(("sha256", (0, 7)),),
            expected_pcr_digest=secrets.token_bytes(32),
            trusted_roots_pem=b"explicit-test-double-root",
        ),
        tpm_appraiser=TestTpmAppraiser(accepted_evidence),
        evidence_for=lambda _request: accepted_evidence,
        tpm_mode="test-double",
        tpm_evidence_verified=False,
    )


def prepare_real_swtpm(
    *,
    worker_image: str,
    state_dir: Path,
    payload_path: Path,
    tcti: str,
    concurrency: int = 8,
    capability_ttl_seconds: int = 300,
) -> WorkerPayload:
    """Issue every capability from fresh quotes by one genuine local ``swtpm`` AK."""

    with real_swtpm_profile(tcti) as profile:
        return _prepare_capabilities(
            worker_image=worker_image,
            state_dir=state_dir,
            payload_path=payload_path,
            concurrency=concurrency,
            capability_ttl_seconds=capability_ttl_seconds,
            tpm_policy=profile.policy,
            tpm_appraiser=profile.appraiser,
            evidence_for=profile.evidence_for,
            tpm_mode="real-swtpm",
            tpm_evidence_verified=True,
        )


def finalize(
    *,
    state_dir: Path,
    worker_response_path: Path,
    endpoint_id: str,
    worker_image: str,
    evidence_dir: Path,
) -> SignedExperimentRecord:
    _require_private_directory(state_dir)
    _require_private_directory(evidence_dir)
    evidence_outputs = (
        evidence_dir / "experiment-record.jws",
        evidence_dir / "experiment-record.json",
        evidence_dir / "experiment-verifier.json",
    )
    if any(path.exists() for path in evidence_outputs):
        raise LabProtocolError("experiment evidence output already exists")
    state = _read_canonical_state(state_dir / STATE_FILENAME)
    if worker_image != state.worker_image:
        raise LabProtocolError("finalize worker image does not match prepared state")
    try:
        if worker_response_path.stat().st_size > MAX_RUNPOD_ENVELOPE_BYTES:
            raise ValueError("response exceeds the bounded envelope size")
        envelope = RunpodJobEnvelope.model_validate(
            strict_json_object(worker_response_path.read_bytes())
        )
    except Exception as exc:
        raise LabProtocolError("Runpod response envelope failed strict validation") from exc

    policy = ResourcePolicy(**state.resource_policy.model_dump(mode="python"))
    store = SQLiteStore(state_dir / state.database_filename)
    inventory_key = OKPKey.import_key(
        cast(dict[str, str | list[str]], state.inventory_receipt_private_jwk)
    )
    inventory_signer = ReceiptSigner(inventory_key, key_id=state.inventory_receipt_key_id)
    inventory_verifier = ReceiptVerifier(
        inventory_signer.public_key(), key_id=state.inventory_receipt_key_id
    )
    broker_verifier = ReceiptVerifier(
        OKPKey.import_key(cast(dict[str, str | list[str]], state.broker_receipt_public_jwk)),
        key_id=state.broker_receipt_key_id,
    )
    experiment_signer = ExperimentRecordSigner.from_private_jwk(
        state.experiment_private_jwk,
        key_id=state.experiment_key_id,
    )
    inventory = InventoryApplication(
        policy=policy,
        store=store,
        challenge_secret=bytes.fromhex(state.resource_challenge_secret),
        receipt_signer=inventory_signer,
    )
    controller = TrustedController(
        inventory=inventory,
        store=store,
        broker_receipt_verifier=broker_verifier,
        resource_receipt_verifier=inventory_verifier,
        experiment_signer=experiment_signer,
        expected_worker_public_key=state.expected_worker_public_key,
        worker_image=state.worker_image,
        worker_code_digest=state.worker_code_digest,
    )
    all_responses = envelope.output.responses
    expected_run_ids = {
        request.run_id for prepared in state.prepared_cases for request in prepared.requests
    }
    if {response.run_id for response in all_responses} != expected_run_ids:
        raise LabProtocolError("Runpod response contains missing or unprepared run IDs")
    runpod_observation = UntrustedRunpodObservation(
        provider="runpod",
        trust="untrusted",
        endpoint_id_sha256=sha256_hex(endpoint_id.encode("utf-8")),
        job_id_sha256=sha256_hex(envelope.id.encode("utf-8")),
        worker_id_sha256=(
            sha256_hex(envelope.workerId.encode("utf-8")) if envelope.workerId is not None else None
        ),
        status=envelope.status,
        worker_image_argument=worker_image,
        delay_time_ms=envelope.delayTime,
        execution_time_ms=envelope.executionTime,
    )
    canonical_json(runpod_observation.model_dump(mode="json"))
    case_inputs = [
        (
            prepared,
            [response for response in all_responses if response.case_id == prepared.spec.case_id],
        )
        for prepared in state.prepared_cases
    ]
    # ``finalize_cases`` authenticates every grant, run binding, holder signature,
    # and claimed worker binding before the first challenge or credential spend.
    cases = controller.finalize_cases(case_inputs)
    payload, signed = controller.sign_record(
        experiment_id=state.experiment_id,
        commit_sha=state.commit_sha,
        uv_lock_sha256=state.uv_lock_sha256,
        tpm_mode=state.tpm_mode,
        tpm_evidence_verified=state.tpm_evidence_verified,
        runpod_observation=runpod_observation,
        cases=cases,
    )
    verifier = ExperimentRecordVerifier.from_public_jwk(
        experiment_signer.public_jwk(), key_id=experiment_signer.key_id
    )
    verifier.verify(signed)

    public_verifier = PublicExperimentVerifier(
        schema_version="atcap-runpod-experiment-verifier/v1",
        key_id=experiment_signer.key_id,
        public_jwk=Ed25519PublicJwk.model_validate(experiment_signer.public_jwk()),
    )
    _write_new_file(
        evidence_dir / "experiment-record.jws",
        signed.compact_jws.encode("ascii") + b"\n",
        mode=0o644,
    )
    _write_new_file(
        evidence_dir / "experiment-record.json",
        canonical_json(payload.model_dump(mode="json")),
        mode=0o644,
    )
    _write_new_file(
        evidence_dir / "experiment-verifier.json",
        canonical_json(public_verifier.model_dump(mode="json")),
        mode=0o644,
    )
    os.chmod(state_dir / state.database_filename, 0o600)
    return signed


def verify_evidence_bundle(evidence_dir: Path) -> SignedExperimentRecord:
    """Verify a complete public bundle for internal signature consistency."""

    try:
        verifier_raw = _read_bounded_regular_file(
            evidence_dir / "experiment-verifier.json",
            limit=MAX_EXPERIMENT_VERIFIER_BYTES,
        )
        record_raw = _read_bounded_regular_file(
            evidence_dir / "experiment-record.json",
            limit=MAX_EXPERIMENT_RECORD_BYTES,
        )
        jws_raw = _read_bounded_regular_file(
            evidence_dir / "experiment-record.jws",
            limit=MAX_EXPERIMENT_RECORD_BYTES,
        )
        verifier_decoded = strict_json_object(verifier_raw)
        record_decoded = strict_json_object(record_raw)
        if canonical_json(verifier_decoded) != verifier_raw:
            raise ValueError("experiment verifier is not canonical")
        if canonical_json(record_decoded) != record_raw:
            raise ValueError("experiment record projection is not canonical")
        if not jws_raw.endswith(b"\n") or jws_raw.count(b"\n") != 1:
            raise ValueError("experiment JWS file has unexpected framing")
        verifier_document = PublicExperimentVerifier.model_validate(verifier_decoded)
        signed = SignedExperimentRecord(compact_jws=jws_raw[:-1].decode("ascii"))
        payload = ExperimentRecordVerifier.from_public_jwk(
            verifier_document.public_jwk,
            key_id=verifier_document.key_id,
        ).verify(signed)
        if canonical_json(payload.model_dump(mode="json")) != record_raw:
            raise ValueError("record projection does not match the authenticated JWS payload")
        return signed
    except Exception as exc:
        raise LabProtocolError("experiment evidence bundle verification failed") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--worker-image", required=True)
    prepare_parser.add_argument("--state-dir", type=Path, required=True)
    prepare_parser.add_argument("--payload", type=Path, required=True)
    prepare_parser.add_argument("--tpm-mode", choices=["test-double", "real-swtpm"], required=True)
    prepare_parser.add_argument(
        "--capability-ttl-seconds",
        type=int,
        default=300,
        help="credential and resource-challenge TTL (60..3600)",
    )
    finalize_parser = subparsers.add_parser("finalize")
    finalize_parser.add_argument("--state-dir", type=Path, required=True)
    finalize_parser.add_argument("--worker-response", type=Path, required=True)
    finalize_parser.add_argument("--endpoint-id", required=True)
    finalize_parser.add_argument("--worker-image", required=True)
    finalize_parser.add_argument("--evidence-dir", type=Path, required=True)
    worker_parser = subparsers.add_parser("worker")
    worker_parser.add_argument("--payload", type=Path, required=True)
    worker_parser.add_argument("--worker-response", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify-record")
    verify_parser.add_argument("--evidence-dir", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "prepare":
            if arguments.tpm_mode == "real-swtpm":
                tcti = os.environ.get("ATCAP_SWTPM_TCTI", "")
                prepare_real_swtpm(
                    worker_image=arguments.worker_image,
                    state_dir=arguments.state_dir,
                    payload_path=arguments.payload,
                    capability_ttl_seconds=arguments.capability_ttl_seconds,
                    tcti=tcti,
                )
            else:
                prepare_test_double(
                    worker_image=arguments.worker_image,
                    state_dir=arguments.state_dir,
                    payload_path=arguments.payload,
                    capability_ttl_seconds=arguments.capability_ttl_seconds,
                )
        elif arguments.command == "worker":
            bundle = DisposableHolderWorker.process_payload(arguments.payload.read_bytes())
            _write_new_file(arguments.worker_response, bundle, mode=0o600)
        elif arguments.command == "finalize":
            finalize(
                state_dir=arguments.state_dir,
                worker_response_path=arguments.worker_response,
                endpoint_id=arguments.endpoint_id,
                worker_image=arguments.worker_image,
                evidence_dir=arguments.evidence_dir,
            )
        else:
            verify_evidence_bundle(arguments.evidence_dir)
    except (LabError, OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
