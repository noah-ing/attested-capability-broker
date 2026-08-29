"""Deterministic-enough host fixtures built from the released public APIs."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from agent_manifest import Ed25519Signer, Manifest, generate_ed25519
from ca2a_runtime.delegation import (
    DelegationCredential,
    build_holder_proof,
    new_keypair,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from atcap.broker import CapabilityBroker, credential_to_dict
from atcap.canonical import canonical_json
from atcap.identity import endorse_request, public_key_hex
from atcap.inventory import InventoryApplication, InventoryArguments, LookupInput
from atcap.manifest_verifier import signed_manifest_digest
from atcap.models import Decision, IssuanceRequest, ResourceChallenge, TpmEvidence
from atcap.policy import BrokerPolicy, ManifestPolicy, ResourcePolicy, TpmPolicy
from atcap.receipt import ReceiptSigner, ReceiptVerifier
from atcap.storage import SQLiteStore
from atcap.tpm import TestTpmAppraiser, TpmAppraiser

SCOPE = "mcp://inventoryd/tool/inventory.lookup"
AUDIENCE = "inventoryd"
METHOD = "inventory.lookup"
BROKER_ID = "spiffe://attested-capability.test/broker/inventoryd"
RESOURCE_ISSUER_KID = "inventoryd-ca2a-v1"
MANIFEST_ISSUER = "spiffe://attested-capability.test/manifest-authority"
SYSTEM_PROMPT_HASH = "sha256:" + "a" * 64
POLICY_BUNDLE_HASH = "sha256:" + "b" * 64
MODEL_HASH = "sha256:" + "c" * 64


@dataclass(slots=True)
class MutableClock:
    """Integer clock whose initial value tracks the cA2A wall clock."""

    value: int

    def __call__(self) -> int:
        return self.value

    def set(self, value: int) -> None:
        self.value = value

    def advance(self, seconds: int) -> None:
        self.value += seconds


@dataclass(slots=True)
class Harness:
    """One isolated broker/resource deployment with real crypto and SQLite."""

    manifest: dict[str, Any]
    policy: BrokerPolicy
    resource_policy: ResourcePolicy
    identity_private: Ed25519PrivateKey
    holder_private: Ed25519PrivateKey
    holder_public: str
    broker_issuer_private: Ed25519PrivateKey
    broker_issuer_public: str
    accepted_evidence: TpmEvidence
    clock: MutableClock
    store: SQLiteStore
    broker: CapabilityBroker
    inventory: InventoryApplication
    broker_receipts: ReceiptVerifier
    inventory_receipts: ReceiptVerifier

    @classmethod
    def create(
        cls,
        database_path: Path,
        *,
        tpm_appraiser: TpmAppraiser | None = None,
    ) -> Harness:
        identity_private = Ed25519PrivateKey.generate()
        holder_private, holder_public = new_keypair()
        broker_issuer_private, broker_issuer_public = new_keypair()
        manifest, manifest_policy = make_signed_manifest(identity_private)
        accepted_evidence = TpmEvidence(
            attest=secrets.token_bytes(96),
            signature=secrets.token_bytes(64),
            ak_chain_pem=b"test-only-ak-chain",
        )
        policy = BrokerPolicy(
            broker_id=BROKER_ID,
            qualified_scope=SCOPE,
            resource_issuer_kid=RESOURCE_ISSUER_KID,
            resource_issuer_public_hex=broker_issuer_public,
            challenge_ttl_seconds=60,
            credential_ttl_seconds=300,
            manifest=manifest_policy,
            tpm=TpmPolicy(
                selection=(("sha256", (0, 7)),),
                expected_pcr_digest=secrets.token_bytes(32),
                trusted_roots_pem=b"test-only-root",
            ),
        )
        resource_policy = ResourcePolicy(
            audience=AUDIENCE,
            method=METHOD,
            qualified_scope=SCOPE,
            trusted_broker_public_hex=broker_issuer_public,
            challenge_ttl_seconds=60,
            max_credential_lifetime_seconds=300,
        )
        store = SQLiteStore(database_path)
        clock = MutableClock(int(time.time()))
        broker_signer = ReceiptSigner.generate(key_id="broker-receipt-test")
        inventory_signer = ReceiptSigner.generate(key_id="inventory-receipt-test")
        broker = CapabilityBroker(
            policy=policy,
            store=store,
            challenge_secret=secrets.token_bytes(32),
            issuer_private_key=broker_issuer_private,
            receipt_signer=broker_signer,
            tpm_appraiser=tpm_appraiser or TestTpmAppraiser(accepted_evidence),
            clock=clock,
        )
        inventory = InventoryApplication(
            policy=resource_policy,
            store=store,
            challenge_secret=secrets.token_bytes(32),
            receipt_signer=inventory_signer,
            clock=clock,
            catalog={"widget-42": 7, "widget-99": 2},
        )
        return cls(
            manifest=manifest,
            policy=policy,
            resource_policy=resource_policy,
            identity_private=identity_private,
            holder_private=holder_private,
            holder_public=holder_public,
            broker_issuer_private=broker_issuer_private,
            broker_issuer_public=broker_issuer_public,
            accepted_evidence=accepted_evidence,
            clock=clock,
            store=store,
            broker=broker,
            inventory=inventory,
            broker_receipts=ReceiptVerifier(
                broker_signer.public_key(), key_id="broker-receipt-test"
            ),
            inventory_receipts=ReceiptVerifier(
                inventory_signer.public_key(), key_id="inventory-receipt-test"
            ),
        )

    def endorsed_request(
        self,
        challenge: str,
        *,
        identity_private: Ed25519PrivateKey | None = None,
        holder_public: str | None = None,
        manifest_digest: str | None = None,
        requested_scope: str = SCOPE,
        resource_issuer_kid: str = RESOURCE_ISSUER_KID,
        resource_issuer_key: str | None = None,
    ) -> IssuanceRequest:
        signer = identity_private or self.identity_private
        request = IssuanceRequest(
            version="atcap-issuance/v1",
            broker_id=BROKER_ID,
            challenge=challenge,
            manifest_digest=manifest_digest or self.policy.manifest.expected_digest,
            identity_key=public_key_hex(signer),
            holder_key=holder_public or self.holder_public,
            resource_issuer_kid=resource_issuer_kid,
            resource_issuer_key=resource_issuer_key or self.broker_issuer_public,
            requested_scope=requested_scope,
        )
        return endorse_request(request, signer)

    def issue(self) -> Decision:
        request = self.endorsed_request(self.broker.new_challenge())
        return self.broker.issue(
            request,
            manifest=self.manifest,
            tpm_evidence=self.accepted_evidence,
        )

    def issue_credential(self) -> tuple[DelegationCredential, Decision]:
        decision = self.issue()
        if not decision.allowed or decision.result is None:
            raise AssertionError(f"fixture issuance failed: {decision.reason}")
        credential = DelegationCredential.from_dict(decision.result["credential"])
        return credential, decision

    def lookup_request(
        self,
        credential: DelegationCredential,
        *,
        sku: str = "widget-42",
        record_id: str | None = None,
        holder_private: Ed25519PrivateKey | None = None,
    ) -> tuple[ResourceChallenge, LookupInput]:
        resolved_record_id = record_id or secrets.token_hex(16)
        challenge = self.inventory.issue_resource_challenge(
            credential_id=credential.credential_id,
            arguments=InventoryArguments(sku=sku),
            record_id=resolved_record_id,
        )
        proof = build_holder_proof(
            holder_private or self.holder_private,
            credential,
            audience=AUDIENCE,
            challenge=challenge.token,
            requested_capability=SCOPE,
            record_id=resolved_record_id,
            sealed_payload=canonical_json({"sku": sku}),
            caller_channel_key=None,
            parent_record_hash=None,
        )
        return challenge, LookupInput(
            sku=sku,
            credential=credential_to_dict(credential),
            holder_proof=proof.to_dict(),
            record_id=resolved_record_id,
        )

    def signed_credential(
        self,
        *,
        scope: str = SCOPE,
        holder_public: str | None = None,
        issuer_private: Ed25519PrivateKey | None = None,
        not_before: int | None = None,
        not_after: int | None = None,
    ) -> DelegationCredential:
        signer = issuer_private or self.broker_issuer_private
        issuer = signer.public_key().public_bytes_raw().hex()
        return DelegationCredential(
            credential_id=secrets.token_hex(32),
            issuer=issuer,
            subject=holder_public or self.holder_public,
            scope=frozenset({scope}),
            depth=0,
            parent_id=None,
            not_before=self.clock() if not_before is None else not_before,
            not_after=self.clock() + 300 if not_after is None else not_after,
        ).sign(signer)


def make_signed_manifest(
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
                    "model_id": "deterministic-fixture",
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
    keypair = generate_ed25519()
    document["signature"] = Ed25519Signer(keypair).sign(document)
    signed = Manifest.model_validate(document).model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    policy = ManifestPolicy(
        expected_digest=signed_manifest_digest(signed),
        issuer=MANIFEST_ISSUER,
        signing_key_id=keypair.key_id,
        signing_public_b64url=keypair.public_b64url(),
        identity_public_hex=public_key_hex(identity_private),
        system_prompt_hash=SYSTEM_PROMPT_HASH,
        policy_bundle_hash=POLICY_BUNDLE_HASH,
        model_hash=MODEL_HASH,
    )
    return signed, policy


HarnessFactory = Callable[..., Harness]
