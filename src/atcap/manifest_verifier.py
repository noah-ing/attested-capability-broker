"""Strict composition of the released Agent Manifest verifier."""

from __future__ import annotations

from typing import Any, cast

from agent_manifest import (
    Manifest,
    OverallResult,
    RevocationStore,
    VerificationContext,
    canonical_hash,
    verify_manifest,
)
from pydantic import ValidationError

from .errors import DecisionError, Reason
from .policy import ManifestPolicy


def normalize_signed_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    try:
        return cast(
            dict[str, Any],
            Manifest.model_validate(manifest).model_dump(
                mode="json", by_alias=True, exclude_none=True
            ),
        )
    except ValidationError as exc:
        raise DecisionError(Reason.MANIFEST_INVALID, "manifest schema validation failed") from exc


def signed_manifest_digest(manifest: dict[str, Any]) -> str:
    return cast(str, canonical_hash(normalize_signed_manifest(manifest)))


def verify_signed_manifest(manifest: dict[str, Any], policy: ManifestPolicy) -> dict[str, Any]:
    normalized = normalize_signed_manifest(manifest)
    if normalized.get("issuer") != policy.issuer:
        raise DecisionError(Reason.MANIFEST_POLICY, "manifest issuer is not authorized")
    if canonical_hash(normalized) != policy.expected_digest:
        raise DecisionError(Reason.MANIFEST_POLICY, "manifest digest is not authorized")

    context = VerificationContext(
        system_prompt_hash=policy.system_prompt_hash,
        policy_bundle_hash=policy.policy_bundle_hash,
        enforcement_mode="enforce",
        model_version=policy.model_hash,
        trusted_keys={policy.signing_key_id: policy.signing_public_b64url},
        trusted_key_issuers={policy.signing_key_id: [policy.issuer]},
        strict_artifact_verification=True,
    )
    result = verify_manifest(normalized, context, RevocationStore())
    if result.result is not OverallResult.VALID or result.signature_verified is not True:
        raise DecisionError(Reason.MANIFEST_INVALID, "Agent Manifest verification was not VALID")
    return normalized
