"""Authorized requester identity endorsement."""

from __future__ import annotations

import hashlib
import re
from dataclasses import replace

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import DecisionError, Reason
from .models import IssuanceRequest
from .policy import BrokerPolicy

_ED25519_PUBLIC_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_ISSUANCE_VERSION = "atcap-issuance/v1"


def public_key_hex(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes_raw().hex()


def identity_key_id(public_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()


def endorse_request(request: IssuanceRequest, private_key: Ed25519PrivateKey) -> IssuanceRequest:
    if public_key_hex(private_key) != request.identity_key:
        raise ValueError("identity private key does not match the issuance request")
    signature = private_key.sign(request.signing_bytes()).hex()
    return replace(request, identity_signature=signature)


def verify_identity_endorsement(request: IssuanceRequest, policy: BrokerPolicy) -> None:
    if request.version != _ISSUANCE_VERSION:
        raise DecisionError(Reason.REQUEST_BINDING, "issuance protocol version is unsupported")
    expected_identity = policy.manifest.identity_public_hex
    if request.identity_key != expected_identity:
        raise DecisionError(
            Reason.IDENTITY_UNAUTHORIZED,
            "requester identity is not the identity bound to this manifest policy",
        )
    if request.manifest_digest != policy.manifest.expected_digest:
        raise DecisionError(Reason.MANIFEST_POLICY, "manifest digest is not authorized")
    if request.broker_id != policy.broker_id:
        raise DecisionError(Reason.REQUEST_BINDING, "issuance request names another broker")
    if request.requested_scope != policy.qualified_scope:
        raise DecisionError(Reason.SCOPE_DENIED, "requested scope is not authorized")
    if request.resource_issuer_kid != policy.resource_issuer_kid:
        raise DecisionError(Reason.REQUEST_BINDING, "resource issuer kid is not authorized")
    if request.resource_issuer_key != policy.resource_issuer_public_hex:
        raise DecisionError(Reason.REQUEST_BINDING, "resource issuer key is not authorized")
    if not _ED25519_PUBLIC_HEX_RE.fullmatch(request.holder_key):
        raise DecisionError(
            Reason.REQUEST_BINDING,
            "holder key must be a lowercase 32-byte Ed25519 public key",
        )
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(request.holder_key))
    except ValueError as exc:
        raise DecisionError(Reason.REQUEST_BINDING, "holder key is malformed") from exc
    if not request.identity_signature:
        raise DecisionError(Reason.IDENTITY_SIGNATURE, "identity endorsement is missing")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(expected_identity))
        public_key.verify(bytes.fromhex(request.identity_signature), request.signing_bytes())
    except (InvalidSignature, ValueError) as exc:
        raise DecisionError(
            Reason.IDENTITY_SIGNATURE, "identity endorsement did not verify"
        ) from exc
