"""Resource-native authorization middleware for the inventory MCP server."""

from __future__ import annotations

import asyncio
import json
import re
import secrets
import threading
import time
from collections.abc import Callable
from typing import Any, Literal

from ca2a_runtime.delegation import (
    DelegationCredential,
    HolderProof,
    verify_chain,
    verify_holder_proof,
)
from ca2a_runtime.errors import (
    CA2AError,
    CredentialExpired,
    HolderProofInvalid,
    InvalidCredential,
    UntrustedDelegationRoot,
)
from mcp.server import Server, ServerRequestContext
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .canonical import canonical_digest, canonical_json, challenge_token_hash
from .challenge import issue_ca2a_challenge_at
from .errors import DecisionError, PostInvocationError, Reason
from .models import Decision, ResourceChallenge, SignedDecisionReceipt
from .policy import ResourcePolicy
from .receipt import DecisionReceiptPayload, ReceiptSigner
from .storage import SQLiteStore

Clock = Callable[[], int]
_CREDENTIAL_ID_RE = re.compile(r"^[0-9a-f]{64}$")


class InventoryArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    sku: str = Field(min_length=1, max_length=128)


class ChallengeInput(InventoryArguments):
    credential_id: str
    record_id: str = Field(min_length=1, max_length=256)


class LookupInput(InventoryArguments):
    credential: dict[str, Any]
    holder_proof: dict[str, Any]
    record_id: str = Field(min_length=1, max_length=256)


class InventoryApplication:
    """The only path to the private inventory lookup handler."""

    def __init__(
        self,
        *,
        policy: ResourcePolicy,
        store: SQLiteStore,
        challenge_secret: bytes,
        receipt_signer: ReceiptSigner,
        clock: Clock | None = None,
        catalog: dict[str, int] | None = None,
    ) -> None:
        if len(challenge_secret) < 32:
            raise ValueError("resource challenge secret must be at least 32 bytes")
        if policy.challenge_ttl_seconds <= 0:
            raise ValueError("resource challenge TTL must be positive")
        if policy.max_credential_lifetime_seconds <= 0:
            raise ValueError("maximum credential lifetime must be positive")
        self.policy = policy
        self.store = store
        self.challenge_secret = challenge_secret
        self.receipt_signer = receipt_signer
        self.clock = clock or (lambda: int(time.time()))
        self._catalog = dict(catalog or {"widget-42": 7})
        self._counter_lock = threading.Lock()
        self._invocation_count = 0
        self.server: Server[None] = Server(
            "inventoryd",
            version="0.1.0",
            instructions=(
                "inventory.lookup is capability protected; first request an "
                "inventory.challenge for the exact call."
            ),
            on_list_tools=self._list_tools,
            on_call_tool=self._call_tool,
        )

    @property
    def invocation_count(self) -> int:
        with self._counter_lock:
            return self._invocation_count

    def issue_resource_challenge(
        self, *, credential_id: str, arguments: InventoryArguments, record_id: str
    ) -> ResourceChallenge:
        if not _CREDENTIAL_ID_RE.fullmatch(credential_id):
            raise DecisionError(
                Reason.CREDENTIAL_INVALID,
                "credential_id must be a 256-bit lowercase hexadecimal identifier",
            )
        issued_at = self.clock()
        token, expires_at = issue_ca2a_challenge_at(
            self.challenge_secret,
            now=issued_at,
            ttl_seconds=self.policy.challenge_ttl_seconds,
        )
        arguments_digest = canonical_digest(arguments.model_dump(mode="json"))
        self.store.store_resource_challenge(
            token_hash=challenge_token_hash(token),
            credential_id=credential_id,
            method=self.policy.method,
            arguments_digest=arguments_digest,
            record_id=record_id,
            audience=self.policy.audience,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        return ResourceChallenge(
            token=token,
            credential_id=credential_id,
            method=self.policy.method,
            arguments_digest=arguments_digest,
            record_id=record_id,
            audience=self.policy.audience,
            expires_at=expires_at,
        )

    def redeem(self, request: LookupInput) -> Decision:
        """Verify, atomically spend, then invoke the private handler."""

        business_arguments = InventoryArguments(sku=request.sku)
        arguments_dict = business_arguments.model_dump(mode="json")
        arguments_digest = canonical_digest(arguments_dict)
        credential_id: str | None = None
        token_hash: str | None = None
        try:
            try:
                credential = DelegationCredential.from_dict(request.credential)
            except (InvalidCredential, TypeError, ValueError) as exc:
                raise DecisionError(Reason.CREDENTIAL_INVALID, "credential is malformed") from exc
            credential_id = credential.credential_id
            if not _CREDENTIAL_ID_RE.fullmatch(credential_id):
                raise DecisionError(
                    Reason.CREDENTIAL_INVALID,
                    "credential_id is not a broker-generated 256-bit identifier",
                )
            if credential.not_before is None or credential.not_after is None:
                raise DecisionError(
                    Reason.CREDENTIAL_INVALID,
                    "credential must carry both signed validity bounds",
                )
            if (
                credential.not_after - credential.not_before
                > self.policy.max_credential_lifetime_seconds
            ):
                raise DecisionError(
                    Reason.CREDENTIAL_INVALID,
                    "credential lifetime exceeds resource policy",
                )
            try:
                verify_chain(
                    [credential],
                    max_depth=0,
                    trusted_root_issuers={self.policy.trusted_broker_public_hex},
                    at_time=self.clock(),
                )
            except CredentialExpired as exc:
                raise DecisionError(Reason.CREDENTIAL_EXPIRED, "credential expired") from exc
            except UntrustedDelegationRoot as exc:
                raise DecisionError(
                    Reason.CREDENTIAL_INVALID, "credential root is untrusted"
                ) from exc
            except CA2AError as exc:
                raise DecisionError(Reason.CREDENTIAL_INVALID, "credential did not verify") from exc

            if credential.scope != frozenset({self.policy.qualified_scope}):
                raise DecisionError(Reason.SCOPE_DENIED, "credential scope is not exact")

            try:
                proof = HolderProof.from_dict(request.holder_proof)
            except (HolderProofInvalid, TypeError, ValueError) as exc:
                raise DecisionError(
                    Reason.HOLDER_PROOF_INVALID, "holder proof is malformed"
                ) from exc
            token_hash = challenge_token_hash(proof.challenge)
            stored = self.store.get_resource_challenge(token_hash)
            if stored is None:
                raise DecisionError(
                    Reason.CHALLENGE_INVALID, "resource challenge was not issued here"
                )
            expected_context = (
                credential_id,
                self.policy.method,
                arguments_digest,
                request.record_id,
                self.policy.audience,
            )
            stored_context = (
                stored.credential_id,
                stored.method,
                stored.arguments_digest,
                stored.record_id,
                stored.audience,
            )
            if stored_context != expected_context:
                raise DecisionError(
                    Reason.HOLDER_PROOF_INVALID,
                    "stored resource challenge is bound to another request",
                )
            if stored.consumed_at is not None:
                raise DecisionError(Reason.CHALLENGE_CONSUMED, "resource challenge was consumed")
            if self.clock() >= stored.expires_at:
                raise DecisionError(Reason.CHALLENGE_STALE, "resource challenge expired")

            try:
                verify_holder_proof(
                    proof,
                    credential,
                    audience=self.policy.audience,
                    challenge_secret=self.challenge_secret,
                    requested_capability=self.policy.qualified_scope,
                    record_id=request.record_id,
                    sealed_payload=canonical_json(arguments_dict),
                    caller_channel_key=None,
                    parent_record_hash=None,
                )
            except HolderProofInvalid as exc:
                raise DecisionError(
                    Reason.HOLDER_PROOF_INVALID, "holder proof did not verify"
                ) from exc

            spend = self.store.consume_challenge_and_spend_credential(
                token_hash=token_hash,
                credential_id=credential_id,
                method=self.policy.method,
                arguments_digest=arguments_digest,
                record_id=request.record_id,
                audience=self.policy.audience,
                credential_not_before=credential.not_before,
                credential_not_after=credential.not_after,
                clock=self.clock,
            )
            if not spend.first_spend:
                raise DecisionError(Reason.CREDENTIAL_SPENT, "credential was already redeemed")

            # Deliberate at-most-once boundary: a crash after the commit above
            # can consume the capability without returning a business result.
            pre_handler_now = self.clock()
            if pre_handler_now >= spend.challenge_expires_at:
                raise DecisionError(
                    Reason.CHALLENGE_STALE,
                    "resource challenge expired after the spend commit",
                )
            if pre_handler_now < credential.not_before or pre_handler_now > credential.not_after:
                raise DecisionError(
                    Reason.CREDENTIAL_EXPIRED,
                    "credential expired after the spend commit",
                )
        except DecisionError as exc:
            receipt = self._receipt(
                decision="deny",
                reason=exc.reason,
                credential_id=credential_id,
                token_hash=token_hash,
                arguments_digest=arguments_digest,
                record_id=request.record_id,
                invocation_id=None,
                handler_invoked=False,
                business_result="not_invoked",
            )
            return Decision(False, exc.reason, receipt)
        except Exception:
            receipt = self._receipt(
                decision="deny",
                reason=Reason.INTERNAL_ERROR,
                credential_id=credential_id,
                token_hash=token_hash,
                arguments_digest=arguments_digest,
                record_id=request.record_id,
                invocation_id=None,
                handler_invoked=False,
                business_result="not_invoked",
            )
            return Decision(False, Reason.INTERNAL_ERROR, receipt)

        invocation_number = self._record_invocation()
        try:
            result = self._inventory_lookup(business_arguments)
        except Exception:
            try:
                receipt = self._receipt(
                    decision="allow",
                    reason=Reason.HANDLER_FAILED,
                    credential_id=credential_id,
                    token_hash=token_hash,
                    arguments_digest=arguments_digest,
                    record_id=request.record_id,
                    invocation_id=invocation_number,
                    handler_invoked=True,
                    business_result="failed",
                )
            except Exception as receipt_error:
                raise PostInvocationError(
                    "handler failed and no signed receipt could be produced",
                    invocation_id=invocation_number,
                    completed=False,
                ) from receipt_error
            return Decision(
                True,
                Reason.HANDLER_FAILED,
                receipt,
                result={
                    "invoked": True,
                    "completed": False,
                    "invocation_number": invocation_number,
                },
            )

        result["invocation_number"] = invocation_number
        try:
            receipt = self._receipt(
                decision="allow",
                reason=Reason.ALLOW,
                credential_id=credential_id,
                token_hash=token_hash,
                arguments_digest=arguments_digest,
                record_id=request.record_id,
                invocation_id=invocation_number,
                handler_invoked=True,
                business_result="completed",
            )
        except Exception as receipt_error:
            raise PostInvocationError(
                "handler completed but no signed receipt could be produced",
                invocation_id=invocation_number,
                completed=True,
            ) from receipt_error
        return Decision(True, Reason.ALLOW, receipt, result=result)

    def direct_lookup_attempt(self, arguments: dict[str, Any]) -> Decision:
        """Model an unauthenticated direct call; the private handler stays unreachable."""

        arguments_digest = canonical_digest(arguments)
        receipt = self._receipt(
            decision="deny",
            reason=Reason.UNAUTHENTICATED,
            credential_id=None,
            token_hash=None,
            arguments_digest=arguments_digest,
            record_id=None,
            invocation_id=None,
            handler_invoked=False,
            business_result="not_invoked",
        )
        return Decision(False, Reason.UNAUTHENTICATED, receipt)

    def _record_invocation(self) -> int:
        with self._counter_lock:
            self._invocation_count += 1
            return self._invocation_count

    def _inventory_lookup(self, arguments: InventoryArguments) -> dict[str, Any]:
        return {
            "sku": arguments.sku,
            "quantity": self._catalog.get(arguments.sku, 0),
        }

    def _receipt(
        self,
        *,
        decision: Literal["allow", "deny"],
        reason: Reason,
        credential_id: str | None,
        token_hash: str | None,
        arguments_digest: str,
        record_id: str | None,
        invocation_id: int | None,
        handler_invoked: bool,
        business_result: Literal["not_invoked", "completed", "failed"],
    ) -> SignedDecisionReceipt:
        return self.receipt_signer.sign(
            DecisionReceiptPayload(
                schema_version="atcap-decision-receipt/v1",
                receipt_id=secrets.token_hex(16),
                deciding_service="inventoryd",
                decision=decision,
                reason=reason,
                decided_at=self.clock(),
                credential_id=credential_id,
                qualified_scope=self.policy.qualified_scope,
                challenge_token_hash=token_hash,
                manifest_digest=None,
                method=self.policy.method,
                audience=self.policy.audience,
                arguments_digest=arguments_digest,
                record_id=record_id,
                invocation_id=invocation_id,
                handler_count_snapshot=self.invocation_count,
                handler_invoked=handler_invoked,
                business_result=business_result,
                artifact_hashes={
                    "resource_policy_sha256": canonical_digest(self.policy.public_dict())
                },
            )
        )

    async def _list_tools(
        self,
        _context: ServerRequestContext[None],
        _params: PaginatedRequestParams | None,
    ) -> ListToolsResult:
        return ListToolsResult(
            tools=[
                Tool(
                    name="inventory.challenge",
                    description="Issue a challenge bound to one exact protected lookup.",
                    input_schema=ChallengeInput.model_json_schema(),
                ),
                Tool(
                    name=self.policy.method,
                    description="Capability-protected inventory lookup.",
                    input_schema=LookupInput.model_json_schema(),
                ),
            ]
        )

    async def _call_tool(
        self,
        _context: ServerRequestContext[None],
        params: CallToolRequestParams,
    ) -> CallToolResult:
        raw_arguments = params.arguments or {}
        if params.name == "inventory.challenge":
            try:
                challenge_request = ChallengeInput.model_validate(raw_arguments)
                challenge = self.issue_resource_challenge(
                    credential_id=challenge_request.credential_id,
                    arguments=InventoryArguments(sku=challenge_request.sku),
                    record_id=challenge_request.record_id,
                )
                value = {
                    "token": challenge.token,
                    "credential_id": challenge.credential_id,
                    "method": challenge.method,
                    "arguments_digest": challenge.arguments_digest,
                    "record_id": challenge.record_id,
                    "audience": challenge.audience,
                    "expires_at": challenge.expires_at,
                }
                return self._mcp_result(value, is_error=False)
            except (ValidationError, DecisionError):
                decision = self.direct_lookup_attempt(dict(raw_arguments))
                return self._mcp_result(decision.to_dict(), is_error=True)

        if params.name == self.policy.method:
            try:
                lookup_request = LookupInput.model_validate(raw_arguments)
            except ValidationError:
                decision = self.direct_lookup_attempt(dict(raw_arguments))
                return self._mcp_result(decision.to_dict(), is_error=True)
            decision = await asyncio.to_thread(self.redeem, lookup_request)
            return self._mcp_result(
                decision.to_dict(),
                is_error=not decision.allowed or decision.reason == Reason.HANDLER_FAILED,
            )

        decision = self.direct_lookup_attempt(dict(raw_arguments))
        return self._mcp_result(decision.to_dict(), is_error=True)

    @staticmethod
    def _mcp_result(value: dict[str, Any], *, is_error: bool) -> CallToolResult:
        encoded = json.dumps(value, separators=(",", ":"), sort_keys=True)
        return CallToolResult(
            content=[TextContent(type="text", text=encoded)],
            structured_content=value,
            is_error=is_error,
        )
