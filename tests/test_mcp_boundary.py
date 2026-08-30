"""MCP registration tests proving the handler has no unauthenticated route."""

from __future__ import annotations

import json
from typing import Any

import pytest
from ca2a_runtime.delegation import build_holder_proof
from mcp import Client
from pydantic import ValidationError

from atcap.broker import credential_to_dict
from atcap.canonical import canonical_digest, canonical_json
from atcap.errors import Reason
from atcap.inventory import UnsignedPostInvocationState
from atcap.models import SignedDecisionReceipt
from atcap.receipt import DecisionReceiptPayload

from .support import AUDIENCE, METHOD, SCOPE, Harness


class _NonJsonSafeHandlerValue:
    def __repr__(self) -> str:
        return "RAW_NON_JSON_HANDLER_VALUE_MUST_NOT_ESCAPE"


def _structured(result: Any) -> dict[str, Any]:
    value = result.structured_content
    assert isinstance(value, dict)
    return value


@pytest.mark.asyncio
async def test_only_challenge_and_protected_lookup_are_registered(harness: Harness) -> None:
    async with Client(harness.inventory.server) as client:
        listed = await client.list_tools()

    assert [tool.name for tool in listed.tools] == ["inventory.challenge", METHOD]
    assert all(tool.name != "_inventory_lookup" for tool in listed.tools)


@pytest.mark.asyncio
async def test_unauthenticated_direct_and_mcp_bypass_attempts_never_invoke_handler(
    harness: Harness,
) -> None:
    direct = harness.inventory.direct_lookup_attempt({"sku": "widget-42"})

    async with Client(harness.inventory.server) as client:
        missing_auth = await client.call_tool(METHOD, {"sku": "widget-42"})
        private_name = await client.call_tool("_inventory_lookup", {"sku": "widget-42"})

    assert direct.allowed is False
    assert direct.reason == Reason.UNAUTHENTICATED
    assert missing_auth.is_error is True
    assert _structured(missing_auth)["reason"] == Reason.UNAUTHENTICATED
    assert private_name.is_error is True
    assert _structured(private_name)["reason"] == Reason.UNAUTHENTICATED
    assert harness.inventory.invocation_count == 0
    assert harness.inventory_receipts.verify(direct.receipt).reason == Reason.UNAUTHENTICATED


@pytest.mark.asyncio
async def test_registered_challenge_to_holder_proof_to_lookup_choreography(
    harness: Harness,
) -> None:
    credential, _ = harness.issue_credential()
    record_id = "registered-mcp-choreography"
    sku = "widget-42"

    async with Client(harness.inventory.server) as client:
        challenge_result = await client.call_tool(
            "inventory.challenge",
            {
                "credential_id": credential.credential_id,
                "record_id": record_id,
                "sku": sku,
            },
        )
        challenge = _structured(challenge_result)
        proof = build_holder_proof(
            harness.holder_private,
            credential,
            audience=AUDIENCE,
            challenge=challenge["token"],
            requested_capability=SCOPE,
            record_id=record_id,
            sealed_payload=canonical_json({"sku": sku}),
            caller_channel_key=None,
            parent_record_hash=None,
        )
        result = await client.call_tool(
            METHOD,
            {
                "sku": sku,
                "credential": credential_to_dict(credential),
                "holder_proof": proof.to_dict(),
                "record_id": record_id,
            },
        )

    value = _structured(result)
    assert challenge_result.is_error is False
    assert challenge["credential_id"] == credential.credential_id
    assert challenge["method"] == METHOD
    assert challenge["arguments_digest"] == canonical_digest({"sku": sku})
    assert challenge["record_id"] == record_id
    assert challenge["audience"] == AUDIENCE
    assert result.is_error is False
    assert value["allowed"] is True
    assert value["reason"] == Reason.ALLOW
    assert value["result"]["quantity"] == 7
    receipt = SignedDecisionReceipt(compact_jws=value["receipt_jws"])
    payload = harness.inventory_receipts.verify(receipt)
    assert payload.decision == "allow"
    assert payload.reason == Reason.ALLOW
    assert payload.handler_invoked is True
    assert payload.business_result == "completed"
    assert payload.invocation_id == value["result"]["invocation_number"] == 1
    assert harness.inventory.invocation_count == 1
    assert harness.store.redemption_count(credential.credential_id) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param(
            {
                "credential_id": "MALFORMED_CREDENTIAL_ID_DO_NOT_ECHO",
                "record_id": "malformed-id",
                "sku": "widget-42",
            },
            id="malformed-credential-id",
        ),
        pytest.param(
            {"credential_id": "0" * 64, "sku": "widget-42"},
            id="missing-record-id",
        ),
        pytest.param(
            {
                "credential_id": "0" * 64,
                "record_id": "extra-field",
                "sku": "widget-42",
                "unexpected": "MALFORMED_EXTRA_FIELD_DO_NOT_ECHO",
            },
            id="extra-field",
        ),
        pytest.param(
            {
                "credential_id": "0" * 64,
                "record_id": "wrong-type",
                "sku": 42,
            },
            id="strict-wrong-type",
        ),
        pytest.param(
            {
                "credential_id": "0" * 64,
                "record_id": "empty-sku",
                "sku": "",
            },
            id="empty-sku",
        ),
    ],
)
async def test_malformed_registered_challenge_requests_are_signed_denials(
    arguments: dict[str, Any],
    harness: Harness,
) -> None:
    async with Client(harness.inventory.server) as client:
        result = await client.call_tool("inventory.challenge", arguments)

    value = _structured(result)
    assert result.is_error is True
    assert value["allowed"] is False
    assert value["reason"] == Reason.UNAUTHENTICATED
    assert "result" not in value
    receipt = SignedDecisionReceipt(compact_jws=value["receipt_jws"])
    payload = harness.inventory_receipts.verify(receipt)
    assert payload.decision == "deny"
    assert payload.reason == Reason.UNAUTHENTICATED
    assert payload.handler_invoked is False
    assert payload.business_result == "not_invoked"
    assert harness.inventory.invocation_count == 0
    exposed = json.dumps(value, sort_keys=True)
    assert "MALFORMED_CREDENTIAL_ID_DO_NOT_ECHO" not in exposed
    assert "MALFORMED_EXTRA_FIELD_DO_NOT_ECHO" not in exposed


@pytest.mark.asyncio
@pytest.mark.parametrize("handler_completed", [True, False], ids=["completed", "failed"])
async def test_mcp_post_invocation_receipt_outage_returns_unsigned_state_without_leakage(
    handler_completed: bool,
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential, _ = harness.issue_credential()
    challenge, request = harness.lookup_request(
        credential,
        record_id=f"post-invocation-{handler_completed}",
    )
    receipt_exception_marker = "RAW_RECEIPT_SIGNER_EXCEPTION_MUST_NOT_ESCAPE"
    handler_exception_marker = "RAW_HANDLER_EXCEPTION_MUST_NOT_ESCAPE"

    if not handler_completed:

        def fail_handler(_arguments: object) -> dict[str, Any]:
            raise RuntimeError(handler_exception_marker)

        monkeypatch.setattr(harness.inventory, "_inventory_lookup", fail_handler)

    def fail_receipt(_payload: DecisionReceiptPayload) -> None:
        raise RuntimeError(receipt_exception_marker)

    monkeypatch.setattr(harness.inventory.receipt_signer, "sign", fail_receipt)

    async with Client(harness.inventory.server) as client:
        result = await client.call_tool(METHOD, request.model_dump(mode="json"))

    value = _structured(result)
    assert result.is_error is True
    assert value == {
        "schema_version": "atcap-unsigned-post-invocation/v1",
        "error_code": "POST_INVOCATION_RECEIPT_UNAVAILABLE",
        "receipt_status": "UNSIGNED",
        "credential_spent": True,
        "handler_invoked": True,
        "handler_completed": handler_completed,
        "invocation_id": 1,
    }
    parsed = UnsignedPostInvocationState.model_validate(value)
    assert parsed.handler_completed is handler_completed
    with pytest.raises(ValidationError):
        UnsignedPostInvocationState.model_validate({**value, "unexpected": "rejected"})
    assert "decision" not in value
    assert "reason" not in value
    assert "receipt_jws" not in value
    assert harness.inventory.invocation_count == 1
    assert harness.store.redemption_count(credential.credential_id) == 1

    exposed = json.dumps(value, sort_keys=True) + "".join(
        getattr(content, "text", "") for content in result.content
    )
    private_markers = (
        receipt_exception_marker,
        handler_exception_marker,
        "handler completed but no signed receipt could be produced",
        "handler failed and no signed receipt could be produced",
        challenge.token,
        request.holder_proof["signature"],
        request.credential["signature"],
        harness.inventory.challenge_secret.hex(),
        harness.holder_private.private_bytes_raw().hex(),
        harness.broker_issuer_private.private_bytes_raw().hex(),
    )
    assert all(marker not in exposed for marker in private_markers)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("malformed_result", "private_marker"),
    [
        pytest.param(
            None,
            "RAW_NON_MAPPING_HANDLER_RESULT_MUST_NOT_ESCAPE",
            id="non-mapping",
        ),
        pytest.param(
            {
                "sku": "widget-42",
                "quantity": 7,
                "unexpected": "RAW_EXTRA_HANDLER_FIELD_MUST_NOT_ESCAPE",
            },
            "RAW_EXTRA_HANDLER_FIELD_MUST_NOT_ESCAPE",
            id="extra-field",
        ),
        pytest.param(
            {
                "sku": "widget-42",
                "quantity": _NonJsonSafeHandlerValue(),
            },
            "RAW_NON_JSON_HANDLER_VALUE_MUST_NOT_ESCAPE",
            id="non-json-safe",
        ),
    ],
)
async def test_mcp_malformed_handler_result_is_signed_failed_execution_without_leakage(
    malformed_result: Any,
    private_marker: str,
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential, _ = harness.issue_credential()
    _, request = harness.lookup_request(
        credential,
        record_id="malformed-handler-result",
    )

    def malformed_handler(_arguments: object) -> Any:
        return malformed_result

    monkeypatch.setattr(harness.inventory, "_inventory_lookup", malformed_handler)

    async with Client(harness.inventory.server) as client:
        result = await client.call_tool(METHOD, request.model_dump(mode="json"))

    value = _structured(result)
    assert result.is_error is True
    assert value["allowed"] is True
    assert value["reason"] == Reason.HANDLER_FAILED
    assert value["result"] == {
        "invoked": True,
        "completed": False,
        "invocation_number": 1,
    }
    receipt = SignedDecisionReceipt(compact_jws=value["receipt_jws"])
    payload = harness.inventory_receipts.verify(receipt)
    assert payload.decision == "allow"
    assert payload.reason == Reason.HANDLER_FAILED
    assert payload.handler_invoked is True
    assert payload.business_result == "failed"
    assert payload.invocation_id == 1
    assert harness.inventory.invocation_count == 1
    assert harness.store.redemption_count(credential.credential_id) == 1

    exposed = json.dumps(value, sort_keys=True) + "".join(
        getattr(content, "text", "") for content in result.content
    )
    assert private_marker not in exposed
    assert "InventoryLookupResult" not in exposed
    assert "ValidationError" not in exposed
    assert "TypeError" not in exposed


@pytest.mark.asyncio
async def test_mcp_malformed_handler_result_and_receipt_outage_preserve_unsigned_state(
    harness: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential, _ = harness.issue_credential()
    _, request = harness.lookup_request(
        credential,
        record_id="malformed-handler-result-receipt-outage",
    )
    result_marker = "RAW_MALFORMED_HANDLER_RESULT_MUST_NOT_ESCAPE"
    receipt_marker = "RAW_RECEIPT_SIGNER_EXCEPTION_MUST_NOT_ESCAPE"

    def malformed_handler(_arguments: object) -> dict[str, Any]:
        return {
            "sku": "widget-42",
            "quantity": 7,
            "unexpected": result_marker,
        }

    def fail_receipt(_payload: DecisionReceiptPayload) -> None:
        raise RuntimeError(receipt_marker)

    monkeypatch.setattr(harness.inventory, "_inventory_lookup", malformed_handler)
    monkeypatch.setattr(harness.inventory.receipt_signer, "sign", fail_receipt)

    async with Client(harness.inventory.server) as client:
        result = await client.call_tool(METHOD, request.model_dump(mode="json"))

    value = _structured(result)
    assert result.is_error is True
    assert value == {
        "schema_version": "atcap-unsigned-post-invocation/v1",
        "error_code": "POST_INVOCATION_RECEIPT_UNAVAILABLE",
        "receipt_status": "UNSIGNED",
        "credential_spent": True,
        "handler_invoked": True,
        "handler_completed": False,
        "invocation_id": 1,
    }
    assert harness.inventory.invocation_count == 1
    assert harness.store.redemption_count(credential.credential_id) == 1
    exposed = json.dumps(value, sort_keys=True) + "".join(
        getattr(content, "text", "") for content in result.content
    )
    assert result_marker not in exposed
    assert receipt_marker not in exposed
    assert "decision" not in value
    assert "reason" not in value
    assert "receipt_jws" not in value
