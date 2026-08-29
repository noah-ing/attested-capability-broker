"""MCP registration tests proving the handler has no unauthenticated route."""

from __future__ import annotations

from typing import Any

import pytest
from mcp import Client

from atcap.errors import Reason

from .support import METHOD, Harness


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
async def test_mcp_allow_path_passes_through_resource_native_middleware(
    harness: Harness,
) -> None:
    credential, _ = harness.issue_credential()
    _, request = harness.lookup_request(credential)

    async with Client(harness.inventory.server) as client:
        result = await client.call_tool(
            METHOD,
            request.model_dump(mode="json"),
        )

    value = _structured(result)
    assert result.is_error is False
    assert value["allowed"] is True
    assert value["reason"] == Reason.ALLOW
    assert value["result"]["quantity"] == 7
    assert harness.inventory.invocation_count == 1
