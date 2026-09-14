from __future__ import annotations

import asyncio

import httpx
import pytest

from umi import competition_exchange as exchange

from .test_competition_exchange import chain_config as chain_config
from .test_competition_exchange import model_setup as model_setup
from .test_competition_exchange import policy as policy
from .test_competition_exchange import relay as relay
from .test_competition_exchange import request
from .test_competition_exchange import runtime as runtime


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [asyncio.TimeoutError, httpx.ReadTimeout])
async def test_retryable_transport_failure_has_no_private_error_text(relay, error):
    def fail(_request):
        raise error("PRIVATE DETAILS")

    with pytest.raises(exchange.ExchangeUnavailableError) as caught:
        await exchange.request_exchange(
            "https://relay.example", request(relay), transport=httpx.MockTransport(fail)
        )
    assert "PRIVATE" not in str(caught.value)


@pytest.mark.asyncio
async def test_lost_listing_response_preserves_cursor_and_retries_once(relay):
    client = relay.clients[0]
    original = relay.transport

    class LostResponse(httpx.AsyncBaseTransport):
        used = False

        async def handle_async_request(self, request):
            response = await original.handle_async_request(request)
            if not self.used:
                self.used = True
                await response.aclose()
                raise httpx.ReadTimeout("response lost after server accepted nonce")
            return response

    client.transport = LostResponse()
    with pytest.raises(exchange.ExchangeUnavailableError):
        await client.sync_once()
    with client.worker.journal.transaction() as db:
        assert (
            db.execute("SELECT value FROM exchange_delivery WHERE name='cursor'").fetchone() is None
        )
    result = await client.sync_once()
    assert result["received"] == 1
    with client.worker.journal.transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM orders").fetchone() == (1,)
    await client.sync_once()
    with client.worker.journal.transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM orders").fetchone() == (1,)


@pytest.mark.asyncio
async def test_rejected_protocol_response_is_not_classified_as_transport_retry(relay):
    with pytest.raises(ValueError) as caught:
        await exchange.request_exchange(
            "https://relay.example",
            request(relay),
            transport=httpx.MockTransport(lambda _: httpx.Response(401, json={"detail": "denied"})),
        )
    assert not isinstance(caught.value, exchange.ExchangeUnavailableError)
