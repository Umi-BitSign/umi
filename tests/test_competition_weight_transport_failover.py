"""Qualify the pinned SDK's submission boundary without a wallet or network."""

import asyncio
import json

import bittensor as bt
import pytest
from bittensor._transport.errors import SubstrateRequestException
from bittensor._transport.rpc import RpcSession

from umi.competition_weights import BittensorCompetitionWeightTransport

PRIMARY = "wss://primary.example"
BACKUPS = ("wss://backup-a.example", "wss://backup-b.example")


async def test_exact_endpoint_list_reaches_actual_sdk_without_implicit_pools():
    selected = []

    class Inspect:
        def __init__(self, endpoint, **options):
            client = bt.Subtensor(endpoint, **options)
            selected.append(client._client._substrate)

        async def __aenter__(self):
            raise ConnectionError("stop before any network or signed-byte handoff")

        async def __aexit__(self, *args):
            pytest.fail("failed entry does not start submission")

    transport = BittensorCompetitionWeightTransport(
        endpoint=PRIMARY, fallback_endpoints=BACKUPS, client_factory=Inspect
    )
    with pytest.raises(ConnectionError):
        await transport.submit(b"fixture signed bytes", None)
    assert len(selected) == 1
    assert selected[0].endpoint == PRIMARY
    assert selected[0].fallback_endpoints == list(BACKUPS)
    assert selected[0].archive_endpoints == []
    assert not selected[0].retry_forever


@pytest.mark.parametrize("method", ["author_submitExtrinsic", "author_submitAndWatchExtrinsic"])
@pytest.mark.parametrize("failure", ["before_send", "during_send", "after_send"])
async def test_pinned_sdk_fallback_never_resends_possible_submission(method, failure):
    connections, sent, reads = [], [], asyncio.Queue()

    class Socket:
        async def send(self, raw):
            frame = json.loads(raw)
            sent.append(frame)
            if failure == "during_send":
                await reads.put(ConnectionError("send outcome unknown"))
                raise ConnectionError("send outcome unknown")
            if failure == "after_send":
                await reads.put(ConnectionError("lost response"))
            else:
                await reads.put(json.dumps({"jsonrpc": "2.0", "id": frame["id"], "result": "ok"}))

        async def recv(self):
            value = await reads.get()
            if isinstance(value, Exception):
                raise value
            return value

        async def close(self):
            pass

    async def connect(endpoint):
        connections.append(endpoint)
        if failure == "before_send" and endpoint != BACKUPS[1]:
            raise ConnectionError("could not connect")
        return Socket()

    session = RpcSession(
        PRIMARY,
        fallback_urls=list(BACKUPS),
        retry_forever=False,
        max_retries=1,
        connect_factory=connect,
    )
    try:
        await asyncio.wait_for(session.connect(), 2)
        if failure == "before_send":
            assert await session.request(method, ["0x1234"]) == "ok"
            assert connections == [PRIMARY, *BACKUPS]
        else:
            with pytest.raises(SubstrateRequestException, match="in flight"):
                await asyncio.wait_for(session.request(method, ["0x1234"]), 2)
            assert connections == [PRIMARY, BACKUPS[0]]
        assert len(sent) == 1 and sent[0]["params"] == ["0x1234"]
    finally:
        await session.close()


@pytest.mark.parametrize(
    "backups",
    [
        (BACKUPS[0],),
        (PRIMARY, BACKUPS[1]),
        (BACKUPS[0], BACKUPS[0]),
        (BACKUPS[0], "wss://user:secret@example.org"),
    ],
)
def test_submission_rejects_incomplete_duplicate_or_credentialed_endpoints(backups):
    with pytest.raises(ValueError):
        BittensorCompetitionWeightTransport(endpoint=PRIMARY, fallback_endpoints=backups)
