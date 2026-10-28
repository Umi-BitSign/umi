"""Fresh model HEAD confirmation reuses transport, including legacy direct callers."""

import asyncio
import json

import httpx
import pytest

from umi.r2_multipart import R2MultipartClient
from umi.r2_sigv4 import R2Credentials, R2SigV4

from .test_competition_chunked_model_backup import backup as backup
from .test_competition_chunked_model_backup import reader
from .test_open_competition import policy as policy


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("outer_scope", [False, True])
async def test_direct_heads_pool_each_operation_without_caching_generations(
    backup, tmp_path, monkeypatch, batch, outer_scope
):
    requests, clients = [], []
    changed = [False]

    def handle(request):
        requests.append(request)
        etag = "changed-generation" if changed[0] else "original-generation"
        if request.method == "POST":
            body = json.loads(request.content)
            return httpx.Response(
                200,
                json=dict(
                    schema="umi-r2-head-batch-response/1",
                    nonce=body["nonce"],
                    endpoint=body["endpoint"],
                    bucket=body["bucket"],
                    objects=[
                        dict(key=k, status=200, size_bytes=len(backup.remote.objects[k]), etag=etag)
                        for k in body["keys"]
                    ],
                ),
            )
        key = request.url.path.removeprefix("/umi-model-artifacts/")
        return httpx.Response(
            200,
            headers={"Content-Length": str(len(backup.remote.objects[key])), "ETag": etag},
        )

    remote = R2MultipartClient(
        R2SigV4(
            backup.remote.signer.endpoint,
            backup.remote.signer.bucket,
            R2Credentials("A" * 20, "S" * 40, "https://metadata.example" if batch else None),
        ),
        transport=httpx.MockTransport(handle),
    )
    create = remote._connections._new_client

    def track():
        client = create()
        clients.append(client)
        return client

    monkeypatch.setattr(remote._connections, "_new_client", track)
    selected = reader(backup, tmp_path, multipart=remote)
    selected.metadata_workers = 2  # Four batches; retain the normal bounded worker path.
    if outer_scope:
        async with remote.connection_scope():
            expected = await selected._heads(None)
            assert len(clients) == 1 and not clients[0].is_closed
        assert clients[0].is_closed
    else:
        expected = await selected._heads(None)
        assert len(clients) == 1 and clients[0].is_closed
    first = len(requests)
    changed[0] = True
    with pytest.raises(ValueError, match="generation changed"):
        await selected._heads(None, expected=expected)
    assert len(clients) == 2 and all(c.is_closed for c in clients)
    assert len(requests) > first  # Every later confirmation observes the provider again.
    if batch:
        nonces = [json.loads(r.content)["nonce"] for r in requests]
        assert len(nonces) == len(set(nonces))
    assert remote._connections.client is None


async def test_cancelled_direct_heads_drains_and_closes_its_pool(backup, tmp_path, monkeypatch):
    entered, release = asyncio.Event(), asyncio.Event()
    clients = []

    async def handle(request):
        entered.set()
        await release.wait()
        return httpx.Response(200, headers={"Content-Length": "1", "ETag": "generation"})

    remote = R2MultipartClient(
        R2SigV4(
            backup.remote.signer.endpoint,
            backup.remote.signer.bucket,
            R2Credentials("A" * 20, "S" * 40),
        ),
        transport=httpx.MockTransport(handle),
    )
    create = remote._connections._new_client

    def track():
        client = create()
        clients.append(client)
        return client

    monkeypatch.setattr(remote._connections, "_new_client", track)
    selected = reader(backup, tmp_path, multipart=remote)
    task = asyncio.create_task(selected._heads(None))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(clients) == 1 and clients[0].is_closed
    assert remote._connections.client is None
    assert remote._connections.active == remote._connections.users == 0
