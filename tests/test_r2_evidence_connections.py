"""Owned proof transfers reuse clients without sharing thread lifetimes."""

import hashlib
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Lock

import httpx
import pytest

from umi.competition_remote_proof_store import ProofArchiveR2Config, RemoteProofStore
from umi.competition_reward_proof_archive import RewardProofArchive
from umi.r2_evidence import R2EvidenceClient
from umi.r2_sigv4 import R2Credentials, R2SigV4


@pytest.fixture
def transport(monkeypatch):
    objects, clients, requests = {}, [], []
    lock = Lock()

    def send(request):
        key = request.url.path
        assert request.headers["authorization"].startswith("AWS4-HMAC-SHA256 ")
        with lock:
            if request.method == "PUT":
                assert request.headers["if-none-match"] == "*"
                if key in objects:
                    return httpx.Response(412)
                objects[key] = request.content
                return httpx.Response(
                    200,
                    headers={
                        "etag": '"'
                        + hashlib.md5(request.content, usedforsecurity=False).hexdigest()
                        + '"'
                    },
                )
            if key not in objects:
                return httpx.Response(404)
            raw = objects[key]
        etag = '"' + hashlib.md5(raw, usedforsecurity=False).hexdigest() + '"'
        headers = {
            "content-length": str(len(raw)),
            "etag": etag,
            "x-amz-meta-sha256": hashlib.sha256(raw).hexdigest(),
        }
        if request.method == "GET":
            assert request.headers["if-match"] == etag
        return httpx.Response(200, headers=headers, content=raw if request.method == "GET" else b"")

    real_client = httpx.Client

    class ObservedClient(real_client):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            with lock:
                clients.append(self)

        def stream(self, method, *args, **kwargs):
            with lock:
                requests.append((self, method))
            return super().stream(method, *args, **kwargs)

    monkeypatch.setattr(httpx, "Client", ObservedClient)
    client = R2EvidenceClient(
        R2SigV4(
            "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com",
            "umi-proof-artifacts",
            R2Credentials("0123456789ABCDEF", "secret-access-key-value"),
        ),
        transport=httpx.MockTransport(send),
    )
    return client, clients, requests, objects


def test_publication_reuses_one_client_and_closes_on_failure(transport):
    client, clients, requests, _ = transport
    raw = b"owned publication"
    sha = hashlib.sha256(raw).hexdigest()
    with pytest.raises(RuntimeError, match="interrupted frame"), client.connection_scope():
        head = client.publish("first", raw, sha)
        with client.connection_scope():
            assert client.read("first", head, maximum=100) == raw
        assert len(clients) == 1 and not clients[0].is_closed
        raise RuntimeError("interrupted frame")
    assert clients[0].is_closed
    assert [method for _, method in requests] == ["PUT", "GET"]
    assert client.publish("first", raw, sha) == head
    assert len(clients) == 2 and clients[1].is_closed
    # Scope lifetime never changes immutable conflict or response checking.
    with pytest.raises(ValueError, match="conflicts"):
        client.publish("first", b"changed", hashlib.sha256(b"changed").hexdigest())
    assert len(clients) == 3 and all(c.is_closed for c in clients)


def test_worker_threads_have_independent_scope_owners(transport):
    client, clients, _, _ = transport
    barrier = Barrier(2)

    def transfer(name):
        raw = name.encode()
        with client.connection_scope():
            head = client.publish(name, raw, hashlib.sha256(raw).hexdigest())
            barrier.wait(timeout=10)
            assert client.read(name, head, maximum=20) == raw

    with ThreadPoolExecutor(max_workers=2) as workers:
        list(workers.map(transfer, ("one", "two")))
    assert len(clients) == 2 and all(c.is_closed for c in clients)


@pytest.mark.parametrize("encoded", [False, True])
def test_native_proof_frame_uses_bounded_owned_publication_clients(tmp_path, transport, encoded):
    client, clients, requests, _ = transport
    config = ProofArchiveR2Config(
        schema="umi-r2-proof-archive/1",
        credentials_file=str(tmp_path / "credentials"),
        bucket="umi-proof-artifacts",
        prefix="proofs",
        read_only=False,
        maximum_cache_bytes=128 * 1024**2,
        maximum_index_bytes=8 * 1024**2,
    )
    remote = RemoteProofStore(tmp_path / "index", config, client=client)
    target = RewardProofArchive(tmp_path / "remote", remote=remote)
    key = "a" * 64
    fields = {"evidence": bytes(range(256)) * 4000, "metadata": b"native metadata"}
    if encoded:
        from umi.competition_evidence_codec import encode_evidence

        recipes, objects = {}, {}
        for name, raw in fields.items():
            encoding = encode_evidence(raw, kind="proof")
            recipes[name] = ((encoding.sha256, len(raw), encoding.recipe),)
            objects.update(encoding.objects)
        assert target.copy_encoded_transport(
            "history", key, context={}, fields=recipes, resolve=lambda sha, maximum: objects[sha]
        )
    else:
        target.write("history", key, context={}, fields=fields)
    publishing = {id(c) for c, method in requests if method == "PUT"}
    from umi.competition_remote_proof_store import PROOF_PUBLICATION_WORKERS

    # Both source encodings use independent bounded graph lanes. The owner
    # writes the frame only after those workers have closed and completed.
    assert 1 < len(publishing) <= PROOF_PUBLICATION_WORKERS + 1
    assert all(c.is_closed for c in clients)
    assert target.read("history", key, bounds={name: len(raw) for name, raw in fields.items()}) == (
        {},
        fields,
    )
    assert all(c.is_closed for c in clients)
