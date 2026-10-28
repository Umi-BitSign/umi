"""An exact single-part PUT acknowledgement completes immutable publication."""

import base64
import hashlib
import json

import pytest

from umi.competition_reward_proof_archive import RewardProofArchive

from .test_competition_remote_proof_store import EvidenceServer, store


@pytest.mark.parametrize("status", [200, 201])
@pytest.mark.parametrize("size", [8, 4096, 4097])
def test_exact_put_ack_completes_once_and_retained_receipt_needs_no_remote_io(
    tmp_path, status, size
):
    class Server(EvidenceServer):
        def send(self, request):
            response = super().send(request)
            if request.method == "PUT":
                assert (
                    request.headers["content-md5"]
                    == base64.b64encode(
                        hashlib.md5(request.content, usedforsecurity=False).digest()
                    ).decode()
                )
                response.status_code = status
            return response

    server = Server()
    raw = b"x" * size
    first = store(tmp_path / "owner", server)
    reference = first.put_bytes(raw)
    assert [method for method, _ in server.calls] == (["HEAD"] if size > 4096 else []) + ["PUT"]
    assert reference["size_bytes"] == size
    assert reference["content_sha256"] == hashlib.sha256(raw).hexdigest()
    server.calls.clear()
    restarted = store(tmp_path / "owner", server)
    assert restarted.put_bytes(raw) == reference
    assert server.calls == []


@pytest.mark.parametrize("bad_etag", ["", "invalid", '"' + "0" * 32 + '"', 'W/"' + "0" * 32 + '"'])
@pytest.mark.parametrize("size", [8, 4097])
def test_explicit_bad_ack_never_records_completion_and_retry_recovers_original(
    tmp_path, bad_etag, size
):
    class Server(EvidenceServer):
        def send(self, request):
            response = super().send(request)
            if request.method == "PUT":
                response.headers["ETag"] = bad_etag
            return response

    server = Server()
    raw = b"x" * size
    first = store(tmp_path / "owner", server)
    with pytest.raises(ValueError, match="publication acknowledgement differs"):
        first.put_bytes(raw)
    assert [method for method, _ in server.calls] == (["HEAD"] if size > 4096 else []) + ["PUT"]
    assert first._publishing_keys == set() and first._publishing_bytes == 0
    retained = dict(server.objects)
    server.calls.clear()
    # No receipt survived. Tiny retries attempt a bounded conditional PUT, then
    # authenticate the original with HEAD; large retries never resend the body.
    assert store(tmp_path / "owner", server).put_bytes(raw)["size_bytes"] == size
    assert [method for method, _ in server.calls] == ([] if size > 4096 else ["PUT"]) + ["HEAD"]
    assert server.objects == retained


def test_missing_put_etag_uses_original_head_verification(tmp_path):
    class Server(EvidenceServer):
        def send(self, request):
            response = super().send(request)
            if request.method == "PUT":
                del response.headers["ETag"]
            return response

    server = Server()
    assert store(tmp_path / "owner", server).put_bytes(b"original")["size_bytes"] == 8
    assert [method for method, _ in server.calls] == ["PUT", "HEAD"]


@pytest.mark.parametrize("same_original", [True, False])
def test_racing_conditional_failure_requires_exact_original_even_with_expected_etag(
    tmp_path, same_original
):
    class Server(EvidenceServer):
        def send(self, request):
            if request.method == "PUT":
                self.objects[request.url.path.removeprefix("/umi-proof-artifacts/")] = (
                    request.content if same_original else b"conflicting generation"
                )
                response = super().send(request)
                assert response.status_code == 412
                response.headers["ETag"] = hashlib.md5(
                    request.content, usedforsecurity=False
                ).hexdigest()
                return response
            return super().send(request)

    server = Server()
    first = store(tmp_path / "owner", server)
    if same_original:
        assert first.put_bytes(b"original")["size_bytes"] == 8
    else:
        with pytest.raises(ValueError, match="conflicts"):
            first.put_bytes(b"original")
    assert [method for method, _ in server.calls] == ["PUT", "HEAD"]


def test_dependency_ack_failure_keeps_frame_unpublished_then_retry_preserves_bytes(tmp_path):
    class Server(EvidenceServer):
        wrong_ack = True

        def __init__(self):
            super().__init__()
            self.retried_bodies = []

        def send(self, request):
            if (
                request.method == "PUT"
                and request.url.path.removeprefix("/umi-proof-artifacts/") in self.objects
            ):
                self.retried_bodies.append(len(request.content))
            response = super().send(request)
            if request.method == "PUT" and self.wrong_ack:
                response.headers["ETag"] = "invalid"
            return response

    server = Server()
    archive = RewardProofArchive(tmp_path / "archive", remote=store(tmp_path / "owner", server))
    with pytest.raises(ValueError, match="publication acknowledgement differs"):
        archive.write("history", "ab" * 32, context={}, fields={"proof": b"original"})
    assert not any("/frames/" in key for key in server.objects)
    retained = dict(server.objects)
    server.wrong_ack = False
    server.calls.clear()
    archive = RewardProofArchive(tmp_path / "archive", remote=store(tmp_path / "owner", server))
    archive.write("history", "ab" * 32, context={}, fields={"proof": b"original"})
    assert all(server.objects[key] == body for key, body in retained.items())
    assert server.retried_bodies and max(server.retried_bodies) <= 4096
    assert any("/frames/" in key for key in server.objects)


def test_retained_local_frames_reduce_requests_without_changing_bytes(
    tmp_path, monkeypatch, record_property
):
    from umi import r2_evidence
    from umi.competition_evidence_codec import encode_evidence_for_reuse
    from umi.protocol import canonical_json_bytes

    from .test_r2_proof_publish_batch import BatchServer

    frames = [
        canonical_json_bytes(
            {
                "shared": [
                    "0x" + (hashlib.sha256(f"shared-{i}".encode()).digest() * 608).hex()
                    for i in range(4)
                ],
                "changes": [
                    "0x" + (hashlib.sha256(f"new-{n}-{i}".encode()).digest() * 6).hex()
                    for i in range(38)
                ],
            }
        )
        for n in range(2)
    ]
    costs, published = {}, {}
    for mode, threshold in (
        ("head_first", 0),
        ("tiny_put_first", 4096),
        ("batch_tiny_put_first", 4096),
    ):
        monkeypatch.setattr(r2_evidence, "_PUT_FIRST_MAX_BYTES", threshold)
        root = tmp_path / mode
        original = RewardProofArchive(root / "archive")
        for number, raw in enumerate(frames):
            original.write("history", f"{number:064x}", context={}, fields={"proof": raw})
        retained = {path: path.read_bytes() for path in original.root.rglob("*.json")}
        server = BatchServer() if mode == "batch_tiny_put_first" else EvidenceServer()
        remote = store(root / "index", server)
        selected = RewardProofArchive(original.root, remote=remote, legacy_read_through=True)
        costs[mode] = []
        for number, raw in enumerate(frames):
            key = f"{number:064x}"
            server.calls.clear()
            if isinstance(server, BatchServer):
                server.batches.clear()
            before = sum(map(len, server.objects.values()))
            selected.write(
                "history",
                key,
                context={},
                fields={"proof": raw},
                prepared_encodings={"proof": (encode_evidence_for_reuse(raw, kind="proof"),)},
            )
            costs[mode].append(
                {
                    "head_requests": sum(method == "HEAD" for method, _ in server.calls),
                    "put_requests": sum(method == "PUT" for method, _ in server.calls),
                    "tiny_put_requests": sum(
                        method == "PUT"
                        and len(server.objects[path.removeprefix("/umi-proof-artifacts/")]) <= 4096
                        for method, path in server.calls
                    ),
                    "new_durable_bytes": sum(map(len, server.objects.values())) - before,
                    "batch_frontend_requests": len(server.batches)
                    if isinstance(server, BatchServer)
                    else 0,
                    "frontend_requests": len(server.calls)
                    + (len(server.batches) if isinstance(server, BatchServer) else 0),
                }
            )
            assert (
                server.objects["proofs/frames/history/" + key]
                == retained[original.root / "history" / (key + ".json")]
            )
        assert all(path.read_bytes() == raw for path, raw in retained.items())
        published[mode] = dict(server.objects)
        server.calls.clear()
        restarted = RewardProofArchive(
            original.root, remote=store(root / "index", server), legacy_read_through=True
        )
        for number, raw in enumerate(frames):
            restarted.write("history", f"{number:064x}", context={}, fields={"proof": raw})
        # Cold frame-cache restoration reads each acknowledged frame once;
        # completed graph publications never need another remote request.
        assert [method for method, _ in server.calls] == ["HEAD", "GET"] * len(frames)
        assert all("/frames/" in path for _, path in server.calls)
    assert (
        published["head_first"] == published["tiny_put_first"] == published["batch_tiny_put_first"]
    )
    for before, after in zip(costs["head_first"], costs["tiny_put_first"], strict=True):
        assert before["put_requests"] == after["put_requests"]
        assert before["new_durable_bytes"] == after["new_durable_bytes"]
        assert before["head_requests"] - after["head_requests"] == after["tiny_put_requests"]
        assert after["tiny_put_requests"] >= 38
    for direct, batched in zip(costs["tiny_put_first"], costs["batch_tiny_put_first"], strict=True):
        assert direct["new_durable_bytes"] == batched["new_durable_bytes"]
        assert batched["frontend_requests"] < direct["frontend_requests"] / 2
    record_property("retained_frame_transport_costs", json.dumps(costs, sort_keys=True))
