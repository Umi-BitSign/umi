"""An exact single-part PUT acknowledgement completes immutable publication."""

import base64
import hashlib

import pytest

from umi.competition_reward_proof_archive import RewardProofArchive

from .test_competition_remote_proof_store import EvidenceServer, store


@pytest.mark.parametrize("status", [200, 201])
def test_exact_put_ack_completes_once_and_retained_receipt_needs_no_remote_io(tmp_path, status):
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
    first = store(tmp_path / "owner", server)
    reference = first.put_bytes(b"original")
    assert [method for method, _ in server.calls] == ["HEAD", "PUT"]
    assert reference["size_bytes"] == 8
    assert reference["content_sha256"] == hashlib.sha256(b"original").hexdigest()
    server.calls.clear()
    restarted = store(tmp_path / "owner", server)
    assert restarted.put_bytes(b"original") == reference
    assert server.calls == []


@pytest.mark.parametrize("bad_etag", ["", "invalid", '"' + "0" * 32 + '"', 'W/"' + "0" * 32 + '"'])
def test_explicit_bad_ack_never_records_completion_and_retry_recovers_original(tmp_path, bad_etag):
    class Server(EvidenceServer):
        def send(self, request):
            response = super().send(request)
            if request.method == "PUT":
                response.headers["ETag"] = bad_etag
            return response

    server = Server()
    first = store(tmp_path / "owner", server)
    with pytest.raises(ValueError, match="publication acknowledgement differs"):
        first.put_bytes(b"original")
    assert [method for method, _ in server.calls] == ["HEAD", "PUT"]
    assert first._publishing_keys == set() and first._publishing_bytes == 0
    server.calls.clear()
    # The failed acknowledgement retained no receipt. Retry authenticates the
    # original remote generation with HEAD, without uploading it again.
    assert store(tmp_path / "owner", server).put_bytes(b"original")["size_bytes"] == 8
    assert [method for method, _ in server.calls] == ["HEAD"]


def test_missing_put_etag_uses_original_head_verification(tmp_path):
    class Server(EvidenceServer):
        def send(self, request):
            response = super().send(request)
            if request.method == "PUT":
                del response.headers["ETag"]
            return response

    server = Server()
    assert store(tmp_path / "owner", server).put_bytes(b"original")["size_bytes"] == 8
    assert [method for method, _ in server.calls] == ["HEAD", "PUT", "HEAD"]


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
        with pytest.raises(ValueError, match="publication acknowledgement differs"):
            first.put_bytes(b"original")
    assert [method for method, _ in server.calls] == ["HEAD", "PUT", "HEAD"]


def test_dependency_ack_failure_keeps_frame_unpublished_then_retry_reuses_bytes(tmp_path):
    class Server(EvidenceServer):
        wrong_ack = True

        def send(self, request):
            response = super().send(request)
            if request.method == "PUT" and self.wrong_ack:
                response.headers["ETag"] = "invalid"
            return response

    server = Server()
    archive = RewardProofArchive(tmp_path / "archive", remote=store(tmp_path / "owner", server))
    with pytest.raises(ValueError, match="publication acknowledgement differs"):
        archive.write("history", "ab" * 32, context={}, fields={"proof": b"original"})
    assert not any("/frames/" in key for key in server.objects)
    retained = set(server.objects)
    server.wrong_ack = False
    server.calls.clear()
    archive = RewardProofArchive(tmp_path / "archive", remote=store(tmp_path / "owner", server))
    archive.write("history", "ab" * 32, context={}, fields={"proof": b"original"})
    assert not any(
        method == "PUT" and path.removeprefix("/umi-proof-artifacts/") in retained
        for method, path in server.calls
    )
    assert any("/frames/" in key for key in server.objects)
