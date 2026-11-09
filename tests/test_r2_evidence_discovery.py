"""First imports bind metadata and exact bytes from one bounded GET response."""

import hashlib

import httpx
import pytest

from umi.r2_evidence import R2EvidenceHTTPError

from .test_competition_remote_proof_store import EvidenceServer, store


class ObservedBody(httpx.SyncByteStream):
    def __init__(self, raw):
        self.raw, self.reads, self.closed = raw, 0, False

    def __iter__(self):
        self.reads += 1
        yield self.raw

    def close(self):
        self.closed = True


class DiscoveryServer(EvidenceServer):
    def __init__(self):
        super().__init__()
        self.headers = {}
        self.bodies = []

    def send(self, request):
        response = super().send(request)
        if request.method == "GET" and response.status_code == 200:
            headers = dict(response.headers)
            for key, value in self.headers.items():
                if value is None:
                    headers.pop(key, None)
                else:
                    headers[key] = value
            body = ObservedBody(response.content)
            self.bodies.append(body)
            return httpx.Response(200, headers=headers, stream=body)
        return response


def original(server, raw=b"original"):
    sha = hashlib.sha256(raw).hexdigest()
    server.objects["proofs/objects/" + sha] = raw
    return sha


def test_first_read_then_warm_reuse_and_retained_restart(tmp_path):
    server = DiscoveryServer()
    sha = original(server)
    reader = store(tmp_path / "reader", server)
    assert reader.read_object(sha, maximum=8) == b"original"
    assert [method for method, _ in server.calls] == ["GET"]
    reference = reader.reference_for_path("objects/" + sha)
    assert reference["content_sha256"] == sha and reference["size_bytes"] == 8
    assert server.bodies[-1].closed
    server.calls.clear()
    assert reader.read_object(sha, maximum=8) == b"original"
    assert not server.calls
    restarted = store(tmp_path / "reader", server)
    assert restarted.reference_for_path("objects/" + sha) == reference
    assert restarted.read_object(sha, maximum=8) == b"original"
    assert [method for method, _ in server.calls] == ["HEAD", "GET"]
    assert restarted.reference_for_path("objects/" + sha) == reference


@pytest.mark.parametrize(
    "headers",
    [
        {"content-length": None},
        {"content-length": "invalid"},
        {"content-length": "0"},
        {"content-length": "9"},
        {"etag": None},
        {"etag": "invalid"},
        {"x-amz-meta-sha256": None},
        {"x-amz-meta-sha256": "invalid"},
        {"x-amz-meta-sha256": "0" * 64},
        {"content-encoding": "gzip"},
    ],
)
def test_invalid_first_metadata_is_rejected_before_body_or_completion(tmp_path, headers):
    server = DiscoveryServer()
    sha = original(server)
    server.headers = headers
    reader = store(tmp_path / "reader", server)
    with pytest.raises(ValueError):
        reader.read_object(sha, maximum=8)
    assert server.bodies[-1].reads == 0 and server.bodies[-1].closed
    assert reader.reference_for_path("objects/" + sha) is None
    server.headers = {}
    assert reader.read_object(sha, maximum=8) == b"original"


@pytest.mark.parametrize("failure", ["truncated", "extra", "corrupt", "interrupted"])
def test_incomplete_first_bytes_never_record_completion_and_retry_recovers(tmp_path, failure):
    class Server(DiscoveryServer):
        broken = True

        def send(self, request):
            response = super().send(request)
            if request.method != "GET" or not self.broken:
                return response
            body = self.bodies[-1]
            if failure == "interrupted":

                class Interrupted(ObservedBody):
                    def __iter__(self):
                        yield b"ori"
                        raise httpx.ReadError("interrupted input")

                body = Interrupted(body.raw)
                self.bodies[-1] = body
                return httpx.Response(200, headers=response.headers, stream=body)
            body.raw = {"truncated": b"orig", "extra": b"original!", "corrupt": b"Original"}[
                failure
            ]
            return response

    server = Server()
    sha = original(server)
    reader = store(tmp_path / "reader", server)
    with pytest.raises((OSError, ValueError)):
        reader.read_object(sha, maximum=8)
    assert server.bodies[-1].closed
    assert reader.reference_for_path("objects/" + sha) is None
    server.broken = False
    assert store(tmp_path / "reader", server).read_object(sha, maximum=8) == b"original"


def test_first_import_capacity_refusal_does_not_read_body(tmp_path, monkeypatch):
    server = DiscoveryServer()
    sha = original(server)
    reader = store(tmp_path / "reader", server)

    def busy(_):
        raise OSError("proof cache capacity is held by active leases")

    monkeypatch.setattr(reader, "_space", busy)
    with pytest.raises(OSError, match="capacity"):
        reader.read_object(sha, maximum=8)
    assert server.bodies[-1].reads == 0 and server.bodies[-1].closed
    assert reader.reference_for_path("objects/" + sha) is None


@pytest.mark.parametrize("status", [404, 403, 429, 503])
def test_first_read_absence_and_transport_errors_preserve_no_receipt(tmp_path, status):
    server = DiscoveryServer()
    sha = original(server)
    server.get_failure = status
    reader = store(tmp_path / "reader", server)
    expected = FileNotFoundError if status == 404 else R2EvidenceHTTPError
    with pytest.raises(expected):
        reader.read_object(sha, maximum=8)
    assert reader.reference_for_path("objects/" + sha) is None


def test_existing_reference_generation_damage_still_requires_explicit_repair(tmp_path):
    server = DiscoveryServer()
    sha = original(server)
    reader = store(tmp_path / "reader", server)
    reader.read_object(sha, maximum=8)
    reader.evict_cache()
    server.objects["proofs/objects/" + sha] = b"changed!"
    with pytest.raises(ValueError, match="generation changed"):
        reader.read_object(sha, maximum=8)
    server.objects["proofs/objects/" + sha] = b"original"
    with pytest.raises(ValueError, match="explicit original-generation repair"):
        store(tmp_path / "reader", server).read_object(sha, maximum=8)


def test_injected_legacy_transport_keeps_head_then_conditional_read(tmp_path):
    server = DiscoveryServer()
    sha = original(server)
    reader = store(tmp_path / "reader", server)

    class LegacyClient:
        signer = reader.client.signer
        head = reader.client.head
        read = reader.client.read

    reader.client = LegacyClient()
    assert reader.read_object(sha, maximum=8) == b"original"
    assert [method for method, _ in server.calls] == ["HEAD", "GET"]
