from __future__ import annotations

import hashlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from umi import competition_delivery_config as delivery_config
from umi.competition_delivery_config import (
    CohostSuccessorClient,
    SuccessorCohostDeliveryConfig,
    successor_delivery_client,
)
from umi.competition_host_artifacts import HostArtifactFile
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor_adapters import PinnedHTTPSClient, ValidatorSupervisorAdapterError

from .test_competition_host_artifacts import sign
from .test_competition_host_artifacts import staged as staged


@pytest.fixture
def local_feed():
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get("Host")))
            body = b'{"signed":"unchanged"}'
            self.send_response(302 if self.path == "/redirect" else 200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Location", "https://unselected.example/private")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def selected(port):
    return SuccessorCohostDeliveryConfig(
        schema="umi-successor-cohost-delivery/1",
        origin="https://selected.example",
        loopback_port=port,
    )


async def test_real_loopback_preserves_logical_origin_and_download_hash(local_feed, tmp_path):
    port, seen = local_feed
    client = CohostSuccessorClient(selected(port))
    payload = await client.fetch_bytes("https://selected.example/directive.json", maximum_bytes=100)
    assert payload == b'{"signed":"unchanged"}'
    target = tmp_path / "release.bundle"
    await client.download_file(
        "https://selected.example/release.bundle",
        destination=target,
        maximum_bytes=100,
        expected_size_bytes=len(payload),
        expected_sha256=hashlib.sha256(payload).hexdigest(),
    )
    assert target.read_bytes() == payload
    assert seen == [
        ("/directive.json", "selected.example"),
        ("/release.bundle", "selected.example"),
    ]


@pytest.mark.parametrize("route,limit", [("/redirect", 100), ("/oversized", 2)])
async def test_local_connection_keeps_status_and_size_checks(local_feed, route, limit):
    port, seen = local_feed
    with pytest.raises(ValidatorSupervisorAdapterError):
        await CohostSuccessorClient(selected(port)).fetch_bytes(
            "https://selected.example" + route, maximum_bytes=limit
        )
    assert len(seen) == 1


async def test_unselected_origin_keeps_public_dns_restrictions(local_feed):
    port, seen = local_feed
    client = CohostSuccessorClient(selected(port))

    async def private_address(hostname, port):
        return ("127.0.0.1",)

    client.resolver = private_address
    with pytest.raises(ValidatorSupervisorAdapterError, match="not_global"):
        await client.fetch_bytes("https://other.example/object", maximum_bytes=100)
    assert seen == []


def test_delivery_pin_requires_signed_host_bytes_and_same_installed_origin(staged, monkeypatch):
    config = staged.config.model_copy(update={"directive_url": "https://selected.example/channel"})
    monkeypatch.setattr(delivery_config, "_HOST_PARENT", staged.path.parent)
    assert (
        type(
            successor_delivery_client(
                config, staged.signed, expected_manifest_sha256=staged.signed.manifest_sha256
            )
        )
        is PinnedHTTPSClient
    )
    payload = canonical_json_bytes(selected(18341))
    path = staged.path / delivery_config.HOST_DELIVERY_PATH
    staged.path.chmod(0o755)
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o444)
    record = HostArtifactFile(
        path=delivery_config.HOST_DELIVERY_PATH,
        sha256=hashlib.sha256(payload).hexdigest(),
        size_bytes=len(payload),
        mode=0o444,
    )
    files = sorted([*staged.manifest.files, record], key=lambda item: item.path)
    signed = sign(
        staged.manifest.model_copy(
            update={"files": files, "total_size_bytes": sum(item.size_bytes for item in files)}
        )
    )
    kwargs = {"expected_manifest_sha256": signed.manifest_sha256}
    assert isinstance(successor_delivery_client(config, signed, **kwargs), CohostSuccessorClient)
    with pytest.raises(ValueError, match="installed directive origin"):
        successor_delivery_client(
            config.model_copy(update={"directive_url": "https://other.example/channel"}),
            signed,
            **kwargs,
        )
    path.chmod(0o644)
    path.write_bytes(payload.replace(b"18341", b"18342"))
    path.chmod(0o444)
    with pytest.raises(ValueError, match="changed"):
        successor_delivery_client(config, signed, **kwargs)


@pytest.mark.parametrize(
    "origin",
    [
        "http://selected.example",
        "https://user@selected.example",
        "https://selected.example/path",
        "https://selected.example/",
        "https://selected.example?query",
    ],
)
def test_cohost_origin_has_no_path_credentials_or_cleartext(origin):
    with pytest.raises(ValueError):
        selected(18341).model_validate(
            {"schema": "umi-successor-cohost-delivery/1", "origin": origin, "loopback_port": 18341}
        )
