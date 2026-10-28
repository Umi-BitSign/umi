"""Portable metadata survives R2-only retention and interrupted retrieval."""

import asyncio
import json
import shutil
from pathlib import Path

import pytest

from umi.competition_model_byte_snapshot import portable_member_path, restore_portable_snapshot
from umi.competition_model_byte_snapshot_r2 import (
    _document,
    _DocumentEnvelope,
    download_portable_snapshot,
    replicate_portable_snapshot,
)
from umi.protocol import canonical_json_bytes, sha256_hex

from .test_competition_chunked_model_backup import backup as backup
from .test_competition_model_byte_snapshot import captured
from .test_competition_model_byte_store import exported, imported
from .test_competition_remote_proof_store import EvidenceServer
from .test_open_competition import policy as policy


async def test_R2_only_roundtrip_repeat_and_native_consumer(backup, tmp_path):
    original, local = await captured(backup, tmp_path)
    server = EvidenceServer()
    remote = replicate_portable_snapshot(local, server.client(), "byte-results/v1/")
    assert all(key.startswith("byte-results/v1/") for key in server.objects)
    assert [path for method, path in server.calls if method == "PUT"][-1].endswith(
        remote.snapshot_sha256 + ".json"
    )
    retained = dict(server.objects)
    server.calls.clear()
    assert replicate_portable_snapshot(local, server.client(), "byte-results/v1/") == remote
    assert server.objects == retained
    assert all(
        len(retained[path.removeprefix("/umi-proof-artifacts/")]) <= 4096
        for method, path in server.calls
        if method == "PUT"
    )
    shutil.rmtree(original.root)
    shutil.rmtree(Path(local.directory))
    server.calls.clear()
    retrieved = download_portable_snapshot(remote, server.client(), tmp_path / "fetched")
    assert any(method == "GET" for method, _ in server.calls)
    server.calls.clear()
    assert download_portable_snapshot(remote, server.client(), tmp_path / "fetched") == retrieved
    assert not server.calls
    destination = tmp_path / "replacement"
    restored = restore_portable_snapshot(retrieved, destination)
    assert restored["restored_files"] == 7
    shutil.rmtree(Path(retrieved.directory))
    target = imported(backup, destination, ())
    result = await target.verify(document_paths=("license.txt",))
    target.require_verified(result)
    assert not backup.remote.reads


async def test_partial_remote_upload_never_publishes_manifest(backup, tmp_path):
    _, local = await captured(backup, tmp_path)
    server = EvidenceServer()
    server.fail_put_suffix = local.export_sha256 + ".json"
    with pytest.raises(OSError):
        replicate_portable_snapshot(local, server.client(), "byte-results/v1/")
    assert not any("/snapshots/" in key for key in server.objects)
    first = dict(server.objects)
    server.fail_put_suffix = None
    remote = replicate_portable_snapshot(local, server.client(), "byte-results/v1/")
    assert all(server.objects[key] == value for key, value in first.items())
    assert any(key.endswith(remote.snapshot_sha256 + ".json") for key in server.objects)


async def test_download_resume_keeps_committed_metadata(backup, tmp_path, monkeypatch):
    _, local = await captured(backup, tmp_path)
    server = EvidenceServer()
    remote = replicate_portable_snapshot(local, server.client(), "byte-results/v1/")
    client = server.client()
    original = client.read

    def interrupted(key, *args, **kwargs):
        if "/documents/" in key:
            raise OSError("interrupted document download")
        return original(key, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(client, "read", interrupted)
        with pytest.raises(OSError):
            download_portable_snapshot(remote, client, tmp_path / "fetched")
    server.calls.clear()
    download_portable_snapshot(remote, server.client(), tmp_path / "fetched")
    assert all("/documents/" in path for _, path in server.calls)
    assert not backup.remote.reads


async def test_local_metadata_repair_is_explicit_and_scoped(backup, tmp_path):
    _, local = await captured(backup, tmp_path)
    server = EvidenceServer()
    remote = replicate_portable_snapshot(local, server.client(), "byte-results/v1/")
    fetched = download_portable_snapshot(remote, server.client(), tmp_path / "fetched")
    path = portable_member_path(Path(fetched.directory), "exports", fetched.export_sha256)
    path.write_bytes(b"broken")
    server.calls.clear()
    with pytest.raises(ValueError, match="explicit scoped repair"):
        download_portable_snapshot(remote, server.client(), tmp_path / "fetched")
    assert not server.calls
    events = []
    download_portable_snapshot(
        remote, server.client(), tmp_path / "fetched", repair=True, report=events.append
    )
    assert [method for method, _ in server.calls] == ["HEAD", "GET"]
    assert all(path.endswith(fetched.export_sha256 + ".json") for _, path in server.calls)
    assert any(v["status"] == "repair_required" for v in events)


@pytest.mark.parametrize("fault", ["missing", "export", "document"])
async def test_remote_damage_refuses_instead_of_borrowing_results(backup, tmp_path, fault):
    _, local = await captured(backup, tmp_path)
    server = EvidenceServer()
    remote = replicate_portable_snapshot(local, server.client(), "byte-results/v1/")
    if fault == "missing":
        key = next(key for key in server.objects if "/exports/" in key)
        del server.objects[key]
    elif fault == "export":
        key = next(key for key in server.objects if "/exports/" in key)
        server.objects[key] = b"{}"
    else:
        key = next(key for key in server.objects if "/documents/" in key)
        value = json.loads(server.objects[key])
        value["content_hex"] = b"forged document".hex()
        server.objects[key] = canonical_json_bytes(value)
    with pytest.raises(ValueError):
        download_portable_snapshot(remote, server.client(), tmp_path / "fetched")
    assert not backup.remote.reads


async def test_remote_namespace_mismatch_refuses_before_files_or_requests(backup, tmp_path):
    _, local = await captured(backup, tmp_path)
    server = EvidenceServer()
    remote = replicate_portable_snapshot(local, server.client(), "byte-results/v1/")
    changed = remote.model_copy(update={"bucket": "another-private-bucket"})
    server.calls.clear()
    with pytest.raises(ValueError, match="another remote namespace"):
        download_portable_snapshot(changed, server.client(), tmp_path / "refused")
    assert not server.calls and not (tmp_path / "refused").exists()


def test_empty_bounded_document_has_a_nonempty_canonical_R2_envelope():
    server = EvidenceServer()
    digest = sha256_hex(b"")
    body = canonical_json_bytes(
        _DocumentEnvelope(
            schema="umi-model-byte-portable-document/1", sha256=digest, content_hex=""
        )
    )
    client = server.client()
    head = client.publish("byte-results/v1/documents/empty.json", body, sha256_hex(body))
    assert (
        _document(client.read("byte-results/v1/documents/empty.json", head, maximum=512), digest, 0)
        == b""
    )


def test_cli_four_stage_dispatch_keeps_protected_canonical_request_boundary(
    backup, tmp_path, monkeypatch, capsys
):
    from umi import competition_model_byte_store_cli as cli

    original, old = asyncio.run(exported(backup, tmp_path))
    server = EvidenceServer()
    selected = []
    control = tmp_path / "root-controlled-request.json"
    active = None

    def protected(path, maximum, *, modes):
        assert path == control and maximum == 64 * 1024**2 and modes == {0o444}
        selected.append((path, maximum, modes))
        return active

    monkeypatch.setattr(cli, "_read_root_control_path", protected)
    monkeypatch.setattr(cli, "_portable_r2_client", lambda *_: server.client())

    def invoke(operation, request):
        nonlocal active
        active = canonical_json_bytes(request)
        assert cli.main([operation, "--request", str(control)]) == 0
        return json.loads(capsys.readouterr().out)

    captured = invoke(
        "portable-export",
        cli.PortableByteExportRequest(
            schema="umi-model-byte-portable-export-request/1",
            source=old,
            directory=str(tmp_path / "portable-cli"),
        ),
    )
    shutil.rmtree(original.root)
    uploaded = invoke(
        "portable-upload",
        cli.PortableByteUploadRequest(
            schema="umi-model-byte-portable-upload-request/1",
            source=captured["snapshot"],
            credentials_file=str(tmp_path / "private-credentials"),
            bucket="umi-proof-artifacts",
            prefix="byte-results/v1/",
        ),
    )
    shutil.rmtree(tmp_path / "portable-cli")
    fetched = invoke(
        "portable-download",
        cli.PortableByteDownloadRequest(
            schema="umi-model-byte-portable-download-request/1",
            source=uploaded["remote_snapshot"],
            credentials_file=str(tmp_path / "private-credentials"),
            directory=str(tmp_path / "fetched-cli"),
        ),
    )
    result = invoke(
        "portable-restore",
        cli.PortableByteRestoreRequest(
            schema="umi-model-byte-portable-restore-request/1",
            source=fetched["snapshot"],
            directory=str(tmp_path / "new-cli"),
        ),
    )
    assert result["restored_files"] == 7 and not result["certification_authority"]
    assert len(selected) == 4 and not backup.remote.reads
