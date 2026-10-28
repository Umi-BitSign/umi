"""Exact immutable transport, bounded leases and persistent owner repair fences."""

import hashlib
from pathlib import Path

import httpx
import pytest

from umi.competition_proof_archive_migration import migrate_proof_archive
from umi.competition_remote_proof_store import (
    MAX_PROOF_OBJECT_BYTES,
    ProofArchiveR2Config,
    ProofArchiveStores,
    RemoteProofStore,
)
from umi.competition_reward_proof_archive import MAX_FRAME_BYTES, RewardProofArchive
from umi.r2_evidence import R2EvidenceClient, R2EvidenceHTTPError
from umi.r2_sigv4 import R2Credentials, R2SigV4


class EvidenceServer:
    def __init__(self):
        self.objects = {}
        self.calls = []
        self.lose_put_ack = False
        self.fail_put_suffix = None
        self.corrupt_get = False
        self.extra_get = False
        self.encoding = None
        self.get_failure = None
        self.invalid_head = False

    def send(self, request):
        self.calls.append((request.method, request.url.path))
        assert request.headers["authorization"].startswith("AWS4-HMAC-SHA256 ")
        key = request.url.path.removeprefix("/umi-proof-artifacts/")
        if request.method == "PUT":
            assert request.headers["if-none-match"] == "*"
            if self.fail_put_suffix is not None and key.endswith(self.fail_put_suffix):
                return httpx.Response(503)
            if key in self.objects:
                return httpx.Response(412)
            raw = request.content
            sha = hashlib.sha256(raw).hexdigest()
            assert request.headers["x-amz-meta-sha256"] == sha
            self.objects[key] = raw
            if self.lose_put_ack:
                self.lose_put_ack = False
                raise httpx.ReadError("lost publication acknowledgement")
            return httpx.Response(
                200,
                headers={"ETag": '"' + hashlib.md5(raw, usedforsecurity=False).hexdigest() + '"'},
            )
        raw = self.objects.get(key)
        if raw is None:
            return httpx.Response(404, content=b"missing")
        headers = {
            "Content-Length": str(len(raw)),
            "ETag": '"' + hashlib.md5(raw, usedforsecurity=False).hexdigest() + '"',
            "x-amz-meta-sha256": hashlib.sha256(raw).hexdigest(),
        }
        if request.method == "HEAD":
            if self.invalid_head:
                headers["ETag"] = "invalid"
            return httpx.Response(200, headers=headers)
        assert request.method == "GET"
        if self.get_failure is not None:
            return httpx.Response(self.get_failure)
        if request.headers["if-match"] != headers["ETag"]:
            return httpx.Response(412)
        if self.corrupt_get:
            raw = bytes((raw[0] ^ 1,)) + raw[1:]
        if self.extra_get:
            raw += b"x"
        if self.encoding:
            headers["Content-Encoding"] = self.encoding
        return httpx.Response(200, headers=headers, content=raw)

    def client(self):
        return R2EvidenceClient(
            R2SigV4(
                "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com",
                "umi-proof-artifacts",
                R2Credentials("0123456789ABCDEF", "secret-access-key-value"),
            ),
            transport=httpx.MockTransport(self.send),
        )


def config(root: Path, *, read_only=False, prefix="proofs"):
    return ProofArchiveR2Config(
        schema="umi-r2-proof-archive/1",
        credentials_file=str(root / "credentials"),
        bucket="umi-proof-artifacts",
        prefix=prefix,
        read_only=read_only,
        maximum_cache_bytes=MAX_PROOF_OBJECT_BYTES,
        maximum_index_bytes=8 * 1024**2,
    )


def store(root, server, **kwargs):
    return RemoteProofStore(root, config(root.parent, **kwargs), client=server.client())


@pytest.mark.parametrize("size", [8, 4096, 4097])
def test_lost_upload_ack_retries_without_overwrite_and_receipt_survives_restart(tmp_path, size):
    server = EvidenceServer()
    raw = b"x" * size
    first = store(tmp_path / "owner", server)
    server.lose_put_ack = True
    with pytest.raises(OSError, match="transport unavailable"):
        first.put_bytes(raw)
    retained = dict(server.objects)
    reference = first.put_bytes(raw)
    assert sum(method == "PUT" for method, _ in server.calls) == (1 if size > 4096 else 2)
    assert server.objects == retained
    server.calls.clear()
    second = store(tmp_path / "owner", server)
    assert second.put_bytes(raw) == reference
    assert second.validate_reference(reference).size_bytes == size
    assert server.calls == []
    assert second.read_bytes(reference, maximum=size) == raw
    assert [method for method, _ in server.calls] == ["HEAD", "GET"]
    server.calls.clear()
    assert second.read_bytes(reference, maximum=size) == raw
    assert not server.calls
    assert second.evict_cache() == size
    second.validate_reference(reference)
    assert not server.calls


def test_named_immutable_object_conflict_never_replaces_original(tmp_path):
    server = EvidenceServer()
    first = store(tmp_path / "one", server)
    first.put_bytes(b"original", path="frames/history/one")
    with pytest.raises(ValueError, match="conflicts"):
        first.put_bytes(b"modified", path="frames/history/one")
    other = store(tmp_path / "other", server)
    with pytest.raises(ValueError, match="conflicts"):
        other.put_bytes(b"modified", path="frames/history/one")
    assert server.objects["proofs/frames/history/one"] == b"original"


@pytest.mark.parametrize("damage", ["deleted", "changed", "corrupt"])
def test_observed_damage_persists_until_explicit_original_generation_repair(tmp_path, damage):
    server = EvidenceServer()
    first = store(tmp_path / "owner", server)
    reference = first.put_bytes(b"original")
    first.evict_cache()  # Exercise a real remote fetch, not freshly published bytes.
    if damage == "deleted":
        del server.objects[reference["key"]]
    elif damage == "changed":
        server.objects[reference["key"]] = b"modified"
    else:
        server.corrupt_get = True
    with pytest.raises(ValueError):
        first.read_bytes(reference, maximum=8)
    second = store(tmp_path / "owner", server)
    with pytest.raises(ValueError, match=r"explicit.*repair"):
        second.validate_reference(reference)
    server.corrupt_get = False
    server.objects[reference["key"]] = b"original"
    with pytest.raises(ValueError, match=r"explicit.*repair"):
        second.put_bytes(b"original")
    second.repair_reference(reference)
    assert second.read_bytes(reference, maximum=8) == b"original"


def test_new_remote_namespace_or_missing_owner_receipt_cannot_restore_reference(tmp_path):
    server = EvidenceServer()
    first = store(tmp_path / "owner", server)
    reference = first.put_bytes(b"original")
    other = store(tmp_path / "other", server)
    with pytest.raises(ValueError, match="receipt is missing"):
        other.validate_reference(reference)
    with pytest.raises(ValueError):
        store(tmp_path / "owner", server, prefix="changed")


@pytest.mark.parametrize("failure", ["head", 404, 412])
def test_observed_metadata_or_generation_race_requires_explicit_repair(tmp_path, failure):
    server = EvidenceServer()
    first = store(tmp_path / "owner", server)
    reference = first.put_bytes(b"original")
    first.evict_cache()
    server.invalid_head = failure == "head"
    server.get_failure = None if failure == "head" else failure
    with pytest.raises(ValueError):
        first.read_bytes(reference, maximum=8)
    server.invalid_head, server.get_failure = False, None
    reopened = store(tmp_path / "owner", server)
    with pytest.raises(ValueError, match="explicit original-generation repair"):
        reopened.read_bytes(reference, maximum=8)
    reopened.repair_reference(reference)
    assert reopened.read_bytes(reference, maximum=8) == b"original"


def test_active_pins_bound_cache_and_release_capacity_after_lease(tmp_path):
    server = EvidenceServer()
    selected = config(tmp_path).model_copy(update={"maximum_cache_bytes": 8})
    first = RemoteProofStore(tmp_path / "owner", selected, client=server.client())
    one, two = first.put_bytes(b"12345678"), first.put_bytes(b"abcdefgh")
    with first.pin(one, maximum=8):
        assert first.evict_cache() == 0
        with pytest.raises(OSError, match="active leases"):
            first.read_bytes(two, maximum=8)
        with first.pin(one, maximum=8):
            assert first._pins
    assert not first._pins
    assert first.read_bytes(two, maximum=8) == b"abcdefgh"
    assert first._bytes == 8 and len(first._cache) == 1


def test_bounded_http_response_and_safe_error_text(tmp_path):
    server = EvidenceServer()
    first = store(tmp_path / "owner", server)
    reference = first.put_bytes(b"original")
    first.evict_cache()
    server.extra_get = True
    with pytest.raises(ValueError, match="byte bound"):
        first.read_bytes(reference, maximum=8)
    client = R2EvidenceClient(
        server.client().signer,
        transport=httpx.MockTransport(lambda _: httpx.Response(503, content=b"SECRET-body")),
    )
    with pytest.raises(R2EvidenceHTTPError, match="HTTP 503") as error:
        client.head("proofs/object")
    assert isinstance(error.value, OSError)
    assert error.value.status_code == 503
    assert "SECRET" not in str(error.value)


def test_read_only_import_authenticates_and_survives_cold_restart(tmp_path):
    server = EvidenceServer()
    writer = store(tmp_path / "writer", server)
    reference = writer.put_bytes(b"original")
    reader = store(tmp_path / "reader", server, read_only=True)
    with pytest.raises(ValueError, match="read-only"):
        reader.put_bytes(b"original")
    assert reader.read_object(reference["content_sha256"], maximum=8) == b"original"
    reader = store(tmp_path / "reader", server, read_only=True)
    server.calls.clear()
    reader.validate_reference(reference)
    assert not server.calls


def test_remote_frame_preserves_legacy_canonical_bytes_and_independent_roundtrip(tmp_path):
    server = EvidenceServer()
    local = RewardProofArchive(tmp_path / "local")
    remote = RewardProofArchive(
        tmp_path / "writer", remote=store(tmp_path / "writer-state", server)
    )
    fields, key, context = {"control": b"original", "metadata": b"metadata"}, "ab" * 32, {"n": 7}
    for archive in (local, remote):
        archive.write("history", key, context=context, fields=fields)
    assert (
        server.objects["proofs/frames/history/" + key]
        == (local.root / "history" / (key + ".json")).read_bytes()
    )
    reader = RewardProofArchive(
        tmp_path / "reader", remote=store(tmp_path / "reader-state", server, read_only=True)
    )
    assert reader.read("history", key, bounds={"control": 8, "metadata": 8}) == (context, fields)
    assert not (remote.root / "objects").exists()
    assert remote.remote.evict_cache() >= 0
    assert reader.remote.read_path("frames/history/" + key, maximum=MAX_FRAME_BYTES)


def test_interrupted_dependency_publication_never_publishes_frame(tmp_path):
    server = EvidenceServer()
    server.fail_put_suffix = hashlib.sha256(b"original").hexdigest()
    archive = RewardProofArchive(tmp_path / "archive", remote=store(tmp_path / "state", server))
    with pytest.raises(OSError, match="503"):
        archive.write("history", "ab" * 32, context={}, fields={"proof": b"original"})
    assert not any("/frames/" in key for key in server.objects)
    server.fail_put_suffix = None
    archive.write("history", "ab" * 32, context={}, fields={"proof": b"original"})
    assert any("/frames/" in key for key in server.objects)


def test_transport_directions_are_explicit(tmp_path):
    with pytest.raises(ValueError, match="read-only"):
        ProofArchiveStores(schema="umi-proof-archive-stores/1", imported=config(tmp_path))
    with pytest.raises(ValueError, match="publication"):
        ProofArchiveStores(
            schema="umi-proof-archive-stores/1", exported=config(tmp_path, read_only=True)
        )


def test_original_archive_migration_resumes_without_payload_reads_then_evicts(
    tmp_path, monkeypatch
):
    from umi import competition_proof_archive_migration as migration

    monkeypatch.setattr(migration, "_publication_clock_ns", lambda: 2**63 - 1)
    server = EvidenceServer()
    original = RewardProofArchive(tmp_path / "original")
    key, fields = "ab" * 32, {"proof": b"original"}
    original.write("history", key, context={"n": 1}, fields=fields)
    original_frame = (original.root / "history" / (key + ".json")).read_bytes()
    selected = RewardProofArchive(
        original.root, remote=store(original.root / ".remote-state", server)
    )
    first = migrate_proof_archive(original, selected)
    assert first["replicated_files"] > 1 and first["removed_files"] == 0
    assert server.objects["proofs/frames/history/" + key] == original_frame
    selected = RewardProofArchive(
        original.root, remote=store(original.root / ".remote-state", server)
    )

    def refuse(*_args, **_kwargs):
        raise AssertionError("completed migration reread original payload")

    monkeypatch.setattr(original, "_read_object", refuse)
    monkeypatch.setattr(original, "_frame", refuse)
    server.calls.clear()
    result = migrate_proof_archive(original, selected, evict=True)
    assert result["restored_files"] == result["removed_files"] == first["replicated_files"]
    assert result["reclaimed_allocated_bytes"] > 0 and not server.calls
    assert (original.root / ".remote-state" / "rounds.sqlite3").is_file()
    assert selected.read("history", key, bounds={"proof": 8}) == ({"n": 1}, fields)
    assert migrate_proof_archive(original, selected, evict=True)["removed_files"] == 0


def test_interrupted_archive_migration_retains_originals_and_no_partial_frame(
    tmp_path, monkeypatch
):
    from umi import competition_proof_archive_migration as migration

    monkeypatch.setattr(migration, "_publication_clock_ns", lambda: 2**63 - 1)
    server = EvidenceServer()
    original = RewardProofArchive(tmp_path / "original")
    key = "ab" * 32
    original.write("history", key, context={}, fields={"proof": b"original"})
    selected = RewardProofArchive(tmp_path / "selected", remote=store(tmp_path / "state", server))
    server.fail_put_suffix = "frames/history/" + key
    with pytest.raises(OSError, match="503"):
        migrate_proof_archive(original, selected, evict=True)
    assert (original.root / "history" / (key + ".json")).is_file()
    assert list((original.root / "objects").iterdir())
    assert not any("/frames/" in key for key in server.objects)
    server.fail_put_suffix = None
    result = migrate_proof_archive(original, selected, evict=True)
    assert result["restored_files"] > 0 and result["replicated_files"] == 1


def test_migration_changed_source_requires_explicit_exact_byte_repair(tmp_path, monkeypatch):
    from umi import competition_proof_archive_migration as migration

    monkeypatch.setattr(migration, "_publication_clock_ns", lambda: 2**63 - 1)
    server = EvidenceServer()
    original = RewardProofArchive(tmp_path / "original")
    original.write("history", "ab" * 32, context={}, fields={"proof": b"original"})
    selected = RewardProofArchive(tmp_path / "selected", remote=store(tmp_path / "state", server))
    migrate_proof_archive(original, selected)
    path = next((original.root / "objects").iterdir())
    replacement = path.with_suffix(".replacement")
    replacement.write_bytes(path.read_bytes())
    replacement.chmod(0o600)
    replacement.replace(path)
    with pytest.raises(ValueError, match="explicit repair"):
        migrate_proof_archive(original, selected)
    result = migrate_proof_archive(original, selected, repair_source_identity=True)
    assert result["replicated_files"] == 1


def select_remote_proofs(
    value,
    tmp_path,
    monkeypatch,
    *,
    import_only=False,
    legacy_read_through=False,
    source_release_batch_records=0,
):
    """Use real selection/owner stores and a bounded authenticated HTTP fixture."""
    from umi import competition_proof_archive_selection as selection
    from umi.protocol import canonical_json_bytes

    server, opened = EvidenceServer(), []

    def remote(root, selected):
        result = RemoteProofStore(root, selected, client=server.client())
        opened.append(result)
        return result

    monkeypatch.setattr(selection, "RemoteProofStore", remote)

    def selected_config(root, *, read_only=False):
        selected = config(root, read_only=read_only)
        if legacy_read_through:
            selected = ProofArchiveR2Config.model_validate(
                selected.model_dump(mode="json", by_alias=True)
                | {"schema": "umi-r2-proof-archive/2", "legacy_read_through": True}
            )
        if source_release_batch_records and not read_only:
            selected = ProofArchiveR2Config.model_validate(
                selected.model_dump(mode="json", by_alias=True)
                | {"source_release_batch_records": source_release_batch_records}
            )
        return selected

    stores = ProofArchiveStores(
        schema="umi-proof-archive-stores/1",
        imported=selected_config(tmp_path / "reader", read_only=True),
        exported=None if import_only else selected_config(tmp_path / "writer"),
    )
    assert b'"proof_stores"' not in canonical_json_bytes(value)
    selected = type(value).model_validate_json(
        canonical_json_bytes(value.model_copy(update={"proof_stores": stores}))
    )
    assert canonical_json_bytes(
        selected.model_copy(update={"proof_stores": None})
    ) == canonical_json_bytes(value)
    return selected, opened, server


def test_selected_exporter_migrates_original_before_startup_and_restarts_without_payloads(
    tmp_path, monkeypatch
):
    from umi import competition_proof_archive_migration as migration
    from umi import competition_proof_archive_selection as selection

    monkeypatch.setattr(migration, "_publication_clock_ns", lambda: 2**63 - 1)
    server = EvidenceServer()
    monkeypatch.setattr(
        selection,
        "RemoteProofStore",
        lambda root, selected: RemoteProofStore(root, selected, client=server.client()),
    )
    root, key = tmp_path / "archive", "ab" * 32
    original = RewardProofArchive(root)
    original.write("history", key, context={"height": 7}, fields={"proof": b"original"})
    before = {path: path.read_bytes() for path in root.rglob("*.json")}
    selected = selection.selected_proof_archive(root, config(tmp_path))
    assert selected.read("history", key, bounds={"proof": 20}) == (
        {"height": 7},
        {"proof": b"original"},
    )
    assert all(path.read_bytes() == raw for path, raw in before.items())
    server.calls.clear()

    def prohibit(*args, **kwargs):
        raise AssertionError("completed startup migration read payloads")

    monkeypatch.setattr(RewardProofArchive, "_read_object", prohibit)
    monkeypatch.setattr(RewardProofArchive, "_frame", prohibit)
    selection.selected_proof_archive(root, config(tmp_path))
    assert not server.calls


def test_retained_local_selection_preserves_old_config_bytes_and_refuses_implicit_upgrade(tmp_path):
    from umi.protocol import canonical_json_bytes

    original = config(tmp_path)
    raw = canonical_json_bytes(original)
    assert b"legacy_read_through" not in raw
    assert b"source_release_batch_records" not in raw
    assert canonical_json_bytes(ProofArchiveR2Config.model_validate_json(raw)) == raw
    with pytest.raises(ValueError, match="explicit archive/2"):
        ProofArchiveR2Config.model_validate(
            original.model_dump(mode="json", by_alias=True) | {"legacy_read_through": True}
        )


@pytest.mark.parametrize("change", [{"read_only": True}, {"legacy_read_through": False}])
def test_owned_source_release_requires_explicit_writable_retained_local_selection(tmp_path, change):
    selected = retained_local_config(tmp_path)
    raw = selected.model_dump(mode="json", by_alias=True) | {"source_release_batch_records": 16}
    configured = ProofArchiveR2Config.model_validate(raw)
    assert configured.source_release_batch_records == 16
    with pytest.raises(ValueError, match="source release requires writable"):
        ProofArchiveR2Config.model_validate(raw | change)


def retained_local_config(root):
    return ProofArchiveR2Config.model_validate(
        config(root).model_dump(mode="json", by_alias=True)
        | {"schema": "umi-r2-proof-archive/2", "legacy_read_through": True}
    )


def test_retained_local_startup_and_restart_never_inventory_or_migrate_history(
    tmp_path, monkeypatch, caplog
):
    import logging
    import os

    from umi import competition_proof_archive_selection as selection

    server = EvidenceServer()
    root, old_key, new_key = tmp_path / "archive", "ab" * 32, "cd" * 32
    original = RewardProofArchive(root)
    original.write("history", old_key, context={"height": 7}, fields={"proof": b"original"})
    before = {
        path: (path.read_bytes(), path.stat().st_ino, path.stat().st_ctime_ns)
        for path in root.rglob("*.json")
    }
    monkeypatch.setattr(
        selection,
        "RemoteProofStore",
        lambda directory, selected: RemoteProofStore(directory, selected, client=server.client()),
    )

    def refuse(*_args, **_kwargs):
        raise AssertionError("retained local startup must not enumerate or migrate the archive")

    monkeypatch.setattr(selection, "migrate_proof_archive", refuse)
    scan = os.scandir

    def bounded_scan(path):
        if path in (root, root / "objects", root / "history"):
            refuse()
        return scan(path)

    monkeypatch.setattr(os, "scandir", bounded_scan)
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    for restart in (False, True):
        selected = selection.selected_proof_archive(root, retained_local_config(tmp_path))
        assert selected.read("history", old_key, bounds={"proof": 20}) == (
            {"height": 7},
            {"proof": b"original"},
        )
        if not restart:
            assert not server.calls
            selected.write("history", new_key, context={"height": 8}, fields={"proof": b"remote"})
        assert selected.read("history", new_key, bounds={"proof": 20}) == (
            {"height": 8},
            {"proof": b"remote"},
        )
        assert not (root / "history" / (new_key + ".json")).exists()
        assert all(
            (path.read_bytes(), path.stat().st_ino, path.stat().st_ctime_ns) == expected
            for path, expected in before.items()
        )
    assert "retained_local_history_remote_new_proofs" in caplog.text
    assert "proof_archive_transport_selection" in caplog.text


def test_retained_local_mode_preserves_immutable_frame_conflicts(tmp_path):
    server = EvidenceServer()
    root, key = tmp_path / "archive", "ab" * 32
    original = RewardProofArchive(root)
    original.write("history", key, context={"height": 7}, fields={"proof": b"original"})
    remote = RemoteProofStore(
        root / ".remote-state", retained_local_config(tmp_path), client=server.client()
    )
    selected = RewardProofArchive(root, remote=remote, legacy_read_through=True)
    with pytest.raises(ValueError, match="differs from selected publication"):
        selected.write("history", key, context={"height": 8}, fields={"proof": b"changed"})
    with pytest.raises(ValueError, match="differs from selected publication"):
        selected.write("history", key, context={"height": 7}, fields={"proof": b"changed"})
    assert "proofs/frames/history/" + key not in server.objects


def test_completed_remote_loss_never_falls_back_to_retained_local_copy(tmp_path):
    server = EvidenceServer()
    root, key = tmp_path / "archive", "ab" * 32
    original = RewardProofArchive(root)
    original.write("history", key, context={"height": 7}, fields={"proof": b"original"})
    selected_config = retained_local_config(tmp_path)
    remote = RemoteProofStore(root / ".remote-state", selected_config, client=server.client())
    selected = RewardProofArchive(root, remote=remote, legacy_read_through=True)
    selected.write("history", key, context={"height": 7}, fields={"proof": b"original"})
    del server.objects["proofs/frames/history/" + key]
    remote.evict_cache()
    with pytest.raises(ValueError, match=r"missing|generation"):
        selected.read("history", key, bounds={"proof": 20})
    restarted = RewardProofArchive(
        root,
        remote=RemoteProofStore(root / ".remote-state", selected_config, client=server.client()),
        legacy_read_through=True,
    )
    with pytest.raises(ValueError, match="explicit original-generation repair"):
        restarted.read("history", key, bounds={"proof": 20})


@pytest.mark.parametrize("damage", ["missing", "malformed", "changed"])
def test_completed_receipt_damage_never_silently_reimports(tmp_path, damage, caplog):
    import logging

    from umi.protocol import canonical_json_bytes

    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    server = EvidenceServer()
    first = store(tmp_path / "owner", server)
    reference = first.put_bytes(b"original", path="named")
    key = hashlib.sha256(reference["key"].encode()).hexdigest()
    with first.journal.transaction() as db:
        original_completion = first.journal.get_raw("remote_proof_completion", key, db=db)
        if damage == "missing":
            db.execute("DELETE FROM records WHERE kind='remote_proof_object' AND id=?", (key,))
        else:
            raw = (
                b"broken"
                if damage == "malformed"
                else canonical_json_bytes(dict(reference, etag='"different-generation"'))
            )
            db.execute(
                "UPDATE records SET body=? WHERE kind='remote_proof_object' AND id=?", (raw, key)
            )
    restarted = store(tmp_path / "owner", server)
    server.calls.clear()
    for action in (
        lambda: restarted.read_path("named", maximum=8),
        lambda: restarted.put_bytes(b"original", path="named"),
        lambda: restarted.reference_for_path("named"),
        lambda: restarted.validate_reference(reference),
    ):
        with pytest.raises(ValueError, match="explicit original-generation repair"):
            action()
    assert not server.calls
    server.objects[reference["key"]] = b"modified"
    with pytest.raises(ValueError, match="original object generation"):
        restarted.repair_reference(reference)
    with pytest.raises(ValueError, match="original completion ledger"):
        restarted.repair_reference(dict(reference, etag='"new-generation"'))
    server.objects[reference["key"]] = b"original"
    restarted.repair_reference(reference)
    assert restarted.journal.get_raw("remote_proof_completion", key) == original_completion
    assert restarted.journal.get_raw("remote_proof_object", key) == original_completion
    assert restarted.read_path("named", maximum=8) == b"original"
    assert '"stage":"proof_repair"' in caplog.text.replace(" ", "")
    assert '"eta_basis"' in caplog.text


@pytest.mark.parametrize("damage", ["ledger", "both_records", "marker", "trigger", "downgrade"])
def test_completion_ledger_damage_requires_original_metadata(tmp_path, damage):
    import sqlite3

    from umi.competition_remote_proof_store import _completion_triggers

    server = EvidenceServer()
    first = store(tmp_path / "owner", server)
    reference = first.put_bytes(b"original", path="named")
    # Deliberately bypass normal immutable fences to emulate damaged retained
    # metadata. Even loss of both copies must not become a new remote import.
    with sqlite3.connect(first.journal.path) as db:
        db.execute("PRAGMA recursive_triggers=ON")
        if damage in {"ledger", "both_records"}:
            name = "round_generation_proof_completion_delete"
            db.execute("DROP TRIGGER " + name)
            kinds = (
                ("remote_proof_completion",)
                if damage == "ledger"
                else ("remote_proof_completion", "remote_proof_object")
            )
            for kind in kinds:
                db.execute("DELETE FROM records WHERE kind=?", (kind,))
            db.execute(_completion_triggers()[name])
        elif damage == "marker":
            db.execute("DELETE FROM round_generation_proof_completion")
        elif damage == "trigger":
            db.execute("DROP TRIGGER round_generation_proof_completion_update")
        else:
            db.execute("PRAGMA user_version=0")
    server.calls.clear()
    for action in (
        lambda: store(tmp_path / "owner", server),
        lambda: first.read_path("named", maximum=8),
        lambda: first.repair_reference(reference),
    ):
        with pytest.raises(ValueError, match=r"restore original metadata|downgraded"):
            action()
    assert not server.calls


def test_completion_ledger_is_immutable_and_old_runtime_refuses(tmp_path):
    import sqlite3

    from umi.competition_round_journal import RoundJournal

    server = EvidenceServer()
    first = store(tmp_path / "owner", server)
    first.put_bytes(b"original")
    for sql in (
        "DELETE FROM records WHERE kind='remote_proof_completion'",
        "UPDATE records SET body='{}' WHERE kind='remote_proof_completion'",
    ):
        with (
            pytest.raises(sqlite3.IntegrityError, match="immutable"),
            first.journal.transaction() as db,
        ):
            db.execute(sql)
    with pytest.raises(ValueError, match="unsupported round journal capability"):
        RoundJournal(first.journal.root, first.binding)


def test_legacy_receipt_migration_preserves_originals_and_never_fetches_payload(tmp_path, caplog):
    import logging

    from umi.competition_round_journal import RoundJournal
    from umi.protocol import canonical_json_bytes

    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    server = EvidenceServer()
    writer = store(tmp_path / "writer", server)
    reference = writer.put_bytes(b"original", path="named")
    legacy = RoundJournal(tmp_path / "owner", writer.binding)
    key = hashlib.sha256(reference["key"].encode()).hexdigest()
    legacy.put("remote_proof_object", key, reference)
    identity = legacy.path.stat().st_ino
    server.calls.clear()
    migrated = store(legacy.root, server)
    assert migrated.journal.path.stat().st_ino == identity
    assert migrated.journal.get_raw("remote_proof_object", key) == canonical_json_bytes(reference)
    assert migrated.reference_for_path("named") == reference
    assert not server.calls
    assert '"stage":"proof_receipt_migration"' in caplog.text.replace(" ", "")
    assert '"planning_eta_seconds"' in caplog.text
    caplog.clear()
    restarted = store(legacy.root, server)
    assert restarted.reference_for_path("named") == reference
    assert "proof_receipt_migration" not in caplog.text and not server.calls


def test_interrupted_receipt_commit_retries_as_first_import_without_partial_ledger(tmp_path):
    import sqlite3

    server = EvidenceServer()
    first = store(tmp_path / "owner", server)
    with first.journal.transaction() as db:
        db.execute(
            "CREATE TRIGGER reject_receipt BEFORE INSERT ON records "
            "WHEN NEW.kind='remote_proof_object' BEGIN SELECT RAISE(ABORT,'interrupted'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="interrupted"):
        first.put_bytes(b"original", path="named")
    assert first.reference_for_path("named") is None
    with first.journal.transaction() as db:
        assert db.execute("SELECT completed FROM round_generation_proof_completion").fetchone() == (
            0,
        )
        db.execute("DROP TRIGGER reject_receipt")
    restarted = store(tmp_path / "owner", server)
    reference = restarted.put_bytes(b"original", path="named")
    assert restarted.reference_for_path("named") == reference
    assert [method for method, _ in server.calls] == ["PUT", "PUT", "HEAD"]
    assert server.objects == {"proofs/named": b"original"}


def test_completion_index_refuses_reservations_without_changing_receipts(tmp_path):
    server = EvidenceServer()
    first = store(tmp_path / "owner", server)
    reference = first.put_bytes(b"original", path="named")
    with first.journal.read_transaction() as db:
        original_schema = db.execute(
            "SELECT type,name,sql FROM sqlite_master ORDER BY name"
        ).fetchall()
    with pytest.raises(ValueError, match="does not support reservations"):
        first.journal.reserve_records("unsupported", ())
    with first.journal.read_transaction() as db:
        assert db.execute("PRAGMA user_version").fetchone() == (4,)
        assert (
            db.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name").fetchall()
            == original_schema
        )
    assert store(tmp_path / "owner", server).reference_for_path("named") == reference


def test_damaged_completion_body_cannot_be_rebuilt_from_remote_or_receipt(tmp_path):
    import sqlite3

    from umi.competition_remote_proof_store import _completion_triggers

    server = EvidenceServer()
    first = store(tmp_path / "owner", server)
    reference = first.put_bytes(b"original", path="named")
    with sqlite3.connect(first.journal.path) as db:
        db.execute("DROP TRIGGER round_generation_proof_completion_update")
        db.execute("UPDATE records SET body=? WHERE kind='remote_proof_completion'", (b"damaged",))
        db.execute(_completion_triggers()["round_generation_proof_completion_update"])
    server.calls.clear()
    restarted = store(tmp_path / "owner", server)
    for action in (
        lambda: restarted.put_bytes(b"original", path="named"),
        lambda: restarted.repair_reference(reference),
    ):
        with pytest.raises(
            ValueError, match="completion ledger damaged; restore original metadata"
        ):
            action()
    assert not server.calls


def test_interrupted_legacy_migration_preserves_original_metadata_and_resumes(
    tmp_path, monkeypatch
):
    from umi.competition_remote_proof_store import _ProofIndex
    from umi.competition_round_journal import RoundJournal

    server = EvidenceServer()
    writer = store(tmp_path / "writer", server)
    references = [writer.put_bytes(raw, path=str(i)) for i, raw in enumerate((b"one", b"two"))]
    legacy = RoundJournal(tmp_path / "owner", writer.binding)
    for reference in references:
        legacy.put(
            "remote_proof_object", hashlib.sha256(reference["key"].encode()).hexdigest(), reference
        )
    server.calls.clear()
    original = _ProofIndex.insert_completion_record
    calls = []

    def interrupt(self, db, kind, key, raw):
        calls.append(key)
        original(self, db, kind, key, raw)
        if len(calls) == 2:
            raise OSError("interrupted metadata upgrade")

    monkeypatch.setattr(_ProofIndex, "insert_completion_record", interrupt)
    with pytest.raises(OSError, match="interrupted metadata upgrade"):
        store(legacy.root, server)
    with legacy.read_transaction() as db:
        assert db.execute("PRAGMA user_version").fetchone() == (0,)
        assert db.execute(
            "SELECT count(*) FROM records WHERE kind='remote_proof_completion'"
        ).fetchone() == (0,)
    monkeypatch.setattr(_ProofIndex, "insert_completion_record", original)
    repaired = store(legacy.root, server)
    for i, reference in enumerate(references):
        assert repaired.reference_for_path(str(i)) == reference
    assert not server.calls
