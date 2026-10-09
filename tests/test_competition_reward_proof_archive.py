"""Portable byte transport is bounded and confers no native proof authority."""

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
import rfc8785

from umi import competition_reward_proof_archive as archive_module
from umi.competition_reward_proof_archive import RewardProofArchive, history_archive_key
from umi.protocol import canonical_json_bytes


@pytest.fixture
def settled_publication_clock(monkeypatch):
    # These tests isolate stamp invalidation/LRU/ownership after the inode's
    # timestamp tick. The separate clock tests cover initial publication.
    monkeypatch.setattr(archive_module, "_publication_clock_ns", lambda: 2**63 - 1)


def test_large_object_publication_reuses_success_with_unchanged_metadata(
    tmp_path, monkeypatch, settled_publication_clock
):
    archive = RewardProofArchive(tmp_path / "export")
    raw = bytes(range(256)) * 8192
    serialize = rfc8785.dumps
    calls = []

    def counted(value):
        calls.append(None)
        return serialize(value)

    monkeypatch.setattr(rfc8785, "dumps", counted)
    sha = archive._retain_bytes(raw)
    path = archive.root / "objects" / (sha + ".json")
    before = path.stat()
    assert archive._retain_bytes(raw) == sha
    assert len(calls) == 1  # A successful unchanged publication is reused.
    assert path.stat().st_ino == before.st_ino
    path.write_bytes(b'{"hex":"00"}')
    with pytest.raises(ValueError, match="different bytes"):
        archive._retain_bytes(raw)


@pytest.mark.parametrize("change", ["replace", "delete", "parent", "mode", "link", "symlink"])
def test_publication_cache_invalidates_changed_objects(
    tmp_path, monkeypatch, change, settled_publication_clock
):
    archive = RewardProofArchive(tmp_path / "export")
    original, calls = archive._publish_bytes, []

    def publish(path, raw):
        calls.append(path)
        return original(path, raw)

    monkeypatch.setattr(archive, "_publish_bytes", publish)
    sha = archive._retain_bytes(b"original")
    path = archive.root / "objects" / (sha + ".json")
    if change == "replace":
        replacement = path.with_suffix(".new")
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(path)
    elif change == "delete":
        path.unlink()
    elif change == "parent":
        previous = archive.root / "previous"
        path.parent.rename(previous)
        path.parent.mkdir(mode=0o700)
        (previous / path.name).rename(path)
    elif change == "mode":
        path.chmod(0o644)
    elif change == "link":
        os.link(path, path.with_suffix(".alias"))
    else:
        previous = path.with_suffix(".previous")
        path.rename(previous)
        path.symlink_to(previous)
    if change in {"mode", "link", "symlink"}:
        with pytest.raises(ValueError):
            archive._retain_bytes(b"original")
        assert sha not in archive._published
    else:
        assert archive._retain_bytes(b"original") == sha
    assert len(calls) == 2


def test_failed_publication_sync_does_not_create_reuse_receipt(
    tmp_path, monkeypatch, settled_publication_clock
):
    archive = RewardProofArchive(tmp_path / "export")
    original, calls = archive._publish_bytes, []

    def publish(path, raw):
        calls.append(path)
        original(path, raw)
        if len(calls) == 1:
            raise OSError("directory sync failed")

    monkeypatch.setattr(archive, "_publish_bytes", publish)
    with pytest.raises(OSError, match="sync failed"):
        archive._retain_bytes(b"original")
    assert not archive._published
    sha = archive._retain_bytes(b"original")
    assert archive._retain_bytes(b"original") == sha
    assert len(calls) == 2


def test_same_size_corruption_with_restored_mtime_cannot_reuse_publication(tmp_path):
    archive = RewardProofArchive(tmp_path / "export")
    sha = archive._retain_bytes(b"original")
    path = archive.root / "objects" / (sha + ".json")
    original = path.stat()
    path.write_bytes(canonical_json_bytes({"hex": b"modified".hex()}))
    os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
    assert path.stat().st_size == original.st_size
    assert path.stat().st_mtime_ns == original.st_mtime_ns
    with pytest.raises(ValueError, match="different bytes"):
        archive._retain_bytes(b"original")
    assert sha not in archive._published


def test_publication_cache_is_bounded_and_process_local(
    tmp_path, monkeypatch, settled_publication_clock
):
    import umi.competition_reward_proof_archive as module

    monkeypatch.setattr(module, "_MAX_PUBLISHED_OBJECTS", 2)
    archive = RewardProofArchive(tmp_path / "export")
    original, calls = archive._publish_bytes, []

    def publish(path, raw):
        calls.append(raw)
        return original(path, raw)

    monkeypatch.setattr(archive, "_publish_bytes", publish)
    for raw in (b"a", b"b", b"a", b"c", b"a", b"b"):
        archive._retain_bytes(raw)
    assert calls == [b"a", b"b", b"c", b"b"]
    assert len(archive._published) == 2
    monkeypatch.setattr(module.os, "getpid", lambda: archive._pid + 1)
    with archive._publication_lock:
        archive._retain_bytes(b"b")
    assert calls[-2:] == [b"b", b"b"]


def test_concurrent_exact_publications_share_one_completed_write(
    tmp_path, monkeypatch, settled_publication_clock
):
    archive = RewardProofArchive(tmp_path / "export")
    original, calls = archive._publish_bytes, []

    def publish(path, raw):
        calls.append(path)
        return original(path, raw)

    monkeypatch.setattr(archive, "_publish_bytes", publish)
    with ThreadPoolExecutor(max_workers=8) as executor:
        values = tuple(executor.map(archive._retain_bytes, [b"original"] * 16))
    assert len(set(values)) == len(calls) == 1


def test_initial_tick_requires_later_verified_publication_before_reuse(tmp_path, monkeypatch):
    archive = RewardProofArchive(tmp_path / "export")
    publish, calls = archive._publish_bytes, []

    def counted(path, raw):
        calls.append(raw)
        publish(path, raw)

    monkeypatch.setattr(archive, "_publish_bytes", counted)
    monkeypatch.setattr(archive_module, "_publication_clock_ns", lambda: 0)
    sha = archive._retain_bytes(b"original")
    assert not archive._published
    path = archive.root / "objects" / (sha + ".json")
    tick = path.stat().st_ctime_ns
    monkeypatch.setattr(archive_module, "_publication_clock_ns", lambda: tick)
    archive._retain_bytes(b"original")
    assert not archive._published
    monkeypatch.setattr(archive_module, "_publication_clock_ns", lambda: tick + 1)
    archive._retain_bytes(b"original")
    assert sha in archive._published and len(calls) == 3
    archive._retain_bytes(b"original")
    assert len(calls) == 3


def test_corruption_in_initial_tick_is_not_trusted_after_time_passes(tmp_path, monkeypatch):
    archive = RewardProofArchive(tmp_path / "export")
    monkeypatch.setattr(archive_module, "_publication_clock_ns", lambda: 0)
    sha = archive._retain_bytes(b"original")
    path = archive.root / "objects" / (sha + ".json")
    stamp = archive._object_stamp(path)
    assert not archive._published
    path.write_bytes(canonical_json_bytes({"hex": b"modified".hex()}))
    monkeypatch.setattr(archive, "_object_stamp", lambda path: stamp)
    monkeypatch.setattr(archive_module, "_publication_clock_ns", lambda: stamp[-1] + 1)
    with pytest.raises(ValueError, match="different bytes"):
        archive._retain_bytes(b"original")
    assert not archive._published


def test_unqualified_clock_uses_ordinary_publication(tmp_path, monkeypatch):
    archive = RewardProofArchive(tmp_path / "export")
    monkeypatch.setattr(archive_module, "_publication_clock_ns", lambda: None)
    sha = archive._retain_bytes(b"original")
    assert archive._retain_bytes(b"original") == sha and not archive._published
    (archive.root / "objects" / (sha + ".json")).write_bytes(
        canonical_json_bytes({"hex": b"modified".hex()})
    )
    with pytest.raises(ValueError, match="different bytes"):
        archive._retain_bytes(b"original")


def test_archive_preserves_original_bytes_and_idempotent_frames(tmp_path):
    archive = RewardProofArchive(tmp_path / "export")
    fields = {"control": b'{"data":"' + b"ab" * 2048 + b'"}', "metadata": bytes(range(256))}
    key = "aa" * 32
    archive.write("endpoint", key, context={"private": True}, fields=fields)
    before = {p.relative_to(archive.root): p.read_bytes() for p in archive.root.rglob("*.json")}
    archive.write("endpoint", key, context={"private": True}, fields=fields)
    assert before == {
        p.relative_to(archive.root): p.read_bytes() for p in archive.root.rglob("*.json")
    }
    assert archive.read("endpoint", key, bounds={k: len(v) for k, v in fields.items()}) == (
        {"private": True},
        fields,
    )
    with pytest.raises(ValueError, match="domain"):
        archive.read("endpoint", key, bounds={"control": 10000})
    with pytest.raises(ValueError, match="expansion"):
        archive.read("endpoint", key, bounds={"control": 1, "metadata": 256})


def test_interrupted_archive_export_reuses_objects_without_partial_frame(tmp_path, monkeypatch):
    import umi.competition_reward_proof_archive as module

    archive = RewardProofArchive(tmp_path / "export")
    original = module.publish_private_model

    def fail_frame(path, *args, **kwargs):
        if path.parent.name == "history":
            raise OSError("disk full")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(module, "publish_private_model", fail_frame)
    with pytest.raises(OSError):
        archive.write("history", "aa" * 32, context={}, fields={"evidence": b"original"})
    assert not (archive.root / "history" / (("aa" * 32) + ".json")).exists()
    objects = tuple((archive.root / "objects").glob("*.json"))
    assert objects
    monkeypatch.setattr(module, "publish_private_model", original)
    archive.write("history", "aa" * 32, context={}, fields={"evidence": b"original"})
    assert tuple((archive.root / "objects").glob("*.json")) == objects
    assert archive.read("history", "aa" * 32, bounds={"evidence": 100})[1] == {
        "evidence": b"original"
    }


@pytest.mark.parametrize("damage", ["object", "recipe", "kind", "key", "oversized"])
def test_changed_archive_content_rejected(tmp_path, damage):
    archive = RewardProofArchive(tmp_path / "export")
    key = "aa" * 32
    archive.write("endpoint", key, context={}, fields={"data": b"original"})
    path = archive.root / "endpoint" / (key + ".json")
    frame = json.loads(path.read_bytes())
    part = frame["fields"]["data"][0]
    if damage in {"object", "recipe"}:
        sha = (
            hashlib.sha256(b"original").hexdigest() if damage == "object" else part["recipe_sha256"]
        )
        target = archive.root / "objects" / (sha + ".json")
        target.write_bytes(canonical_json_bytes({"hex": b"changed".hex()}))
    elif damage == "kind":
        frame["kind"] = "history"
    elif damage == "key":
        frame["key"] = "bb" * 32
    else:
        part["expanded_bytes"] = 1000
    path.write_bytes(canonical_json_bytes(frame))
    with pytest.raises(ValueError):
        archive.read("endpoint", key, bounds={"data": 100})


def test_archive_domains_do_not_alias_hotkeys_or_chains():
    from .test_open_competition import wallet

    alice = wallet("Alice").hotkey.ss58_address
    bob = wallet("Bob").hotkey.ss58_address
    assert (
        len(
            {
                history_archive_key(chain, hotkey, height)
                for chain in ("aa" * 32, "bb" * 32)
                for hotkey in (alice, bob)
                for height in (10, 11)
            }
        )
        == 8
    )
