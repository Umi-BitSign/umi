"""Frame-local byte reuse retains storage checks without repeating every lookup."""

import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from umi import competition_reward_proof_archive as module
from umi.competition_evidence_codec import encode_evidence
from umi.competition_reward_proof_archive import RewardProofArchive, _FrameRead
from umi.protocol import canonical_json_bytes

KEY = "a" * 64
RAW = b'{"items":[' + b",".join([b'"0x' + b"ab" * 1024 + b'"'] * 20) + b"]}"


@pytest.fixture
def archived(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "_publication_clock_ns", lambda: 2**63 - 1)
    archive = RewardProofArchive(tmp_path / "archive")
    archive.write("history", KEY, context={"block": 1}, fields={"proof": RAW})
    return archive


def test_duplicate_resolution_rechecks_once_before_returning_frame(archived, monkeypatch):
    counts = {}
    original = module._ObjectDirectory.stamp
    original_path = archived._object_stamp

    def counted(directory, path):
        counts[path.name] = counts.get(path.name, 0) + 1
        return original(directory, path)

    def counted_path(path):
        counts[path.name] = counts.get(path.name, 0) + 1
        return original_path(path)

    monkeypatch.setattr(module._ObjectDirectory, "stamp", counted)
    monkeypatch.setattr(archived, "_object_stamp", counted_path)
    for cold in (True, False):
        counts.clear()
        assert archived.read("history", KEY, bounds={"proof": len(RAW)}) == (
            {"block": 1},
            {"proof": RAW},
        )
        # Cold reads pair ordinary before/after path stamps with actual I/O,
        # in addition to the first/final descriptor stamps. The next frame
        # independently validates every cached object.
        assert max(counts.values()) == (4 if cold else 2)
        assert sum(counts.values()) <= 20


@pytest.mark.parametrize(
    "change", ["replace", "delete", "parent", "mode", "link", "symlink", "corrupt"]
)
def test_frame_cannot_hide_mutation_after_duplicate_resolution(archived, monkeypatch, change):
    object_sha = next(
        sha
        for sha, raw in encode_evidence(RAW, kind="proof").objects.items()
        if raw == b"\xab" * 1024
    )
    path = archived.root / "objects" / (object_sha + ".json")
    decode = module.decode_evidence

    def change_after_decode(*args, **kwargs):
        value = decode(*args, **kwargs)
        if change == "replace":
            replacement = path.with_suffix(".new")
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(path)
        elif change == "parent":
            previous = archived.root / "previous"
            path.parent.rename(previous)
            path.parent.mkdir(mode=0o700)
            for child in previous.iterdir():
                child.rename(path.parent / child.name)
        elif change == "delete":
            path.unlink()
        elif change == "mode":
            path.chmod(0o644)
        elif change == "link":
            os.link(path, path.with_suffix(".alias"))
        elif change == "symlink":
            previous = path.with_suffix(".previous")
            path.rename(previous)
            path.symlink_to(previous)
        else:
            before = path.stat()
            path.write_bytes(canonical_json_bytes({"hex": (b"\xcd" * 1024).hex()}))
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        return value

    monkeypatch.setattr(module, "decode_evidence", change_after_decode)
    if change in {"replace", "parent"}:
        assert archived.read("history", KEY, bounds={"proof": len(RAW)})[1]["proof"] == RAW
    else:
        with pytest.raises((ValueError, OSError)):
            archived.read("history", KEY, bounds={"proof": len(RAW)})


def test_reused_eviction_is_checked_before_forgetting_receipt(archived, monkeypatch):
    monkeypatch.setattr(module, "_MAX_READ_OBJECTS", 2)
    digests = [archived._retain_bytes(value) for value in (b"aa", b"bb", b"cc")]
    scope = _FrameRead(archived)
    assert scope.resolve(digests[0], 2) == scope.resolve(digests[0], 2) == b"aa"
    assert scope.resolve(digests[1], 2) == b"bb"
    path = archived.root / "objects" / (digests[0] + ".json")
    path.write_bytes(canonical_json_bytes({"hex": b"xx".hex()}))
    with pytest.raises(ValueError):
        scope.resolve(digests[2], 2)


def test_scope_is_bounded_and_each_reference_keeps_its_limit(archived, monkeypatch):
    monkeypatch.setattr(module, "_MAX_READ_OBJECTS", 2)
    monkeypatch.setattr(module, "_MAX_READ_BYTES", 5)
    scope = _FrameRead(archived)
    for value in (b"aa", b"bbb", b"c", b"dddddd"):
        sha = archived._retain_bytes(value)
        assert scope.resolve(sha, 100) == value
        assert scope.bytes <= 5 and len(scope.objects) <= 2
    sha = archived._retain_bytes(b"ee")
    assert scope.resolve(sha, 2) == b"ee"
    with pytest.raises(ValueError):
        scope.resolve(sha, 1)
    with pytest.raises(ValueError):
        scope.resolve(sha, module.MAX_EVIDENCE_BYTES + 1)
    scope.finish()


@pytest.mark.parametrize("tick", [None, 0])
def test_scope_never_reuses_same_tick_or_unqualified_receipt(archived, monkeypatch, tick):
    sha = archived._retain_bytes(b"original")
    path = archived.root / "objects" / (sha + ".json")
    stamp = archived._object_stamp(path)
    monkeypatch.setattr(module, "_publication_clock_ns", lambda: tick)
    scope = _FrameRead(archived)
    assert scope.resolve(sha, 100) == b"original"
    assert not scope.objects
    path.write_bytes(canonical_json_bytes({"hex": b"modified".hex()}))
    monkeypatch.setattr(archived, "_object_stamp", lambda _path: stamp)
    monkeypatch.setattr(module, "_publication_clock_ns", lambda: stamp[-1] + 1)
    with pytest.raises(ValueError):
        scope.resolve(sha, 100)


def test_scope_never_reuses_inherited_receipt_or_lock(archived, monkeypatch):
    sha = archived._retain_bytes(b"original")
    scope = _FrameRead(archived)
    assert scope.resolve(sha, 100) == b"original"
    assert scope.resolve(sha, 100) == b"original"
    path = archived.root / "objects" / (sha + ".json")
    path.write_bytes(canonical_json_bytes({"hex": b"modified".hex()}))
    monkeypatch.setattr(module.os, "getpid", lambda: archived._pid + 1)
    with archived._read_lock:
        with pytest.raises(ValueError):
            scope.resolve(sha, 100)
        with pytest.raises(ValueError):
            scope.finish()


def test_concurrent_frames_use_separate_local_receipts(archived):
    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(
            workers.map(
                lambda _: archived.read("history", KEY, bounds={"proof": len(RAW)}), range(8)
            )
        )
    assert results == [({"block": 1}, {"proof": RAW})] * 8


def test_remote_reads_keep_transport_receipt_checks(archived):
    class Remote:
        calls = 0

        def read_object(self, sha, *, maximum):
            self.calls += 1
            return archived._bytes(sha, maximum)

    remote = Remote()
    imported = RewardProofArchive(archived.root.parent / "remote", remote=remote)
    scope = _FrameRead(imported)
    sha = archived._retain_bytes(b"original")
    for _ in range(3):
        assert scope.resolve(sha, 100) == b"original"
    assert remote.calls == 3 and not scope.objects
    scope.finish()


@pytest.mark.parametrize("operation", ["read", "write"])
@pytest.mark.parametrize("change", ["parent_swap", "ancestor_symlink", "directory_mode"])
def test_pinned_directory_rechecks_selected_namespace(archived, monkeypatch, operation, change):
    original = module.decode_evidence if operation == "read" else archived._publish_bytes
    moved = False

    def mutate(*args, **kwargs):
        nonlocal moved
        result = original(*args, **kwargs)
        if moved:
            return result
        moved = True
        if change == "directory_mode":
            (archived.root / "objects").chmod(0o755)
        elif change == "ancestor_symlink":
            previous = archived.root.with_name("old-archive")
            archived.root.rename(previous)
            archived.root.symlink_to(previous, target_is_directory=True)
        else:
            objects = archived.root / "objects"
            objects.rename(archived.root / "old-objects")
            objects.mkdir(mode=0o700)
        return result

    if operation == "read":
        monkeypatch.setattr(module, "decode_evidence", mutate)
        with pytest.raises((OSError, ValueError)):
            archived.read("history", KEY, bounds={"proof": len(RAW)})
    else:
        monkeypatch.setattr(archived, "_publish_bytes", mutate)
        with pytest.raises((OSError, ValueError)):
            archived.write("history", "b" * 64, context={}, fields={"proof": b"new-value"})
        # No completed frame can name bytes published under a different namespace.
        if change != "ancestor_symlink":
            assert not (archived.root / "history" / ("b" * 64 + ".json")).exists()


@pytest.mark.parametrize("operation", ["read", "write"])
def test_pinned_directory_descriptor_closes_on_failures(archived, monkeypatch, operation):
    opened = []
    original = module._ObjectDirectory.__init__

    def capture(directory, path):
        original(directory, path)
        opened.append(directory.fd)

    def fail(*args, **kwargs):
        raise ValueError("injected codec failure")

    monkeypatch.setattr(module._ObjectDirectory, "__init__", capture)
    if operation == "read":
        monkeypatch.setattr(module, "decode_evidence", fail)
        with pytest.raises(ValueError, match="injected"):
            archived.read("history", KEY, bounds={"proof": len(RAW)})
    else:
        monkeypatch.setattr(module, "encode_evidence", fail)
        with pytest.raises(ValueError, match="injected"):
            archived.write("history", "b" * 64, context={}, fields={"proof": RAW})
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])


def test_failed_directory_constructor_closes_descriptor(archived, monkeypatch):
    opened = []
    original = module.os.open

    def capture(*args, **kwargs):
        fd = original(*args, **kwargs)
        opened.append(fd)
        return fd

    monkeypatch.setattr(module.os, "open", capture)
    monkeypatch.setattr(module._ObjectDirectory, "unchanged", lambda _: False)
    with pytest.raises(ValueError, match="while opening"):
        module._ObjectDirectory(archived.root / "objects")
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])


def test_single_use_warm_receipt_rechecks_changed_directory(archived, monkeypatch):
    archive = RewardProofArchive(archived.root.parent / "single")
    archive.write("history", KEY, context={}, fields={"proof": b"single-object"})
    archive.read("history", KEY, bounds={"proof": 100})
    original = module.decode_evidence

    def mutate(*args, **kwargs):
        result = original(*args, **kwargs)
        objects = archive.root / "objects"
        objects.rename(archive.root / "old-objects")
        objects.mkdir(mode=0o700)
        return result

    monkeypatch.setattr(module, "decode_evidence", mutate)
    with pytest.raises((OSError, ValueError)):
        archive.read("history", KEY, bounds={"proof": 100})


def test_context_only_frames_do_not_create_object_directory(tmp_path):
    archive = RewardProofArchive(tmp_path / "archive")
    archive.write("interval", KEY, context={"block": 1}, fields={})
    assert archive.read("interval", KEY, bounds={}) == ({"block": 1}, {})
    assert not (archive.root / "objects").exists()


def test_forked_scope_does_not_reuse_pinned_descriptor(archived, monkeypatch):
    with archived._directory_scope() as directory:
        scope = _FrameRead(archived, directory)
        sha = archived._retain_bytes(b"original")
        assert scope.resolve(sha, 100) == b"original"
        monkeypatch.setattr(module.os, "getpid", lambda: archived._pid + 1)
        path = archived.root / "objects" / (sha + ".json")
        path.write_bytes(canonical_json_bytes({"hex": b"modified".hex()}))
        with archived._read_lock:
            with pytest.raises(ValueError):
                scope.resolve(sha, 100)
            with pytest.raises(ValueError):
                scope.finish()


@pytest.mark.parametrize("operation", ["read", "publish"])
def test_cold_receipt_cannot_bind_other_directory_content(archived, monkeypatch, operation):
    """A path-based cold I/O must never authenticate a held directory's inode."""
    raw = b"original"
    sha = archived._retain_bytes(raw)
    objects = archived.root / "objects"
    path = objects / (sha + ".json")
    path.write_bytes(canonical_json_bytes({"hex": b"modified".hex()}))
    archived._published.clear()
    archived._read_objects.clear()
    archived._read_bytes = 0
    moved = False
    original = archived._read_object if operation == "read" else archived._publish_bytes

    def swap_before_cold_io(*args, **kwargs):
        nonlocal moved
        if not moved:
            moved = True
            objects.rename(archived.root / "old-objects")
            objects.mkdir(mode=0o700)
            if operation == "read":
                path.write_bytes(canonical_json_bytes({"hex": raw.hex()}))
                path.chmod(0o600)
        return original(*args, **kwargs)

    monkeypatch.setattr(
        archived, "_read_object" if operation == "read" else "_publish_bytes", swap_before_cold_io
    )
    with archived._directory_scope() as directory:
        if operation == "read":
            scope = _FrameRead(archived, directory)
            assert scope.resolve(sha, 100) == raw
            scope.finish()
        else:
            assert archived._retain_bytes(raw, directory=directory) == sha
            assert not directory.unchanged()
    # Restore the old corrupt inode. Its stamp was observed through the held
    # descriptor but its bytes were never verified/published by the cold I/O.
    objects.rename(archived.root / "new-objects")
    (archived.root / "old-objects").rename(objects)
    with pytest.raises(ValueError):
        if operation == "read":
            archived._bytes(sha, 100)
        else:
            archived._retain_bytes(raw)
