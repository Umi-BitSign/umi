"""Portable byte transport is bounded and confers no native proof authority."""

import hashlib
import json

import pytest
import rfc8785

from umi.competition_reward_proof_archive import RewardProofArchive, history_archive_key
from umi.protocol import canonical_json_bytes


def test_large_object_publication_reuses_serialization_but_rereads_current_file(
    tmp_path, monkeypatch
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
    assert len(calls) == 2  # One canonical serialization per operation.
    assert path.stat().st_ino == before.st_ino
    path.write_bytes(b'{"hex":"00"}')
    with pytest.raises(ValueError, match="different bytes"):
        archive._retain_bytes(raw)


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
