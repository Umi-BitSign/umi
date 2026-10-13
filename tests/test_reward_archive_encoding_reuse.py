"""Export reuses only an actually checked exact byte representation."""

import hashlib
from dataclasses import replace

import pytest

from umi import competition_reward_proof_archive as archive_module
from umi.competition_evidence_codec import (
    PreparedEvidenceEncoding,
    decode_evidence_for_reuse,
    encode_evidence,
    encode_evidence_for_reuse,
)
from umi.competition_reward_proof_archive import RewardProofArchive
from umi.protocol import canonical_json_bytes

RAW = b'{"code":"0x' + b"ab" * 4096 + b'","block":123}'
KEY = "1" * 64


def _decode(encoded):
    return decode_evidence_for_reuse(
        encoded.recipe,
        sha256=encoded.sha256,
        expanded_bytes=encoded.expanded_bytes,
        kind="proof",
        resolve=lambda key, size: encoded.objects[key],
    )


def test_capture_can_publish_same_original_bytes_without_second_encoding(tmp_path, monkeypatch):
    prepared = encode_evidence_for_reuse(RAW, kind="proof")
    monkeypatch.setattr(
        archive_module, "encode_evidence", lambda *_a, **_kw: pytest.fail("encoded twice")
    )
    archive = RewardProofArchive(tmp_path / "export")
    archive.write(
        "history",
        KEY,
        context={"block": 123},
        fields={"proof": RAW},
        prepared_encodings={"proof": (prepared,)},
    )
    assert archive.read("history", KEY, bounds={"proof": len(RAW)}) == (
        {"block": 123},
        {"proof": RAW},
    )


def test_retained_decode_and_repeat_export_keep_original_frame_bytes(tmp_path, monkeypatch):
    archive = RewardProofArchive(tmp_path / "export")
    archive.write("history", KEY, context={}, fields={"proof": RAW})
    frame = archive.root / "history" / (KEY + ".json")
    original = frame.read_bytes()
    prepared = _decode(encode_evidence(RAW, kind="proof"))
    monkeypatch.setattr(
        archive_module,
        "encode_evidence",
        lambda *_a, **_kw: pytest.fail("reencoded retained recipe"),
    )
    reopened = RewardProofArchive(archive.root)
    reopened.write(
        "history", KEY, context={}, fields={"proof": RAW}, prepared_encodings={"proof": (prepared,)}
    )
    assert frame.read_bytes() == original


@pytest.mark.parametrize("published", [False, True])
def test_valid_legacy_alternate_recipe_uses_current_encoder_for_compatibility(
    tmp_path, monkeypatch, published
):
    archive = RewardProofArchive(tmp_path / "export")
    if published:
        archive.write("history", KEY, context={}, fields={"proof": RAW})
    digest = hashlib.sha256(RAW).hexdigest()
    recipe = canonical_json_bytes(
        {
            "schema": "umi-weight-evidence-recipe/1",
            "length": len(RAW),
            "segments": [["b", digest, len(RAW)]],
        }
    )
    prepared = decode_evidence_for_reuse(
        recipe,
        sha256=digest,
        expanded_bytes=len(RAW),
        kind="proof",
        resolve=lambda _key, _size: RAW,
    )
    called = []

    def original(raw, *, kind):
        called.append(True)
        return encode_evidence(raw, kind=kind)

    monkeypatch.setattr(archive_module, "encode_evidence", original)
    archive.write(
        "history", KEY, context={}, fields={"proof": RAW}, prepared_encodings={"proof": (prepared,)}
    )
    assert len(called) == 1
    assert archive.read("history", KEY, bounds={"proof": len(RAW)})[1]["proof"] == RAW


def test_prepared_export_still_detects_corrupt_stored_objects(tmp_path):
    prepared = encode_evidence_for_reuse(RAW, kind="proof")
    archive = RewardProofArchive(tmp_path / "export")
    archive.write(
        "history", KEY, context={}, fields={"proof": RAW}, prepared_encodings={"proof": (prepared,)}
    )
    key = prepared.objects[0][0]
    path = archive.root / "objects" / (key + ".json")
    path.write_bytes(b'{"hex":"00"}')
    with pytest.raises(ValueError, match="different bytes"):
        RewardProofArchive(archive.root).write(
            "history",
            KEY,
            context={},
            fields={"proof": RAW},
            prepared_encodings={"proof": (prepared,)},
        )


@pytest.mark.parametrize(
    "change", ["raw", "kind", "recipe", "objects", "canonical_encoder", "issuer"]
)
def test_prepared_encoding_cannot_be_rebound_without_another_codec_pass(change):
    prepared = _decode(encode_evidence(RAW, kind="proof"))
    fields = {
        "raw": b"different",
        "kind": "metadata",
        "recipe": b"{}",
        "objects": (),
        "canonical_encoder": True,
        "issuer": None,
    }
    changed = replace(prepared, **{("_issuer" if change == "issuer" else change): fields[change]})
    with pytest.raises(ValueError, match="decoded original"):
        changed.for_bytes(changed.raw, kind=changed.kind)
    with pytest.raises(ValueError, match="decoded original"):
        prepared.for_bytes(b"changed", kind="proof")


def test_unissued_encoding_is_not_accepted():
    with pytest.raises(ValueError, match="decoded original"):
        PreparedEvidenceEncoding(RAW, "proof", "0" * 64, b"{}", ()).for_bytes(RAW, kind="proof")


def test_decoded_reuse_still_rejects_bad_original_object_hash():
    encoded = encode_evidence(RAW, kind="proof")
    with pytest.raises(ValueError, match="digest changed"):
        decode_evidence_for_reuse(
            encoded.recipe,
            sha256=encoded.sha256,
            expanded_bytes=encoded.expanded_bytes,
            kind="proof",
            resolve=lambda key, size: b"x" * size,
        )
