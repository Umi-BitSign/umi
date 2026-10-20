"""R2 request count changes preserve original bytes, recipes and repair fences."""

import hashlib

import pytest

from umi.competition_evidence_codec import (
    MAX_METADATA_BYTES,
    decode_evidence,
    encode_evidence,
    encode_evidence_for_reuse,
    prepare_evidence_with_recipe,
)
from umi.competition_remote_proof_store import RemoteProofStore
from umi.competition_reward_proof_archive import RewardProofArchive
from umi.protocol import canonical_json_bytes

from .test_competition_remote_proof_store import EvidenceServer, config, store


def payload():
    return canonical_json_bytes(
        [
            {"index": i, "hash": "0x" + hashlib.sha256(str(i).encode()).hexdigest() * 16}
            for i in range(256)
        ]
    )


@pytest.mark.parametrize("single", [False, True])
def test_old_decoder_accepts_both_representations_and_original_hash(single):
    raw = payload()
    encoded = encode_evidence(raw, kind="proof", single_object=single)
    assert encoded.sha256 == hashlib.sha256(raw).hexdigest()
    assert (
        decode_evidence(
            encoded.recipe,
            sha256=encoded.sha256,
            expanded_bytes=len(raw),
            kind="proof",
            resolve=lambda sha, size: encoded.objects[sha],
        )
        == raw
    )
    assert (len(encoded.objects) == 1) if single else (len(encoded.objects) > 64)
    prepared = prepare_evidence_with_recipe(raw, encoded.recipe, kind="proof")
    assert prepared.for_bytes(raw, kind="proof") == encoded


def test_retained_decoder_valid_recipe_is_preserved_without_external_payload_reads():
    raw = b"abcdefghabcdefgh"
    part = b"abcdefgh"
    sha = hashlib.sha256(part).hexdigest()
    recipe = canonical_json_bytes(
        {
            "schema": "umi-weight-evidence-recipe/1",
            "length": len(raw),
            "segments": [["b", sha, 8], ["b", sha, 8]],
        }
    )
    restored = prepare_evidence_with_recipe(raw, recipe, kind="proof")
    assert restored.recipe == recipe and restored.objects == ((sha, part),)
    with pytest.raises(ValueError, match="differs"):
        prepare_evidence_with_recipe(raw[:-1] + b"X", recipe, kind="proof")


def test_flat_encoding_preserves_original_kind_bounds_and_issuer_binding():
    with pytest.raises(ValueError):
        encode_evidence(b"x" * (MAX_METADATA_BYTES + 1), kind="metadata", single_object=True)
    with pytest.raises(ValueError):
        encode_evidence(b"x", kind="proof", single_object=1)
    prepared = encode_evidence_for_reuse(payload(), kind="proof", single_object=True)
    assert not prepared.canonical_encoder
    with pytest.raises(ValueError):
        prepared.for_bytes(payload() + b"x", kind="proof")


def test_remote_fresh_frame_uses_three_objects_and_survives_restart_old_encoder(tmp_path):
    server = EvidenceServer()
    remote = store(tmp_path / "index", server)
    archive = RewardProofArchive(tmp_path / "archive", remote=remote, legacy_read_through=True)
    raw = payload()
    archive.write("history", "a" * 64, context={}, fields={"evidence": raw})
    assert len(server.objects) == 3  # Original bytes, existing /1 recipe, frame.
    original = dict(server.objects)
    server.calls.clear()
    remote = store(tmp_path / "index", server)
    restarted = RewardProofArchive(tmp_path / "archive", remote=remote, legacy_read_through=True)
    restarted.write(
        "history",
        "a" * 64,
        context={},
        fields={"evidence": raw},
        prepared_encodings={"evidence": (encode_evidence_for_reuse(raw, kind="proof"),)},
    )
    assert server.objects == original
    assert not any(method == "PUT" for method, _ in server.calls)
    assert restarted.read("history", "a" * 64, bounds={"evidence": len(raw)})[1]["evidence"] == raw


def test_compact_remote_restart_uses_durable_receipts_without_resolving_payload(tmp_path):
    server = EvidenceServer()
    remote = store(tmp_path / "index", server)
    raw = payload()
    encoded = encode_evidence(raw, kind="proof")
    fields = {"evidence": ((encoded.sha256, len(raw), encoded.recipe),)}
    archive = RewardProofArchive(tmp_path / "archive", remote=remote)
    assert archive.copy_encoded_transport(
        "history",
        "a" * 64,
        context={},
        fields=fields,
        resolve=lambda sha, size: encoded.objects[sha],
    )
    remote = store(tmp_path / "index", server)
    restarted = RewardProofArchive(tmp_path / "archive", remote=remote)
    server.calls.clear()

    def forbidden(*unused):
        pytest.fail("completed remote transport must not reread source payloads")

    assert restarted.copy_encoded_transport(
        "history", "a" * 64, context={}, fields=fields, resolve=forbidden
    )
    assert not any(method == "PUT" for method, _ in server.calls)


def test_new_publication_readback_reuses_bounded_original_bytes(tmp_path):
    server = EvidenceServer()
    remote = store(tmp_path / "index", server)
    reference = remote.put_bytes(b"original")
    server.calls.clear()
    assert remote.read_bytes(reference, maximum=8) == b"original"
    assert server.calls == [] and remote._bytes == 8
    assert remote.evict_cache() == 8
    assert remote.read_bytes(reference, maximum=8) == b"original"
    assert [method for method, _ in server.calls] == ["HEAD", "GET"]


def test_pinned_cache_pressure_does_not_reject_a_durable_new_publication(tmp_path):
    server = EvidenceServer()
    selected = config(tmp_path).model_copy(update={"maximum_cache_bytes": 8})
    remote = RemoteProofStore(tmp_path / "index", selected, client=server.client())
    first = remote.put_bytes(b"12345678")
    with remote.pin(first, maximum=8):
        second = remote.put_bytes(b"abcdefgh")
        assert remote.validate_reference(second).size_bytes == 8
        assert remote._bytes == 8
        with pytest.raises(OSError, match="active leases"):
            remote.read_bytes(second, maximum=8)
    assert remote.read_bytes(second, maximum=8) == b"abcdefgh"
