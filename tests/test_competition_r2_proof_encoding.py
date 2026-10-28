"""R2 request count changes preserve original bytes, recipes and repair fences."""

import hashlib
import json
from dataclasses import replace

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
from .test_competition_reward_history import chain as chain
from .test_competition_reward_history import chain_config as chain_config
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import history_case as history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case


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


def test_prepared_coalesced_selection_reuses_codec_digest_without_scanning(monkeypatch):
    from umi import competition_evidence_codec as codec

    raw = payload()
    prepared = encode_evidence_for_reuse(raw, kind="proof")
    expected = encode_evidence(raw, kind="proof", single_object=True)

    def forbidden(*args, **kwargs):
        pytest.fail("prepared literal selection repeated payload hashing or encoding")

    monkeypatch.setattr(codec.hashlib, "sha256", forbidden)
    monkeypatch.setattr(codec, "encode_evidence", forbidden)
    assert prepared.for_bytes(raw, kind="proof", coalesce_small=True) == expected
    for changed in (
        replace(prepared, sha256="0" * 64),
        replace(prepared, raw=b"changed"),
        replace(prepared, _issuer=None),
    ):
        with pytest.raises(ValueError, match="decoded original"):
            changed.for_bytes(changed.raw, kind="proof", coalesce_small=True)
    with pytest.raises(ValueError, match="explicit"):
        prepared.for_bytes(raw, kind="proof", coalesce_small=1)


@pytest.mark.parametrize("existing", [None, "compact", "literal"])
def test_prepared_fresh_remote_is_literal_but_retains_existing_exact_frame(tmp_path, existing):
    server = EvidenceServer()
    remote = store(tmp_path / "index", server)
    archive = RewardProofArchive(tmp_path / "archive", remote=remote)
    raw = payload()
    encoded = encode_evidence(raw, kind="proof", single_object=existing == "literal")
    if existing is not None:
        assert archive.copy_encoded_transport(
            "history",
            "b" * 64,
            context={},
            fields={"evidence": ((encoded.sha256, len(raw), encoded.recipe),)},
            resolve=lambda sha, size: encoded.objects[sha],
        )
    originals = dict(server.objects)
    server.calls.clear()
    archive = RewardProofArchive(tmp_path / "archive", remote=store(tmp_path / "index", server))
    prepared = encode_evidence_for_reuse(raw, kind="proof")
    original_recipe = prepared.recipe
    archive.write(
        "history",
        "b" * 64,
        context={},
        fields={"evidence": raw},
        prepared_encodings={"evidence": (prepared,)},
    )
    assert prepared.recipe == original_recipe
    if existing is None:
        assert len(server.objects) == 3
    else:
        assert server.objects == originals
        assert not any(method == "PUT" for method, _ in server.calls)
    assert archive.read("history", "b" * 64, bounds={"evidence": len(raw)})[1] == {"evidence": raw}


def geometry_comparison(tmp_path, frames, *, modes=("retained_compact", "prepared_coalesced")):
    """Record request/byte costs, not a synthetic estimate of network throughput."""
    result = {}
    for mode in modes:
        server = EvidenceServer()
        remote = store(tmp_path / mode / "index", server)
        archive = RewardProofArchive(tmp_path / mode / "archive", remote=remote)
        costs = []
        for index, fields in enumerate(frames):
            encoded = {name: encode_evidence(raw, kind="proof") for name, raw in fields.items()}
            before = sum(map(len, server.objects.values()))
            server.calls.clear()
            if mode == "retained_compact":
                objects = {
                    sha: value for item in encoded.values() for sha, value in item.objects.items()
                }
                assert archive.copy_encoded_transport(
                    "history",
                    f"{index:064x}",
                    context={},
                    fields={
                        name: ((item.sha256, len(fields[name]), item.recipe),)
                        for name, item in encoded.items()
                    },
                    resolve=lambda sha, size, objects=objects: objects[sha],
                )
            else:
                archive.write(
                    "history",
                    f"{index:064x}",
                    context={},
                    fields=fields,
                    prepared_encodings={
                        name: (
                            prepare_evidence_with_recipe(fields[name], item.recipe, kind="proof"),
                        )
                        for name, item in encoded.items()
                    },
                )
            costs.append(
                {
                    "new_durable_bytes": sum(map(len, server.objects.values())) - before,
                    "put_requests": sum(method == "PUT" for method, _ in server.calls),
                    "head_requests": sum(method == "HEAD" for method, _ in server.calls),
                    "cache_bytes": remote._bytes,
                    "expanded_input_bytes": sum(map(len, fields.values())),
                }
            )
            assert remote._bytes <= remote.config.maximum_cache_bytes
            assert (
                archive.read(
                    "history",
                    f"{index:064x}",
                    bounds={name: len(raw) for name, raw in fields.items()},
                )[1]
                == fields
            )
        result[mode] = {
            "frames": costs,
            "total_durable_bytes": sum(map(len, server.objects.values())),
            "distinct_objects": len(server.objects),
        }
    return result


def test_consecutive_high_shared_frames_record_request_and_storage_tradeoff(
    tmp_path, record_property
):
    frames = []
    for n in range(3):
        proofs = json.loads(payload())
        for i in range(32):
            proofs[i]["hash"] = "0x" + hashlib.sha256(f"{n}-{i}".encode()).hexdigest() * 16
        frames.append(
            {
                "evidence": canonical_json_bytes(proofs),
                "metadata": b"shared-runtime-metadata" * 4096,
            }
        )
    costs = geometry_comparison(tmp_path, frames)
    record_property("geometry_costs", json.dumps(costs, sort_keys=True))
    compact = costs["retained_compact"]["frames"]
    literal = costs["prepared_coalesced"]["frames"]
    assert all(b["put_requests"] < a["put_requests"] for a, b in zip(compact, literal, strict=True))
    assert (
        costs["prepared_coalesced"]["total_durable_bytes"]
        > costs["retained_compact"]["total_durable_bytes"]
    )


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
async def test_native_history_fixture_records_geometry_cost(
    history_case, tmp_path, record_property
):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    frames = [h.reader._load(height) for height in range(h.old.height, h.end + 1)]
    costs = geometry_comparison(tmp_path, frames)
    record_property("native_history_geometry_costs", json.dumps(costs, sort_keys=True))
    assert all(
        frame["put_requests"] <= 2 * len(fields) + 1
        for frame, fields in zip(costs["prepared_coalesced"]["frames"], frames, strict=True)
    )


@pytest.mark.parametrize("layout", ["mixed", "adjacent_large", "only_large", "only_small"])
def test_coalescing_preserves_large_shared_objects_and_exact_original_order(layout, monkeypatch):
    from umi import competition_evidence_codec as codec

    large = b"shared-runtime-object" * 4096
    small = b"changing-node"
    items = {
        "mixed": [
            ("b", b"prefix"),
            ("x", small),
            ("x", large),
            ("x", large),
            ("b", b"tail"),
            ("x", small),
        ],
        "adjacent_large": [("x", large), ("b", large), ("x", large)],
        "only_large": [("x", large)],
        "only_small": [("b", b"prefix"), ("x", small), ("b", b"tail")],
    }[layout]
    objects = {hashlib.sha256(raw).hexdigest(): raw for _, raw in items}
    raw = b"".join(part.hex().encode() if mode == "x" else part for mode, part in items)
    recipe = canonical_json_bytes(
        {
            "schema": "umi-weight-evidence-recipe/1",
            "length": len(raw),
            "segments": [
                [mode, hashlib.sha256(part).hexdigest(), len(part)] for mode, part in items
            ],
        }
    )
    prepared = prepare_evidence_with_recipe(raw, recipe, kind="proof")
    large_sha = hashlib.sha256(large).hexdigest()
    hash_bytes = hashlib.sha256

    def no_large_rehash(value=b"", **kwargs):
        assert value is not dict(prepared.objects).get(large_sha)
        return hash_bytes(value, **kwargs)

    with monkeypatch.context() as context:
        context.setattr(codec.hashlib, "sha256", no_large_rehash)
        compact = prepared.for_bytes(raw, kind="proof", coalesce_small=True)
    assert compact.sha256 == prepared.sha256 and compact.expanded_bytes == len(raw)
    assert prepared.recipe == recipe and dict(prepared.objects) == objects
    if layout != "only_small":
        assert compact.objects[large_sha] is dict(prepared.objects)[large_sha]
    assert (
        decode_evidence(
            compact.recipe,
            sha256=compact.sha256,
            expanded_bytes=len(raw),
            kind="proof",
            resolve=lambda sha, size: compact.objects[sha],
        )
        == raw
    )
    assert len(json.loads(compact.recipe)["segments"]) <= len(items)


def test_embedded_shared_large_payload_keeps_storage_reuse(tmp_path, record_property):
    frames = []
    shared = (b"shared-runtime-object" * 8192).hex()
    for n in range(3):
        parts = json.loads(payload())
        for i in range(32):
            parts[i]["hash"] = "0x" + hashlib.sha256(f"{n}-{i}".encode()).hexdigest() * 16
        frames.append(
            {"evidence": canonical_json_bytes({"runtime": "0x" + shared, "proofs": parts})}
        )
    costs = geometry_comparison(tmp_path, frames)
    record_property("embedded_shared_geometry_costs", json.dumps(costs, sort_keys=True))
    compact = costs["retained_compact"]["frames"]
    coalesced = costs["prepared_coalesced"]["frames"]
    # A large embedded runtime is published once, independently of the changing
    # small proof nodes. Allow frame/recipe metadata, but require saving at
    # least the large binary object's size versus the full expanded field.
    assert all(
        frame["new_durable_bytes"] < len(frames[i]["evidence"]) - len(shared) // 2
        for i, frame in enumerate(coalesced)
        if i > 0
    )
    assert all(
        b["put_requests"] < a["put_requests"] for a, b in zip(compact, coalesced, strict=True)
    )


def test_prepared_multiple_chunks_keep_original_bounds_and_roundtrip(tmp_path):
    from umi.competition_evidence_codec import MAX_EVIDENCE_BYTES

    server = EvidenceServer()
    archive = RewardProofArchive(tmp_path / "archive", remote=store(tmp_path / "index", server))
    chunks = (b"a" * MAX_EVIDENCE_BYTES, payload())
    raw = b"".join(chunks)
    archive.write(
        "history",
        "c" * 64,
        context={},
        fields={"evidence": raw},
        prepared_encodings={
            "evidence": tuple(encode_evidence_for_reuse(chunk, kind="proof") for chunk in chunks)
        },
    )
    assert len(archive._frame("history", "c" * 64).fields["evidence"]) == 2
    assert archive.read("history", "c" * 64, bounds={"evidence": len(raw)})[1]["evidence"] == raw
    assert archive.remote._bytes <= archive.remote.config.maximum_cache_bytes


@pytest.mark.parametrize("failure", ["dependency", "frame_ack"])
def test_prepared_coalesced_interruption_preserves_barrier_and_original_retry(tmp_path, failure):
    import httpx

    class Server(EvidenceServer):
        lose_frame_ack = failure == "frame_ack"

        def send(self, request):
            if request.method == "PUT" and "/frames/" in request.url.path and self.lose_frame_ack:
                self.lose_frame_ack = False
                super().send(request)
                raise httpx.ReadError("lost frame acknowledgement")
            return super().send(request)

    server = Server()
    raw = payload()
    prepared = encode_evidence_for_reuse(raw, kind="proof")
    source_recipe = prepared.recipe
    source_objects = prepared.objects
    if failure == "dependency":
        server.fail_put_suffix = prepared.sha256
    kwargs = dict(
        context={}, fields={"evidence": raw}, prepared_encodings={"evidence": (prepared,)}
    )
    archive = RewardProofArchive(tmp_path / "archive", remote=store(tmp_path / "index", server))
    with pytest.raises(OSError):
        archive.write("history", "d" * 64, **kwargs)
    assert bool(any("/frames/" in key for key in server.objects)) == (failure == "frame_ack")
    assert not archive.remote._publishing_keys and archive.remote._publishing_bytes == 0
    retained = dict(server.objects)
    server.fail_put_suffix = None
    server.calls.clear()
    archive = RewardProofArchive(tmp_path / "archive", remote=store(tmp_path / "index", server))
    archive.write("history", "d" * 64, **kwargs)
    assert prepared.recipe == source_recipe and prepared.objects == source_objects
    assert not any(
        method == "PUT" and path.removeprefix("/umi-proof-artifacts/") in retained
        for method, path in server.calls
    )
    assert archive.read("history", "d" * 64, bounds={"evidence": len(raw)})[1] == {"evidence": raw}


def test_shared_medium_nodes_compare_geometry_thresholds(tmp_path, monkeypatch, record_property):
    from umi import competition_evidence_codec as codec

    shared = [
        "0x" + (hashlib.sha256(f"shared-{i}".encode()).digest() * 608).hex() for i in range(156)
    ]
    frames = []
    for n in range(3):
        changes = [
            "0x" + (hashlib.sha256(f"new-{n}-{i}".encode()).digest() * 6).hex() for i in range(38)
        ]
        frames.append(
            {"evidence": canonical_json_bytes({"runtime_nodes": shared, "proofs": changes})}
        )
    result = geometry_comparison(tmp_path / "old", frames, modes=("retained_compact",))
    for kib in (4, 8, 16, 64):
        with monkeypatch.context() as context:
            context.setattr(codec, "_MIN_REMOTE_OBJECT_BYTES", kib * 1024)
            result[str(kib) + "KiB"] = geometry_comparison(
                tmp_path / str(kib), frames, modes=("prepared_coalesced",)
            )["prepared_coalesced"]
    record_property("medium_shared_geometry_costs", json.dumps(result, sort_keys=True))
    old = result["retained_compact"]["frames"]
    selected = result["4KiB"]["frames"]
    assert all(
        new["put_requests"] < prior["put_requests"]
        for prior, new in zip(old, selected, strict=True)
    )
    assert all(new["new_durable_bytes"] < 64 * 1024 for new in selected[1:])
    assert all(
        result["64KiB"]["frames"][i]["new_durable_bytes"] > 100 * selected[i]["new_durable_bytes"]
        for i in (1, 2)
    )
