"""Native archive replay with synthetic chain, codec and proof-verifier ports."""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from contextlib import closing
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.chain_evidence import FinalizedSnapshotRef
from umi.competition_execution import execution_boundary
from umi.competition_historical_registration import HistoricalRegistrationProvider
from umi.finalized_ancestry import encode_rpc_header
from umi.protocol import canonical_json_bytes
from umi.validator_chain import FinalizedProofCollector, ProofCollectionLimits, ValidatorChainError

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_storage_codec import configured, version_bump
from .test_open_competition import policy as policy


def change_block(chain, height):
    header = {
        "number": hex(height),
        "parentHash": chain.finality.ref.parent_hash,
        "stateRoot": chain.finality.ref.state_root,
        "extrinsicsRoot": "0x" + "33" * 32,
        "digest": {"logs": []},
    }
    encoded = encode_rpc_header(header)
    block_hash = "0x" + hashlib.blake2b(bytes.fromhex(encoded[2:]), digest_size=32).hexdigest()
    chain.finality.ref = FinalizedSnapshotRef(
        height, block_hash, header["parentHash"], header["stateRoot"]
    )
    chain.finality.timestamp = chain.clock.now - 1000
    chain.rpc.values["Timestamp", "Now", ()] = chain.finality.timestamp
    return encoded


@pytest.fixture(params=["pinned_runtime", "reviewed_codec"])
async def archive(chain, request, tmp_path, monkeypatch):
    if request.param == "reviewed_codec":
        chain.config = configured(chain, tmp_path)
        version_bump(monkeypatch, chain.rpc)
        chain.provider = HistoricalRegistrationProvider(
            chain.config,
            chain.policy,
            finality=chain.finality,
            proofs=chain.proofs,
            now_ms=lambda: chain.clock.now,
        )
    encoded = change_block(chain, chain.finality.ref.block_number)
    old = await chain.finality.verified_block_at(chain.finality.ref.block_number)
    original = canonical_json_bytes(
        {
            **json.loads(old.finality_evidence),
            "block": {"scale_header": encoded},
            "request_id": "intake-observer",
        }
    )
    old = replace(
        old,
        finality_evidence=original,
        finality_evidence_sha256=hashlib.sha256(original).hexdigest(),
    )
    blocks = {old.height: old}

    async def at(height):
        return blocks.get(height)

    chain.finality.verified_block_at = at
    capture = await chain.provider.collect()
    expected = execution_boundary(capture)
    chain.clock.now += 4 * 60 * 60 * 1000
    encoded = change_block(chain, old.height + 1200)
    fresh_raw = canonical_json_bytes(
        {
            **json.loads(original),
            "block": {"scale_header": encoded},
            "request_id": "review-observer",
        }
    )
    fresh = replace(
        old,
        height=chain.finality.ref.block_number,
        block_hash=chain.finality.ref.block_hash,
        timestamp_ms=chain.finality.timestamp,
        finality_evidence=fresh_raw,
        finality_evidence_sha256=hashlib.sha256(fresh_raw).hexdigest(),
    )
    blocks[fresh.height] = fresh
    reviewer = HistoricalRegistrationProvider(
        chain.config,
        chain.policy,
        finality=chain.finality,
        proofs=chain.proofs,
        now_ms=lambda: chain.clock.now,
        retained_capture_blocks=lambda: frozenset({old.height}),
    )
    raw, metadata = reviewer._retained_archive(expected)
    return SimpleNamespace(
        chain=chain,
        blocks=blocks,
        old=old,
        fresh=fresh,
        capture=capture,
        expected=expected,
        reviewer=reviewer,
        raw=raw,
        metadata=metadata,
    )


async def test_four_hour_outage_replays_exact_old_membership_without_old_rpc(archive):
    a = archive
    before = len(a.chain.rpc.calls)
    checked = len(a.chain.verifier.checked)
    result = await a.reviewer.review_retained(a.expected)
    assert result.snapshot == a.capture.snapshot
    assert result.original == a.expected
    assert result.replayed_at == a.chain.finality.ref
    assert len(a.chain.verifier.checked) == checked + 3
    assert a.chain.rpc.calls[before:] == [
        ("chain_getHeader", (a.fresh.block_hash,)),
        ("chain_getBlockHash", (a.fresh.height,)),
    ]
    assert not hasattr(result, "provenance")
    with pytest.raises(AttributeError):
        execution_boundary(result)
    with pytest.raises(ValueError, match=r"stale|outside"):
        await a.reviewer.collect_at(a.old.height)
    fresh = await a.reviewer.collect()
    assert fresh.snapshot.block == a.fresh.height
    # A normal fresh capture/prune still preserves accepted original evidence.
    assert (await a.reviewer.review_retained(a.expected)).snapshot == result.snapshot


async def test_independent_observer_receipts_can_differ_for_the_same_header(archive):
    a = archive
    raw = canonical_json_bytes(
        {**json.loads(a.old.finality_evidence), "request_id": "independent-peer"}
    )
    a.blocks[a.old.height] = replace(
        a.old, finality_evidence=raw, finality_evidence_sha256=hashlib.sha256(raw).hexdigest()
    )
    assert (
        await a.reviewer.review_archive(a.expected, a.raw, a.metadata)
    ).snapshot == a.capture.snapshot


@pytest.mark.parametrize(
    "failure",
    [
        "missing_header",
        "stale_head",
        "stopped",
        "rollback",
        "wrong_header",
        "wrong_policy",
        "future_original",
    ],
)
async def test_owned_finality_is_required_even_with_complete_archive(archive, failure):
    a = archive
    if failure == "missing_header":
        del a.blocks[a.old.height]
    elif failure == "stale_head":
        a.chain.clock.now += 180_000
    elif failure == "stopped":
        a.reviewer._owned = True
        a.reviewer._task = SimpleNamespace(done=lambda: True)
    elif failure == "rollback":
        with closing(a.reviewer._connect()) as db:
            db.execute("UPDATE observed_head SET block=?", (a.fresh.height + 1,))
    elif failure == "wrong_header":
        a.blocks[a.old.height] = replace(a.old, block_hash="0x" + "ab" * 32)
    elif failure == "wrong_policy":
        a.blocks[a.old.height] = replace(a.old, scoring_policy_hash="ab" * 32)
    elif failure == "future_original":
        a.blocks[a.old.height] = replace(a.old, timestamp_ms=a.fresh.timestamp_ms + 1)
    with pytest.raises(FileNotFoundError if failure == "missing_header" else ValueError):
        await a.reviewer.review_retained(a.expected)


@pytest.mark.parametrize(
    "failure",
    [
        "proof",
        "timestamp",
        "snapshot",
        "state_root",
        "omitted_claim",
        "duplicate_claim",
        "extra_claim",
        "extra_batch",
        "codec_mode",
        "metadata_pin",
        "finality",
        "noncanonical",
    ],
)
async def test_archive_claims_are_reproved_even_if_digest_is_bound(archive, failure):
    a = archive
    body = json.loads(a.raw)
    if failure == "proof":
        body["storage_batches"][0]["proof"] = ["0x626164"]
    elif failure == "timestamp":
        for c in body["storage_batches"][0]["claims"]:
            if json.loads(bytes.fromhex(c["key"][2:]))[:2] == ["Timestamp", "Now"]:
                c["value"] = "0x" + canonical_json_bytes(a.fresh.timestamp_ms).hex()
    elif failure == "snapshot":
        body["snapshot"]["registrations"][0]["uid"] = 4
    elif failure == "state_root":
        body["storage_batches"][0]["state_root"] = "0x" + "ab" * 32
    elif failure == "omitted_claim":
        body["storage_batches"][0]["claims"].pop()
    elif failure == "duplicate_claim":
        body["storage_batches"][1]["claims"].append(body["storage_batches"][0]["claims"][0])
    elif failure == "extra_claim":
        body["storage_batches"][0]["claims"].append({"key": "0xffff", "value": "0x00"})
    elif failure == "extra_batch":
        body["storage_batches"].append(body["storage_batches"][0])
    elif failure == "codec_mode":
        if "storage_codec_mode" in body:
            del body["storage_codec_mode"]
        else:
            body["storage_codec_mode"] = "reviewed_storage_codec/1"
    elif failure == "metadata_pin":
        body["runtime_metadata_sha256"] = "00" * 32
    elif failure == "finality":
        body["finality"]["block"]["scale_header"] = json.loads(a.fresh.finality_evidence)["block"][
            "scale_header"
        ]
    raw = canonical_json_bytes(body) + (b" " if failure == "noncanonical" else b"")
    expected = a.expected.model_copy(update={"evidence_sha256": hashlib.sha256(raw).hexdigest()})
    with pytest.raises((ValueError, ValidatorChainError)):
        await a.reviewer.review_archive(expected, raw, a.metadata)


@pytest.mark.parametrize(
    "failure",
    ["index", "missing_archive", "missing_metadata", "changed_metadata", "unbound_digest"],
)
async def test_retained_archive_is_exact_and_complete(archive, failure):
    a = archive
    with closing(a.reviewer._connect()) as db:
        if failure == "index":
            db.execute("UPDATE captures SET snapshot=?", ("00" * 32,))
        elif failure == "missing_archive":
            db.execute("DELETE FROM captures")
        elif failure == "missing_metadata":
            db.execute("DELETE FROM artifacts")
        elif failure == "changed_metadata":
            db.execute("UPDATE artifacts SET body=?", (b"wrong",))
        elif failure == "unbound_digest":
            db.execute("UPDATE captures SET evidence=?", (a.raw + b" ",))
    with pytest.raises((ValueError, FileNotFoundError)):
        await a.reviewer.review_retained(a.expected)


async def test_long_review_rechecks_freshness_and_monotonic_head(archive):
    a = archive
    check = a.chain.verifier.verify_many

    def slow(**kwargs):
        a.chain.clock.now += 180_000
        return check(**kwargs)

    a.chain.verifier.verify_many = slow
    with pytest.raises(ValueError, match="stale"):
        await a.reviewer.review_retained(a.expected)
    a.chain.clock.now = a.fresh.timestamp_ms + 1000

    def rollback(**kwargs):
        result = check(**kwargs)
        a.chain.finality.ref = replace(a.chain.finality.ref, block_number=a.old.height)
        return result

    a.chain.verifier.verify_many = rollback
    with pytest.raises(ValueError, match="rolled back"):
        await a.reviewer.review_retained(a.expected)


async def test_cancellation_drains_verifier_before_releasing_provider_lock(archive):
    a = archive
    entered, release = threading.Event(), threading.Event()
    original = a.chain.verifier.verify_many

    def wait(**kwargs):
        entered.set()
        assert release.wait(5)
        return original(**kwargs)

    a.chain.verifier.verify_many = wait
    task = asyncio.create_task(a.reviewer.review_retained(a.expected))
    try:
        for _ in range(1000):
            if entered.is_set():
                break
            if task.done():
                await task
            await asyncio.sleep(0.001)
        assert entered.is_set()
        task.cancel()
        await asyncio.sleep(0.02)
        assert not task.done() and a.reviewer._lock.locked()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not a.reviewer._lock.locked()
    a.chain.verifier.verify_many = original
    assert (await a.reviewer.review_retained(a.expected)).snapshot == a.capture.snapshot


async def test_replay_preserves_owned_proof_resource_limits(archive):
    a = archive
    a.reviewer._proofs = FinalizedProofCollector(
        a.chain.rpc,
        finality=a.chain.finality,
        verifier=a.chain.verifier,
        limits=ProofCollectionLimits(maximum_proof_node_bytes=1),
    )
    checked = len(a.chain.verifier.checked)
    with pytest.raises(ValidatorChainError, match="proof_node"):
        await a.reviewer.review_retained(a.expected)
    assert len(a.chain.verifier.checked) == checked


@pytest.mark.parametrize("field", ["raw", "metadata"])
async def test_review_rejects_oversized_archive_before_using_finality(archive, monkeypatch, field):
    a = archive
    module = "umi.competition_registration_archive"
    monkeypatch.setattr(
        module + (".MAX_ARCHIVE_BYTES" if field == "raw" else ".MAX_METADATA_BYTES"), 1
    )
    before = a.chain.finality.calls
    with pytest.raises(ValueError, match="byte bound"):
        await a.reviewer.review_archive(a.expected, a.raw, a.metadata)
    assert a.chain.finality.calls == before
