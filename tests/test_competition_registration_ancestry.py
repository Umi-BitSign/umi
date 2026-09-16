"""Skipped registration roots are proved from an owned finalized descendant."""

import asyncio
import json
import sqlite3
from dataclasses import replace

import pytest

from umi.competition_execution import execution_boundary, registration_boundary
from umi.open_competition import digest

from .test_finalized_ancestry import chain as chain
from .test_finalized_ancestry import chain_config as chain_config
from .test_finalized_ancestry import policy as policy
from .test_finalized_ancestry import recovery as recovery


@pytest.fixture
def skipped(recovery, monkeypatch):
    async def absent(height):
        return None

    monkeypatch.setattr(recovery.source._finality, "verified_identity_at", absent, raising=False)
    return recovery


async def test_skipped_snapshot_proves_membership_and_retains_actual_derivation(skipped):
    source, height = skipped.source, skipped.first + 1
    capture = await source.collect_at(height)
    assert capture.snapshot.block == height
    assert capture.snapshot.block_hash == skipped.by_height[height]
    assert len(capture.snapshot.registrations) == 2
    assert skipped.state.roots == [bytes.fromhex(capture.provenance["state_root"][2:])] * 3
    assert capture.provenance["evidence_class"] == "verified_finalized_ancestry"
    assert capture.provenance["timestamp_ms"] == skipped.anchor.timestamp_ms - 36_000
    assert capture.provenance["chain_submission_authorized"] is False
    with sqlite3.connect(source._path) as db:
        evidence = json.loads(db.execute("SELECT evidence FROM captures").fetchone()[0])
        assert db.execute("SELECT block FROM observed_head").fetchone()[0] == skipped.anchor.height
    finality = evidence["finality"]
    assert finality["anchor_sha256"] == skipped.anchor.finality_evidence_sha256
    assert finality["snapshot"]["block_hash"] == capture.snapshot.block_hash
    assert len(finality["headers"]) == 3
    assert capture.provenance["finality_evidence_sha256"] == digest(finality)
    assert "accepted_at_unix_ms" not in finality
    assert await source._finality.verified_block_at(height) is None
    assert registration_boundary(capture).source == "verified_finalized_ancestry"
    with pytest.raises(ValueError):
        execution_boundary(capture)
    # Original current observations retain their existing execution boundary.
    assert execution_boundary(await source.collect()).source == "verifier_attested_finality"
    assert "chain_getFinalizedHead" not in skipped.state.calls


@pytest.mark.parametrize(
    "mode", ["header", "proof", "timestamp", "stale", "old_target", "unowned", "capacity"]
)
async def test_recovered_snapshot_does_not_relax_verification(skipped, mode):
    source, height = skipped.source, skipped.first + 1
    if mode == "header":
        skipped.headers[skipped.by_height[height]]["stateRoot"] = "0x" + "ff" * 32
    elif mode == "proof":
        skipped.state.bad_proof = True
    elif mode == "timestamp":
        skipped.state.bad_timestamp = True
    elif mode == "stale":
        skipped.chain.clock.now += 121_000
    elif mode == "old_target":
        skipped.chain.clock.now += 85_000  # Fresh anchor, stale target.
    elif mode == "unowned":
        source._owned = False
    else:
        source.config = source.config.model_copy(update={"maximum_cache_bytes": 1})
    with pytest.raises((ValueError, RuntimeError)):
        await source.collect_at(height)
    with sqlite3.connect(source._path) as db:
        assert db.execute("SELECT count(*) FROM captures").fetchone()[0] == 0


@pytest.mark.parametrize("mode", ["absent", "future", "policy", "verifier", "chain", "evidence"])
async def test_recovery_requires_owned_bound_anchor(skipped, monkeypatch, mode):
    anchor = skipped.anchor
    if mode == "absent":
        anchor = None
    elif mode == "future":
        anchor = replace(anchor, height=anchor.height + 1)
    elif mode == "policy":
        anchor = replace(anchor, scoring_policy_hash="ff" * 32)
    elif mode == "verifier":
        anchor = replace(anchor, finality_verifier_sha256="ff" * 32)
    elif mode == "chain":
        anchor = replace(
            anchor,
            chain_observation=anchor.chain_observation.model_copy(
                update={"runtime_spec_version": 123}
            ),
        )
    else:
        anchor = replace(anchor, state_root="0x" + "ff" * 32)

    async def changed(*args, **kwargs):
        return anchor

    monkeypatch.setattr(skipped.source._finality, "verified_block_after", changed)
    with pytest.raises(ValueError):
        await skipped.source.collect_at(skipped.first + 1)
    assert not skipped.state.roots


async def test_cached_headers_never_replace_timestamp_and_membership_proofs(skipped):
    height = skipped.first + 1
    await skipped.source.collect_at(height)
    assert skipped.source._registration_ancestry_headers._headers
    skipped.state.bad_proof = True
    with pytest.raises(RuntimeError):
        await skipped.source.collect_at(height)


async def test_ancestry_does_not_bypass_runtime_binding(skipped, monkeypatch):
    original = skipped.source._registration_rpc.request

    async def changed(method, params):
        if method == "state_getMetadata":
            return "0x" + b"unapproved metadata".hex()
        return await original(method, params)

    monkeypatch.setattr(skipped.source._registration_rpc, "request", changed)
    with pytest.raises((ValueError, RuntimeError)):
        await skipped.source.collect_at(skipped.first + 1)
    assert not skipped.state.roots


async def test_recovery_timeout_leaves_no_partial_capture(skipped, monkeypatch):
    closed = asyncio.Event()

    async def stalled(*args):
        try:
            await asyncio.Event().wait()
        finally:
            closed.set()

    monkeypatch.setattr(skipped.source._registration_rpc, "request", stalled)
    skipped.source.config = skipped.source.config.model_copy(
        update={"collection_timeout_seconds": 0.01}
    )
    with pytest.raises(ValueError, match="timed out"):
        await skipped.source.collect_at(skipped.first + 1)
    assert closed.is_set()
    with sqlite3.connect(skipped.source._path) as db:
        assert db.execute("SELECT count(*) FROM captures").fetchone()[0] == 0
