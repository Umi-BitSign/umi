"""Admission recovery through native journals with synthetic chain proof ports."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.chain_evidence import FinalizedSnapshotRef
from umi.finalized_ancestry import encode_rpc_header
from umi.grandpa_finality import _decode_header
from umi.historical_header_recovery import HistoricalHeaderRecovery, HistoricalHeaderRecoveryPending
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_cohort_admission_queue import relay as relay
from .test_competition_cohort_admission_queue import status, submit
from .test_competition_cohort_admission_review import accepted as accepted
from .test_competition_cohort_admission_signer import harness as harness
from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_historical_registration import archive as archive
from .test_open_competition import policy as policy


@pytest.fixture
def linked(archive, request):
    a = archive
    distance = 1200 if "four_hour" in request.node.name else 8
    decoded = _decode_header(
        json.loads(a.old.finality_evidence)["block"]["scale_header"], maximum_bytes=65536
    )
    headers = {
        a.old.block_hash: {
            "number": hex(a.old.height),
            "parentHash": decoded["parent_hash"],
            "stateRoot": a.old.state_root,
            "extrinsicsRoot": decoded["extrinsics_root"],
            "digest": {"logs": []},
        }
    }
    parent = a.old.block_hash
    for height in range(a.old.height + 1, a.old.height + distance + 1):
        header = {
            "number": hex(height),
            "parentHash": parent,
            "stateRoot": a.old.state_root,
            "extrinsicsRoot": decoded["extrinsics_root"],
            "digest": {"logs": []},
        }
        encoded = encode_rpc_header(header)
        current = "0x" + hashlib.blake2b(bytes.fromhex(encoded[2:]), digest_size=32).hexdigest()
        headers[current] = header
        parent = current
    raw = canonical_json_bytes(
        {**json.loads(a.fresh.finality_evidence), "block": {"scale_header": encoded}}
    )
    a.fresh = replace(
        a.fresh,
        height=height,
        block_hash=current,
        finality_evidence=raw,
        finality_evidence_sha256=hashlib.sha256(raw).hexdigest(),
    )
    a.chain.finality.ref = FinalizedSnapshotRef(
        height, current, header["parentHash"], a.old.state_root
    )
    a.blocks.clear()
    a.blocks[height] = a.fresh
    a.headers, a.header_calls = headers, []

    async def nearest(block, *, maximum_distance):
        assert block == a.old.height and maximum_distance is None
        return a.fresh

    async def rpc(method, params):
        assert method == "chain_getHeader"
        a.header_calls.append(params[0])
        return headers[params[0]]

    a.chain.finality.verified_block_after = nearest
    a.reviewer._registration_rpc = SimpleNamespace(request=rpc)
    a.reviewer._owned = True
    a.reviewer._startup_floor = a.fresh.height - 1
    a.reviewer._task = SimpleNamespace(done=lambda: False)
    a.reviewer._historical_headers.batch_size = 256 if distance == 1200 else 4
    return a


async def reviewed(a):
    for _ in range(30):
        try:
            return await a.reviewer.review_retained(a.expected)
        except HistoricalHeaderRecoveryPending:
            pass
    pytest.fail("header recovery did not converge")


async def test_four_hour_gap_restores_original_membership_without_forging_observer_record(linked):
    a = linked
    with pytest.raises(HistoricalHeaderRecoveryPending):
        await a.reviewer.review_retained(a.expected)
    a.reviewer._historical_headers = HistoricalHeaderRecovery(a.reviewer._connect)
    result = await reviewed(a)
    assert result.snapshot == a.capture.snapshot
    assert result.original == a.expected and result.replayed_at == a.chain.finality.ref
    assert len(a.header_calls) == len(set(a.header_calls)) == 1200
    assert await a.chain.finality.verified_block_at(a.old.height) is None
    # Recovered old membership never passes for a current execution observation.
    with pytest.raises(ValueError, match="stale"):
        await a.reviewer.collect_at(a.old.height)


@pytest.mark.parametrize(
    "mode", ["header", "anchor_policy", "anchor_future", "anchor_missing", "unowned", "stale"]
)
async def test_recovery_requires_matching_ancestry_and_owned_current_context(linked, mode):
    a = linked
    if mode == "header":
        a.headers[a.old.block_hash]["stateRoot"] = "0x" + "ff" * 32
    elif mode == "anchor_policy":
        a.fresh = replace(a.fresh, scoring_policy_hash="ff" * 32)
    elif mode == "anchor_future":
        a.fresh = replace(a.fresh, height=a.fresh.height + 1)
    elif mode == "anchor_missing":
        a.fresh = None
    elif mode == "unowned":
        a.reviewer._owned = False
    else:
        a.chain.clock.now += 180_000
    with pytest.raises((ValueError, FileNotFoundError)):
        await reviewed(a)


async def test_historical_target_timestamp_must_be_proven_before_its_owned_anchor(linked):
    a = linked
    a.fresh = replace(a.fresh, timestamp_ms=a.old.timestamp_ms - 1)
    with pytest.raises(ValueError, match="timestamp"):
        await reviewed(a)


async def test_four_hour_gap_completes_queued_admission_after_reviewer_restart(relay, linked):
    h, a = relay, linked
    await submit(h)
    first = await h.reviewer("Charlie").poll_once()
    assert first["retry_count"] == 1 and not h.calls
    a.reviewer._historical_headers = HistoricalHeaderRecovery(a.reviewer._connect)
    for _ in range(30):
        outcome = await h.reviewer("Charlie").poll_once()
        if outcome["votes_published"]:
            break
    assert outcome["votes_published"] == 1
    assert (await h.reviewer("Dave").poll_once())["certificates_published"] == 1
    assert (await status(h)).status == "admission_certified"
    assert len(h.calls) == 2 and len(a.header_calls) == 1200
