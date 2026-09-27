"""Real history/signature/archive consumers with synthetic chain and trie ports."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.chain_evidence import FinalizedSnapshotRef
from umi.competition_reward_control import (
    FinalizedRewardControlProvider,
    validate_owned_reward_control,
)
from umi.competition_reward_control_archive import (
    HistoricalRewardControlProvider,
    validate_historical_reward_control,
)
from umi.finalized_ancestry import encode_rpc_header
from umi.historical_header_recovery import HistoricalHeaderRecoveryPending
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.validator_chain import ValidatorChainError

from .test_competition_historical_registration import change_block
from .test_competition_reward_control import commitment
from .test_competition_reward_decisions import chain as chain
from .test_competition_reward_decisions import chain_config as chain_config
from .test_competition_reward_decisions import control as control
from .test_competition_reward_decisions import policy as policy
from .test_competition_reward_decisions import series_case as series_case
from .test_competition_storage_codec import configured, version_bump
from .test_finalized_ancestry import make_headers


@pytest.fixture(params=["exact_runtime", "reviewed_codec"])
async def historical(series_case, request, monkeypatch, tmp_path):
    return await make_historical(series_case, request.param, monkeypatch, tmp_path)


async def make_historical(series_case, mode, monkeypatch, tmp_path):
    c = series_case
    item = c.control
    await item.provider.aclose()
    if mode == "reviewed_codec":
        item.config = configured(item, tmp_path)
        version_bump(monkeypatch, item.rpc)

    def reopen():
        return HistoricalRewardControlProvider(
            item.config,
            item.policy,
            historical_header_directory=tmp_path / "control-history",
            finality=item.finality,
            proofs=item.proofs,
            now_ms=lambda: item.clock.now,
        )

    item.provider = reopen()
    c.reader = c.reopen()
    encoded = change_block(item, item.finality.ref.block_number)
    old = await item.finality.verified_block_at(item.finality.ref.block_number)
    evidence = canonical_json_bytes(
        {
            **json.loads(old.finality_evidence),
            "block": {"scale_header": encoded},
            "request_id": "series-admission-capture",
        }
    )
    old = replace(
        old,
        finality_evidence=evidence,
        finality_evidence_sha256=hashlib.sha256(evidence).hexdigest(),
    )
    blocks = {old.height: old}

    async def at(height):
        return blocks.get(height)

    item.finality.verified_block_at = at
    item.rpc.values[item.spec] = commitment(
        digest(c.genesis.decision), c.genesis.decision.observed_at_block
    )
    captured = await item.provider.collect_control(item.hotkey)

    def advance(distance=3000):
        item.clock.now += 10 * 60 * 60 * 1000
        encoded = change_block(item, item.finality.ref.block_number + distance)
        evidence = canonical_json_bytes(
            {
                **json.loads(old.finality_evidence),
                "block": {"scale_header": encoded},
                "request_id": "independent-review",
            }
        )
        fresh = replace(
            old,
            height=item.finality.ref.block_number,
            block_hash=item.finality.ref.block_hash,
            timestamp_ms=item.finality.timestamp,
            finality_evidence=evidence,
            finality_evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        )
        blocks[fresh.height] = fresh
        return fresh

    fresh = advance()
    return SimpleNamespace(
        c=c,
        item=item,
        old=old,
        fresh=fresh,
        blocks=blocks,
        raw=captured.evidence,
        metadata=captured.runtime.metadata_bytes,
        advance=advance,
        reopen=reopen,
    )


def check(h, observation):
    validate_historical_reward_control(
        observation,
        expected_control_hotkey=h.item.hotkey,
        expected_chain_config_sha256=digest(h.item.config),
    )


async def test_late_first_admission_uses_original_proof_and_fresh_control(historical):
    h = historical
    c, item = h.c, h.item
    before = len(item.rpc.calls)
    original = await item.provider.review_control(h.raw, h.metadata)
    check(h, original)
    assert original.committed_at_block == 160
    assert original.snapshot.block_number == h.old.height
    assert item.rpc.calls[before:] == [
        ("chain_getHeader", (h.fresh.block_hash,)),
        ("chain_getBlockHash", (h.fresh.height,)),
    ]
    with pytest.raises(ValueError):
        validate_owned_reward_control(
            original,
            expected_control_hotkey=item.hotkey,
            expected_chain_config_sha256=digest(item.config),
        )
    activation = c.decision(c.genesis, 5, observed=h.fresh.height - 1000)
    current = await c.observe(activation, block=h.fresh.height - 900)
    selected = c.reader.select_admitted(current, c.source, original)
    assert selected.selection.state == "selected"
    assert not selected.chain_submission_authorized
    retained = tuple(c.reader.journal.keys("reward_control_decision"))

    # Cold replay after another long outage. No current or old storage claims
    # come from the coordinator; the exact old admission remains usable.
    h.advance(1_000_000)
    await item.provider.aclose()
    item.provider = h.reopen()
    c.reader = c.reopen()
    replay = await c.reader.replay_admission(item.provider)
    current = await c.observe(activation, block=h.fresh.height - 900)
    resumed = c.reader.select_admitted(current, lambda _: None, replay)
    assert resumed.selection.decision_sha256 == selected.selection.decision_sha256
    assert tuple(c.reader.journal.keys("reward_control_decision")) == retained


async def test_old_owned_history_needs_no_wall_clock_renewal(historical):
    h = historical
    h.item.clock.now += 100_000_000
    proof = await h.item.provider.review_control(h.raw, h.metadata)
    check(h, proof)
    # That fact grants no fresh control or transaction preflight.
    with pytest.raises(ValueError, match="stale"):
        await h.item.provider.collect_control(h.item.hotkey)


@pytest.mark.parametrize(
    "failure",
    [
        "proof",
        "metadata",
        "metadata_digest",
        "header",
        "state_root",
        "timestamp",
        "control_digest",
        "committed_block",
        "claim_missing",
        "claim_repeated",
        "claim_extra",
        "genesis",
        "finality_class",
        "codec_mode",
        "runtime_version",
        "noncanonical",
    ],
)
async def test_untrusted_archive_cannot_create_admission(historical, failure):
    h = historical
    body = json.loads(h.raw)
    metadata = h.metadata
    if failure == "proof":
        body["proof"] = ["0x626164"]
    elif failure == "metadata":
        metadata += b"bad"
    elif failure == "metadata_digest":
        body["runtime_metadata_sha256"] = "ab" * 32
    elif failure == "header":
        body["finality"]["block"]["scale_header"] = json.loads(h.fresh.finality_evidence)["block"][
            "scale_header"
        ]
    elif failure == "state_root":
        body["state_root"] = "0x" + "ab" * 32
    elif failure == "timestamp":
        for claim in body["claims"]:
            if json.loads(bytes.fromhex(claim["key"][2:]))[:2] == ["Timestamp", "Now"]:
                claim["value"] = "0x" + canonical_json_bytes(h.fresh.timestamp_ms).hex()
    elif failure == "control_digest":
        body["control_sha256"] = "bb" * 32
    elif failure == "committed_block":
        body["committed_at_block"] += 1
    elif failure == "claim_missing":
        body["claims"].pop()
    elif failure == "claim_repeated":
        body["claims"][1] = body["claims"][0]
    elif failure == "claim_extra":
        body["claims"].append({"key": "0xffff", "value": "0x00"})
    elif failure == "genesis":
        body["finality"]["genesis_hash"] = "0x" + "ff" * 32
    elif failure == "finality_class":
        body["finality"]["evidence_class"] = "rpc_finalized"
    elif failure == "codec_mode":
        body["storage_codec_mode"] = "unknown"
    elif failure == "runtime_version":
        body["runtime_version"]["stateVersion"] = 2
    raw = canonical_json_bytes(body) + (b" " if failure == "noncanonical" else b"")
    with pytest.raises((ValueError, ValidatorChainError)):
        await h.item.provider.review_control(raw, metadata)


@pytest.mark.parametrize("failure", ["missing", "wrong_hash", "wrong_policy", "future_time"])
async def test_archive_still_needs_owned_historical_finality(historical, failure):
    h = historical
    if failure == "missing":
        del h.blocks[h.old.height]
    elif failure == "wrong_hash":
        h.blocks[h.old.height] = replace(h.old, block_hash="0x" + "ff" * 32)
    elif failure == "wrong_policy":
        h.blocks[h.old.height] = replace(h.old, scoring_policy_hash="ff" * 32)
    else:
        h.blocks[h.old.height] = replace(h.old, timestamp_ms=h.fresh.timestamp_ms + 1)
    with pytest.raises(FileNotFoundError if failure == "missing" else ValueError):
        await h.item.provider.review_control(h.raw, h.metadata)


@pytest.mark.parametrize(
    "field,value",
    [
        ("control_sha256", "ff" * 32),
        ("committed_at_block", 161),
        ("evidence_sha256", "ee" * 32),
        ("chain_config_sha256", "dd" * 32),
        ("_issuer", None),
    ],
)
async def test_replaced_proof_fields_do_not_retain_owned_authority(historical, field, value):
    original = await historical.item.provider.review_control(historical.raw, historical.metadata)
    with pytest.raises(ValueError):
        check(historical, replace(original, **{field: value}))


async def test_unrelated_genesis_cannot_be_attached_to_selected_history(historical):
    h = historical
    original = await h.item.provider.review_control(h.raw, h.metadata)
    other_genesis = h.c.decision(observed=161)
    active = h.c.decision(other_genesis, 5, observed=h.fresh.height - 1000)
    current = await h.c.observe(active, block=h.fresh.height - 900)
    with pytest.raises(ValueError, match="original chain admission"):
        h.c.reader.select_admitted(current, h.c.source, original)
    assert h.c.reader.journal.keys("reward_control_decision") == []


async def test_archived_spec_version_is_informational_only_with_reviewed_codec(historical):
    h = historical
    body = json.loads(h.raw)
    body["runtime_version"]["specVersion"] += 1
    raw = canonical_json_bytes(body)
    if h.item.config.storage_codec_metadata_path is None:
        with pytest.raises(ValidatorChainError, match="runtime_version_pin_mismatch"):
            await h.item.provider.review_control(raw, h.metadata)
    else:
        before = await h.item.provider.review_control(h.raw, h.metadata)
        after = await h.item.provider.review_control(raw, h.metadata)
        check(h, after)
        assert after.snapshot == before.snapshot
        assert after.control_sha256 == before.control_sha256
        assert after.committed_at_block == before.committed_at_block
        assert after.evidence_sha256 != before.evidence_sha256


@pytest.mark.parametrize("commit_block", [None, 159, 1001])
async def test_missing_or_untimely_genesis_never_advances_admission(historical, commit_block):
    h = historical
    h.item.rpc.values[h.item.spec] = (
        None if commit_block is None else commitment(digest(h.c.genesis.decision), commit_block)
    )
    original = await h.item.provider.collect_control(h.item.hotkey)
    proof = await h.item.provider.review_control(original.evidence, original.runtime.metadata_bytes)
    active = h.c.decision(h.c.genesis, 5, observed=h.fresh.height - 1000)
    current = await h.c.observe(active, block=h.fresh.height - 900)
    with pytest.raises(ValueError, match="original chain admission"):
        h.c.reader.select_admitted(current, h.c.source, proof)
    assert h.c.reader.journal.keys("reward_control_decision") == []


async def test_series_admission_survives_six_delayed_cohorts_and_current_revocation(historical):
    h = historical
    original = await h.item.provider.review_control(h.raw, h.metadata)
    tip = h.c.genesis
    for n in range(5, 11):
        fresh = h.advance(1_000_000)
        tip = h.c.decision(tip, n, observed=fresh.height - 1000)
        current = await h.c.observe(tip, block=fresh.height - 900)
        value = h.c.reader.select_admitted(current, h.c.source, original)
        assert value.selection.state == "selected"
        assert value.selection.activation.cohort_sha256 == digest(h.c.series.cohorts[n - 5])
        assert not value.chain_submission_authorized
        h.c.reader = h.c.reopen()
    revoke = h.c.decision(tip, kind="revoke", observed=fresh.height - 800)
    current = await h.c.observe(revoke, block=fresh.height - 700)
    value = h.c.reader.select_admitted(current, h.c.source, original)
    assert value.selection.state == "revoked" and value.selection.activation is None


async def test_original_proof_never_allows_unavailable_successor_to_use_cached_selection(
    historical,
):
    h = historical
    proof = await h.item.provider.review_control(h.raw, h.metadata)
    first = h.c.decision(h.c.genesis, 5, observed=h.fresh.height - 1000)
    current = await h.c.observe(first, block=h.fresh.height - 900)
    h.c.reader.select_admitted(current, h.c.source, proof)
    second = h.c.decision(first, 6, observed=h.fresh.height - 800)
    current = await h.c.observe(second, block=h.fresh.height - 700)

    def offline(_):
        raise FileNotFoundError("successor has not been replicated")

    with pytest.raises(FileNotFoundError):
        h.c.reader.select_admitted(current, offline, proof)
    assert h.c.reader.journal.keys("reward_control_decision") == ["0000", "0001"]


async def test_long_local_proof_replay_does_not_expire_original_admission(historical, monkeypatch):
    h = historical
    verify = h.item.verifier.verify_many

    def slow(**kwargs):
        h.item.clock.now += 10 * 60 * 60 * 1000
        return verify(**kwargs)

    monkeypatch.setattr(h.item.verifier, "verify_many", slow)
    check(h, await h.item.provider.review_control(h.raw, h.metadata))
    with pytest.raises(ValueError, match="stale"):
        await h.item.provider.collect_control(h.item.hotkey)


async def test_cancelled_history_verification_finishes_before_close(historical, monkeypatch):
    h = historical
    entered, release = threading.Event(), threading.Event()
    verify = h.item.verifier.verify_many

    def blocked(**kwargs):
        entered.set()
        assert release.wait(10)
        return verify(**kwargs)

    monkeypatch.setattr(h.item.verifier, "verify_many", blocked)
    task = asyncio.create_task(h.item.provider.review_control(h.raw, h.metadata))
    closing = None
    try:
        assert await asyncio.to_thread(entered.wait, 10)
        task.cancel()
        closing = asyncio.create_task(h.item.provider.aclose())
        await asyncio.sleep(0.02)
        assert not task.done() and not closing.done() and h.item.provider._lock.locked()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    await closing
    monkeypatch.setattr(h.item.verifier, "verify_many", verify)
    h.item.provider = h.reopen()
    check(h, await h.item.provider.review_control(h.raw, h.metadata))


async def _linked_history(h, monkeypatch, distance):
    item = h.item
    headers, heights = make_headers(h.old.height, h.old.height + distance)

    def selected(height, timestamp):
        header = headers[heights[height]]
        ref = FinalizedSnapshotRef(
            height, heights[height], header["parentHash"], header["stateRoot"]
        )
        raw = canonical_json_bytes(
            {
                **json.loads(h.old.finality_evidence),
                "block": {"scale_header": encode_rpc_header(header)},
            }
        )
        block = replace(
            h.old,
            height=height,
            block_hash=ref.block_hash,
            state_root=ref.state_root,
            timestamp_ms=timestamp,
            finality_evidence=raw,
            finality_evidence_sha256=hashlib.sha256(raw).hexdigest(),
        )
        item.finality.ref, item.finality.timestamp = ref, timestamp
        item.rpc.values["Timestamp", "Now", ()] = timestamp
        h.blocks[height] = block
        return block

    # Capture the real archive at the original block, then retain only its
    # independently owned descendant. The recovery walk uses linked SCALE
    # headers and the durable native hint store, not fake observer receipts.
    original = selected(h.old.height, item.clock.now - 1000)
    capture = await item.provider.collect_control(item.hotkey)
    saved = json.loads(capture.evidence)
    expected_items = tuple(
        (bytes.fromhex(c["key"][2:]), None if c["value"] is None else bytes.fromhex(c["value"][2:]))
        for c in saved["claims"]
    )

    def verify_original(**kwargs):
        assert kwargs["state_root"] == bytes.fromhex(original.state_root[2:])
        assert kwargs["items"] == expected_items
        return kwargs["proof"] == (b"proof",)

    monkeypatch.setattr(item.verifier, "verify_many", verify_original)
    item.clock.now += 10 * 60 * 60 * 1000
    head = selected(h.old.height + distance, item.clock.now - 1000)
    del h.blocks[original.height]
    calls = []

    async def after(height, *, maximum_distance):
        assert height == original.height and maximum_distance is None
        return head

    async def request(method, params):
        assert method == "chain_getHeader"
        calls.append(params[0])
        return headers[params[0]]

    async def close():
        pass

    monkeypatch.setattr(item.finality, "verified_block_after", after, raising=False)

    def owned(provider):
        provider._owned = True
        provider._registration_rpc = SimpleNamespace(request=request, aclose=close)
        provider._historical_headers.batch_size = 256
        return provider

    owned(item.provider)
    return SimpleNamespace(
        raw=capture.evidence,
        metadata=capture.runtime.metadata_bytes,
        head=head,
        original=original,
        headers=headers,
        heights=heights,
        calls=calls,
        owned=owned,
    )


async def test_missing_admission_header_recovers_beyond_2048_after_restart(historical, monkeypatch):
    h = historical
    w = await _linked_history(h, monkeypatch, 2050)
    with pytest.raises(HistoricalHeaderRecoveryPending):
        await h.item.provider.review_control(w.raw, w.metadata)
    assert len(w.calls) == 256
    await h.item.provider.aclose()
    h.item.provider = w.owned(h.reopen())
    for _ in range(20):
        try:
            proof = await h.item.provider.review_control(w.raw, w.metadata)
            break
        except HistoricalHeaderRecoveryPending:
            pass
    else:
        pytest.fail("historical admission did not converge")
    check(h, proof)
    assert proof.snapshot.block_number == w.original.height
    assert len(w.calls) == len(set(w.calls)) == 2050
    assert (await h.item.provider.review_control(w.raw, w.metadata)) == proof
    assert len(w.calls) == 2050
    assert h.blocks.get(w.original.height) is None


async def test_corrupt_historical_parent_stays_pending_until_valid_header_returns(
    historical, monkeypatch
):
    h = historical
    w = await _linked_history(h, monkeypatch, 40)
    broken_hash = w.heights[w.head.height - 9]
    saved = dict(w.headers[broken_hash])
    w.headers[broken_hash]["stateRoot"] = "0x" + "fe" * 32
    with pytest.raises(ValueError, match="committed parent"):
        await h.item.provider.review_control(w.raw, w.metadata)
    w.headers[broken_hash] = saved
    proof = await h.item.provider.review_control(w.raw, w.metadata)
    check(h, proof)
    assert len(w.calls) == 41


async def test_migration_selects_original_decoder_separately_from_current_control(
    historical, tmp_path
):
    h = historical
    original_config = digest(h.item.config)
    proof = await h.item.provider.review_control(h.raw, h.metadata)
    active = h.c.decision(h.c.genesis, 5, observed=h.fresh.height - 1000)
    current = await h.c.observe(active, block=h.fresh.height - 900)
    h.c.reader.select_admitted(current, h.c.source, proof)
    # A different state path and explicit reviewed decoder are independently
    # approved at migration. The private original archive stays immutable.
    (tmp_path / "migration").mkdir()
    cfg = configured(h.item, tmp_path / "migration")
    provider = FinalizedRewardControlProvider(
        cfg,
        h.item.policy,
        finality=h.item.finality,
        proofs=h.item.proofs,
        now_ms=lambda: h.item.clock.now,
    )
    try:
        new_current = await provider.collect_control(h.item.hotkey)
        reader = h.c.reopen(expected_chain_config_sha256=digest(cfg))
        with pytest.raises(ValueError, match="selected owned proof"):
            reader.select_admitted(new_current, h.c.source, proof)
        reader = h.c.reopen(
            expected_chain_config_sha256=digest(cfg),
            expected_admission_chain_config_sha256=original_config,
        )
        original = await reader.replay_admission(h.item.provider)
        assert original.evidence == proof.evidence
        selected = reader.select_admitted(new_current, lambda _: None, original)
        assert selected.selection.state == "selected"
        with pytest.raises(ValueError, match="selected current proof adapter"):
            reader.select_admitted(current, h.c.source, original)
    finally:
        await provider.aclose()


async def test_admission_and_decisions_commit_together_before_acknowledgement(
    historical, monkeypatch
):
    h = historical
    proof = await h.item.provider.review_control(h.raw, h.metadata)
    active = h.c.decision(h.c.genesis, 5, observed=h.fresh.height - 1000)
    current = await h.c.observe(active, block=h.fresh.height - 900)
    put = h.c.reader.journal.put_many

    def lost_reply(*args, **kwargs):
        put(*args, **kwargs)
        raise OSError("lost acknowledgement")

    monkeypatch.setattr(h.c.reader.journal, "put_many", lost_reply)
    with pytest.raises(OSError, match="lost acknowledgement"):
        h.c.reader.select_admitted(current, h.c.source, proof)
    h.c.reader = h.c.reopen()
    saved = await h.c.reader.replay_admission(h.item.provider)
    current = await h.c.observe(active, block=h.fresh.height - 900)
    selected = h.c.reader.select_admitted(current, lambda _: None, saved)
    assert selected.selection.state == "selected"
    assert h.c.reader.journal.keys("reward_series_admission") == ["original"]
    assert h.c.reader.journal.keys("reward_control_decision") == ["0000", "0001"]


async def test_equivalent_admission_proof_preserves_first_archive_and_restart(historical):
    h = historical
    first = await h.item.provider.review_control(h.raw, h.metadata)
    current = await h.c.observe(h.c.genesis)
    assert h.c.reader.select_admitted(current, h.c.source, first).selection.state == "admitted"
    retained = h.c.reader.journal.get("reward_series_admission", "original")
    # The same original commitment is now proved at a later finalized block.
    second = await h.item.provider.review_control(current.evidence, h.metadata)
    assert second.snapshot != first.snapshot and second.evidence != first.evidence
    assert second.control_sha256 == first.control_sha256
    assert second.committed_at_block == first.committed_at_block
    h.c.reader.select_admitted(current, h.c.source, second)
    assert h.c.reader.journal.get("reward_series_admission", "original") == retained
    h.c.reader = h.c.reopen()
    replayed = await h.c.reader.replay_admission(h.item.provider)
    assert replayed.evidence == first.evidence
    selected = h.c.reader.select_admitted(current, lambda _: None, replayed)
    assert selected.selection.state == "admitted"


async def test_recommitted_genesis_requires_original_timely_admission(historical):
    h = historical
    original = await h.item.provider.review_control(h.raw, h.metadata)
    h.c.reader.select_admitted(await h.c.observe(h.c.genesis), h.c.source, original)
    current = await h.c.observe(h.c.genesis, block=h.fresh.height - 1)
    assert current.committed_at_block > h.item.policy.valid_through_block
    with pytest.raises(ValueError, match="after its admission window"):
        h.c.reader.select(current, h.c.source)
    h.c.reader = h.c.reopen()
    retained = await h.c.reader.replay_admission(h.item.provider)
    assert (
        h.c.reader.select_admitted(current, lambda _: None, retained).selection.state == "admitted"
    )
    late = await h.item.provider.review_control(current.evidence, h.metadata)
    with pytest.raises(ValueError, match="timely original"):
        h.c.reader.select_admitted(current, h.c.source, late)


@pytest.mark.parametrize("revoked", [False, True])
async def test_timely_admission_never_allows_genesis_rollback_after_activation(historical, revoked):
    h = historical
    original = await h.item.provider.review_control(h.raw, h.metadata)
    active = h.c.decision(h.c.genesis, 5, observed=h.fresh.height - 1000)
    h.c.reader.select_admitted(
        await h.c.observe(active, block=h.fresh.height - 900), h.c.source, original
    )
    if revoked:
        tip = h.c.decision(active, kind="revoke", observed=h.fresh.height - 800)
        h.c.reader.select_admitted(
            await h.c.observe(tip, block=h.fresh.height - 700), h.c.source, original
        )
    h.c.reader = h.c.reopen()
    retained = await h.c.reader.replay_admission(h.item.provider)
    with pytest.raises(ValueError, match="conflicts with retained history"):
        h.c.reader.select_admitted(
            await h.c.observe(h.c.genesis, block=h.fresh.height - 1), h.c.source, retained
        )


async def test_failed_admission_write_does_not_leave_a_selected_history(historical):
    h = historical
    proof = await h.item.provider.review_control(h.raw, h.metadata)
    active = h.c.decision(h.c.genesis, 5, observed=h.fresh.height - 1000)
    current = await h.c.observe(active, block=h.fresh.height - 900)
    with h.c.reader.journal.transaction() as db:
        db.execute(
            "CREATE TRIGGER fail_admission BEFORE INSERT ON records "
            "WHEN NEW.kind='reward_series_admission' "
            "BEGIN SELECT RAISE(ABORT,'injected admission failure'); END"
        )
    with pytest.raises(sqlite3.Error):
        h.c.reader.select_admitted(current, h.c.source, proof)
    assert not h.c.reader.journal.keys("reward_control_decision")
    assert not h.c.reader.journal.keys("reward_series_admission")
    with h.c.reader.journal.transaction() as db:
        assert db.execute("SELECT block FROM highwater").fetchall() == []
        db.execute("DROP TRIGGER fail_admission")
    assert h.c.reader.select_admitted(current, h.c.source, proof).selection.state == "selected"


async def test_retained_admission_is_reproved_after_restart(historical):
    h = historical
    proof = await h.item.provider.review_control(h.raw, h.metadata)
    current = await h.c.observe(h.c.genesis)
    h.c.reader.select_admitted(current, h.c.source, proof)
    saved = h.c.reader.journal.get("reward_series_admission", "original")
    saved["evidence"]["proof"] = ["0x626164"]
    with h.c.reader.journal.transaction() as db:
        db.execute(
            "UPDATE records SET body=? WHERE kind='reward_series_admission' AND id='original'",
            (canonical_json_bytes(saved),),
        )
    h.c.reader = h.c.reopen()
    with pytest.raises(ValidatorChainError):
        await h.c.reader.replay_admission(h.item.provider)
