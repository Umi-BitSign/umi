"""Native multi-block history with synthetic linked headers, trie and SCALE ports."""

import asyncio
import hashlib
import json
import threading
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_reward_history import RewardControlHistoryReader, validate_control_history
from umi.encoding import account_id32
from umi.finalized_ancestry import encode_rpc_header
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from . import test_competition_reward_control_archive as archive_tests
from .test_competition_chain import _Runtime
from .test_competition_reward_control import commitment
from .test_competition_reward_control_capture import capture_source
from .test_competition_reward_control_writes import chain as chain
from .test_competition_reward_control_writes import chain_config as chain_config
from .test_competition_reward_control_writes import commit
from .test_competition_reward_control_writes import control as control
from .test_competition_reward_control_writes import historical as historical
from .test_competition_reward_control_writes import policy as policy
from .test_competition_reward_control_writes import series_case as series_case
from .test_finalized_ancestry import make_headers
from .test_validator_chain_scan import Entry, extrinsic, success

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


async def test_retained_control_requires_replayed_prefix_and_survives_offline_restart(history_case):
    h = history_case
    with pytest.raises(ValueError, match="not been natively verified"):
        await h.reader.review_control(h.item.provider, h.end)
    await h.reader.advance(h.item.provider, through_block=h.end)
    before = await h.reader.review_control(h.item.provider, h.end)
    h.reader = await h.restart()
    with pytest.raises(ValueError, match="not been natively verified"):
        await h.reader.review_control(h.item.provider, h.end)
    h.offline_through = h.end
    await h.reader.advance(h.item.provider, through_block=h.end)
    h.rpc_calls.clear()
    after = await h.reader.review_control(h.item.provider, h.end)
    assert after == before
    assert set(h.rpc_calls) <= {"chain_getHeader", "chain_getBlockHash"}


async def test_export_uses_the_verified_frame_without_reloading_it(
    history_case, tmp_path, monkeypatch
):
    from umi.competition_reward_proof_archive import RewardProofArchive, history_archive_key

    h = history_case
    archive = RewardProofArchive(tmp_path / "export")
    h.reader.export_archive = archive
    load = h.reader._load
    heights = []

    def counted(height):
        heights.append(height)
        return load(height)

    monkeypatch.setattr(h.reader, "_load", counted)
    result = await h.reader.advance(h.item.provider, through_block=h.end)
    assert result.history is not None
    assert heights == list(range(h.reader.first_block, h.end + 1))
    for height in heights:
        saved = load(height)
        context, received = archive.read(
            "history",
            history_archive_key(h.reader.config_sha256, h.reader.hotkey, height),
            bounds={key: len(value) for key, value in saved.items()},
        )
        assert context == h.reader._archive_context(height)
        assert received == saved


async def test_retained_frame_load_uses_one_read_snapshot_during_unrelated_writer(
    history_case, monkeypatch
):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    expected = h.reader._load(h.end)
    journal = h.reader.journal
    read = journal.read_transaction
    snapshots = []

    @contextmanager
    def counted():
        with read() as db:
            assert db.execute("PRAGMA query_only").fetchone() == (1,)
            snapshots.append(db)
            yield db

    monkeypatch.setattr(journal, "read_transaction", counted)
    with journal.transaction():
        assert h.reader._load(h.end) == expected
    assert len(snapshots) == 1
    assert h.reader._load(h.end + 1) is None
    assert len(snapshots) == 2


@pytest.mark.parametrize(
    "kind", ["control_history_block", "control_history_chunk", "control_history_object"]
)
async def test_retained_frame_load_observes_new_conflict_on_next_read(history_case, kind):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader._load(h.end) is not None
    journal = h.reader.journal
    # Every frame has its own key; select the last frame and all its actual
    # chunk/object keys so this tests its complete newly committed fence.
    keys = [str(h.end)] if kind == "control_history_block" else journal.keys(kind)
    with pytest.raises(ValueError, match="conflict"):
        journal.put_many((kind, key, {"different": True}) for key in keys)
    with pytest.raises(ValueError, match="conflict held"):
        h.reader._load(h.end)


@pytest.mark.parametrize("bound", ["normal", "bytes", "entries"])
async def test_frame_object_reuse_is_bounded_and_does_not_cross_snapshots(
    history_case, monkeypatch, bound
):
    from collections import Counter

    from umi import competition_reward_history as module

    h = history_case
    raw = canonical_json_bytes({"proof": (b"repeated native object" * 512).hex()})
    height = h.end + 1
    h.reader._save(
        SimpleNamespace(
            slot=SimpleNamespace(
                evidence=raw, metadata=raw, snapshot=SimpleNamespace(block_number=height)
            ),
            evidence=raw,
        )
    )
    if bound == "bytes":
        monkeypatch.setattr(module, "_MAX_FRAME_OBJECT_BYTES", 0)
    elif bound == "entries":
        monkeypatch.setattr(module, "_MAX_FRAME_OBJECTS", 0)
    original, calls = h.reader._object, []

    def counted(sha, size, *, db):
        calls.append((sha, size))
        return original(sha, size, db=db)

    monkeypatch.setattr(h.reader, "_object", counted)
    expected = dict.fromkeys(("slot_evidence", "slot_metadata", "evidence"), raw)
    assert h.reader._load(height) == expected
    counts = Counter(calls)
    assert set(counts.values()) == ({1} if bound == "normal" else {3})
    calls.clear()
    assert h.reader._load(height) == expected
    assert Counter(calls) == counts  # A new snapshot rechecks every retained object.
    sha, _ = next(iter(counts))
    with pytest.raises(ValueError, match="conflict"):
        h.reader.journal.put("control_history_object", sha, {"hex": "00"})
    with pytest.raises(ValueError, match="conflict held"):
        h.reader._load(height)


@pytest.fixture
async def history_case(historical, monkeypatch, tmp_path):
    return await make_history_case(historical, monkeypatch, tmp_path)


async def test_scale_fixture_captures_across_old_head_and_past_ten_hours(
    historical, monkeypatch, tmp_path
):
    first = historical.old.height
    historical.c.control_writes = {height: () for height in range(first, first + 3101)}
    historical.c.control_writes[first] = (digest(historical.c.genesis.decision),)
    h = await make_history_case(historical, monkeypatch, tmp_path, distance=3100)
    try:
        for height in (first + 3000, first + 3099):
            captured = await h.item.provider.capture_control_at(h.item.hotkey, height)
            assert captured.snapshot.block_number == height
            assert captured.control_sha256 == digest(h.c.genesis.decision)
            assert (
                await h.item.provider.review_control(captured.evidence, captured.metadata)
            ) == captured
    finally:
        await h.item.provider.aclose()


async def make_history_case(historical, monkeypatch, tmp_path, *, distance=5):
    h = historical

    def headers(first, last):
        old, heights = make_headers(first - 1, last)
        result, by_height = {}, {}
        parent = old[heights[first - 1]]["parentHash"]
        for height, old_hash in heights.items():
            header = {
                **old[old_hash],
                "parentHash": parent,
                "extrinsicsRoot": "0x" + hashlib.sha256(f"body-{height}".encode()).hexdigest(),
            }
            encoded = encode_rpc_header(header)
            parent = "0x" + hashlib.blake2b(bytes.fromhex(encoded[2:]), digest_size=32).hexdigest()
            result[parent], by_height[height] = header, parent
        return result, by_height

    monkeypatch.setattr(archive_tests, "make_headers", headers)
    h.item.rpc.values[h.item.spec] = commitment("bb" * 32, h.old.height)
    h.source = await capture_source(h, monkeypatch, distance=distance)
    w = h.source.w
    first = h.old.height
    h.end = first + distance - 1
    h.offline_through = -1
    h.fail_block = None
    h.body_requests = []
    h.rpc_calls = []
    histories = getattr(h.c, "control_writes", None) or {
        first: ("aa" * 32, "bb" * 32),
        first + 1: ("cc" * 32, "bb" * 32),  # An overwritten decision must remain visible.
        first + 2: (),
        first + 3: (),  # Slot was cleared by an effect this call decoder cannot attribute.
        first + 4: ("bb" * 32,),
    }
    cleared = getattr(
        h.c, "cleared_blocks", set() if hasattr(h.c, "control_writes") else {first + 3}
    )
    raws, decoded, events, values, roots = {}, {}, {}, {}, {}
    last = None
    for height, writes in histories.items():
        header = w.headers[w.heights[height]]
        root = bytes.fromhex(header["stateRoot"][2:])
        roots[root] = height
        bodies = tuple(f"write-{height}-{i}".encode() for i in range(len(writes)))
        raws[height] = bodies
        decoded.update(
            {
                raw: extrinsic(raw, commit(sha), account_id32(h.item.hotkey))
                for raw, sha in zip(bodies, writes, strict=True)
            }
        )
        events[height] = [success(i) for i in range(len(writes))]
        if writes:
            last = commitment(writes[-1], height)
        elif height in cleared:
            last = None
        at = dict(h.source.archive.values)
        for spec, value in getattr(h.c, "additional_state", {}).items():
            key = "0x" + canonical_json_bytes(spec).hex()
            at[key] = None if value is None else "0x" + canonical_json_bytes(value).hex()
        for key in at:
            if key == "0x3a636f6465":
                continue
            path = json.loads(bytes.fromhex(key[2:]))
            if path[:2] == ["Commitments", "CommitmentOf"]:
                at[key] = None if last is None else "0x" + canonical_json_bytes(last).hex()
            elif path[:2] == ["Timestamp", "Now"]:
                at[key] = (
                    "0x"
                    + canonical_json_bytes(w.original.timestamp_ms + (height - first) * 12000).hex()
                )
        values[height] = at

    if "0x3a636f6465" in values[first]:
        # Block-call decoding executes the parent's runtime, including the
        # first block in the retained interval.
        parent = w.headers[w.heights[first - 1]]
        roots[bytes.fromhex(parent["stateRoot"][2:])] = first - 1
        values[first - 1] = {"0x3a636f6465": values[first]["0x3a636f6465"]}

    event_key = b"system-events-key"

    class Codec(_Runtime):
        def storage_key(self, pallet, item, params):
            if (pallet, item) == ("System", "Events"):
                return event_key
            return super().storage_key(pallet, item, params)

        def storage_entry(self, pallet, item):
            return (
                Entry()
                if (pallet, item) == ("System", "Events")
                else super().storage_entry(pallet, item)
            )

        def decode(self, value_type, data, *, strict):
            if value_type == "Vec<EventRecord>":
                assert strict
                return events[int(data)]
            return super().decode(value_type, data, strict=strict)

        def decode_extrinsic(self, raw, strict=True):
            assert strict
            return decoded[raw]

    monkeypatch.setattr("umi.validator_chain.bittensor_core.Runtime", Codec)

    async def after(height, *, maximum_distance):
        assert first <= height <= w.head.height and maximum_distance is None
        return w.head

    monkeypatch.setattr(h.item.finality, "verified_block_after", after)

    async def request(method, params):
        h.rpc_calls.append(method)
        if method == "chain_getBlockHash":
            return w.heights[params[0]]
        if method == "chain_getHeader":
            return w.headers[params[0]]
        header = w.headers[params[-1]]
        height = int(header["number"], 16)
        if method == "state_getRuntimeVersion":
            return {"specVersion": 452, "transactionVersion": 1, "stateVersion": 1}
        if method == "state_getMetadata":
            return "0x" + h.metadata.hex()
        if height <= h.offline_through:
            raise OSError("historical storage/body RPC is disabled")
        if method == "chain_getBlock":
            h.body_requests.append(height)
            if height == h.fail_block:
                raise OSError("interrupted body read")
            return {
                "block": {"header": header, "extrinsics": ["0x" + v.hex() for v in raws[height]]}
            }
        if method == "state_getStorageAt":
            if params[0] == "0x" + event_key.hex():
                return "0x" + str(height).encode().hex()
            return values[height][params[0]]
        if method == "state_getReadProof":
            return {"at": params[-1], "proof": ["0x" + b"proof".hex()]}
        raise AssertionError(method)

    def own(provider):
        h.source.w.owned(provider)
        provider._registration_rpc = SimpleNamespace(request=request, aclose=h.source.close)
        return provider

    own(h.item.provider)
    monkeypatch.setattr(h.item.rpc, "request", request)

    def verify_many(**kw):
        height = roots[kw["state_root"]]
        expected = {
            bytes.fromhex(k[2:]): None if v is None else bytes.fromhex(v[2:])
            for k, v in values[height].items()
        }
        return (
            bool(kw["items"])
            and all(k in expected and expected[k] == v for k, v in kw["items"])
            and kw["proof"] == (b"proof",)
        )

    monkeypatch.setattr(h.item.verifier, "verify_many", verify_many)

    def read_many(*, state_root, storage_keys, proof, **limits):
        if proof != (b"proof",):
            raise ValueError("invalid synthetic historical proof")
        expected = values[roots[state_root]]
        return tuple(
            (
                key,
                None
                if expected["0x" + key.hex()] is None
                else bytes.fromhex(expected["0x" + key.hex()][2:]),
            )
            for key in storage_keys
        )

    monkeypatch.setattr(h.item.verifier, "read_many", read_many)

    def verify_events(self, **kw):
        height = roots[kw["state_root"]]
        if kw["storage_key"] == b":code" and "0x3a636f6465" in values[height]:
            return kw["expected_value"] == bytes.fromhex(values[height]["0x3a636f6465"][2:]) and kw[
                "proof"
            ] == (b"proof",)
        return (
            kw["storage_key"] == event_key
            and kw["expected_value"] == str(height).encode()
            and kw["proof"] == (b"proof",)
        )

    monkeypatch.setattr(type(h.item.verifier), "__call__", verify_events)
    root_bodies = {
        bytes.fromhex(w.headers[w.heights[n]]["extrinsicsRoot"][2:]): v for n, v in raws.items()
    }
    monkeypatch.setattr(
        h.item.verifier,
        "verify_extrinsics_root",
        lambda **kw: (
            kw["state_version"] == 0 and kw["extrinsics"] == root_bodies[kw["expected_root"]]
        ),
        raising=False,
    )

    def reader(maximum_bytes=4 * 1024**2):
        return RewardControlHistoryReader(
            tmp_path / "history-journal",
            control_hotkey=h.item.hotkey,
            chain_config_sha256=digest(h.item.config),
            first_block=first,
            maximum_bytes=maximum_bytes,
        )

    async def reopen():
        await h.item.provider.aclose()
        h.item.provider = own(h.reopen())
        return reader()

    h.reader, h.new_reader, h.restart = reader(), reader, reopen
    return h


async def test_history_replays_saved_prefix_after_restart_then_finishes_missing_blocks(
    history_case,
):
    h = history_case
    first = h.old.height
    partial = await h.reader.advance(h.item.provider, through_block=h.end, maximum_blocks=2)
    assert partial.history is None and partial.next_block == first + 2
    prefix = await h.reader.verified_prefix(first)
    assert all(w.block_number == first for w in prefix.writes)
    with pytest.raises(ValueError, match="not been natively verified"):
        await h.reader.verified_prefix(first + 2)
    assert h.body_requests == [first, first + 1]
    h.offline_through = first + 1
    h.reader = await h.restart()
    with pytest.raises(ValueError, match="not been natively verified"):
        await h.reader.verified_prefix(first)
    replay = await h.reader.advance(h.item.provider, through_block=h.end, maximum_blocks=2)
    assert replay.history is None and replay.next_block == first + 2
    assert await h.reader.verified_prefix(first) == prefix
    assert h.body_requests == [first, first + 1]
    result = (await h.reader.advance(h.item.provider, through_block=h.end)).history
    assert await h.reader.verified_prefix(first) == prefix
    assert await h.reader.verified_prefix(h.end) == result
    validate_control_history(
        result,
        first_block=first,
        tip=result.tip,
        control_hotkey=h.item.hotkey,
        chain_config_sha256=digest(h.item.config),
    )
    assert [(w.block_number, w.extrinsic_index, w.decision_sha256) for w in result.writes] == [
        (first, 0, "aa" * 32),
        (first, 1, "bb" * 32),
        (first + 1, 0, "cc" * 32),
        (first + 1, 1, "bb" * 32),
        (first + 4, 0, "bb" * 32),
    ]
    assert result.unresolved_blocks == (first + 3,)
    assert h.body_requests == list(range(first, h.end + 1))
    h.offline_through = h.end
    h.reader = await h.restart()
    h.rpc_calls.clear()
    replayed = (await h.reader.advance(h.item.provider, through_block=h.end)).history
    assert replayed == result
    assert set(h.rpc_calls) <= {"chain_getHeader", "chain_getBlockHash"}
    with pytest.raises(ValueError, match="native interval"):
        validate_control_history(
            replace(result, writes=()),
            first_block=first,
            tip=result.tip,
            control_hotkey=h.item.hotkey,
            chain_config_sha256=digest(h.item.config),
        )


async def test_interrupted_network_preserves_prefix_and_retries_only_missing_block(history_case):
    h = history_case
    h.fail_block = h.old.height + 2
    with pytest.raises(RuntimeError, match="block_body_fetch_failed"):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader._next == h.fail_block
    assert h.reader.journal.get("control_history_block", str(h.fail_block)) is None
    h.fail_block = None
    result = await h.reader.advance(h.item.provider, through_block=h.end)
    assert result.history is not None
    assert h.body_requests.count(h.old.height) == 1
    assert h.body_requests.count(h.old.height + 2) == 2


async def test_lost_commit_acknowledgement_recovers_exact_archive(history_case, monkeypatch):
    h = history_case
    save = h.reader._save

    def lose_reply(observation):
        save(observation)
        raise OSError("lost local acknowledgement")

    monkeypatch.setattr(h.reader, "_save", lose_reply)
    with pytest.raises(OSError, match="acknowledgement"):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader._next == h.old.height
    assert h.reader.journal.get("control_history_block", str(h.old.height)) is not None
    h.reader = await h.restart()
    h.offline_through = h.old.height
    assert (await h.reader.advance(h.item.provider, through_block=h.end)).history is not None
    assert h.body_requests.count(h.old.height) == 1


async def test_capacity_can_grow_without_changing_history_binding(history_case):
    h = history_case
    h.reader = h.new_reader(maximum_bytes=1024)
    with pytest.raises(ValueError, match="capacity"):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader._next == h.old.height
    assert h.reader.journal.get("control_history_block", str(h.old.height)) is None
    h.reader = h.new_reader()
    assert (await h.reader.advance(h.item.provider, through_block=h.end)).history is not None


@pytest.mark.parametrize("mutation", ["frame", "object", "missing", "gap"])
async def test_retained_cursor_cannot_skip_missing_or_changed_proofs(history_case, mutation):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    journal = h.reader.journal
    with journal.transaction() as db:
        if mutation == "frame":
            # Valid proofs under the wrong block key are still not that block.
            db.execute(
                "UPDATE records SET body=(SELECT body FROM records "
                "WHERE kind='control_history_block' AND id=?) "
                "WHERE kind='control_history_block' AND id=?",
                (str(h.old.height), str(h.old.height + 1)),
            )
        elif mutation == "object":
            db.execute(
                "UPDATE records SET body=? WHERE kind='control_history_object'",
                (canonical_json_bytes({"hex": "00"}),),
            )
        elif mutation == "missing":
            db.execute("DELETE FROM records WHERE kind='control_history_chunk'")
        else:
            db.execute(
                "DELETE FROM records WHERE kind='control_history_block' AND id=?",
                (str(h.old.height + 1),),
            )
    h.reader = await h.restart()
    h.offline_through = h.end
    with pytest.raises((ValueError, RuntimeError)):
        await h.reader.advance(h.item.provider, through_block=h.end)
    assert h.reader._next <= h.old.height + 1


async def test_target_and_boundaries_cannot_regress_or_change(history_case):
    h = history_case
    await h.reader.advance(h.item.provider, through_block=h.end)
    with pytest.raises(ValueError, match="regressed"):
        await h.reader.advance(h.item.provider, through_block=h.end - 1)
    with pytest.raises(ValueError, match="configuration changed"):
        RewardControlHistoryReader(
            h.reader.journal.root,
            control_hotkey=h.item.hotkey,
            chain_config_sha256=digest(h.item.config),
            first_block=h.old.height + 1,
        )


@pytest.mark.parametrize("committed", [False, True])
async def test_cancelled_save_drains_before_releasing_archive_owner(
    history_case, monkeypatch, committed
):
    h = history_case
    save = h.reader._save
    entered, release = asyncio.Event(), threading.Event()
    loop = asyncio.get_running_loop()

    def blocked(observation):
        if committed:
            save(observation)
        loop.call_soon_threadsafe(entered.set)
        assert release.wait(5)
        if not committed:
            save(observation)

    monkeypatch.setattr(h.reader, "_save", blocked)
    task = asyncio.create_task(h.reader.advance(h.item.provider, through_block=h.end))
    try:
        await asyncio.wait_for(entered.wait(), 3)
        task.cancel()
        for _ in range(3):
            await asyncio.sleep(0)
            task.cancel()
        assert not task.done()
        # A different reader cannot take over while its predecessor owns disk I/O.
        with pytest.raises((ValueError, RuntimeError, BlockingIOError)):
            await h.new_reader().advance(h.item.provider, through_block=h.end)
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert h.reader._next == h.old.height
    h.offline_through = h.old.height
    h.reader = await h.restart()
    assert (await h.reader.advance(h.item.provider, through_block=h.end)).history is not None
    assert h.body_requests.count(h.old.height) == 1
