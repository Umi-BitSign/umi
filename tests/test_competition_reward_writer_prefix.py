"""Strict native empty-original checks under genuine stopped journal ownership.

Only systemd/Podman observations use the existing synthetic transport ports.
Every anchor, startup lease, journal owner and history reader is natively issued.
"""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_reward_history import RewardControlHistoryReader
from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from umi.competition_reward_writer_journals import hold_stopped_writer_journals
from umi.competition_reward_writer_prefix import (
    EmptyOriginalWriterHistory,
    retained_completed_tip,
    review_empty_original,
)
from umi.competition_reward_writer_reconciliation import hold_stopped_standing_writer
from umi.competition_round_journal import RoundJournal
from umi.competition_supervisor_runtime import hold_successor_startup_lease
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_reward_writer_review import (  # noqa: F401
    activation_case,
    anchor_case,
    chain,
    chain_config,
    control,
    explicit,
    inputs,
    limits,
    owner_case,
    package_case,
    package_limits,
    policy,
    release_identity,
    replay_limits,
    selected_boot,
    series_case,
    signed_case,
    successor_release,
    trusted_ports,
    worker_capacity,
)


@pytest.fixture
async def empty_original(selected_boot):  # noqa: F811
    case, item = selected_boot
    series = item.value.series
    root = case.root / "standing-rewards" / digest(series)
    root.parent.mkdir(mode=0o700)
    root.mkdir(mode=0o700)
    binding = {
        "schema": "umi-reward-control-history/1",
        "control_hotkey": series.control_hotkey,
        "chain_config_sha256": digest(item.value.chain),
        "first_block": series.recovery.authority.issued_at_block,
    }
    # A retained legacy empty journal exists before the maintenance owner opens
    # it. The native checkpoint schema is installed only after taking the real
    # startup and stopped-journal leases, as the production assembly requires.
    RoundJournal(root / "history", binding, maximum_bytes=8 * 1024**2)
    RoundJournal(root / "control", {"fixture": "control"}, maximum_bytes=8 * 1024**2)
    with hold_successor_startup_lease(case.anchor) as startup:
        async with hold_stopped_standing_writer(
            startup, unit=case.unit, config_path=case.config_path
        ) as owner:
            async with hold_stopped_writer_journals(owner, series) as journals:
                reader = RewardControlHistoryReader(
                    root / "history",
                    control_hotkey=series.control_hotkey,
                    chain_config_sha256=digest(item.value.chain),
                    first_block=series.recovery.authority.issued_at_block,
                    maximum_bytes=8 * 1024**2,
                )
                yield SimpleNamespace(reader=reader, journals=journals, root=root)


def legacy_frontier(reader):
    """Retain the original layout from before folded-prefix metadata existed."""
    with reader.journal.transaction() as db:
        for name in reader.folded_frontier.triggers:
            db.execute("DROP TRIGGER " + name)
        db.execute("DROP TABLE history_folded_state")
        db.execute("DROP TABLE history_folded_anchors")
        db.execute("DELETE FROM records WHERE kind LIKE 'control_history_folded_%'")


@pytest.mark.parametrize("layout", ["current", "legacy"])
async def test_genuine_empty_original_is_bound_and_repeat_preserves_journal(empty_original, layout):
    case = empty_original
    if layout == "legacy":
        legacy_frontier(case.reader)
    before = case.reader.journal.path.read_bytes()
    inode = case.reader.journal.path.stat().st_ino
    original = review_empty_original(case.reader, case.journals)
    repeated = review_empty_original(case.reader, case.journals)
    assert type(original) is EmptyOriginalWriterHistory
    original.validate()
    assert original == repeated
    assert retained_completed_tip(case.reader) == case.reader.first_block - 1
    assert original.original_owner == case.reader.checkpoints.owner
    assert case.reader.journal.path.stat().st_ino == inode
    assert case.reader.journal.path.read_bytes() == before
    with pytest.raises(ValueError, match="native retained owner"):
        replace(original, first_block=original.first_block + 1).validate()


@pytest.mark.parametrize(
    "fault",
    [
        "raw_source",
        "remote_alias",
        "source_tombstone",
        "result_without_index",
        "completion_without_index",
        "admission_marker_without_index",
        "admission_table_without_marker",
        "checkpoint_without_result",
        "highwater",
        "conflict_hold",
        "plan_index",
        "unknown_auxiliary_table",
        "missing_owner_marker",
        "missing_checkpoint_state",
        "missing_source_trigger",
        "regressed_highest",
    ],
)
async def test_retained_work_or_damaged_state_never_becomes_empty(empty_original, fault):
    reader, journals = empty_original.reader, empty_original.journals
    if fault in {
        "raw_source",
        "remote_alias",
        "result_without_index",
        "completion_without_index",
        "admission_marker_without_index",
    }:
        kind, key, value = {
            "raw_source": ("control_history_block", str(reader.first_block), {}),
            "remote_alias": ("control_history_remote_source", "ab" * 32, {}),
            "result_without_index": ("control_history_verified", "ab" * 32, {}),
            "completion_without_index": (
                "control_history_checkpoint_done",
                str(reader.first_block),
                {"height": reader.first_block, "owner": reader.checkpoints.owner},
            ),
            "admission_marker_without_index": (
                "control_history_completed_admission_done",
                "original",
                {"owner": reader.checkpoints.owner, "key": "ab" * 32},
            ),
        }[fault]
        reader.journal.put(kind, key, value)
    else:
        with reader.journal.transaction() as db:
            if fault == "source_tombstone":
                db.execute(
                    "INSERT INTO history_source_identity VALUES (?,?,1,0)",
                    ("control_history_block", str(reader.first_block)),
                )
            elif fault == "admission_table_without_marker":
                db.execute(
                    "CREATE TABLE history_completed_admission "
                    "(owner TEXT NOT NULL,key TEXT NOT NULL,revision INTEGER NOT NULL)"
                )
            elif fault == "checkpoint_without_result":
                db.execute(
                    "INSERT INTO history_checkpoint_index VALUES (?,?)",
                    (reader.first_block, "ab" * 32),
                )
                db.execute("UPDATE history_checkpoint_state SET highest=?", (reader.first_block,))
            elif fault == "highwater":
                db.execute("INSERT INTO highwater VALUES (?)", (reader.first_block,))
            elif fault == "conflict_hold":
                db.execute("INSERT INTO holds VALUES (?)", ("ab" * 32,))
            elif fault == "plan_index":
                db.execute("INSERT INTO plan_index VALUES (?,1,2)", ("ab" * 32,))
            elif fault == "unknown_auxiliary_table":
                db.execute("CREATE TABLE unrecognized_retained_state (value TEXT)")
            elif fault == "missing_owner_marker":
                db.execute("DELETE FROM records WHERE kind='control_history_checkpoint_owner'")
            elif fault == "missing_checkpoint_state":
                db.execute("DROP TABLE history_checkpoint_state")
            elif fault == "missing_source_trigger":
                db.execute("DROP TRIGGER history_source_delete")
            elif fault == "regressed_highest":
                db.execute(
                    "UPDATE history_checkpoint_state SET highest=?", (reader.first_block - 2,)
                )
            else:
                pytest.fail("unhandled fixture fault")
    before = reader.journal.path.read_bytes()
    with pytest.raises(HistoryCheckpointRepairRequired):
        review_empty_original(reader, journals)
    assert reader.journal.path.read_bytes() == before
    if fault != "raw_source":
        from umi.competition_reward_writer_sources import review_source_only_original

        with pytest.raises((HistoryCheckpointRepairRequired, ValueError)):
            review_source_only_original(reader, journals, through_block=reader.first_block + 5)
        assert reader.journal.path.read_bytes() == before


@pytest.mark.parametrize("fault", ["missing_index", "orphan_index", "regressed_highest"])
async def test_completed_tip_refuses_inconsistent_metadata(empty_original, fault):
    reader = empty_original.reader
    with reader.journal.transaction() as db:
        if fault == "missing_index":
            db.execute("UPDATE history_checkpoint_state SET highest=?", (reader.first_block,))
        elif fault == "orphan_index":
            db.execute(
                "INSERT INTO history_checkpoint_index VALUES (?,?)",
                (reader.first_block, "ab" * 32),
            )
        else:
            db.execute("UPDATE history_checkpoint_state SET highest=?", (reader.first_block - 2,))
    with pytest.raises(HistoryCheckpointRepairRequired, match="tip is damaged"):
        retained_completed_tip(reader)


async def test_empty_capability_cannot_outlive_original_journal_owner(empty_original):
    case = empty_original
    original = review_empty_original(case.reader, case.journals)
    case.journals._active[0] = False
    try:
        with pytest.raises(ValueError, match="original live ownership"):
            original.validate()
    finally:
        case.journals._active[0] = True


@pytest.mark.parametrize("layout", ["current", "legacy"])
async def test_source_only_review_is_explicit_frozen_and_not_completed(empty_original, layout):
    from umi.competition_reward_writer_sources import review_source_only_original

    case = empty_original
    if layout == "legacy":
        legacy_frontier(case.reader)
    first = case.reader.first_block
    case.reader.journal.put("control_history_block", str(first), {"retained": "source"})
    before = case.reader.journal.path.read_bytes()
    original = review_source_only_original(case.reader, case.journals, through_block=first)
    original.validate()
    assert original.source_tip == first
    assert retained_completed_tip(case.reader) == first - 1
    assert case.reader.journal.path.read_bytes() == before
    with pytest.raises(ValueError):
        replace(original, source_tip=first + 1).validate()
    with pytest.raises(HistoryCheckpointRepairRequired):
        review_empty_original(case.reader, case.journals)
    case.reader.journal.put("control_history_chunk", "ab" * 32, {"late": "mutation"})
    with pytest.raises(HistoryCheckpointRepairRequired, match="database changed"):
        original.validate()


@pytest.mark.parametrize("source_only", [False, True])
@pytest.mark.parametrize(
    "fault",
    [
        "revision",
        "highest",
        "selection",
        "missing_owner",
        "missing_generation",
        "missing_table",
        "missing_trigger",
        "unknown_trigger",
        "extra_owner",
        "extra_generation",
        "replaced_generation",
        "populated",
        "frontier_record",
        "anchor_record",
        "anchor_index",
        "legacy_orphan_trigger",
    ],
)
async def test_original_review_refuses_noninitial_frontier(empty_original, source_only, fault):
    from umi.competition_reward_writer_sources import review_source_only_original

    reader, journals = empty_original.reader, empty_original.journals
    if source_only:
        reader.journal.put("control_history_block", str(reader.first_block), {"retained": "source"})
    if fault == "legacy_orphan_trigger":
        legacy_frontier(reader)
    with reader.journal.transaction() as db:
        if fault == "revision":
            db.execute("UPDATE history_folded_state SET revision=1")
        elif fault == "highest":
            db.execute("UPDATE history_folded_state SET highest=highest+1")
        elif fault == "selection":
            db.execute("UPDATE history_folded_state SET key=?", ("ab" * 32,))
        elif fault in {"missing_owner", "missing_generation"}:
            kind = "control_history_folded_" + fault.removeprefix("missing_")
            db.execute("DELETE FROM records WHERE kind=?", (kind,))
        elif fault == "missing_table":
            db.execute("DROP TABLE history_folded_anchors")
        elif fault == "missing_trigger":
            db.execute("DROP TRIGGER history_folded_source")
        elif fault in {"unknown_trigger", "legacy_orphan_trigger"}:
            db.execute(
                "CREATE TRIGGER history_folded_unknown AFTER INSERT ON records BEGIN SELECT 1; END"
            )
        elif fault == "anchor_index":
            db.execute(
                "INSERT INTO history_folded_anchors VALUES (?,?)", (reader.first_block, "ab" * 32)
            )
        else:
            kind, key, body = {
                "extra_owner": (
                    "control_history_folded_owner",
                    "other",
                    reader.folded_frontier.marker,
                ),
                "extra_generation": (
                    "control_history_folded_generation",
                    "other",
                    reader.folded_frontier.generation("other"),
                ),
                "replaced_generation": (
                    "control_history_folded_generation",
                    "other",
                    reader.folded_frontier.generation("other"),
                ),
                "populated": (
                    "control_history_folded_populated",
                    "initial",
                    reader.folded_frontier.populated("initial"),
                ),
                "frontier_record": ("control_history_folded_frontier", "ab" * 32, {}),
                "anchor_record": ("control_history_folded_anchor", "ab" * 32, {}),
            }[fault]
            db.execute(
                "INSERT INTO records VALUES (?,?,?)", (kind, key, canonical_json_bytes(body))
            )
            if fault == "replaced_generation":
                db.execute(
                    "DELETE FROM records WHERE kind='control_history_folded_generation' "
                    "AND id='initial'"
                )
                db.execute("UPDATE history_folded_state SET revision=0,generation='other'")
    before = reader.journal.path.read_bytes()
    with pytest.raises(HistoryCheckpointRepairRequired):
        if source_only:
            review_source_only_original(reader, journals, through_block=reader.first_block)
        else:
            review_empty_original(reader, journals)
    assert reader.journal.path.read_bytes() == before


@pytest.mark.parametrize(
    "fault", ["gap", "beyond_target", "noncanonical_height", "orphan_identity"]
)
async def test_source_only_refuses_unsupported_intervals(empty_original, fault):
    from umi.competition_reward_writer_sources import review_source_only_original

    case = empty_original
    first = case.reader.first_block
    key = (
        str(first + 1)
        if fault == "gap"
        else "0" + str(first)
        if fault == "noncanonical_height"
        else str(first)
    )
    case.reader.journal.put("control_history_block", key, {"retained": "source"})
    if fault == "orphan_identity":
        with case.reader.journal.transaction() as db:
            db.execute(
                "INSERT INTO history_source_identity VALUES ('control_history_chunk',?,0,1)",
                ("ab" * 32,),
            )
    with pytest.raises(ValueError):
        review_source_only_original(
            case.reader,
            case.journals,
            through_block=first - 1 if fault == "beyond_target" else first + 1,
        )
