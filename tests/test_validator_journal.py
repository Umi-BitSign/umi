from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from umi.protocol import canonical_json_bytes
from umi.validator_journal import (
    StageJournalConflict,
    StageJournalError,
    StageObjectInput,
    ValidatorStageJournal,
)
from umi.validator_state import WindowStage

WINDOW_ID = "12" * 32


def _object(label: str) -> StageObjectInput:
    return StageObjectInput(
        data=canonical_json_bytes({"label": label}),
        media_type="application/json",
    )


def test_stage_receipts_are_durable_canonical_and_idempotent(tmp_path: Path) -> None:
    journal = ValidatorStageJournal(tmp_path / "journal")
    first = journal.record(
        window_id=WINDOW_ID,
        stage=WindowStage.POOL_AND_SELECTION,
        operation_id="window-0.pool.v1",
        objects=(_object("selection"),),
        metadata={"closing_block": 42},
    )
    repeated = journal.record(
        window_id=WINDOW_ID,
        stage=WindowStage.POOL_AND_SELECTION,
        operation_id="window-0.pool.v1",
        objects=(_object("selection"),),
        metadata={"closing_block": 42},
    )

    assert first == repeated
    assert first.evidence_sha256 == hashlib.sha256(first.receipt_bytes).hexdigest()
    assert first.path.read_bytes() == first.receipt_bytes
    assert json.loads(first.receipt_bytes)["stage"] == "pool_and_selection"

    assignment = journal.record(
        window_id=WINDOW_ID,
        stage=WindowStage.ASSIGNMENT,
        operation_id="window-0.assignment.v1",
        objects=(_object("assignment"),),
    )
    restarted = ValidatorStageJournal(tmp_path / "journal")
    assert restarted.load(WINDOW_ID, WindowStage.POOL_AND_SELECTION) == first
    assert restarted.load(WINDOW_ID, WindowStage.ASSIGNMENT) == assignment
    assert [item.receipt.stage for item in restarted.load_window(WINDOW_ID)] == [
        "pool_and_selection",
        "assignment",
    ]
    assert restarted.read_object(first.receipt.objects[0]) == _object("selection").data


def test_one_window_stage_cannot_be_rewritten_or_skip_a_stage(tmp_path: Path) -> None:
    journal = ValidatorStageJournal(tmp_path / "journal")
    journal.record(
        window_id=WINDOW_ID,
        stage=WindowStage.POOL_AND_SELECTION,
        operation_id="pool",
        objects=(_object("first"),),
    )
    with pytest.raises(StageJournalConflict, match="another receipt"):
        journal.record(
            window_id=WINDOW_ID,
            stage=WindowStage.POOL_AND_SELECTION,
            operation_id="pool",
            objects=(_object("different"),),
        )
    with pytest.raises(StageJournalConflict, match="skip"):
        journal.record(
            window_id=WINDOW_ID,
            stage=WindowStage.REQUEST_TRANSCRIPT,
            operation_id="request",
            objects=(_object("request"),),
        )


def test_receipt_and_object_tampering_fail_on_restart(tmp_path: Path) -> None:
    root = tmp_path / "journal"
    journal = ValidatorStageJournal(root)
    record = journal.record(
        window_id=WINDOW_ID,
        stage=WindowStage.POOL_AND_SELECTION,
        operation_id="pool",
        objects=(_object("selection"),),
    )

    record.path.write_text("{}")
    with pytest.raises(StageJournalError, match="invalid"):
        ValidatorStageJournal(root)

    record.path.write_bytes(record.receipt_bytes)
    object_path = root / "objects" / record.receipt.objects[0].sha256
    object_path.write_bytes(b"tampered")
    with pytest.raises(ValueError, match=r"wrong byte length|SHA-256"):
        ValidatorStageJournal(root)


def test_receipt_symlinks_and_unknown_paths_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "journal"
    journal = ValidatorStageJournal(root)
    record = journal.record(
        window_id=WINDOW_ID,
        stage=WindowStage.POOL_AND_SELECTION,
        operation_id="pool",
        objects=(_object("selection"),),
    )
    outside = tmp_path / "outside.json"
    outside.write_bytes(record.receipt_bytes)
    record.path.unlink()
    record.path.symlink_to(outside)
    with pytest.raises(StageJournalError, match="opened safely"):
        ValidatorStageJournal(root)

    record.path.unlink()
    unknown = record.path.parent / "unknown.json"
    unknown.write_bytes(b"{}")
    with pytest.raises(StageJournalError, match="unknown stage"):
        ValidatorStageJournal(root)


def test_strict_bounds_and_inputs_are_enforced(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="aggregate"):
        ValidatorStageJournal(
            tmp_path / "bad",
            maximum_object_bytes=2,
            maximum_total_object_bytes=1,
        )

    journal = ValidatorStageJournal(
        tmp_path / "journal",
        maximum_object_bytes=4,
        maximum_total_object_bytes=4,
    )
    with pytest.raises(ValueError, match="object exceeds"):
        journal.record(
            window_id=WINDOW_ID,
            stage=WindowStage.POOL_AND_SELECTION,
            operation_id="pool",
            objects=(StageObjectInput(b"12345", "application/octet-stream"),),
        )
    with pytest.raises(ValueError, match="window ID"):
        journal.record(
            window_id="../escape",
            stage=WindowStage.POOL_AND_SELECTION,
            operation_id="pool",
            objects=(StageObjectInput(b"1", "application/octet-stream"),),
        )


def test_aggregate_object_limit_is_per_window_and_survives_restart(tmp_path: Path) -> None:
    root = tmp_path / "journal"
    first_window = "21" * 32
    second_window = "22" * 32
    journal = ValidatorStageJournal(
        root,
        maximum_object_bytes=4,
        maximum_total_object_bytes=4,
        maximum_retained_object_bytes=8,
    )
    journal.record(
        window_id=first_window,
        stage=WindowStage.POOL_AND_SELECTION,
        operation_id="first.pool",
        objects=(StageObjectInput(b"1234", "application/octet-stream"),),
    )
    journal.record(
        window_id=second_window,
        stage=WindowStage.POOL_AND_SELECTION,
        operation_id="second.pool",
        objects=(StageObjectInput(b"5678", "application/octet-stream"),),
    )

    restarted = ValidatorStageJournal(
        root,
        maximum_object_bytes=4,
        maximum_total_object_bytes=4,
        maximum_retained_object_bytes=8,
    )
    assert len(restarted.load_window(first_window)) == 1
    assert len(restarted.load_window(second_window)) == 1


def test_per_window_and_retained_object_limits_are_independent(tmp_path: Path) -> None:
    root = tmp_path / "journal"
    journal = ValidatorStageJournal(
        root,
        maximum_object_bytes=4,
        maximum_total_object_bytes=4,
        maximum_retained_object_bytes=7,
    )
    journal.record(
        window_id=WINDOW_ID,
        stage=WindowStage.POOL_AND_SELECTION,
        operation_id="pool",
        objects=(StageObjectInput(b"123", "application/octet-stream"),),
    )
    with pytest.raises(ValueError, match="window stage evidence exceeds"):
        journal.record(
            window_id=WINDOW_ID,
            stage=WindowStage.ASSIGNMENT,
            operation_id="assignment",
            objects=(StageObjectInput(b"45", "application/octet-stream"),),
        )

    second_window = "23" * 32
    journal.record(
        window_id=second_window,
        stage=WindowStage.POOL_AND_SELECTION,
        operation_id="second.pool",
        objects=(StageObjectInput(b"6789", "application/octet-stream"),),
    )
    with pytest.raises(ValueError, match="aggregate object-byte ceiling"):
        journal.record(
            window_id="24" * 32,
            stage=WindowStage.POOL_AND_SELECTION,
            operation_id="third.pool",
            objects=(StageObjectInput(b"x", "application/octet-stream"),),
        )
