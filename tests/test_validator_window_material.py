from __future__ import annotations

import hashlib
import os
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from umi.protocol import PROTOCOL_VERSION, canonical_json_bytes
from umi.validator import prepare_request_attempt
from umi.validator_assignments import WINDOW_SCHEMA, TranscriptWindowSpec
from umi.validator_journal import STAGE_RECEIPT_SCHEMA, StageObject, StageReceipt
from umi.validator_state import (
    ControlState,
    PauseScope,
    StageEvidence,
    StageWorkItem,
    WindowPlan,
    WindowRecord,
    WindowStage,
)
from umi.validator_transcript_effects import TranscriptAssignment, TranscriptExecutionPlan
from umi.validator_window_material import (
    ValidatorWindowMaterialStore,
    WindowMaterialBindingError,
    WindowMaterialConflict,
    WindowMaterialStoreError,
)

from .factories import POLICY_HASH, TEST_REVEAL_ROUND, challenge_request, dev_wallet

VALIDATOR_WALLET = dev_wallet("//Alice")
VALIDATOR = VALIDATOR_WALLET.hotkey.ss58_address
MINER = dev_wallet("//Bob").hotkey.ss58_address
REVEAL_ROUND = TEST_REVEAL_ROUND
RESPONSE_CLOSE_ROUND = REVEAL_ROUND - 2
ISSUE_CLOSE_ROUND = RESPONSE_CLOSE_ROUND - 1
SOURCE_BYTES = b"canonical-pool-selection-evidence"
SOURCE_SHA256 = hashlib.sha256(SOURCE_BYTES).hexdigest()


def _plan(assignment_count: int = 2) -> TranscriptExecutionPlan:
    assignments = []
    for index in range(1, assignment_count + 1):
        prepared = prepare_request_attempt(
            challenge_request(index, reveal_round=REVEAL_ROUND),
            wallet=VALIDATOR_WALLET,
            miner_hotkey=MINER,
            nonce_ns=10_000 + index,
        )
        assignments.append(
            TranscriptAssignment(
                initial_attempt=prepared,
                miner_url=f"https://miner-{index}.example",
            )
        )
    ordered = tuple(sorted(assignments, key=lambda item: item.assignment_id))
    return TranscriptExecutionPlan(
        spec=TranscriptWindowSpec(
            schema=WINDOW_SCHEMA,
            protocol=PROTOCOL_VERSION,
            window_id=ordered[0].initial_attempt.request.window_id,
            validator_hotkey=VALIDATOR,
            expected_assignment_count=assignment_count,
            maximum_request_transmissions_per_assignment=2,
            issue_close_round=ISSUE_CLOSE_ROUND,
            response_close_round=RESPONSE_CLOSE_ROUND,
            reveal_round=REVEAL_ROUND,
            maximum_request_body_bytes=64 * 1024,
            maximum_response_body_bytes=64 * 1024,
            maximum_retained_prefix_bytes=64,
        ),
        assignments=ordered,
    )


def _window(plan: TranscriptExecutionPlan) -> WindowPlan:
    return WindowPlan(
        window_id=plan.spec.window_id,
        window_index=7,
        scoring_policy_hash=POLICY_HASH,
        announcement_block=1_000,
        proposal_close_block=1_030,
        closing_block=1_045,
        selection_round=plan.spec.issue_close_round - 10,
        issue_close_round=plan.spec.issue_close_round,
        response_close_round=plan.spec.response_close_round,
        reveal_round=plan.spec.reveal_round,
    )


def _pool_receipt_bytes(
    stored,
    *,
    include_material: bool = True,
    include_plan: bool = True,
    include_source: bool = True,
    metadata_marker: str = "first",
) -> bytes:
    objects = []
    if include_material:
        objects.append(
            StageObject(
                sha256=stored.receipt_sha256,
                media_type="application/json",
                size_bytes=len(stored.receipt_bytes),
            )
        )
    if include_plan:
        objects.append(
            StageObject(
                sha256=stored.receipt.material_sha256,
                media_type="application/json",
                size_bytes=len(stored.material_bytes),
            )
        )
    if include_source:
        objects.append(
            StageObject(
                sha256=SOURCE_SHA256,
                media_type="application/octet-stream",
                size_bytes=len(SOURCE_BYTES),
            )
        )
    objects.sort(key=lambda item: bytes.fromhex(item.sha256))
    receipt = StageReceipt(
        schema=STAGE_RECEIPT_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=stored.receipt.window_id,
        stage=WindowStage.POOL_AND_SELECTION.value,
        operation_id=(
            f"umi-stage-v1/{stored.receipt.window_id}/{WindowStage.POOL_AND_SELECTION.value}"
        ),
        objects=objects,
        metadata={"marker": metadata_marker},
    )
    return canonical_json_bytes(receipt)


def _work(
    window: WindowPlan,
    *,
    pool_evidence_sha256: str,
) -> StageWorkItem:
    return StageWorkItem(
        window=WindowRecord(
            plan=window,
            stage=WindowStage.ASSIGNMENT,
            terminal_outcome=None,
            terminal_reason_code=None,
            terminal_evidence_sha256=None,
            audit_release_block=None,
            created_at_unix_ns=1,
            updated_at_unix_ns=1,
            revision=1,
        ),
        completed_evidence=(
            StageEvidence(
                window_id=window.window_id,
                stage=WindowStage.POOL_AND_SELECTION,
                evidence_sha256=pool_evidence_sha256,
                recorded_at_unix_ns=1,
            ),
        ),
        controls=(
            ControlState(PauseScope.WINDOW_INTAKE, ()),
            ControlState(PauseScope.WEIGHT_SUBMISSION, ()),
        ),
    )


def _put_and_bind(root: Path):
    plan = _plan()
    window = _window(plan)
    store = ValidatorWindowMaterialStore(root)
    stored = store.put(window, plan, source_evidence_sha256=SOURCE_SHA256)
    receipt_bytes = _pool_receipt_bytes(stored)
    binding = store.attach_pool_stage_receipt(window.window_id, receipt_bytes)
    return store, plan, window, stored, binding, receipt_bytes


def test_exact_plan_round_trip_restart_and_plan_port_binding(tmp_path: Path) -> None:
    root = tmp_path / "material"
    store, plan, window, stored, binding, receipt_bytes = _put_and_bind(root)

    loaded = store(_work(window, pool_evidence_sha256=binding.pool_stage_evidence_sha256))
    assert loaded == plan
    assert loaded is not plan
    assert [item.miner_url for item in loaded.assignments] == [
        item.miner_url for item in plan.assignments
    ]
    for replayed, original in zip(loaded.assignments, plan.assignments, strict=True):
        assert replayed.initial_attempt.request_bytes == original.initial_attempt.request_bytes
        assert replayed.initial_attempt.auth_headers == original.initial_attempt.auth_headers
        assert replayed.initial_attempt.auth_evidence == original.initial_attempt.auth_evidence
        assert replayed.assignment_id == original.assignment_id
    bound = store.load_for_work(
        _work(window, pool_evidence_sha256=binding.pool_stage_evidence_sha256)
    )
    assert bound.receipt.material_sha256 == stored.receipt.material_sha256
    assert bound.receipt_sha256 == stored.receipt_sha256

    restarted = ValidatorWindowMaterialStore(root)
    restarted_record = restarted.load(window.window_id)
    assert restarted_record.receipt_bytes == stored.receipt_bytes
    assert restarted_record.receipt_sha256 == stored.receipt_sha256
    assert restarted_record.pool_stage_evidence_sha256 == hashlib.sha256(receipt_bytes).hexdigest()
    assert restarted(_work(window, pool_evidence_sha256=binding.pool_stage_evidence_sha256)) == plan


def test_put_and_pool_receipt_attachment_are_exactly_idempotent(tmp_path: Path) -> None:
    store, plan, window, stored, binding, receipt_bytes = _put_and_bind(tmp_path / "store")

    repeated = store.put(window, plan, source_evidence_sha256=SOURCE_SHA256)
    repeated_binding = store.attach_pool_stage_receipt(window.window_id, receipt_bytes)

    assert repeated.receipt_bytes == stored.receipt_bytes
    assert repeated.receipt_sha256 == stored.receipt_sha256
    assert repeated_binding == binding


def test_same_window_rejects_different_plan_or_source_evidence(tmp_path: Path) -> None:
    plan = _plan()
    window = _window(plan)
    store = ValidatorWindowMaterialStore(tmp_path / "store")
    store.put(window, plan, source_evidence_sha256=SOURCE_SHA256)

    changed_assignments = list(plan.assignments)
    first = changed_assignments[0]
    changed_assignments[0] = TranscriptAssignment(
        initial_attempt=first.initial_attempt,
        miner_url="https://different-miner.example",
    )
    changed = TranscriptExecutionPlan(
        spec=plan.spec,
        assignments=tuple(sorted(changed_assignments, key=lambda item: item.assignment_id)),
    )
    with pytest.raises(WindowMaterialConflict, match="different execution material"):
        store.put(window, changed, source_evidence_sha256=SOURCE_SHA256)
    with pytest.raises(WindowMaterialConflict, match="different execution material"):
        store.put(window, plan, source_evidence_sha256="99" * 32)


def test_policy_schedule_and_origin_bindings_fail_closed(tmp_path: Path) -> None:
    plan = _plan()
    window = _window(plan)
    store = ValidatorWindowMaterialStore(tmp_path / "store")

    with pytest.raises(WindowMaterialConflict, match="scoring policy"):
        store.put(
            replace(window, scoring_policy_hash="91" * 32),
            plan,
            source_evidence_sha256=SOURCE_SHA256,
        )
    with pytest.raises(WindowMaterialConflict, match="issue-close"):
        store.put(
            replace(window, issue_close_round=window.issue_close_round - 1),
            plan,
            source_evidence_sha256=SOURCE_SHA256,
        )

    assignment = plan.assignments[0]
    invalid_origin_plan = TranscriptExecutionPlan(
        spec=plan.spec,
        assignments=tuple(
            sorted(
                (
                    TranscriptAssignment(
                        initial_attempt=assignment.initial_attempt,
                        miner_url="https://miner.example/path",
                    ),
                    *plan.assignments[1:],
                ),
                key=lambda item: item.assignment_id,
            )
        ),
    )
    with pytest.raises(ValueError, match="path, query, or fragment"):
        store.put(window, invalid_origin_plan, source_evidence_sha256=SOURCE_SHA256)


def test_per_window_byte_and_assignment_count_ceilings(tmp_path: Path) -> None:
    plan = _plan(2)
    window = _window(plan)
    count_limited = ValidatorWindowMaterialStore(
        tmp_path / "count",
        maximum_assignments_per_window=1,
    )
    with pytest.raises(WindowMaterialStoreError, match="assignment-count ceiling"):
        count_limited.put(window, plan, source_evidence_sha256=SOURCE_SHA256)

    byte_limited = ValidatorWindowMaterialStore(
        tmp_path / "bytes",
        maximum_material_bytes=128,
        maximum_store_bytes=4096,
    )
    with pytest.raises(WindowMaterialStoreError, match="per-window byte ceiling"):
        byte_limited.put(window, plan, source_evidence_sha256=SOURCE_SHA256)


def test_pool_stage_receipt_must_reference_material_and_source(tmp_path: Path) -> None:
    plan = _plan()
    window = _window(plan)
    store = ValidatorWindowMaterialStore(tmp_path / "store")
    stored = store.put(window, plan, source_evidence_sha256=SOURCE_SHA256)

    with pytest.raises(WindowMaterialBindingError, match="material receipt"):
        store.attach_pool_stage_receipt(
            window.window_id,
            _pool_receipt_bytes(stored, include_material=False),
        )
    with pytest.raises(WindowMaterialBindingError, match="window material"):
        store.attach_pool_stage_receipt(
            window.window_id,
            _pool_receipt_bytes(stored, include_plan=False),
        )
    with pytest.raises(WindowMaterialBindingError, match="source evidence"):
        store.attach_pool_stage_receipt(
            window.window_id,
            _pool_receipt_bytes(stored, include_source=False),
        )

    first_receipt = _pool_receipt_bytes(stored, metadata_marker="first")
    store.attach_pool_stage_receipt(window.window_id, first_receipt)
    with pytest.raises(WindowMaterialConflict, match="another pool-stage receipt"):
        store.attach_pool_stage_receipt(
            window.window_id,
            _pool_receipt_bytes(stored, metadata_marker="second"),
        )


def test_plan_port_requires_attached_and_matching_pool_evidence(tmp_path: Path) -> None:
    plan = _plan()
    window = _window(plan)
    store = ValidatorWindowMaterialStore(tmp_path / "store")
    stored = store.put(window, plan, source_evidence_sha256=SOURCE_SHA256)

    with pytest.raises(WindowMaterialBindingError, match="no authoritative"):
        store(_work(window, pool_evidence_sha256="81" * 32))

    binding = store.attach_pool_stage_receipt(
        window.window_id,
        _pool_receipt_bytes(stored),
    )
    with pytest.raises(WindowMaterialBindingError, match="evidence disagrees"):
        store(_work(window, pool_evidence_sha256="82" * 32))
    with pytest.raises(WindowMaterialBindingError, match="pending work disagrees"):
        store(
            _work(
                replace(window, window_index=window.window_index + 1),
                pool_evidence_sha256=binding.pool_stage_evidence_sha256,
            )
        )


def test_startup_audit_detects_content_and_database_tampering(tmp_path: Path) -> None:
    root = tmp_path / "objects-tamper"
    _store, _plan_value, _window_value, stored, _binding, _receipt = _put_and_bind(root)
    material_path = root / "objects" / stored.receipt.material_sha256
    material_path.write_bytes(material_path.read_bytes() + b"x")
    with pytest.raises(WindowMaterialStoreError, match="name does not match"):
        ValidatorWindowMaterialStore(root)

    database_root = tmp_path / "database-tamper"
    _store, _plan_value, window, _stored, _binding, _receipt = _put_and_bind(database_root)
    with sqlite3.connect(database_root / "window-material.sqlite3") as connection:
        connection.execute(
            "UPDATE materials SET assignment_count = assignment_count + 1 WHERE window_id = ?",
            (window.window_id,),
        )
    with pytest.raises(WindowMaterialStoreError, match="row disagrees"):
        ValidatorWindowMaterialStore(database_root)


def test_symlink_root_database_and_object_are_rejected(tmp_path: Path) -> None:
    real_root = tmp_path / "real"
    real_root.mkdir()
    linked_root = tmp_path / "linked"
    linked_root.symlink_to(real_root, target_is_directory=True)
    with pytest.raises(WindowMaterialStoreError, match="symbolic link"):
        ValidatorWindowMaterialStore(linked_root)

    ancestor_target = tmp_path / "ancestor-target"
    ancestor_target.mkdir()
    ancestor_link = tmp_path / "ancestor-link"
    ancestor_link.symlink_to(ancestor_target, target_is_directory=True)
    with pytest.raises(WindowMaterialStoreError, match="symbolic link"):
        ValidatorWindowMaterialStore(ancestor_link / "must-not-be-created")
    assert not (ancestor_target / "must-not-be-created").exists()

    database_root = tmp_path / "database"
    database_root.mkdir()
    target_database = tmp_path / "target.sqlite3"
    target_database.write_bytes(b"")
    (database_root / "window-material.sqlite3").symlink_to(target_database)
    with pytest.raises(WindowMaterialStoreError, match="must not be a symbolic link"):
        ValidatorWindowMaterialStore(database_root)

    object_root = tmp_path / "object"
    _store, _plan_value, _window_value, stored, _binding, _receipt = _put_and_bind(object_root)
    object_path = object_root / "objects" / stored.receipt.material_sha256
    object_path.unlink()
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"not the material")
    os.symlink(replacement, object_path)
    with pytest.raises(WindowMaterialStoreError, match="cannot be opened safely"):
        ValidatorWindowMaterialStore(object_root)
