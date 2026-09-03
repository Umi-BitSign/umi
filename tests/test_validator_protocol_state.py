from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from fractions import Fraction
from pathlib import Path
from threading import Barrier
from typing import Any

import pytest

from umi.protocol import base64url_encode, canonical_json_bytes
from umi.registries import (
    PublisherFaultFinding,
    PublisherFaultReason,
    SpentCohortBatch,
)
from umi.rolling import AssignmentScore, ScoredBatch
from umi.validator_protocol_state import (
    ProtocolStateConflict,
    ProtocolStateCorruption,
    ProtocolStateLimitError,
    ProtocolStatePolicyLimits,
    ProtocolStateStoreBounds,
    ProtocolStateStoreError,
    ValidatorProtocolStateStore,
)

ROOT_A = b"A" * 32
ROOT_B = b"B" * 32
STRATA = ("fingerspelling", "short_utterance", "continuous")
LIMITS = ProtocolStatePolicyLimits(
    rolling_batch_count=4,
    score_max_age_windows=2,
    publisher_fault_cooldown_windows=3,
)


def _hash(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


def _window_id(window_index: int, suffix: str = "") -> bytes:
    return _hash(f"window-{window_index}{suffix}")


def _challenge_bytes(window_index: int, pool_ordinal: int, ordinal: int) -> bytes:
    return (
        window_index.to_bytes(8, "big")
        + pool_ordinal.to_bytes(4, "big")
        + ordinal.to_bytes(4, "big")
    )


def _scored_batch(
    window_index: int,
    pool_ordinal: int,
    *,
    roots: tuple[bytes, ...] = (ROOT_A, ROOT_B),
) -> ScoredBatch:
    challenge_bytes = tuple(
        _challenge_bytes(window_index, pool_ordinal, ordinal) for ordinal in range(4)
    )
    challenge_ids = tuple(base64url_encode(value) for value in challenge_bytes)
    scores = (Fraction(1, 3), Fraction(2, 7), Fraction(5, 11))
    assignments = tuple(
        AssignmentScore(
            miner_root=root,
            challenge_id=challenge_ids[ordinal],
            request_leaf=hashlib.sha256(b"request\0" + root + challenge_bytes[ordinal]).digest(),
            stratum=(STRATA[ordinal] if ordinal < 3 else "continuous"),  # type: ignore[arg-type]
            canary=ordinal == 3,
            score=None if ordinal == 3 else scores[ordinal],
        )
        for root in sorted(roots)
        for ordinal in range(4)
    )
    return ScoredBatch(
        window_index=window_index,
        batch_rank=bytes([pool_ordinal]) * 32,
        pool_leaf=_hash(f"pool-{window_index}-{pool_ordinal}"),
        challenge_ids=challenge_ids,
        miner_roots=tuple(sorted(roots)),
        assignments=assignments,
    )


def _scored_window(window_index: int) -> tuple[ScoredBatch, ScoredBatch]:
    return (
        _scored_batch(window_index, 1),
        _scored_batch(window_index, 2),
    )


def _issued_roots(batches: tuple[ScoredBatch, ...]) -> tuple[bytes, ...]:
    return tuple(sorted(assignment.root for batch in batches for assignment in batch.assignments))


def _spent_batch(
    ordinal: int,
    *,
    video_hash: bytes | None = None,
) -> SpentCohortBatch:
    return SpentCohortBatch(
        batch_commitment=_hash(f"commitment-{ordinal}"),
        video_hashes=(video_hash or _hash(f"video-{ordinal}"),),
        frame_digests=(_hash(f"frame-{ordinal}"),),
        revealed_script_hashes=(_hash(f"script-{ordinal}"),),
    )


def _sorted_spent(*batches: SpentCohortBatch) -> tuple[SpentCohortBatch, ...]:
    return tuple(sorted(batches, key=lambda batch: bytes(batch.batch_commitment)))


def _fault(window_index: int, ordinal: int = 0) -> PublisherFaultFinding:
    return PublisherFaultFinding(
        control_group_id=_hash(f"group-{ordinal}"),
        publisher_hotkey=_hash(f"publisher-{ordinal}"),
        window_id=_window_id(window_index),
        batch_commitment=_hash(f"fault-batch-{window_index}-{ordinal}"),
        reason=PublisherFaultReason.COMMITTED_BINDING_MISMATCH,
        reason_code=3,
    )


def _window_kwargs(
    window_index: int,
    *,
    operation_suffix: str = "",
    window_suffix: str = "",
    spent: tuple[SpentCohortBatch, ...] = (),
    faults: tuple[PublisherFaultFinding, ...] = (),
    scored: tuple[ScoredBatch, ...] = (),
    issued: tuple[bytes, ...] | None = None,
    limits: ProtocolStatePolicyLimits = LIMITS,
) -> dict[str, Any]:
    return {
        "operation_id": _hash(f"operation-{window_index}{operation_suffix}"),
        "window_index": window_index,
        "window_id": _window_id(window_index, window_suffix),
        "reveal_round": 10_000 + window_index,
        "evidence_digest": _hash(f"evidence-{window_index}{operation_suffix}"),
        "spent_cohort_batches": spent,
        "objective_fault_findings": faults,
        "scored_batches": scored,
        "issued_miner_roots": _issued_roots(scored) if issued is None else issued,
        "policy_limits": limits,
    }


def _database_path(tmp_path: Path, name: str = "protocol-state.sqlite3") -> Path:
    return (tmp_path / name).resolve()


def test_valid_void_and_skipped_windows_advance_every_protocol_state(tmp_path: Path) -> None:
    path = _database_path(tmp_path)
    first_scored = _scored_window(0)
    first_spent = _sorted_spent(_spent_batch(1), _spent_batch(2))

    with ValidatorProtocolStateStore(path) as store:
        valid = store.apply_window(**_window_kwargs(0, spent=first_spent, scored=first_scored))
        assert valid.snapshot.rolling_scores.batches == first_scored
        assert valid.snapshot.spent_registry.last_reveal_round == 10_000
        assert valid.snapshot.assigned_observation_count(ROOT_A) == 8
        assert valid.snapshot.assigned_observation_count(ROOT_B) == 8

        finding = _fault(1)
        void = store.apply_window(
            **_window_kwargs(
                1,
                faults=(finding,),
                issued=(ROOT_A, ROOT_A, ROOT_B),
            )
        )
        assert void.snapshot.rolling_scores.batches == first_scored
        assert void.snapshot.assigned_observation_count(ROOT_A) == 10
        assert void.snapshot.assigned_observation_count(ROOT_B) == 9
        assert void.snapshot.publisher_faults.strikes == ((finding.control_group_id, 1),)

        skipped = store.apply_window(**_window_kwargs(2))
        assert skipped.snapshot.last_window_index == 2
        assert skipped.snapshot.spent_registry.last_reveal_round == 10_002
        assert skipped.snapshot.publisher_faults.last_window_index == 2
        assert skipped.snapshot.rolling_scores.batches == ()
        assert skipped.snapshot.assigned_observation_count(ROOT_A) == 10
        assert skipped.snapshot.assigned_observation_count(ROOT_B) == 9
        assert store.audit() == skipped.snapshot

        result = json.loads(skipped.result_bytes)
        assert canonical_json_bytes(result) == skipped.result_bytes
        assert result["assigned_observations"]["issued_request_count"] == 0


def test_restart_recovers_exact_fractions_and_all_normalized_state(tmp_path: Path) -> None:
    path = _database_path(tmp_path)
    scored = _scored_window(0)
    with ValidatorProtocolStateStore(path) as store:
        applied = store.apply_window(
            **_window_kwargs(0, spent=_sorted_spent(_spent_batch(3)), scored=scored)
        )
        expected = applied.snapshot

    with ValidatorProtocolStateStore(path) as recovered:
        assert recovered.snapshot == expected
        assignments = recovered.snapshot.rolling_scores.batches[0].assignments
        assert assignments[0].score == Fraction(1, 3)
        assert assignments[1].score == Fraction(2, 7)
        assert assignments[2].score == Fraction(5, 11)
        assert assignments[3].score is None
        assert recovered.audit() == expected


def test_idempotent_retry_and_conflicting_replays_fail_closed(tmp_path: Path) -> None:
    path = _database_path(tmp_path)
    kwargs = _window_kwargs(0)
    with ValidatorProtocolStateStore(path) as store:
        first = store.apply_window(**kwargs)
        retry = store.apply_window(**kwargs)
        assert retry.idempotent
        assert retry.request_bytes == first.request_bytes
        assert retry.result_bytes == first.result_bytes
        assert retry.snapshot == first.snapshot

        changed = dict(kwargs)
        changed["evidence_digest"] = _hash("different-evidence")
        with pytest.raises(ProtocolStateConflict) as operation_conflict:
            store.apply_window(**changed)
        assert operation_conflict.value.reason_code == "operation_id_conflict"

        with pytest.raises(ProtocolStateConflict) as window_conflict:
            store.apply_window(
                **_window_kwargs(0, operation_suffix="-other", window_suffix="-other")
            )
        assert window_conflict.value.reason_code == "window_replay_conflict"
        assert store.snapshot == first.snapshot


def test_duplicate_inputs_roll_back_and_spent_collisions_are_recorded(tmp_path: Path) -> None:
    path = _database_path(tmp_path)
    duplicate = _spent_batch(5)
    with ValidatorProtocolStateStore(path) as store:
        with pytest.raises(ValueError, match="duplicate batch commitment"):
            store.apply_window(**_window_kwargs(0, spent=_sorted_spent(duplicate, duplicate)))
        assert store.snapshot.last_window_index == -1

        first = store.apply_window(**_window_kwargs(0, spent=_sorted_spent(duplicate)))
        colliding = _spent_batch(6, video_hash=bytes(duplicate.video_hashes[0]))
        second = store.apply_window(**_window_kwargs(1, spent=_sorted_spent(colliding)))
        result = json.loads(second.result_bytes)
        assert result["spent"]["has_eligibility_fault"] is True
        assert len(result["spent"]["prior_collisions"]) == 1
        assert first.snapshot.spent_registry.leaves < second.snapshot.spent_registry.leaves


def test_unsorted_and_duplicate_canonical_collections_are_rejected(tmp_path: Path) -> None:
    path = _database_path(tmp_path)
    first, second = _sorted_spent(_spent_batch(7), _spent_batch(8))
    finding = _fault(0)
    with ValidatorProtocolStateStore(path) as store:
        with pytest.raises(ValueError, match="sorted by batch commitment"):
            store.apply_window(**_window_kwargs(0, spent=(second, first)))
        with pytest.raises(ValueError, match="unique and sorted"):
            store.apply_window(**_window_kwargs(0, faults=(finding, finding)))
        with pytest.raises(ValueError, match="issued miner roots must be sorted"):
            store.apply_window(**_window_kwargs(0, issued=(ROOT_B, ROOT_A)))
        assert store.snapshot.last_window_index == -1


@pytest.mark.parametrize("target", ["checkpoint", "normalized"])
def test_startup_audit_detects_checkpoint_or_current_table_corruption(
    tmp_path: Path,
    target: str,
) -> None:
    path = _database_path(tmp_path, f"{target}.sqlite3")
    with ValidatorProtocolStateStore(path) as store:
        store.apply_window(
            **_window_kwargs(0, spent=_sorted_spent(_spent_batch(9)), scored=_scored_window(0))
        )
        store.apply_window(**_window_kwargs(1, issued=(ROOT_A, ROOT_A)))

    connection = sqlite3.connect(path)
    try:
        if target == "checkpoint":
            encoded = connection.execute(
                "SELECT result_bytes FROM operations WHERE window_index = 0"
            ).fetchone()[0]
            corrupted = bytes(encoded) + b" "
            connection.execute(
                "UPDATE operations SET result_bytes = ?, result_sha256 = ? WHERE window_index = 0",
                (corrupted, hashlib.sha256(corrupted).digest()),
            )
        else:
            connection.execute(
                "UPDATE assigned_observation_counts SET assigned_count = '999' "
                "WHERE miner_root = ?",
                (ROOT_A,),
            )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(ProtocolStateCorruption):
        ValidatorProtocolStateStore(path)


def test_concurrent_writers_serialize_and_loser_adopts_committed_head(tmp_path: Path) -> None:
    path = _database_path(tmp_path)
    first_store = ValidatorProtocolStateStore(path)
    second_store = ValidatorProtocolStateStore(path)
    barrier = Barrier(2)

    def apply(store: ValidatorProtocolStateStore, suffix: str) -> object:
        barrier.wait()
        try:
            return store.apply_window(
                **_window_kwargs(0, operation_suffix=suffix, window_suffix=suffix)
            )
        except Exception as error:  # returned so both futures always join
            return error

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = (
                executor.submit(apply, first_store, "-a"),
                executor.submit(apply, second_store, "-b"),
            )
            outcomes = tuple(future.result(timeout=15) for future in futures)
        assert sum(not isinstance(outcome, Exception) for outcome in outcomes) == 1
        conflicts = [outcome for outcome in outcomes if isinstance(outcome, Exception)]
        assert len(conflicts) == 1
        assert isinstance(conflicts[0], ProtocolStateConflict)
        assert first_store.snapshot.last_window_index == 0
        assert second_store.snapshot.last_window_index == 0
    finally:
        first_store.close()
        second_store.close()

    with ValidatorProtocolStateStore(path) as recovered:
        assert recovered.snapshot.last_window_index == 0
        assert recovered.audit() == recovered.snapshot


def test_write_failure_rolls_back_log_and_every_normalized_table(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _database_path(tmp_path)
    with ValidatorProtocolStateStore(path) as store:
        original = store._write_current_state_locked

        def fail_after_writes(transition: object) -> None:
            original(transition)  # type: ignore[arg-type]
            raise RuntimeError("injected write failure")

        monkeypatch.setattr(store, "_write_current_state_locked", fail_after_writes)
        with pytest.raises(RuntimeError, match="injected write failure"):
            store.apply_window(
                **_window_kwargs(
                    0,
                    spent=_sorted_spent(_spent_batch(10)),
                    scored=_scored_window(0),
                )
            )
        assert store.snapshot.last_window_index == -1
        assert store.audit().last_window_index == -1
        assert store._connection.execute("SELECT count(*) FROM operations").fetchone()[0] == 0

        monkeypatch.setattr(store, "_write_current_state_locked", original)
        assert store.apply_window(**_window_kwargs(0)).snapshot.last_window_index == 0


def test_request_and_result_byte_limits_fail_before_commit(tmp_path: Path) -> None:
    request_path = _database_path(tmp_path, "request.sqlite3")
    request_bounds = replace(ProtocolStateStoreBounds(), maximum_request_bytes=128)
    with ValidatorProtocolStateStore(request_path, bounds=request_bounds) as store:
        with pytest.raises(ProtocolStateLimitError) as error:
            store.apply_window(**_window_kwargs(0))
        assert error.value.reason_code == "canonical_request_size_limit"
        assert store.snapshot.last_window_index == -1

    result_path = _database_path(tmp_path, "result.sqlite3")
    result_bounds = replace(ProtocolStateStoreBounds(), maximum_result_bytes=128)
    with ValidatorProtocolStateStore(result_path, bounds=result_bounds) as store:
        with pytest.raises(ProtocolStateLimitError) as error:
            store.apply_window(**_window_kwargs(0))
        assert error.value.reason_code == "canonical_result_size_limit"
        assert store.audit().last_window_index == -1


def test_database_path_rejects_relative_symlink_and_unsafe_parent(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="absolute"):
        ValidatorProtocolStateStore(Path("relative.sqlite3"))

    real_path = _database_path(tmp_path, "real.sqlite3")
    real_path.write_bytes(b"")
    os.chmod(real_path, 0o600)
    symlink_path = tmp_path / "linked.sqlite3"
    symlink_path.symlink_to(real_path)
    with pytest.raises(ProtocolStateStoreError) as symlink_error:
        ValidatorProtocolStateStore(symlink_path.absolute())
    assert symlink_error.value.reason_code == "unsafe_database_file"

    unsafe_parent = tmp_path / "unsafe"
    unsafe_parent.mkdir(mode=0o700)
    os.chmod(unsafe_parent, 0o777)
    try:
        with pytest.raises(ProtocolStateStoreError) as parent_error:
            ValidatorProtocolStateStore((unsafe_parent / "state.sqlite3").absolute())
        assert parent_error.value.reason_code == "unsafe_database_parent"
    finally:
        os.chmod(unsafe_parent, 0o700)


def test_sqlite_durability_and_integrity_pragmas_are_live(tmp_path: Path) -> None:
    with ValidatorProtocolStateStore(_database_path(tmp_path)) as store:
        connection = store._connection
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
