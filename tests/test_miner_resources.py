from __future__ import annotations

import hashlib
import os
import select
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from umi.config import Limits
from umi.miner_resources import (
    MinerAssignmentBinding,
    MinerResourceError,
    SQLiteMinerResourceLedger,
)

from .factories import VIDEO_BYTES, challenge_request, dev_wallet

POLICY_HASH = "20" * 32
SIGNATURE = "0x" + "11" * 64


def binding(index: int = 1) -> MinerAssignmentBinding:
    validator = dev_wallet("//Alice")
    return MinerAssignmentBinding.from_request(
        challenge_request(index, reveal_round=10_000_000_000),
        validator_hotkey=validator.hotkey.ss58_address,
    )


def custom_binding(
    index: int,
    *,
    window_id: str = "10" * 32,
    window_index: int = 0,
    video_sha256: str = "20" * 32,
    video_size_bytes: int = 10,
    response_close_round: int = 10_000_000_000,
    validator_uri: str = "//Alice",
) -> MinerAssignmentBinding:
    request = challenge_request(index, reveal_round=response_close_round + 2)
    request = request.model_copy(
        update={
            "window_id": window_id,
            "response_close_round": response_close_round,
            "reveal_round": response_close_round + 2,
            "video": request.video.model_copy(
                update={"sha256": video_sha256, "size_bytes": video_size_bytes}
            ),
        }
    )
    return MinerAssignmentBinding.from_request(
        request,
        validator_hotkey=dev_wallet(validator_uri).hotkey.ss58_address,
        window_index=window_index,
    )


def ledger(
    path: str | Path = ":memory:",
    *,
    limits: Limits | None = None,
) -> SQLiteMinerResourceLedger:
    miner = dev_wallet("//Bob")
    return SQLiteMinerResourceLedger(
        path,
        miner_hotkey=miner.hotkey.ss58_address,
        scoring_policy_sha256=POLICY_HASH,
        limits=limits or Limits(),
    )


def test_counts_request_fetch_response_and_reuses_exact_cache() -> None:
    store = ledger()
    assignment = binding()
    assert store.record_request(assignment, observed_wire_bytes=100) is None
    operation = store.begin_video_fetch(assignment)
    store.finish_video_fetch(
        operation,
        observed_wire_bytes=200,
        error_code=None,
        data=VIDEO_BYTES,
    )
    store.record_response(assignment, body=b"{}", signature=SIGNATURE)

    cached = store.record_request(assignment, observed_wire_bytes=101)
    assert cached is not None
    assert cached.body == b"{}"
    assert cached.signature == SIGNATURE
    store.record_response(assignment, body=cached.body, signature=cached.signature)

    snapshot = store.snapshot(assignment)
    assert snapshot.request_transmissions == 2
    assert snapshot.video_fetch_attempts == 1
    assert snapshot.response_bodies == 2
    assert snapshot.observed_wire_bytes == snapshot.accounted_wire_bytes
    assert snapshot.cached_response_sha256 is not None


def test_request_attempt_limit_is_transactional_under_concurrency() -> None:
    store = ledger()
    assignment = binding()

    def attempt() -> str:
        try:
            store.record_request(assignment, observed_wire_bytes=1)
        except MinerResourceError as error:
            return error.reason_code
        return "accepted"

    with ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = list(executor.map(lambda _index: attempt(), range(8)))

    assert outcomes.count("accepted") == 2
    assert outcomes.count("request_transmission_limit") == 6
    assert store.snapshot(assignment).request_transmissions == 2


def test_video_attempt_limit_is_shared_by_hash_and_window() -> None:
    store = ledger()
    first = binding(1)
    second = binding(2)
    store.record_request(first, observed_wire_bytes=1)
    store.record_request(second, observed_wire_bytes=1)
    first_operation = store.begin_video_fetch(first)
    store.finish_video_fetch(
        first_operation,
        observed_wire_bytes=len(VIDEO_BYTES),
        error_code=None,
        data=VIDEO_BYTES,
    )
    second_operation = store.begin_video_fetch(second)
    store.finish_video_fetch(
        second_operation,
        observed_wire_bytes=len(VIDEO_BYTES),
        error_code=None,
        data=VIDEO_BYTES,
    )

    with pytest.raises(MinerResourceError, match="video_fetch_attempt_limit"):
        store.begin_video_fetch(first)


def test_concurrent_shared_video_fetch_has_one_owner_without_spending_an_attempt() -> None:
    store = ledger()
    first = binding(1)
    second = binding(2)
    store.record_request(first, observed_wire_bytes=1)
    store.record_request(second, observed_wire_bytes=1)
    operation = store.begin_video_fetch(first)

    with pytest.raises(MinerResourceError, match="video_fetch_in_progress"):
        store.begin_video_fetch(second)
    assert store.snapshot(second).video_fetch_attempts == 0

    store.finish_video_fetch(
        operation,
        observed_wire_bytes=len(VIDEO_BYTES),
        error_code=None,
        data=VIDEO_BYTES,
    )
    assert store.cached_video(second) == VIDEO_BYTES


def test_verified_video_cache_is_shared_and_pruned_at_response_close() -> None:
    store = ledger()
    first = binding(1)
    second = binding(2)
    store.record_request(first, observed_wire_bytes=1)
    store.record_request(second, observed_wire_bytes=1)
    operation = store.begin_video_fetch(first)
    store.finish_video_fetch(
        operation,
        observed_wire_bytes=len(VIDEO_BYTES),
        error_code=None,
        data=VIDEO_BYTES,
    )

    assert store.cached_video(second) == VIDEO_BYTES
    assert store.prune_closed_video_cache(first.response_close_round - 1) == 0
    assert store.prune_closed_video_cache(first.response_close_round) == 1
    assert store.cached_video(second) is None


def test_assignment_binding_cannot_be_rewritten() -> None:
    store = ledger()
    assignment = binding()
    store.record_request(assignment, observed_wire_bytes=1)
    conflicting = replace(assignment, request_digest="99" * 32)
    with pytest.raises(MinerResourceError, match="assignment_binding_conflict"):
        store.record_request(conflicting, observed_wire_bytes=1)


def test_one_validator_cannot_rebind_video_metadata_within_a_window() -> None:
    store = ledger()
    first = binding(1)
    second = replace(binding(2), response_close_round=first.response_close_round + 1)
    store.record_request(first, observed_wire_bytes=1)
    with pytest.raises(MinerResourceError, match="validator_video_binding_conflict"):
        store.record_request(second, observed_wire_bytes=1)


def test_wrong_size_preclaim_cannot_poison_another_validator() -> None:
    store = ledger()
    attacker = custom_binding(
        1,
        video_sha256=hashlib.sha256(VIDEO_BYTES).hexdigest(),
        video_size_bytes=len(VIDEO_BYTES) + 1,
        validator_uri="//Alice",
    )
    honest = custom_binding(
        2,
        video_sha256=hashlib.sha256(VIDEO_BYTES).hexdigest(),
        video_size_bytes=len(VIDEO_BYTES),
        validator_uri="//Charlie",
    )

    store.record_request(attacker, observed_wire_bytes=1)
    store.record_request(honest, observed_wire_bytes=1)
    operation = store.begin_video_fetch(honest)
    store.finish_video_fetch(
        operation,
        observed_wire_bytes=len(VIDEO_BYTES),
        error_code=None,
        data=VIDEO_BYTES,
    )

    assert store.cached_video(honest) == VIDEO_BYTES
    with pytest.raises(MinerResourceError, match="video_cache_invalid"):
        store.cached_video(attacker)


def test_failed_fetch_budget_cannot_poison_another_validator() -> None:
    store = ledger()
    attacker = custom_binding(
        1,
        video_sha256=hashlib.sha256(VIDEO_BYTES).hexdigest(),
        video_size_bytes=len(VIDEO_BYTES),
        validator_uri="//Alice",
    )
    honest = custom_binding(
        2,
        video_sha256=hashlib.sha256(VIDEO_BYTES).hexdigest(),
        video_size_bytes=len(VIDEO_BYTES),
        validator_uri="//Charlie",
    )
    store.record_request(attacker, observed_wire_bytes=1)
    store.record_request(honest, observed_wire_bytes=1)
    for _ in range(2):
        operation = store.begin_video_fetch(attacker)
        store.finish_video_fetch(
            operation,
            observed_wire_bytes=0,
            error_code="video_fetch_failed",
        )
    with pytest.raises(MinerResourceError, match="video_fetch_attempt_limit"):
        store.begin_video_fetch(attacker)

    operation = store.begin_video_fetch(honest)
    store.finish_video_fetch(
        operation,
        observed_wire_bytes=len(VIDEO_BYTES),
        error_code=None,
        data=VIDEO_BYTES,
    )
    assert store.cached_video(honest) == VIDEO_BYTES


def test_only_one_authoritative_window_can_reserve_resources_until_close() -> None:
    store = ledger()
    first = custom_binding(1, response_close_round=100)
    second = custom_binding(
        2,
        window_id="11" * 32,
        window_index=1,
        response_close_round=200,
    )
    store.record_request(first, observed_wire_bytes=1, current_round=99)

    with pytest.raises(MinerResourceError, match="active_window_limit"):
        store.record_request(second, observed_wire_bytes=1, current_round=99)

    assert store.record_request(second, observed_wire_bytes=1, current_round=100) is None
    with pytest.raises(MinerResourceError, match="assignment_not_recorded"):
        store.snapshot(first)


def test_global_unique_video_and_retained_byte_caps_precede_fetch() -> None:
    selected_limits = Limits(
        maximum_unique_videos_per_window=2,
        maximum_retained_video_bytes=25,
    )
    store = ledger(limits=selected_limits)
    store.record_request(
        custom_binding(1, video_sha256="31" * 32, video_size_bytes=10),
        observed_wire_bytes=1,
    )
    store.record_request(
        custom_binding(2, video_sha256="32" * 32, video_size_bytes=10),
        observed_wire_bytes=1,
    )
    with pytest.raises(MinerResourceError, match="unique_video_count_limit"):
        store.record_request(
            custom_binding(3, video_sha256="33" * 32, video_size_bytes=1),
            observed_wire_bytes=1,
        )

    bytes_store = ledger(
        limits=Limits(
            maximum_unique_videos_per_window=3,
            maximum_retained_video_bytes=25,
        )
    )
    bytes_store.record_request(
        custom_binding(1, video_sha256="41" * 32, video_size_bytes=20),
        observed_wire_bytes=1,
    )
    with pytest.raises(MinerResourceError, match="retained_video_byte_limit"):
        bytes_store.record_request(
            custom_binding(2, video_sha256="42" * 32, video_size_bytes=6),
            observed_wire_bytes=1,
        )


def test_validator_video_partition_prevents_one_validator_from_spending_anothers_quota() -> None:
    selected_limits = Limits(
        maximum_unique_videos_per_validator_window=1,
        maximum_retained_video_bytes_per_validator_window=10,
        maximum_unique_videos_per_window=2,
        maximum_retained_video_bytes=20,
    )
    store = ledger(limits=selected_limits)
    store.record_request(
        custom_binding(1, video_sha256="51" * 32, video_size_bytes=10),
        observed_wire_bytes=1,
    )
    with pytest.raises(MinerResourceError, match="validator_unique_video_count_limit"):
        store.record_request(
            custom_binding(2, video_sha256="52" * 32, video_size_bytes=1),
            observed_wire_bytes=1,
        )

    assert (
        store.record_request(
            custom_binding(
                2,
                video_sha256="52" * 32,
                video_size_bytes=10,
                validator_uri="//Charlie",
            ),
            observed_wire_bytes=1,
        )
        is None
    )


def test_total_assignment_cap_is_independent_of_validator_namespace() -> None:
    selected_limits = Limits(
        maximum_assignments_per_validator_window=10,
        maximum_total_assignments_per_window=2,
    )
    store = ledger(limits=selected_limits)
    store.record_request(custom_binding(1), observed_wire_bytes=1)
    store.record_request(custom_binding(2), observed_wire_bytes=1)
    with pytest.raises(MinerResourceError, match="total_assignment_count_limit"):
        store.record_request(custom_binding(3), observed_wire_bytes=1)


def test_closed_request_is_rejected_without_leaving_a_ledger_row() -> None:
    store = ledger()
    assignment = custom_binding(1, response_close_round=100)
    with pytest.raises(MinerResourceError, match="response_window_closed"):
        store.record_request(assignment, observed_wire_bytes=1, current_round=100)
    with pytest.raises(MinerResourceError, match="assignment_not_recorded"):
        store.snapshot(assignment)


def test_response_cache_cannot_change_between_retries() -> None:
    store = ledger()
    assignment = binding()
    store.record_request(assignment, observed_wire_bytes=1)
    store.record_response(assignment, body=b"first", signature=SIGNATURE)
    store.record_request(assignment, observed_wire_bytes=1)
    with pytest.raises(MinerResourceError, match="cached_response_conflict"):
        store.record_response(assignment, body=b"second", signature=SIGNATURE)
    assert store.snapshot(assignment).response_bodies == 1


def test_assignment_wire_reservation_fails_before_video_io() -> None:
    selected_limits = Limits(maximum_assignment_wire_bytes=100)
    store = ledger(limits=selected_limits)
    assignment = binding()
    store.record_request(assignment, observed_wire_bytes=1)
    with pytest.raises(MinerResourceError, match="assignment_wire_limit"):
        store.begin_video_fetch(assignment)
    assert store.snapshot(assignment).video_fetch_attempts == 0


def test_violating_peer_bytes_replace_a_smaller_fetch_reservation_exactly() -> None:
    store = ledger()
    assignment = binding()
    store.record_request(assignment, observed_wire_bytes=1)
    operation = store.begin_video_fetch(assignment)
    observed = operation.reserved_wire_bytes + 1
    store.finish_video_fetch(
        operation,
        observed_wire_bytes=observed,
        error_code="oversized_headers",
    )

    snapshot = store.snapshot(assignment)
    assert snapshot.accounted_wire_bytes == 1 + observed
    assert snapshot.observed_wire_bytes == 1 + observed


def test_restart_preserves_cache_and_conservatively_settles_pending_fetch(
    tmp_path: Path,
) -> None:
    path = tmp_path / "miner.sqlite3"
    assignment = binding()
    first = ledger(path)
    first.record_request(assignment, observed_wire_bytes=1)
    operation = first.begin_video_fetch(assignment)
    reserved = operation.reserved_wire_bytes
    first.close()

    restarted = ledger(path)
    snapshot = restarted.snapshot(assignment)
    assert snapshot.video_fetch_attempts == 1
    assert snapshot.accounted_wire_bytes == 1 + reserved
    assert snapshot.observed_wire_bytes == 1
    second = restarted.begin_video_fetch(assignment)
    restarted.finish_video_fetch(
        second,
        observed_wire_bytes=assignment.video_size_bytes,
        error_code=None,
        data=VIDEO_BYTES,
    )


def test_cancelled_fetch_retains_reservation_and_releases_shared_claim() -> None:
    store = ledger()
    first = binding(1)
    second = binding(2)
    store.record_request(first, observed_wire_bytes=1)
    store.record_request(second, observed_wire_bytes=1)
    operation = store.begin_video_fetch(first)
    store.abandon_video_fetch(operation, error_code="cancelled")

    snapshot = store.snapshot(first)
    assert snapshot.accounted_wire_bytes == 1 + operation.reserved_wire_bytes
    assert snapshot.observed_wire_bytes == 1
    assert store.begin_video_fetch(second).sequence == 1


def test_reopen_rejects_policy_or_miner_identity_drift(tmp_path: Path) -> None:
    path = tmp_path / "miner.sqlite3"
    first = ledger(path)
    first.close()
    other_miner = dev_wallet("//Charlie")
    with pytest.raises(MinerResourceError, match="resource_ledger_identity_conflict"):
        SQLiteMinerResourceLedger(
            path,
            miner_hotkey=other_miner.hotkey.ss58_address,
            scoring_policy_sha256=POLICY_HASH,
            limits=Limits(),
        )


def test_startup_detects_counter_tampering(tmp_path: Path) -> None:
    path = tmp_path / "miner.sqlite3"
    assignment = binding()
    first = ledger(path)
    first.record_request(assignment, observed_wire_bytes=1)
    first.close()
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE assignments SET accounted_wire_bytes = 2 WHERE assignment_id = ?",
            (assignment.assignment_id,),
        )
    with pytest.raises(MinerResourceError, match="resource_ledger_counter_mismatch"):
        ledger(path)


def test_startup_detects_cached_video_tampering(tmp_path: Path) -> None:
    path = tmp_path / "miner.sqlite3"
    assignment = binding()
    first = ledger(path)
    first.record_request(assignment, observed_wire_bytes=1)
    operation = first.begin_video_fetch(assignment)
    first.finish_video_fetch(
        operation,
        observed_wire_bytes=len(VIDEO_BYTES),
        error_code=None,
        data=VIDEO_BYTES,
    )
    first.close()
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE videos SET body = ?", (b"tampered",))
    with pytest.raises(MinerResourceError, match="video_cache_invalid"):
        ledger(path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file-mode assertion")
def test_database_and_wal_files_are_private(tmp_path: Path) -> None:
    path = tmp_path / "miner.sqlite3"
    store = ledger(path)
    assignment = binding()
    store.record_request(assignment, observed_wire_bytes=1)

    for candidate in (
        path,
        Path(str(path) + "-wal"),
        Path(str(path) + "-shm"),
        Path(str(path) + ".lock"),
    ):
        if candidate.exists():
            assert candidate.stat().st_mode & 0o777 == 0o600
    store.close()


@pytest.mark.skipif(os.name != "posix", reason="POSIX file-mode assertion")
def test_database_rejects_symlinks_hardlinks_and_public_modes(tmp_path: Path) -> None:
    target = tmp_path / "target.sqlite3"
    target.write_bytes(b"not a database")
    target.chmod(0o600)

    symlink = tmp_path / "symlink.sqlite3"
    symlink.symlink_to(target)
    with pytest.raises(MinerResourceError, match="resource_ledger_database"):
        ledger(symlink)

    hardlink = tmp_path / "hardlink.sqlite3"
    os.link(target, hardlink)
    with pytest.raises(MinerResourceError, match="resource_ledger_database_unsafe"):
        ledger(hardlink)

    public = tmp_path / "public.sqlite3"
    public.touch(mode=0o644)
    public.chmod(0o644)
    with pytest.raises(MinerResourceError, match="resource_ledger_database_unsafe"):
        ledger(public)


@pytest.mark.skipif(os.name != "posix", reason="POSIX file-mode assertion")
def test_database_rejects_an_unsafe_parent_or_auxiliary_file(tmp_path: Path) -> None:
    public_parent = tmp_path / "public"
    public_parent.mkdir(mode=0o755)
    public_parent.chmod(0o755)
    with pytest.raises(MinerResourceError, match="resource_ledger_parent_unsafe"):
        ledger(public_parent / "miner.sqlite3")

    path = tmp_path / "miner.sqlite3"
    first = ledger(path)
    first.close()
    target = tmp_path / "foreign-wal"
    target.touch(mode=0o600)
    target.chmod(0o600)
    Path(f"{path}-wal").symlink_to(target)
    with pytest.raises(MinerResourceError, match="resource_ledger_database_unsafe"):
        ledger(path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX advisory-lock assertion")
def test_database_lock_excludes_another_process_and_survives_unclean_exit(
    tmp_path: Path,
) -> None:
    path = tmp_path / "miner.sqlite3"
    miner_hotkey = dev_wallet("//Bob").hotkey.ss58_address
    child_code = "\n".join(
        (
            "import sys",
            "from umi.config import Limits",
            "from umi.miner_resources import SQLiteMinerResourceLedger",
            "store = SQLiteMinerResourceLedger(",
            "    sys.argv[1],",
            "    miner_hotkey=sys.argv[2],",
            "    scoring_policy_sha256=sys.argv[3],",
            "    limits=Limits(),",
            ")",
            "print('ready', flush=True)",
            "sys.stdin.readline()",
            "store.close()",
        )
    )
    process = subprocess.Popen(
        [sys.executable, "-c", child_code, str(path), miner_hotkey, POLICY_HASH],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        ready, _, _ = select.select((process.stdout,), (), (), 10)
        if not ready:
            process.terminate()
            _, errors = process.communicate(timeout=5)
            pytest.fail(f"ledger holder did not start: {errors}")
        assert process.stdout.readline() == "ready\n"

        with pytest.raises(MinerResourceError, match="resource_ledger_already_open"):
            ledger(path)
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)

    reopened = ledger(path)
    reopened.close()
    assert Path(str(path) + ".lock").exists()
