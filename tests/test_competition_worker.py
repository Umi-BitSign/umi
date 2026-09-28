from __future__ import annotations

import fcntl
import os
import sqlite3

import pytest

from umi.competition_package import prepare_competition_package
from umi.competition_publication import (
    PublicationJournal,
    PublicationJournalCapacity,
    build_cutoff_publication,
)
from umi.competition_worker import (
    CompetitionReplayWorker,
    CompetitionWorkerBusyError,
    CompetitionWorkerCapacity,
    CompetitionWorkerCapacityError,
    competition_worker_receipt_digest,
)
from umi.protocol import canonical_json_bytes

from .test_competition_package import carried_package as carried_package
from .test_competition_package import package_case as package_case
from .test_competition_package import package_limits as package_limits
from .test_competition_package import release_identity as release_identity
from .test_competition_publication import _certificate
from .test_competition_publication import replay_limits as replay_limits
from .test_open_competition import digest
from .test_open_competition import policy as policy


@pytest.fixture
def worker_capacity() -> CompetitionWorkerCapacity:
    return CompetitionWorkerCapacity(
        maximum_receipts=20,
        maximum_bytes=10_000_000,
        publication_journal=PublicationJournalCapacity(
            maximum_certificates=20,
            maximum_bytes=50_000_000,
        ),
    )


def _worker(tmp_path, package_limits, worker_capacity, name="worker"):
    return CompetitionReplayWorker(
        tmp_path / name,
        package_limits=package_limits,
        capacity=worker_capacity,
    )


def _run(worker, case, policy, release_identity):
    return worker.run(
        case.path,
        expected_package_sha256=case.prepared.package_sha256,
        expected_policy_sha256=digest(policy),
        observed_release=release_identity,
    )


def test_carried_package_worker_replays_and_restarts_without_registry(
    carried_package, package_limits, worker_capacity, release_identity, tmp_path
):
    from umi.competition_policy_lineage import clear_lineage_registry, registered_lineage

    case = carried_package
    clear_lineage_registry()
    first = _run(
        _worker(tmp_path, package_limits, worker_capacity), case, case.policy, release_identity
    )
    clear_lineage_registry()
    second = _run(
        _worker(tmp_path, package_limits, worker_capacity), case, case.policy, release_identity
    )
    assert first.receipt == second.receipt
    assert registered_lineage(case.policy).admitted_policy_sha256s == (digest(case.policy),)


def _record_cutoff_conflict(worker, case, policy, replay_limits):
    scenario = case.scenario
    alternate_snapshot = scenario.cutoff_publication.registration_snapshot.model_copy(
        update={"block_hash": "0x" + "ff" * 32}
    )
    publication = build_cutoff_publication(
        round_=scenario.round,
        cutoff_schedule=scenario.schedule,
        registration_snapshot=alternate_snapshot,
        submissions=scenario.submissions,
        policy=policy,
        limits=replay_limits,
    )
    certificate = _certificate(publication)
    journal = PublicationJournal(
        worker.publication_root / digest(policy),
        policy,
        capacity=worker.capacity.publication_journal,
    )
    return journal.record_cutoff(
        certificate,
        submissions=scenario.submissions,
        limits=replay_limits,
    )


def _variant_package(case, policy, replay_limits, package_limits, release_identity):
    changed_release = release_identity.model_copy(update={"release_bundle_sha256": "12" * 32})
    scenario = case.scenario
    prepared = prepare_competition_package(
        policy=policy,
        cutoff_certificate=scenario.cutoff_certificate,
        settlement_certificate=scenario.settlement_certificate,
        retained_settlement=scenario.settlement,
        roster=scenario.submissions,
        evidence=scenario.evidence,
        replay_limits=replay_limits,
        release_identity=changed_release,
        destination_root=case.path.parent,
        limits=package_limits,
    )
    return case.path.with_name(prepared.package_sha256), prepared, changed_release


def test_first_run_and_exact_restart_return_the_same_receipt(
    package_case, policy, package_limits, release_identity, worker_capacity, tmp_path
):
    worker = _worker(tmp_path, package_limits, worker_capacity)
    first = _run(worker, package_case, policy, release_identity)
    restarted = _worker(tmp_path, package_limits, worker_capacity)
    second = _run(restarted, package_case, policy, release_identity)

    assert first.receipt.status == "replayed_no_weight"
    assert first.current_status.held is False
    assert first.receipt == second.receipt
    assert first.current_status == second.current_status
    assert first.receipt.chain_submission_authorized is False
    assert first.receipt.runtime_identity_authenticated is False


@pytest.mark.parametrize("restart", [False, True])
def test_completed_replay_reuses_publications_after_retry_or_restart(
    package_case,
    policy,
    package_limits,
    release_identity,
    worker_capacity,
    tmp_path,
    monkeypatch,
    restart,
):
    worker = _worker(tmp_path, package_limits, worker_capacity)
    first = _run(worker, package_case, policy, release_identity)

    def duplicate(*args, **kwargs):
        raise AssertionError("completed evidence must not be replayed into the journal again")

    monkeypatch.setattr(PublicationJournal, "record_cutoff", duplicate)
    monkeypatch.setattr(PublicationJournal, "record_settlement", duplicate)
    if restart:
        worker = _worker(tmp_path, package_limits, worker_capacity)
    second = _run(worker, package_case, policy, release_identity)
    assert second == first
    worker.verify_publication_unchanged(second)


def test_completed_replay_still_rejects_changed_package_bytes(
    package_case,
    policy,
    package_limits,
    release_identity,
    worker_capacity,
    tmp_path,
):
    worker = _worker(tmp_path, package_limits, worker_capacity)
    _run(worker, package_case, policy, release_identity)
    manifest = package_case.path / "manifest.json"
    manifest.chmod(0o600)
    original = manifest.read_bytes()
    try:
        manifest.write_bytes(original + b" ")
        manifest.chmod(0o400)
        with pytest.raises(ValueError):
            _run(worker, package_case, policy, release_identity)
    finally:
        manifest.chmod(0o600)
        manifest.write_bytes(original)
        manifest.chmod(0o400)


def test_cached_receipt_gets_fresh_conflict_status_after_restart(
    package_case,
    policy,
    replay_limits,
    package_limits,
    release_identity,
    worker_capacity,
    tmp_path,
    monkeypatch,
):
    worker = _worker(tmp_path, package_limits, worker_capacity)
    first = _run(worker, package_case, policy, release_identity)
    conflict = _record_cutoff_conflict(worker, package_case, policy, replay_limits)
    assert conflict["held"] is True

    def forbidden(*_args, **_kwargs):
        raise AssertionError("cached worker receipt was replaced")

    monkeypatch.setattr(worker, "_new_receipt", forbidden)
    second = _run(worker, package_case, policy, release_identity)
    restarted = _worker(tmp_path, package_limits, worker_capacity)
    third = _run(restarted, package_case, policy, release_identity)

    assert second.receipt == first.receipt == third.receipt
    assert first.current_status.held is False
    assert second.current_status.held is True
    assert third.current_status.held is True
    assert second.current_status.publication_conflicts == 1


def test_receipt_capacity_never_evicts_and_exact_retry_still_works(
    package_case,
    policy,
    replay_limits,
    package_limits,
    release_identity,
    worker_capacity,
    tmp_path,
):
    capacity = worker_capacity.model_copy(update={"maximum_receipts": 1})
    worker = _worker(tmp_path, package_limits, capacity)
    first = _run(worker, package_case, policy, release_identity)
    path, prepared, changed_release = _variant_package(
        package_case,
        policy,
        replay_limits,
        package_limits,
        release_identity,
    )
    try:
        with pytest.raises(CompetitionWorkerCapacityError):
            worker.run(
                path,
                expected_package_sha256=prepared.package_sha256,
                expected_policy_sha256=digest(policy),
                observed_release=changed_release,
            )
        restarted = _worker(tmp_path, package_limits, capacity)
        assert _run(restarted, package_case, policy, release_identity).receipt == first.receipt
        with sqlite3.connect(worker.path) as connection:
            assert connection.execute("SELECT COUNT(*) FROM runs").fetchone() == (1,)
    finally:
        path.chmod(0o700)


def test_publication_capacity_rejection_is_durable_and_idempotent(
    package_case, policy, package_limits, release_identity, worker_capacity, tmp_path
):
    capacity = worker_capacity.model_copy(
        update={
            "publication_journal": PublicationJournalCapacity(
                maximum_certificates=1,
                maximum_bytes=50_000_000,
            )
        }
    )
    worker = _worker(tmp_path, package_limits, capacity)
    first = _run(worker, package_case, policy, release_identity)
    restarted = _worker(tmp_path, package_limits, capacity)
    second = _run(restarted, package_case, policy, release_identity)

    assert first.receipt.status == "rejected"
    assert first.receipt.reason == "publication_capacity_exhausted"
    assert first.receipt.cutoff_certificate_retained is True
    assert first.receipt.settlement_certificate_retained is False
    assert first.current_status.held is True
    assert first.current_status.halt_reason == "capacity_exhausted"
    assert second.receipt == first.receipt
    assert second.current_status.held is True


def test_running_reservation_resumes_after_crash(
    package_case,
    policy,
    package_limits,
    release_identity,
    worker_capacity,
    tmp_path,
    monkeypatch,
):
    worker = _worker(tmp_path, package_limits, worker_capacity)
    original = worker._publication_journal

    def crash(_package):
        raise RuntimeError("injected worker crash")

    monkeypatch.setattr(worker, "_publication_journal", crash)
    with pytest.raises(RuntimeError, match="injected worker crash"):
        _run(worker, package_case, policy, release_identity)
    with sqlite3.connect(worker.path) as connection:
        assert connection.execute("SELECT status FROM runs").fetchone() == ("running",)

    monkeypatch.setattr(worker, "_publication_journal", original)
    completed = _run(worker, package_case, policy, release_identity)
    assert completed.receipt.status == "replayed_no_weight"


@pytest.mark.parametrize("change", ["missing", "replaced"])
def test_cached_receipt_refuses_missing_or_replaced_publication_journal(
    package_case,
    policy,
    package_limits,
    release_identity,
    worker_capacity,
    tmp_path,
    change,
):
    worker = _worker(tmp_path, package_limits, worker_capacity)
    _run(worker, package_case, policy, release_identity)
    database = worker.publication_root / digest(policy) / "competition-publication.sqlite3"
    database.unlink()
    if change == "replaced":
        database.write_bytes(b"")
        database.chmod(0o600)

    restarted = _worker(tmp_path, package_limits, worker_capacity)
    with pytest.raises(ValueError, match=r"publication state.*(missing|generation)"):
        _run(restarted, package_case, policy, release_identity)


@pytest.mark.parametrize("unsafe_entry", ["database", "wal"])
def test_publication_sqlite_links_are_rejected_before_target_access(
    package_case,
    policy,
    package_limits,
    release_identity,
    worker_capacity,
    tmp_path,
    unsafe_entry,
):
    worker = _worker(tmp_path, package_limits, worker_capacity)
    policy_id = digest(policy)
    policy_directory = worker.publication_root / policy_id
    policy_directory.mkdir(mode=0o700)
    database = policy_directory / "competition-publication.sqlite3"
    target = tmp_path / "link-target"
    target.write_bytes(b"must remain untouched")
    target.chmod(0o600)
    if unsafe_entry == "database":
        database.symlink_to(target)
    else:
        database.write_bytes(b"")
        database.chmod(0o600)
        (policy_directory / f"{database.name}-wal").symlink_to(target)
    with sqlite3.connect(worker.path) as connection:
        connection.execute(
            "INSERT INTO publication_bindings VALUES (?, ?, 'initializing')",
            (policy_id, "12" * 32),
        )

    with pytest.raises(OSError):
        _run(worker, package_case, policy, release_identity)
    assert target.read_bytes() == b"must remain untouched"


@pytest.mark.parametrize("table", ["publication_heads", "publication_conflicts"])
def test_derived_publication_state_tamper_fails_closed(
    package_case,
    policy,
    replay_limits,
    package_limits,
    release_identity,
    worker_capacity,
    tmp_path,
    table,
):
    worker = _worker(tmp_path, package_limits, worker_capacity)
    _run(worker, package_case, policy, release_identity)
    _record_cutoff_conflict(worker, package_case, policy, replay_limits)
    database = worker.publication_root / digest(policy) / "competition-publication.sqlite3"
    with sqlite3.connect(database) as connection:
        if table == "publication_heads":
            connection.execute(
                "UPDATE publication_heads SET publication=? WHERE kind='cutoff'",
                ("00" * 32,),
            )
        else:
            connection.execute(
                "UPDATE publication_conflicts SET other_publication=? WHERE kind='cutoff'",
                ("00" * 32,),
            )

    restarted = _worker(tmp_path, package_limits, worker_capacity)
    with pytest.raises(ValueError):
        _run(restarted, package_case, policy, release_identity)


def test_exclusive_lock_rejects_a_second_worker_before_reservation(
    package_case, policy, package_limits, release_identity, worker_capacity, tmp_path
):
    worker = _worker(tmp_path, package_limits, worker_capacity)
    descriptor = os.open(worker.lock_path, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(CompetitionWorkerBusyError):
            _run(worker, package_case, policy, release_identity)
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)

    assert _run(worker, package_case, policy, release_identity).receipt.status == (
        "replayed_no_weight"
    )


@pytest.mark.parametrize("corruption", ["body", "projection-binding"])
def test_stored_receipt_corruption_is_never_returned(
    package_case,
    policy,
    package_limits,
    release_identity,
    worker_capacity,
    tmp_path,
    corruption,
):
    worker = _worker(tmp_path, package_limits, worker_capacity)
    result = _run(worker, package_case, policy, release_identity)
    if corruption == "body":
        body = b"{}"
        receipt_sha256 = competition_worker_receipt_digest(result.receipt)
    else:
        changed = result.receipt.model_copy(update={"projection_sha256": "12" * 32})
        body = canonical_json_bytes(changed)
        receipt_sha256 = competition_worker_receipt_digest(changed)
    with sqlite3.connect(worker.path) as connection:
        connection.execute(
            "UPDATE runs SET receipt=?, receipt_sha256=? WHERE package=?",
            (body, receipt_sha256, package_case.prepared.package_sha256),
        )

    with pytest.raises(ValueError, match=r"receipt.*(corrupt|incomplete)|validation"):
        _run(worker, package_case, policy, release_identity)


def test_restart_rejects_a_corrupt_reservation_undercount(
    package_case,
    policy,
    package_limits,
    release_identity,
    worker_capacity,
    tmp_path,
):
    worker = _worker(tmp_path, package_limits, worker_capacity)
    _run(worker, package_case, policy, release_identity)
    with sqlite3.connect(worker.path) as connection:
        connection.execute(
            "UPDATE runs SET reserved=1 WHERE package=?",
            (package_case.prepared.package_sha256,),
        )

    with pytest.raises(ValueError, match="corrupt byte reservation"):
        _worker(tmp_path, package_limits, worker_capacity)
