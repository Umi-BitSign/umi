"""Native intake, admission certificates and durable preparation; synthetic finality."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from umi.competition_artifacts import preserve_bundle
from umi.competition_cohort_admission_journal import CohortAdmissionVote
from umi.competition_cohort_admission_queue import CohortAdmissionQueue
from umi.competition_cohort_intake import CohortIntake, cohort_intake_bytes, history_tip
from umi.competition_cohort_participation import CohortParticipantAdmission
from umi.competition_cohort_preparation import PreparedCohortRound
from umi.competition_cohort_preparation_owner import CohortPreparation
from umi.competition_cohort_preparation_publisher import CohortPreparationPublisher
from umi.competition_cohort_roster import verify_recoverable_roster_membership
from umi.competition_store import AdmissionCapacity, AdmissionCapacityError, CompetitionStore
from umi.open_competition import digest, sign_object
from umi.private_files import read_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_consumers import transition
from .test_competition_cohort_intake import capture_at, request_for, seal_and_close
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_roster import close
from .test_open_competition import bundle_at, wallet
from .test_open_competition import policy as policy


@pytest.fixture
def preparation(intake, scenario, tmp_path):
    h = SimpleNamespace(intake=intake, scenario=scenario)
    h.cohort = digest(scenario["intake_history"].plan)
    h.old = intake.retain(request_for(scenario), capture_at(210))
    h.selected = intake.retain(request_for(scenario, sequence=2, block=240), capture_at(240))
    h.history, h.closing, h.seal = seal_and_close(intake, scenario)
    intake.publish(h.history, capture_at(300), closure_input=h.closing)
    h.queue = CohortAdmissionQueue(intake)
    h.store = CompetitionStore(tmp_path / "promotion", intake.policy)
    bundle = bundle_at(tmp_path / "model")
    preserve_bundle(bundle, tmp_path / "model", tmp_path / "archive", intake.policy)
    h.store.initialize_baseline(bundle, tmp_path / "archive")
    h.owner = CohortPreparation(h.queue, h.store)

    def certify():
        consent = h.seal.selected[0].consent_sha256
        for name in ("Charlie", "Dave"):
            proposed = h.queue.intake.receipt(request_for(scenario, sequence=2, block=240))[
                "proposed_admission"
            ]
            admission = CohortParticipantAdmission.model_validate(proposed)
            h.queue.publish_vote(
                CohortAdmissionVote(
                    admission=admission, signature=sign_object(admission, wallet(name))
                ),
                capture_at(320),
            )
        return h.queue.certificate(h.cohort, consent)

    h.certify = certify
    return h


def run(h, *, block=330, owner=None):
    return (owner or h.owner).prepare(
        h.cohort, capture_at(block), expected_tip_sha256=history_tip(h.history)
    )


def test_preparation_waits_for_certificate_and_keeps_complete_original_intake(preparation):
    h = preparation
    with pytest.raises(FileNotFoundError, match="admission is not certified"):
        run(h)
    with h.queue._connection() as (db, _):
        assert db.execute("SELECT COUNT(*) FROM cohort_prepared_rounds").fetchone()[0] == 0
    certificate = h.certify()
    result = run(h)
    roster = result.roster
    assert len(roster.participants) == 1
    assert roster.intake_seal.record_count == 2
    assert roster.round.participants[0].admission_sha256 == digest(certificate.admission)
    assert roster.round.prepared_at_block == 330
    assert roster.round.suite_sha256 == h.history.plan.suite_sha256
    assert roster.round.runtime_sha256 == h.intake.policy.evaluation_runtime_sha256
    assert roster.round.incumbent_model_sha256 == result.promotion_head.model_sha256
    assert not roster.chain_submission_authorized
    assert 330 in h.intake.retained_registration_blocks()


def test_late_restart_replays_original_round_without_selecting_a_new_incumbent(
    preparation, monkeypatch
):
    h = preparation
    h.certify()
    first = run(h)

    def changed_head(*args, **kwargs):
        raise AssertionError("a recovered round must not select today's incumbent")

    monkeypatch.setattr(h.store, "reviewed_promotion_head", changed_head)
    queue = CohortAdmissionQueue(CohortIntake(h.intake.config, h.intake.policy))
    second = run(h, block=100_330, owner=CohortPreparation(queue, h.store))
    assert canonical_json_bytes(second) == canonical_json_bytes(first)
    assert second.observation.block == 330


def test_repeated_retained_round_reuses_verified_history_generation(preparation, monkeypatch):
    h = preparation
    h.certify()
    first = run(h)
    owner = CohortPreparation(CohortAdmissionQueue(h.intake), h.store)
    expected = history_tip(h.history)
    assert owner.retained(h.cohort, expected_tip_sha256=expected, current_block=100_330) == first

    def repeated_replay(*args, **kwargs):
        raise AssertionError("an unchanged retained generation must not replay every participant")

    monkeypatch.setattr(owner, "_prepare", repeated_replay)
    assert owner.retained(h.cohort, expected_tip_sha256=expected, current_block=100_340) == first


def test_retained_round_reuses_private_object_with_fresh_authority(preparation, monkeypatch):
    from umi import competition_cohort_preparation_owner as owner_module

    h = preparation
    h.certify()
    run(h)
    expected = history_tip(h.history)
    first = h.owner.retained(h.cohort, expected_tip_sha256=expected, current_block=100_330)
    original = canonical_json_bytes(first)
    object.__setattr__(first.observation, "block", 999)
    calls = []
    native_verify = owner_module.verify_cohort_history

    def verify(*args, **kwargs):
        calls.append(kwargs["current_block"])
        return native_verify(*args, **kwargs)

    def reparse(*args, **kwargs):
        raise AssertionError("unchanged private prepared round must not be reparsed")

    monkeypatch.setattr(owner_module, "verify_cohort_history", verify)
    monkeypatch.setattr(PreparedCohortRound, "model_validate_json", reparse)
    second = h.owner.retained(h.cohort, expected_tip_sha256=expected, current_block=100_340)
    assert canonical_json_bytes(second) == original
    assert calls == [100_340]
    object.__setattr__(second.observation, "block", 998)
    third = h.owner.retained(h.cohort, expected_tip_sha256=expected, current_block=100_350)
    assert canonical_json_bytes(third) == original
    assert calls == [100_340, 100_350]
    assert len(h.owner._retained_cache) == 1


@pytest.mark.parametrize("change", ["body", "digest", "observed", "delete"])
def test_retained_object_reuse_rejects_changed_durable_record(preparation, change):
    h = preparation
    h.certify()
    run(h)
    expected = history_tip(h.history)
    h.owner.retained(h.cohort, expected_tip_sha256=expected, current_block=100_330)
    with h.queue._connection() as (db, _):
        if change == "delete":
            db.execute("DELETE FROM cohort_prepared_rounds WHERE cohort=?", (h.cohort,))
        elif change == "body":
            db.execute("UPDATE cohort_prepared_rounds SET body=? WHERE cohort=?", (b"{}", h.cohort))
        elif change == "digest":
            db.execute(
                "UPDATE cohort_prepared_rounds SET digest=? WHERE cohort=?", ("0" * 64, h.cohort)
            )
        else:
            db.execute(
                "UPDATE cohort_prepared_rounds SET observed=observed+1 WHERE cohort=?", (h.cohort,)
            )
    with pytest.raises(ValueError, match="retained preparation changed"):
        h.owner.retained(h.cohort, expected_tip_sha256=expected, current_block=100_340)
    assert not h.owner._retained_cache


def test_original_round_passes_native_roster_review_after_certification(preparation):
    h = preparation
    h.certify()
    result = run(h)
    decisions = {digest(h.closing): h.closing}
    h.history = close(h.history, h.intake.policy, decisions, 400, digest(result.roster.round))
    h.intake.publish(h.history, capture_at(410), decision_inputs=tuple(decisions.values()))
    assert run(h, block=100_000) == result
    with h.queue._connection() as (db, _):
        members = verify_recoverable_roster_membership(
            result.roster,
            h.intake.policy,
            h.history,
            decision_source=decisions.__getitem__,
            intake_records=h.intake._records(db, h.history),
            expected_tip_sha256=history_tip(h.history),
            current_block=100_000,
        )
        assert tuple(members) == tuple(
            p.submission_sha256 for p in result.roster.round.participants
        )
        db.execute("DELETE FROM cohort_prepared_rounds")
    with pytest.raises(FileNotFoundError, match="must be restored"):
        run(h, block=100_000)


def test_missing_superseded_consent_cannot_shrink_the_round(preparation):
    h = preparation
    h.certify()
    run(h)
    with h.queue._connection() as (db, _):
        db.execute(
            "DELETE FROM cohort_consents WHERE consent=?",
            (h.old["proposed_admission"]["consent_sha256"],),
        )
    with pytest.raises(ValueError, match="original records"):
        run(h, block=100_000)


def test_capacity_failure_commits_no_partial_round_and_recovers_after_enlargement(preparation):
    h = preparation
    h.certify()
    with h.queue._connection() as (db, _):
        before = cohort_intake_bytes(db)
    h.intake.capacity = AdmissionCapacity(maximum_bytes=before + 1)
    with pytest.raises(AdmissionCapacityError, match="capacity"):
        run(h)
    with h.queue._connection() as (db, _):
        assert db.execute("SELECT COUNT(*) FROM cohort_prepared_rounds").fetchone()[0] == 0
        assert cohort_intake_bytes(db) == before
    h.intake.capacity = AdmissionCapacity()
    result = run(h, block=100_000)
    with h.queue._connection() as (db, _):
        assert cohort_intake_bytes(db) == before + len(canonical_json_bytes(result))


def test_lost_commit_ack_recovers_exact_round(preparation, monkeypatch):
    h = preparation
    h.certify()
    transaction = h.queue._transaction

    @contextmanager
    def lost(db):
        with transaction(db):
            yield
        raise OSError("commit acknowledgement lost")

    monkeypatch.setattr(h.queue, "_transaction", lost)
    with pytest.raises(OSError, match="acknowledgement lost"):
        run(h)
    monkeypatch.setattr(h.queue, "_transaction", transaction)
    result = run(h, block=100_000)
    assert result.observation.block == 330


@pytest.mark.parametrize("first_block,second_block", [(330, 340), (340, 330)])
def test_two_local_preparers_return_one_identical_committed_round(
    preparation, monkeypatch, first_block, second_block
):
    from threading import Event
    from unittest.mock import Mock

    h = preparation
    sign = Mock(wraps=sign_object)
    monkeypatch.setattr(f"{__name__}.sign_object", sign)
    certificate = h.certify()
    assert sign.call_count == 2
    other = CohortPreparation(
        CohortAdmissionQueue(CohortIntake(h.intake.config, h.intake.policy)), h.store
    )
    first_locked, second_ready = Event(), Event()
    connection = h.queue._connection

    @contextmanager
    def first_connection():
        with connection() as owned:
            # Hold the native intake lock while the other owner captures its
            # observation. Both acquisition orders are exercised explicitly.
            first_locked.set()
            assert second_ready.wait(10)
            yield owned

    def second_preparer():
        capture = capture_at(second_block)
        second_ready.set()
        return other.prepare(h.cohort, capture, expected_tip_sha256=history_tip(h.history))

    with monkeypatch.context() as patch:
        patch.setattr(h.queue, "_connection", first_connection)
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(run, h, block=first_block)
            try:
                assert first_locked.wait(10)
                second = pool.submit(second_preparer)
                original = first.result(timeout=10)
                if second_block < first_block:
                    with pytest.raises(ValueError, match="outside the closed intake interval"):
                        second.result(timeout=10)
                    # A stale capture cannot replay an observation from its
                    # future. Refresh finality and recover the original round.
                    recovered = pool.submit(run, h, block=350, owner=other).result(timeout=10)
                else:
                    recovered = second.result(timeout=10)
            finally:
                second_ready.set()
    assert canonical_json_bytes(recovered) == canonical_json_bytes(original)
    assert original.observation.block == original.roster.round.prepared_at_block == first_block
    assert original.roster.participants[0].admission == certificate
    assert sign.call_count == 2
    with h.queue._connection() as (db, _):
        assert db.execute("SELECT digest,body,observed FROM cohort_prepared_rounds").fetchall() == [
            (digest(original), canonical_json_bytes(original), first_block)
        ]


@pytest.mark.parametrize("after_prepare", [False, True])
def test_revocation_blocks_preparation_and_republication(preparation, after_prepare):
    h = preparation
    h.certify()
    if after_prepare:
        run(h)
    h.history = transition(h.history, h.intake.policy, "revoke", 350)
    h.intake.publish(h.history, capture_at(350), decision_inputs=(h.closing,))
    with pytest.raises(ValueError, match="active authority"):
        run(h, block=360)


@pytest.mark.parametrize(
    "failure", ["tip", "stored_body", "stored_limit", "new_limit", "certificate"]
)
def test_changed_or_incomplete_state_cannot_produce_a_different_round(preparation, failure):
    h = preparation
    h.certify()
    if failure != "new_limit":
        run(h)
    if failure == "tip":
        with pytest.raises(ValueError, match="history changed"):
            h.owner.prepare(h.cohort, capture_at(400), expected_tip_sha256="ff" * 32)
        return
    if failure == "stored_body":
        with h.queue._connection() as (db, _):
            db.execute("UPDATE cohort_prepared_rounds SET body=?", (b"{}",))
    elif failure == "certificate":
        with h.queue._connection() as (db, _):
            db.execute("DELETE FROM cohort_admission_certificates")
    elif failure in {"stored_limit", "new_limit"}:
        h.owner = CohortPreparation(h.queue, h.store, maximum_bytes=1)
    with pytest.raises((ValueError, FileNotFoundError)):
        run(h, block=100_000)


def test_open_intake_cannot_be_prepared(intake, scenario, tmp_path):
    queue = CohortAdmissionQueue(intake)
    owner = CohortPreparation(queue, CompetitionStore(tmp_path / "promotion", intake.policy))
    cohort = digest(scenario["intake_history"].plan)
    with pytest.raises(ValueError, match="certified intake"):
        owner.prepare(
            cohort, capture_at(330), expected_tip_sha256=history_tip(intake.history(cohort))
        )


async def test_publisher_waits_for_admission_then_restores_missing_delivery(preparation, tmp_path):
    h = preparation
    provider = SimpleNamespace(
        policy=h.intake.policy,
        collect=AsyncMock(return_value=capture_at(330)),
        current_finalized_block=AsyncMock(return_value=100_330),
        ensure_observer_running=lambda: None,
    )
    output = tmp_path / "outbox"
    publisher = CohortPreparationPublisher(h.owner, provider, output)
    assert (await publisher.poll_once())["retry_count"] == 1
    assert not output.exists()
    h.certify()
    first = await publisher.poll_once()
    assert first["rounds_published"] == 1 and first["retry_count"] == 0
    path = output / (h.cohort + ".json")
    raw = path.read_bytes()
    assert read_private_model(path, PreparedCohortRound).roster.round.prepared_at_block == 330
    provider.collect.side_effect = AssertionError(
        "retained lifecycle publication must not recollect registration membership"
    )
    await publisher.publish_history(h.history)
    assert path.read_bytes() == raw
    provider.current_finalized_block.assert_awaited_once_with()
    provider.collect.side_effect = None
    path.unlink()
    provider.collect.return_value = capture_at(100_330)
    restarted = CohortPreparationPublisher(
        CohortPreparation(
            CohortAdmissionQueue(CohortIntake(h.intake.config, h.intake.policy)), h.store
        ),
        provider,
        output,
    )
    assert (await restarted.poll_once())["rounds_published"] == 1
    assert path.read_bytes() == raw
    h.history = transition(h.history, h.intake.policy, "revoke", 100_400)
    h.intake.publish(h.history, capture_at(100_400), decision_inputs=(h.closing,))
    provider.collect.return_value = capture_at(100_500)
    assert (await restarted.poll_once())["revoked_cohorts"] == 1
    assert path.read_bytes() == raw  # Historical evidence is not current authority.
