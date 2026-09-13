from __future__ import annotations

import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_authorization import (
    SignedEndpointAuthorization,
    assignment_batch_id,
    assignment_challenge_id,
)
from umi.competition_scheduling import AssignmentPublicationJournal, assignment_key
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .test_competition_authorization import build_authorization_fixture
from .test_open_competition import policy as policy
from .test_open_competition import wallet


@pytest.fixture
def schedule(tmp_path, policy, monkeypatch):
    authorization = build_authorization_fixture(policy)
    now = [
        QUICKNET_GENESIS_MS
        + (authorization.schedule.selection_round - 1) * QUICKNET_PERIOD_MS
        + 1000
    ]
    monkeypatch.setattr("umi.competition_scheduling.time.time_ns", lambda: now[0] * 1_000_000)
    directory = tmp_path / "scheduling"
    return SimpleNamespace(
        authorization=authorization,
        now=now,
        directory=directory,
        journal=AssignmentPublicationJournal(
            directory, authorization.policy, authorization.legacy_policy
        ),
        announcement=authorization.finalized_blocks.blocks[1000],
        observed=authorization.finalized_blocks.blocks[authorization.request.issued_block],
    )


def _journal(fixture, **kwargs):
    a = fixture.authorization
    return AssignmentPublicationJournal(fixture.directory, a.policy, a.legacy_policy, **kwargs)


def _publish(fixture, **kwargs):
    return fixture.journal.publish(
        **{
            "publication": fixture.authorization.publication,
            "observed": fixture.observed,
            "announcements": (fixture.announcement,),
            **kwargs,
        }
    )


def _key(fixture, index=0):
    a = fixture.authorization
    return assignment_key(a.publication, a.publication.publication.assignments[index])


def _claim(fixture, **kwargs):
    return fixture.journal.claim(
        **{
            "key": _key(fixture),
            "observed": fixture.observed,
            "issuance": fixture.observed,
            **kwargs,
        }
    )


def _resign(fixture, body):
    return SignedEndpointAuthorization(
        publication=body,
        signatures=tuple(sign_object(body, w) for w in fixture.authorization.evaluator_wallets[:2]),
    )


def _new_sequence(fixture, sequence):
    body = fixture.authorization.publication.publication
    round_ = body.round.model_copy(update={"sequence": sequence})
    assignments = []
    for assignment in body.assignments:
        ids = dict(
            policy_sha256=body.policy_sha256,
            round_sha256=digest(round_),
            submission_sha256=assignment.submission_sha256,
            evaluator_hotkey=assignment.evaluator_hotkey,
        )
        request = assignment.request.model_copy(
            update={
                "batch_id": assignment_batch_id(**ids),
                "challenge_id": assignment_challenge_id(**ids, case_sha256=assignment.case_sha256),
            }
        )
        assignments.append(assignment.model_copy(update={"request": request}))
    return _resign(
        fixture, body.model_copy(update={"round": round_, "assignments": tuple(assignments)})
    )


def _fresh_head(fixture, *, height=None):
    return replace(
        fixture.observed,
        height=height or fixture.observed.height + 1,
        block_hash="0x" + "61" * 32,
        state_root="0x" + "62" * 32,
        timestamp_ms=fixture.now[0],
    )


def test_publication_is_atomic_private_and_reference_free(schedule):
    result = _publish(schedule)
    publication = schedule.authorization.publication
    assert result["publication_sha256"] == digest(publication.publication)
    assert result["first_observed_unix_ms"] == schedule.now[0]
    assert result["first_observed_finalized_height"] == schedule.observed.height
    assert len(result["assignments"]) == 6
    assert all(
        a["state"] == "published" and not a["dispatch_allowed"] for a in result["assignments"]
    )
    assert schedule.directory.stat().st_mode & 0o777 == 0o700
    assert schedule.journal.path.stat().st_mode & 0o777 == 0o600
    retained = schedule.journal.publication(result["publication_sha256"])
    assert canonical_json_bytes(retained) == canonical_json_bytes(publication)
    assert b'"references"' not in canonical_json_bytes(retained)
    evidence = schedule.journal.observation_evidence(schedule.observed.height)
    assert evidence["evidence_class"] == "verifier_attested_finality"
    assert evidence["offline_finality_proof"] is False
    assert evidence["publication_timing_proven"] is False
    assert evidence["evidence"] == schedule.observed.finality_evidence


def test_republication_keeps_original_signed_bytes_and_first_observation(schedule):
    first = _publish(schedule)
    schedule.now[0] += 900_000
    reversed_signatures = schedule.authorization.publication.model_copy(
        update={"signatures": tuple(reversed(schedule.authorization.publication.signatures))}
    )
    # Idempotent recovery does not require a network/finality dependency.
    second = _publish(schedule, publication=reversed_signatures, observed=None, announcements=())
    assert second["first_observed_unix_ms"] == first["first_observed_unix_ms"]
    assert second["signed_publication_sha256"] == first["signed_publication_sha256"]
    assert all(item["state"] == "expired" for item in second["assignments"])
    reopened = _journal(schedule)
    assert canonical_json_bytes(
        reopened.publication(first["publication_sha256"])
    ) == canonical_json_bytes(schedule.authorization.publication)
    status = reopened.publication_status(first["publication_sha256"])
    assert status["first_observed_unix_ms"] == first["first_observed_unix_ms"]
    assert all(item["state"] == "expired" for item in status["assignments"])


def test_distinct_assignments_have_distinct_single_use_claims(schedule):
    _publish(schedule)
    first, second = _claim(schedule), _claim(schedule, key=_key(schedule, 1))
    assert first.assignment_key != second.assignment_key
    assert first.claim_id != second.claim_id
    assert first.assignment == schedule.authorization.publication.publication.assignments[0]
    assert first.no_weight is True
    assert first.serving_origin == schedule.authorization.serving_origin
    assert schedule.journal.status(first.assignment_key)["state"] == "uncertain_dispatched"
    with pytest.raises(ValueError, match="never retried"):
        _claim(schedule, observed=None, issuance=None)


def test_crash_after_claim_never_reissues_dispatch_token(schedule):
    _publish(schedule)
    claim = _claim(schedule)
    schedule.journal = _journal(schedule)
    with pytest.raises(ValueError, match="never retried"):
        _claim(schedule, observed=None, issuance=None)
    assert schedule.journal.status(claim.assignment_key)["state"] == "uncertain_dispatched"
    assert [e["kind"] for e in schedule.journal.events(claim.assignment_key)] == [
        "published",
        "dispatched",
    ]


def test_concurrent_claims_commit_one_dispatch(schedule):
    _publish(schedule)
    journals = (_journal(schedule), _journal(schedule))

    def claim(journal):
        try:
            return journal.claim(
                _key(schedule), observed=schedule.observed, issuance=schedule.observed
            )
        except ValueError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(claim, journals))
    assert sum(isinstance(r, ValueError) for r in results) == 1
    assert len(schedule.journal.events(_key(schedule))) == 2


def test_completion_is_idempotent_append_only_and_opaque(schedule):
    _publish(schedule)
    claim = _claim(schedule)
    evidence = b"retained transport transcript; validation occurs separately"
    first = schedule.journal.complete(claim, evidence=evidence)
    second = _journal(schedule).complete(claim, evidence=evidence)
    assert first == second
    assert first["outcome_evidence_sha256"] == hashlib.sha256(evidence).hexdigest()
    assert schedule.journal.outcome(claim.assignment_key) == evidence
    assert (
        json.loads(schedule.journal.events(claim.assignment_key)[-1]["body"])["evidence_verified"]
        is False
    )
    with pytest.raises(ValueError, match="different evidence"):
        schedule.journal.complete(claim, evidence=b"different transcript")
    with pytest.raises(ValueError, match="never retried"):
        _claim(schedule, observed=None, issuance=None)
    assert len(schedule.journal.events(claim.assignment_key)) == 3
    with (
        sqlite3.connect(schedule.journal.path) as db,
        pytest.raises(sqlite3.IntegrityError, match="append-only"),
    ):
        db.execute("DELETE FROM events")


@pytest.mark.parametrize("change", ["key", "token", "request", "profile", "miner", "origin"])
def test_completion_cannot_relabel_claim(schedule, change):
    _publish(schedule)
    claim = _claim(schedule)
    updates = {
        "key": {"assignment_key": _key(schedule, 1)},
        "token": {"claim_id": "00" * 32},
        "request": {"assignment": schedule.authorization.publication.publication.assignments[1]},
        "profile": {"no_weight": False},
        "miner": {"miner_hotkey": wallet("Eve").hotkey.ss58_address},
        "origin": {"serving_origin": "https://9.9.9.9:443"},
    }
    with pytest.raises((ValueError, TypeError)):
        schedule.journal.complete(replace(claim, **updates[change]), evidence=b"transcript")
    assert schedule.journal.status(_key(schedule))["state"] == "uncertain_dispatched"


def test_late_publication_is_retained_expired_without_miner_fault(schedule):
    schedule.now[0] = (
        QUICKNET_GENESIS_MS
        + (schedule.authorization.schedule.issue_close_round - 1) * QUICKNET_PERIOD_MS
    )
    result = _publish(schedule, observed=_fresh_head(schedule))
    assert all(a["state"] == "expired" and a["miner_fault"] is False for a in result["assignments"])
    assert _claim(schedule, observed=None, issuance=None) is None
    assert len(schedule.journal.events(_key(schedule))) == 1


@pytest.mark.parametrize("expiry", ["time", "block"])
def test_prepared_assignment_expires_durably_at_claim(schedule, expiry):
    _publish(schedule)
    if expiry == "time":
        schedule.now[0] = (
            QUICKNET_GENESIS_MS
            + (schedule.authorization.schedule.issue_close_round - 1) * QUICKNET_PERIOD_MS
        )
        observed = _fresh_head(schedule)
    else:
        observed = _fresh_head(schedule, height=schedule.authorization.request.deadline_block + 1)
    assert _claim(schedule, observed=observed) is None
    status = _journal(schedule).status(_key(schedule))
    assert status["state"] == "expired"
    assert status["miner_fault"] is False
    assert [e["kind"] for e in schedule.journal.events(_key(schedule))] == ["published", "expired"]


def test_future_issuance_remains_scheduled_without_consuming_claim(schedule):
    observed = _fresh_head(schedule, height=schedule.observed.height - 1)
    _publish(schedule, observed=observed)
    assert _claim(schedule, observed=observed, issuance=None) is None
    assert len(schedule.journal.events(_key(schedule))) == 1
    assert _claim(schedule) is not None


@pytest.mark.parametrize("change", ["hash", "height", "timestamp", "none"])
def test_claim_requires_exact_owned_issuance(schedule, change):
    _publish(schedule)
    issuance = {
        "hash": replace(schedule.observed, block_hash="0x" + "99" * 32),
        "height": replace(schedule.observed, height=schedule.observed.height + 1),
        "timestamp": replace(schedule.observed, timestamp_ms=schedule.announcement.timestamp_ms),
        "none": None,
    }[change]
    with pytest.raises((ValueError, TypeError)):
        _claim(schedule, issuance=issuance)
    assert schedule.journal.status(_key(schedule))["state"] == "published"
    assert len(schedule.journal.events(_key(schedule))) == 1


@pytest.mark.parametrize(
    "change", ["stale", "future", "policy", "pin", "chain", "dict", "evidence"]
)
def test_invalid_observation_cannot_publish_or_poison_history(schedule, change):
    observed = schedule.observed
    if change == "stale":
        observed = replace(observed, timestamp_ms=schedule.now[0] - 60_001)
    elif change == "future":
        observed = replace(observed, timestamp_ms=schedule.now[0] + 5_001)
    elif change == "policy":
        observed = replace(observed, scoring_policy_hash="ee" * 32)
    elif change == "pin":
        observed = replace(observed, finality_verifier_sha256="ee" * 32)
    elif change == "chain":
        observed = replace(
            observed,
            chain_observation=observed.chain_observation.model_copy(
                update={"genesis_block_hash": "ee" * 32}
            ),
        )
    elif change == "dict":
        observed = {"height": observed.height, "verified": True}
    else:
        observed = replace(observed)
        object.__setattr__(observed, "finality_evidence", b"changed after construction")
    with pytest.raises((ValueError, TypeError)):
        _publish(schedule, observed=observed)
    with sqlite3.connect(schedule.journal.path) as db:
        assert db.execute("SELECT COUNT(*) FROM publications").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0] == 0
    assert len(_publish(schedule)["assignments"]) == 6


def test_clock_and_finalized_head_rollback_survive_restart(schedule):
    _publish(schedule)
    initial = schedule.now[0]
    schedule.now[0] -= 1
    with pytest.raises(ValueError, match="rolled back"):
        _journal(schedule).claim(
            _key(schedule), observed=schedule.observed, issuance=schedule.observed
        )
    schedule.now[0] = initial
    with pytest.raises(ValueError, match="rolled back"):
        _claim(schedule, observed=_fresh_head(schedule, height=schedule.observed.height - 1))
    assert _claim(schedule) is not None


@pytest.mark.parametrize("change", ["missing", "duplicate", "unrelated", "wrong_schedule"])
def test_announcements_must_exactly_cover_verified_schedules(schedule, change):
    announcements = (schedule.announcement,)
    if change == "missing":
        announcements = ()
    elif change == "duplicate":
        announcements *= 2
    elif change == "unrelated":
        announcements += (replace(schedule.announcement, height=1001),)
    else:
        announcements = (replace(schedule.announcement, block_hash="0x" + "99" * 32),)
    with pytest.raises(ValueError):
        _publish(schedule, announcements=announcements)
    assert len(_publish(schedule)["assignments"]) == 6


def test_assignment_cannot_be_republished_with_retimed_request(schedule):
    _publish(schedule)
    body = schedule.authorization.publication.publication
    assignments = tuple(
        a.model_copy(
            update={
                "request": a.request.model_copy(
                    update={
                        "issued_block": a.request.issued_block + 1,
                        "deadline_block": a.request.deadline_block + 1,
                    }
                )
            }
        )
        for a in body.assignments
    )
    changed = _resign(schedule, body.model_copy(update={"assignments": assignments}))
    assert assignment_key(changed, assignments[0]) == _key(schedule)
    with pytest.raises(ValueError, match="retiming or reuse"):
        _publish(schedule, publication=changed)


def test_aggregate_window_quotas_cannot_reset_with_new_publication(schedule):
    a = build_authorization_fixture(schedule.authorization.policy, case_count=15)
    schedule.authorization = a
    schedule.announcement = a.finalized_blocks.blocks[1000]
    schedule.observed = a.finalized_blocks.blocks[a.request.issued_block]
    schedule.now[0] = schedule.observed.timestamp_ms + 1000
    _publish(schedule)
    with pytest.raises(ValueError, match="aggregate scheduling"):
        _publish(schedule, publication=_new_sequence(schedule, 2))
    assert (
        len(schedule.journal.publication_status(digest(a.publication.publication))["assignments"])
        == 30
    )
    with sqlite3.connect(schedule.journal.path) as db:
        assert db.execute("SELECT COUNT(*) FROM publications").fetchone()[0] == 1


def test_quorum_or_unsafe_copy_cannot_bypass_publication_validation(schedule):
    publication = schedule.authorization.publication
    invalid = publication.model_copy(update={"signatures": publication.signatures[:1]})
    with pytest.raises(ValueError, match="quorum"):
        _publish(schedule, publication=invalid)
    invalid = publication.model_copy(
        update={"publication": publication.publication.model_copy(update={"no_weight": False})}
    )
    with pytest.raises(ValueError):
        _publish(schedule, publication=invalid)
    with sqlite3.connect(schedule.journal.path) as db:
        assert db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0] == 0
    _publish(schedule)


def test_conflicting_same_height_observation_cannot_change_claim(schedule):
    _publish(schedule)
    with pytest.raises(ValueError, match="changed at a retained height"):
        _claim(schedule, observed=replace(schedule.observed, state_root="0x" + "dd" * 32))
    assert _claim(schedule) is not None


def test_round_sequence_cannot_reset_lifetime_with_changed_round(schedule):
    _publish(schedule)
    body = schedule.authorization.publication.publication
    round_ = body.round.model_copy(
        update={"valid_through_block": body.round.valid_through_block + 1}
    )
    assignments = []
    for assignment in body.assignments:
        ids = dict(
            policy_sha256=body.policy_sha256,
            round_sha256=digest(round_),
            submission_sha256=assignment.submission_sha256,
            evaluator_hotkey=assignment.evaluator_hotkey,
        )
        request = assignment.request.model_copy(
            update={
                "batch_id": assignment_batch_id(**ids),
                "challenge_id": assignment_challenge_id(**ids, case_sha256=assignment.case_sha256),
            }
        )
        assignments.append(assignment.model_copy(update={"request": request}))
    changed = _resign(
        schedule, body.model_copy(update={"round": round_, "assignments": tuple(assignments)})
    )
    with pytest.raises(ValueError, match="immutable round"):
        _publish(schedule, publication=changed)


@pytest.mark.parametrize("limit", ["publications", "assignments", "bytes"])
def test_capacity_fails_closed_without_discarding_any_evidence(schedule, limit):
    kwargs = {
        "publications": {"maximum_publications": 1},
        "assignments": {"maximum_assignments": 5},
        "bytes": {"maximum_bytes": 1024},
    }[limit]
    journal = _journal(schedule, **kwargs)
    if limit == "publications":
        _publish(schedule)
        with pytest.raises(ValueError, match="capacity exhausted"):
            journal.publish(
                _new_sequence(schedule, 2),
                observed=schedule.observed,
                announcements=(schedule.announcement,),
            )
        assert (
            journal.publication(digest(schedule.authorization.publication.publication))
            == schedule.authorization.publication
        )
    else:
        with pytest.raises(ValueError, match="capacity exhausted"):
            journal.publish(
                schedule.authorization.publication,
                observed=schedule.observed,
                announcements=(schedule.announcement,),
            )
        with sqlite3.connect(journal.path) as db:
            assert db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0] == 0


@pytest.mark.parametrize("change", ["policy", "legacy", "schema", "outcome"])
def test_restart_refuses_changed_binding_or_schema(schedule, change):
    _publish(schedule)
    a = schedule.authorization
    kwargs = {}
    policy, legacy = a.policy, a.legacy_policy
    if change == "policy":
        policy = policy.model_copy(update={"valid_through_block": 2001})
    elif change == "legacy":
        legacy = legacy.model_copy(update={"activation_block": 1001})
    elif change == "schema":
        with sqlite3.connect(schedule.journal.path) as db:
            db.execute("PRAGMA user_version=99")
    else:
        kwargs["maximum_outcome_bytes"] = 10
    with pytest.raises(ValueError, match=r"schema|mismatch"):
        AssignmentPublicationJournal(schedule.directory, policy, legacy, **kwargs)


def test_listing_is_bounded_account_filtered_and_never_exposes_request(schedule):
    _publish(schedule)
    hotkey = schedule.authorization.miner_wallet.hotkey.ss58_address
    first = schedule.journal.list_assignments(miner_hotkey=hotkey, limit=2)
    second = schedule.journal.list_assignments(
        miner_hotkey=hotkey, after=first["next_cursor"], limit=2
    )
    assert len(first["items"]) == len(second["items"]) == 2
    assert not {i["assignment_key"] for i in first["items"]} & {
        i["assignment_key"] for i in second["items"]
    }
    encoded = canonical_json_bytes(first)
    assert (
        b"https://" not in encoded
        and b'"request"' not in encoded
        and b'"references"' not in encoded
    )
    assert (
        schedule.journal.list_assignments(miner_hotkey=wallet("Eve").hotkey.ss58_address)["items"]
        == []
    )
    for limit in (True, 0, 101):
        with pytest.raises(ValueError):
            schedule.journal.list_assignments(miner_hotkey=hotkey, limit=limit)


def test_listing_durably_expires_elapsed_work_before_showing_active_items(schedule):
    _publish(schedule)
    schedule.now[0] += 900_000
    hotkey = schedule.authorization.miner_wallet.hotkey.ss58_address
    assert schedule.journal.list_assignments(miner_hotkey=hotkey)["items"] == []
    history = _journal(schedule).list_assignments(miner_hotkey=hotkey, include_history=True)
    assert len(history["items"]) == 6
    assert all(a["state"] == "expired" and a["miner_fault"] is False for a in history["items"])
    assert all(
        json.loads(schedule.journal.events(_key(schedule, index))[-1]["body"])["local_clock_only"]
        is True
        for index in range(6)
    )


def test_oversized_outcome_does_not_release_uncertain_claim(schedule):
    _publish(schedule)
    claim = _claim(schedule)
    with pytest.raises(ValueError, match="reserved byte capacity"):
        schedule.journal.complete(
            claim, evidence=b"x" * (schedule.journal.maximum_outcome_bytes + 1)
        )
    with pytest.raises(ValueError, match="never retried"):
        _claim(schedule)


def test_database_symlink_and_public_directory_are_rejected(tmp_path, policy):
    a = build_authorization_fixture(policy)
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    with pytest.raises(ValueError, match="0700"):
        AssignmentPublicationJournal(public, a.policy, a.legacy_policy)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    (private / "scheduling.sqlite3").symlink_to(tmp_path / "elsewhere")
    with pytest.raises(ValueError, match="symlink"):
        AssignmentPublicationJournal(private, a.policy, a.legacy_policy)


def test_release_returns_exact_signed_bytes_without_claiming_work(schedule):
    result = _publish(schedule)
    publication = schedule.journal.releasable_publication(result["publication_sha256"])
    assert canonical_json_bytes(publication) == canonical_json_bytes(
        schedule.authorization.publication
    )
    assert len(schedule.journal.events(_key(schedule))) == 1
    assert schedule.journal.status(_key(schedule))["state"] == "published"


def test_release_waits_for_selection_despite_small_clock_skew(schedule):
    schedule.now[0] = schedule.observed.timestamp_ms - 1
    result = _publish(schedule)
    with pytest.raises(ValueError, match="future unreleased"):
        schedule.journal.releasable_publication(result["publication_sha256"])
    schedule.now[0] += 1001
    assert (
        schedule.journal.releasable_publication(result["publication_sha256"])
        == schedule.authorization.publication
    )


def test_release_needs_exact_issuance_then_observe_unlocks_without_dispatch(schedule):
    observed = _fresh_head(schedule)
    result = _publish(schedule, observed=observed)
    with pytest.raises(ValueError, match="not retained"):
        schedule.journal.releasable_publication(result["publication_sha256"])
    captured = schedule.journal.observe(observed=observed, issuances=(schedule.observed,))
    assert captured["retained_issuance_heights"] == [schedule.observed.height]
    assert captured["publication_timing_proven"] is False
    assert (
        schedule.journal.releasable_publication(result["publication_sha256"])
        == schedule.authorization.publication
    )
    assert len(schedule.journal.events(_key(schedule))) == 1


def test_release_does_not_publish_mixed_assignments_until_every_issuance_is_verified(schedule):
    body = schedule.authorization.publication.publication
    later_hash = "0x" + "66" * 32
    assignments = tuple(
        assignment.model_copy(
            update={
                "request": assignment.request.model_copy(
                    update={
                        "issued_block": assignment.request.issued_block + 1,
                        "issued_block_hash": later_hash,
                        "deadline_block": assignment.request.deadline_block + 1,
                    }
                )
            }
        )
        if index % 3 == 1
        else assignment
        for index, assignment in enumerate(body.assignments)
    )
    publication = _resign(schedule, body.model_copy(update={"assignments": assignments}))
    result = _publish(schedule, publication=publication)
    with pytest.raises(ValueError, match="future unreleased"):
        schedule.journal.releasable_publication(result["publication_sha256"])
    schedule.now[0] += 1000
    later = replace(_fresh_head(schedule), block_hash=later_hash)
    schedule.journal.observe(observed=later, issuances=(later,))
    assert schedule.journal.releasable_publication(result["publication_sha256"]) == publication


def test_release_checks_exact_issuance_hash_even_when_height_is_known(schedule):
    result = _publish(schedule, observed=replace(schedule.observed, block_hash="0x" + "ee" * 32))
    with pytest.raises(ValueError, match="issuance differs"):
        schedule.journal.releasable_publication(result["publication_sha256"])


def test_release_denial_commits_expiry_evidence_without_miner_fault(schedule):
    result = _publish(schedule)
    schedule.now[0] += 900_000
    with pytest.raises(ValueError):
        schedule.journal.releasable_publication(result["publication_sha256"])
    # Read raw events without triggering a second expiry pass.
    assert schedule.journal.events(_key(schedule))[-1]["kind"] == "expired"
    assert json.loads(schedule.journal.events(_key(schedule))[-1]["body"])["miner_fault"] is False


def test_release_cannot_refresh_stale_finality_using_only_local_time(schedule):
    result = _publish(schedule)
    schedule.now[0] += 60_001
    with pytest.raises(ValueError, match="fresh retained"):
        schedule.journal.releasable_publication(result["publication_sha256"])
    schedule.journal.observe(observed=_fresh_head(schedule))
    assert (
        schedule.journal.releasable_publication(result["publication_sha256"])
        == schedule.authorization.publication
    )


def test_release_has_no_new_work_after_every_assignment_was_claimed(schedule):
    result = _publish(schedule)
    for index in range(6):
        _claim(schedule, key=_key(schedule, index))
    with pytest.raises(ValueError, match="no usable unclaimed"):
        schedule.journal.releasable_publication(result["publication_sha256"])


@pytest.mark.parametrize("change", ["unrelated", "hash", "future", "duplicate", "unbounded"])
def test_observe_accepts_only_bounded_existing_exact_issuances(schedule, change):
    _publish(schedule)
    observed = _fresh_head(schedule, height=schedule.observed.height + 2)
    if change == "unrelated":
        issuances = (replace(schedule.observed, height=schedule.observed.height + 1),)
    elif change == "hash":
        issuances = (replace(schedule.observed, block_hash="0x" + "77" * 32),)
    elif change == "future":
        issuances = (replace(schedule.observed, height=observed.height + 1),)
    elif change == "duplicate":
        issuances = (schedule.observed,) * 2
    else:
        issuances = (schedule.observed,) * 257
    with pytest.raises(ValueError):
        schedule.journal.observe(observed=observed, issuances=issuances)
    with pytest.raises(ValueError, match="unknown retained"):
        schedule.journal.observation_evidence(observed.height)
    assert schedule.journal.status(_key(schedule))["state"] == "published"


def test_publication_crossing_deadline_during_checks_returns_expired(schedule, monkeypatch):
    original = schedule.journal._quotas
    first_observed = schedule.now[0]

    def slow_checks(*args):
        original(*args)
        schedule.now[0] = (
            QUICKNET_GENESIS_MS
            + (schedule.authorization.schedule.issue_close_round - 1) * QUICKNET_PERIOD_MS
        )

    monkeypatch.setattr(schedule.journal, "_quotas", slow_checks)
    result = _publish(schedule)
    assert result["first_observed_unix_ms"] == first_observed
    assert all(a["state"] == "expired" for a in result["assignments"])


def test_claim_crossing_deadline_commits_expiry_without_dispatch_token(schedule, monkeypatch):
    _publish(schedule)
    original = schedule.journal._publication

    def slow_checks(*args):
        value = original(*args)
        schedule.now[0] = (
            QUICKNET_GENESIS_MS
            + (schedule.authorization.schedule.issue_close_round - 1) * QUICKNET_PERIOD_MS
        )
        return value

    monkeypatch.setattr(schedule.journal, "_publication", slow_checks)
    assert _claim(schedule) is None
    assert [event["kind"] for event in schedule.journal.events(_key(schedule))] == [
        "published",
        "expired",
    ]
    assert _journal(schedule).claim(_key(schedule), observed=None, issuance=None) is None


def test_claim_checks_final_observation_freshness_after_slow_checks(schedule, monkeypatch):
    _publish(schedule)
    original = schedule.journal._publication

    def slow_checks(*args):
        value = original(*args)
        schedule.now[0] += 60_001
        return value

    monkeypatch.setattr(schedule.journal, "_publication", slow_checks)
    with pytest.raises(ValueError, match="became stale"):
        _claim(schedule)
    assert [event["kind"] for event in schedule.journal.events(_key(schedule))] == ["published"]


def test_release_crossing_deadline_during_schedule_checks_commits_expiry(schedule, monkeypatch):
    result = _publish(schedule)
    original = schedule.journal._schedule

    def slow_checks(*args):
        value = original(*args)
        schedule.now[0] = (
            QUICKNET_GENESIS_MS
            + (schedule.authorization.schedule.issue_close_round - 1) * QUICKNET_PERIOD_MS
        )
        return value

    monkeypatch.setattr(schedule.journal, "_schedule", slow_checks)
    with pytest.raises(ValueError, match="no usable unclaimed"):
        schedule.journal.releasable_publication(result["publication_sha256"])
    assert schedule.journal.events(_key(schedule))[-1]["kind"] == "expired"
