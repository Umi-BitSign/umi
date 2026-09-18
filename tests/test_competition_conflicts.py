from __future__ import annotations

import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import pytest

from umi import competition_store
from umi.competition_artifacts import preserve_bundle
from umi.competition_store import CompetitionStore
from umi.open_competition import AttestedResult, Evaluator, digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_open_competition import (
    attested,
    bundle_at,
    result_for,
    review_for,
    round_for,
    snapshot,
    submission,
    suite_for,
    wallet,
)
from .test_open_competition import (
    policy as policy,
)
from .test_open_competition import (
    scenario as scenario,
)


@pytest.fixture
def conflict_scenario(scenario):
    scenario.signed = scenario.model
    scenario.entries = (
        (scenario.model, scenario.evaluation),
        (scenario.endpoint, result_for(scenario.endpoint, scenario.round, scenario.suite)),
    )
    return scenario


def _endpoint_scenario(policy, root):
    policy = policy.model_copy(update={"endpoint_reward_bps": 10_000, "model_reward_bps": 0})
    archive = root / "archive"
    baseline = bundle_at(root / "baseline")
    preserve_bundle(baseline, root / "baseline", archive, policy)
    store = CompetitionStore(root / "state", policy)
    store.initialize_baseline(baseline, archive)
    signed = submission(policy)
    other = submission(policy, name="Bob")
    for item in (signed, other):
        store.admit(item, snapshot(), 110)
    suite = suite_for(policy)
    round_ = round_for(policy, suite, (signed, other), digest(baseline))
    store.close_round(round_, current_block=120)
    evaluation = result_for(signed, round_, suite)
    return SimpleNamespace(
        policy=policy,
        store=store,
        signed=signed,
        round=round_,
        suite=suite,
        evaluation=evaluation,
        entries=((signed, evaluation), (other, result_for(other, round_, suite))),
    )


@pytest.fixture
def endpoint_scenario(policy, tmp_path):
    return _endpoint_scenario(policy, tmp_path)


def _record(s, evaluation=None, *, observed_block=150):
    return s.store.record_evaluation(
        signed=s.signed,
        attested=s.evaluation if evaluation is None else evaluation,
        round_=s.round,
        suite=s.suite,
        observed_block=observed_block,
    )


def _project(s, *, entries=None, current_block=150, snapshot_block=None):
    return s.store.project(
        round_=s.round,
        suite=s.suite,
        evaluations=s.entries if entries is None else entries,
        snapshot=snapshot(current_block if snapshot_block is None else snapshot_block),
        current_block=current_block,
    )


def _promote(s, *, current_block=150, **updates):
    arguments = {
        "signed": s.signed,
        "attested": s.evaluation,
        "round_": s.round,
        "suite": s.suite,
        "review": s.review,
        "archive": s.archive,
        "snapshot": snapshot(current_block),
        "current_block": current_block,
    }
    arguments.update(updates)
    return s.store.promote(**arguments)


def _different(s, *, hypothesis="hell", status="ok"):
    return result_for(s.signed, s.round, s.suite, hypothesis=hypothesis, status=status)


def _assert_conflicted(s):
    status = s.store.round_status(digest(s.round))
    assert status["conflicted"] is True
    assert status["results"]


@pytest.mark.parametrize("reverse", [False, True])
def test_project_conflict_persists_after_rejection_and_restart(endpoint_scenario, reverse):
    s = endpoint_scenario
    first, second = s.evaluation, _different(s)
    if reverse:
        first, second = second, first
    row = _project(s, entries=((s.signed, first), s.entries[1]))
    assert row.chain_submission_authorized is False
    assert row.weights[6] > 0 and row.weights[247] > 0
    before = s.store.baseline()
    with pytest.raises(ValueError, match="conflict"):
        _project(s, entries=((s.signed, second), s.entries[1]))
    _assert_conflicted(s)
    s.store = CompetitionStore(s.store.directory, s.policy)
    _assert_conflicted(s)
    with pytest.raises(ValueError, match="conflict"):
        _project(s, entries=((s.signed, first), s.entries[1]))
    assert s.store.baseline() == before


def test_same_result_accepts_reordered_and_additional_signatures(policy, tmp_path):
    extra = Evaluator(hotkey=wallet("Eve").hotkey.ss58_address, control_group="e")
    s = _endpoint_scenario(
        policy.model_copy(update={"evaluators": (*policy.evaluators, extra)}), tmp_path
    )
    first = _record(s)
    count = len(s.store.round_status(digest(s.round))["results"])
    for signatures in (
        tuple(reversed(s.evaluation.signatures)),
        (*s.evaluation.signatures, sign_object(s.evaluation.result, wallet("Eve"))),
    ):
        retry = _record(s, s.evaluation.model_copy(update={"signatures": signatures}))
        assert retry["result_sha256"] == first["result_sha256"] == digest(s.evaluation.result)
        assert retry["round_sha256"] == digest(s.round)
        assert retry["submission_sha256"] == digest(s.signed.submission)
        assert retry["conflicted"] is False
    assert len(s.store.round_status(digest(s.round))["results"]) == count
    assert sum(_project(s).weights) == 65535


def test_same_result_accepts_another_key_in_the_same_group(policy, tmp_path):
    extra = Evaluator(hotkey=wallet("Eve").hotkey.ss58_address, control_group="c")
    s = _endpoint_scenario(
        policy.model_copy(update={"evaluators": (*policy.evaluators, extra)}), tmp_path
    )
    _record(s)
    alternate = s.evaluation.model_copy(
        update={
            "signatures": (
                sign_object(s.evaluation.result, wallet("Eve")),
                s.evaluation.signatures[1],
            )
        }
    )
    assert _record(s, alternate)["conflicted"] is False
    assert s.store.round_status(digest(s.round))["equivocations"] == []
    assert sum(_project(s).weights) == 65535


@pytest.mark.parametrize("replace_group_keys", [False, True])
def test_conflicting_quorums_need_no_shared_hotkeys(policy, tmp_path, replace_group_keys):
    extra = tuple(
        Evaluator(hotkey=wallet(name).hotkey.ss58_address, control_group=group)
        for name, group in (
            ("Eve", "c" if replace_group_keys else "e"),
            ("Ferdie", "d" if replace_group_keys else "f"),
        )
    )
    s = _endpoint_scenario(
        policy.model_copy(update={"evaluators": (*policy.evaluators, *extra)}), tmp_path
    )
    assert _record(s)["conflicted"] is False
    conflicting = _different(s).result
    second = AttestedResult(
        result=conflicting,
        signatures=tuple(sign_object(conflicting, wallet(name)) for name in ("Eve", "Ferdie")),
    )
    assert _record(s, second)["conflicted"] is True
    assert _record(s)["conflicted"] is True
    _assert_conflicted(s)
    groups = {
        evidence["control_group"]
        for evidence in s.store.round_status(digest(s.round))["equivocations"]
    }
    assert groups == ({"c", "d"} if replace_group_keys else set())


@pytest.mark.parametrize(
    "mutation",
    [
        "signature",
        "unauthorized",
        "minority",
        "duplicate_group",
        "round",
        "submission",
        "model",
        "runtime",
        "output_order",
        "missing_output",
        "finished_late",
    ],
)
def test_invalid_or_minority_input_cannot_poison_round(endpoint_scenario, mutation):
    s = endpoint_scenario
    _record(s)
    bad = _different(s)
    if mutation == "signature":
        bad = bad.model_copy(update={"signatures": s.evaluation.signatures})
    elif mutation == "unauthorized":
        bad = bad.model_copy(
            update={"signatures": (sign_object(bad.result, wallet("Eve")), bad.signatures[1])}
        )
    elif mutation == "minority":
        bad = bad.model_copy(update={"signatures": bad.signatures[:1]})
    elif mutation == "duplicate_group":
        bad = bad.model_copy(update={"signatures": (bad.signatures[0],) * 2})
    else:
        changes = {
            "round": {"round_sha256": "d1" * 32},
            "submission": {"submission_sha256": "d2" * 32},
            "model": {"model_revision": "d3" * 32},
            "runtime": {"runtime_sha256": "d4" * 32},
            "output_order": {"candidate": tuple(reversed(bad.result.candidate))},
            "missing_output": {"candidate": bad.result.candidate[:-1]},
            "finished_late": {"finished_block": 141},
        }
        bad = attested(bad.result.model_copy(update=changes[mutation]))
    with pytest.raises(ValueError):
        _record(s, bad, observed_block=190)
    assert s.store.round_status(digest(s.round))["conflicted"] is False
    assert _record(s, observed_block=150)["conflicted"] is False
    assert sum(_project(s).weights) == 65535


def test_historical_conflict_can_be_recorded_after_expiry(endpoint_scenario):
    s = endpoint_scenario
    with pytest.raises(ValueError):
        _record(s, observed_block=149)
    assert _record(s)["conflicted"] is False
    with pytest.raises(ValueError):
        _record(s, _different(s), observed_block=149)
    assert s.store.round_status(digest(s.round))["conflicted"] is False
    assert _record(s, _different(s), observed_block=1001)["conflicted"] is True
    s.store = CompetitionStore(s.store.directory, s.policy)
    _assert_conflicted(s)
    with pytest.raises(ValueError, match="conflict"):
        _project(s, current_block=1001)
    with pytest.raises(ValueError):
        _record(s, observed_block=1000)


@pytest.mark.parametrize("failure", ["stale_snapshot", "invalid_sibling", "missing_sibling"])
def test_projection_errors_do_not_discard_authenticated_conflict(endpoint_scenario, failure):
    s = endpoint_scenario
    _project(s)
    entries = ((s.signed, _different(s)), s.entries[1])
    snapshot_block = 150
    if failure == "stale_snapshot":
        snapshot_block = 130
    elif failure == "invalid_sibling":
        other, evaluation = entries[1]
        invalid = evaluation.model_copy(
            update={"result": evaluation.result.model_copy(update={"finished_block": 131})}
        )
        entries = ((other, invalid), entries[0])
    else:
        entries = entries[:1]
    with pytest.raises(ValueError):
        _project(s, entries=entries, snapshot_block=snapshot_block)
    _assert_conflicted(s)
    s.store = CompetitionStore(s.store.directory, s.policy)
    with pytest.raises(ValueError, match="conflict"):
        _project(s)


@pytest.mark.parametrize("failure", ["snapshot", "quality", "infrastructure", "archive", "review"])
def test_promotion_errors_do_not_discard_authenticated_conflict(
    conflict_scenario, tmp_path, failure
):
    s = conflict_scenario
    _record(s)
    before = s.store.baseline()
    conflicting = _different(s, hypothesis="hi")
    if failure in {"quality", "infrastructure"}:
        conflicting = _different(
            s,
            hypothesis="",
            status="miner_failure" if failure == "quality" else "infrastructure_failure",
        )
    updates = {
        "attested": conflicting,
        "review": review_for(s.policy, s.signed, s.round, conflicting),
    }
    if failure == "snapshot":
        updates["snapshot"] = snapshot(130)
    elif failure == "archive":
        updates["archive"] = tmp_path / "missing-archive"
    elif failure == "review":
        updates["review"] = updates["review"].model_copy(
            update={"signatures": updates["review"].signatures[:1]}
        )
    with pytest.raises(ValueError):
        _promote(s, **updates)
    _assert_conflicted(s)
    assert s.store.baseline() == before
    s.store = CompetitionStore(s.store.directory, s.policy)
    with pytest.raises(ValueError, match="conflict"):
        _promote(s)


def test_late_conflict_holds_existing_promotion_and_its_retry(conflict_scenario):
    s = conflict_scenario
    promotion = _promote(s)
    assert sum(_project(s).weights) == 65535
    with pytest.raises(ValueError, match="conflict"):
        _project(s, entries=((s.signed, _different(s)), s.entries[1]))
    s.store = CompetitionStore(s.store.directory, s.policy)
    assert s.store.baseline() == promotion
    with pytest.raises(ValueError, match="conflict"):
        _promote(s)
    with pytest.raises(ValueError, match="conflict"):
        _project(s)


def test_conflict_arriving_during_promotion_prevents_commit(conflict_scenario, monkeypatch):
    s = conflict_scenario
    before = s.store.baseline()
    verify_archive = competition_store.verify_preserved_bundle

    def verify_then_observe_conflict(*args, **kwargs):
        verified = verify_archive(*args, **kwargs)
        assert _record(s, _different(s))["conflicted"] is True
        return verified

    monkeypatch.setattr(competition_store, "verify_preserved_bundle", verify_then_observe_conflict)
    with pytest.raises(ValueError, match="conflict"):
        _promote(s)
    _assert_conflicted(s)
    assert s.store.baseline() == before


def test_conflict_holds_descendant_baseline_without_rewriting_history(conflict_scenario, tmp_path):
    s = conflict_scenario
    first = _promote(s)
    bundle = bundle_at(tmp_path / "descendant", "descendant", first["model_sha256"])
    preserve_bundle(bundle, tmp_path / "descendant", s.archive, s.policy)
    signed = submission(s.policy, bundle=bundle, sequence=2)
    s.store.admit(signed, snapshot(151), 151)
    suite = s.suite.model_copy(
        update={
            "cases": tuple(
                case.model_copy(update={"video_sha256": f"{i + 1000:064x}"})
                for i, case in enumerate(s.suite.cases)
            )
        }
    )
    round_ = round_for(s.policy, suite, (signed, s.endpoint), first["model_sha256"]).model_copy(
        update={
            "sequence": 2,
            "public_schedule": s.round.public_schedule.model_copy(
                update={
                    "roster_close_earliest_block": 160,
                    "roster_close_latest_block": 165,
                    "work_signing_close_block": 170,
                    "evaluation_close_block": 180,
                    "protected_reference_reveal_block": 190,
                    "evidence_cutoff_block": 200,
                    "round_valid_through_block": 250,
                }
            ),
            "submission_close_block": 160,
            "evaluation_close_block": 180,
            "reveal_block": 190,
            "valid_through_block": 250,
        }
    )
    s.store.close_round(round_, current_block=160)
    evaluation = attested(
        result_for(signed, round_, suite).result.model_copy(update={"finished_block": 170})
    )
    other = attested(
        result_for(s.endpoint, round_, suite).result.model_copy(update={"finished_block": 170})
    )
    descendant = SimpleNamespace(
        policy=s.policy,
        store=s.store,
        signed=signed,
        evaluation=evaluation,
        entries=((signed, evaluation), (s.endpoint, other)),
        round=round_,
        suite=suite,
        archive=s.archive,
        review=review_for(s.policy, signed, round_, evaluation),
    )
    second = _promote(descendant, current_block=190)
    assert sum(_project(descendant, current_block=190).weights) == 65535
    assert _record(s, _different(s), observed_block=191)["conflicted"] is True
    descendant.store = CompetitionStore(s.store.directory, s.policy)
    assert descendant.store.baseline() == second
    assert descendant.store.round_status(digest(round_))["conflicted"] is False
    with pytest.raises(ValueError, match="conflict"):
        _project(descendant, current_block=191)
    with pytest.raises(ValueError, match="conflict"):
        _promote(descendant, current_block=191)
    assert descendant.store.baseline() == second


def test_simultaneous_certificate_intake_preserves_both_sides(endpoint_scenario):
    s = endpoint_scenario
    barrier = Barrier(2)

    def record_together(evaluation):
        barrier.wait(timeout=10)
        return _record(s, evaluation)

    with ThreadPoolExecutor(max_workers=2) as executor:
        replies = list(executor.map(record_together, (s.evaluation, _different(s))))
    assert sorted(reply["conflicted"] for reply in replies) == [False, True]
    s.store = CompetitionStore(s.store.directory, s.policy)
    _assert_conflicted(s)
    with pytest.raises(ValueError, match="conflict"):
        _project(s)


def test_simultaneous_conflicting_projections_cannot_both_return_rows(endpoint_scenario):
    s = endpoint_scenario
    barrier = Barrier(2)

    def project_together(evaluation):
        barrier.wait(timeout=10)
        try:
            return _project(s, entries=((s.signed, evaluation), s.entries[1]))
        except ValueError as error:
            assert "conflict" in str(error)
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        replies = list(executor.map(project_together, (s.evaluation, _different(s))))
    assert sum(reply is not None for reply in replies) <= 1
    _assert_conflicted(s)


@pytest.mark.parametrize("legacy_alias", [False, True])
def test_existing_promotion_hydrates_evidence_on_store_open(
    conflict_scenario, tmp_path, legacy_alias
):
    s = conflict_scenario
    promotion = _promote(s)
    legacy_directory = tmp_path / "legacy-state"
    legacy_directory.mkdir(mode=0o700)
    legacy_path = legacy_directory / "competition.sqlite3"
    original_tables = (
        "metadata",
        "submissions",
        "rounds",
        "promotions",
        "model_identities",
        "suite_usage",
    )
    with sqlite3.connect(s.store.path) as source, sqlite3.connect(legacy_path) as target:
        for table in original_tables:
            schema = source.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()[0]
            target.execute(schema)
            rows = source.execute(f"SELECT * FROM {table}").fetchall()
            if rows:
                placeholders = ",".join("?" for _ in rows[0])
                target.executemany(f"INSERT INTO {table} VALUES ({placeholders})", rows)
        if legacy_alias:
            for body in (promotion["evaluation"]["result"], promotion["review"]["review"]):
                if "schema" in body:
                    body["schema_"] = body.pop("schema")
            record = canonical_json_bytes(promotion)
            record_id = hashlib.sha256(b"umi-baseline-history-v1\0" + record).hexdigest()
            target.execute(
                "UPDATE promotions SET digest=?, body=? WHERE sequence=?",
                (record_id, record, promotion["sequence"]),
            )
    s.store = CompetitionStore(legacy_directory, s.policy)
    assert s.store.baseline() == promotion
    assert s.store.round_status(digest(s.round))["results"]
    assert _record(s, _different(s))["conflicted"] is True
    with pytest.raises(ValueError, match="conflict"):
        _promote(s)
