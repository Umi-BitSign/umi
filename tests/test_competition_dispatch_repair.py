"""Synthetic lost-completion recovery; never replay production private inputs."""

from types import SimpleNamespace

import pytest

from umi.competition_dispatch_repair import (
    DispatchRepairAmendment,
    SignedDispatchRepair,
    UnavailableDispatchClaim,
    assemble_unavailable_observations,
    retained_claim,
    validate_local_repair,
)
from umi.competition_endpoint_execution import RetainedRevealPulse, assemble_endpoint_observations
from umi.competition_execution import common_execution_result
from umi.competition_package import (
    _evidence,
    _verify_repair_release,
    competition_release_identity_digest,
)
from umi.competition_void import VoidEvaluationEvidence, replay_void_evidence
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_endpoint_execution import (
    dispatch as dispatch,
)
from .test_competition_endpoint_execution import (
    feed as feed,
)
from .test_competition_endpoint_execution import (
    make_job,
    pair,
    run_incumbent,
)
from .test_competition_endpoint_execution import (
    paired_setup as paired_setup,
)
from .test_competition_evaluator import signed_order
from .test_competition_execution import boundary
from .test_competition_package import package_limits as package_limits
from .test_competition_package import release_identity as release_identity
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_runner import runtime as runtime
from .test_competition_void import announce, certify
from .test_drand import ROUND, pulse_record
from .test_open_competition import policy as policy
from .test_open_competition import wallet


@pytest.fixture
def authorization(policy, runtime, tmp_path, monkeypatch, request):
    import time

    import bittensor as bt

    from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

    from .test_competition_authorization import build_authorization_fixture
    from .test_competition_dispatch import dispatch_legacy_policy
    from .test_open_competition import bundle_at

    baseline = bundle_at(tmp_path / "baseline")
    policy = policy.model_copy(update={"evaluation_runtime_sha256": digest(runtime)})
    legacy = dispatch_legacy_policy()
    now = 1789300000000000000
    monkeypatch.setattr(time, "time_ns", lambda: now)
    monkeypatch.setattr(time, "time", lambda: time.time_ns() / 1_000_000_000)
    initial = build_authorization_fixture(policy, legacy_policy=legacy)
    now += (ROUND - initial.request.reveal_round) * QUICKNET_PERIOD_MS * 1_000_000
    item = build_authorization_fixture(
        policy,
        legacy_policy=legacy,
        incumbent_sha256=digest(baseline),
        extra_endpoint_count=getattr(request, "param", 0),
    )
    monkeypatch.setattr(
        bt.timelock,
        "current_round",
        lambda: (time.time_ns() // 1_000_000 - QUICKNET_GENESIS_MS) // QUICKNET_PERIOD_MS + 1,
    )
    item.baseline, item.runtime = baseline, runtime
    return item


@pytest.fixture
async def lost(paired_setup, tmp_path, monkeypatch, release_identity):
    setup = paired_setup
    dispatch = setup.dispatch
    item = dispatch.feed.item
    driver, journal = dispatch.driver, dispatch.feed.journal
    incumbent, _ = await run_incumbent(setup, tmp_path)
    key = dispatch.key
    complete = journal.complete
    original = []
    original_evidence = []

    def lose(claim, *, evidence):
        if claim.assignment_key == key:
            original.append(claim)
            original_evidence.append(evidence)
            raise OSError("synthetic completion storage failure")
        return complete(claim, evidence=evidence)

    monkeypatch.setattr(journal, "complete", lose)
    for i in range(6):
        await driver.poll_once()
        await driver.drain()
        await dispatch.miner.competition_authority.poll_once()
        dispatch.feed.clock.ns += 1
        if i == 0:
            dispatch.feed.clock.ns += dispatch.config.discovery_grace_seconds * 1_000_000_000
    assert driver._counts["completed"] == 2 and len(original) == 1
    assert journal.status(key)["state"] == "uncertain_dispatched"
    monkeypatch.setattr(journal, "complete", complete)
    second = await pair(setup, tmp_path, evaluator=1, assemble=assemble_endpoint_observations)
    signers = tuple(item.evaluator_wallets[:2])
    order = signed_order(make_job(setup), signers, publication=item.publication)
    sha, block, ms, req = retained_claim(journal, key)
    claim = UnavailableDispatchClaim(
        assignment_key=key,
        evaluator_hotkey=incumbent.job.evaluator_hotkey,
        claim_sha256=sha,
        claim_block=block,
        claim_unix_ms=ms,
        request_sha256=req,
        deadline_block=original[0].assignment.request.deadline_block,
    )
    predecessor = release_identity.model_copy(update={"umi_revision": "01" * 20})
    target = competition_release_identity_digest(release_identity)
    body = DispatchRepairAmendment(
        schema="umi-coordinator-outcome-repair/1",
        policy_sha256=digest(item.policy),
        round_sha256=digest(item.round),
        order_sha256=digest(order.order),
        publication_sha256=digest(item.publication.publication),
        submission_sha256=digest(item.signed_submission.submission),
        predecessor_release_identity_sha256=competition_release_identity_digest(predecessor),
        successor_release_identity_sha256=target,
        audit_sha256="cd" * 32,
        observed=boundary(item.round.reveal_block),
        unavailable=(claim,),
        reason="coordinator_outcome_unavailable",
    )
    repair = SignedDispatchRepair(
        amendment=body, signatures=tuple(sign_object(body, w) for w in signers)
    )
    context = dict(
        signed_order=order,
        suite=item.suite,
        policy=item.policy,
        current_block=item.round.reveal_block,
        legacy=item.legacy_policy,
    )
    first = assemble_unavailable_observations(
        incumbent=incumbent,
        journal=journal,
        signed_order=order,
        repair=repair,
        suite=item.suite,
        pulses={ROUND: RetainedRevealPulse(**pulse_record())},
        current_block=item.round.reveal_block,
    )
    observations = tuple(
        announce(e, order, w) for e, w in zip((first, second), signers, strict=True)
    )
    certificate = certify(context, observations, signers)
    evidence = VoidEvaluationEvidence(
        schema="umi-competition-void-evidence/2",
        order=order,
        certificate=certificate,
        legacy_policy=item.legacy_policy,
    )
    return SimpleNamespace(**locals())


async def test_real_retained_claim_becomes_explicit_neutral_void_only(lost):
    assert lost.certificate.void.reason == "coordinator_outcome_unavailable"
    assert lost.certificate.void.schema_ == "umi-competition-evaluation-void/2"
    assert len(lost.first.dispatches) == 2
    assert lost.journal.status(lost.key)["state"] == "uncertain_dispatched"
    assert lost.dispatch.miner.translator.calls == 6
    assert not lost.evidence.certificate.void.chain_submission_authorized
    assert (
        replay_void_evidence(
            lost.evidence,
            suite=lost.item.suite,
            policy=lost.item.policy,
            current_block=lost.item.round.reveal_block,
        )
        == lost.evidence
    )
    with pytest.raises(ValueError):
        common_execution_result(
            (lost.first, lost.second),
            lost.item.suite,
            lost.item.policy,
            current_block=lost.item.round.reveal_block,
        )
    with pytest.raises(ValueError, match="incomplete"):
        assemble_endpoint_observations(
            incumbent=lost.incumbent,
            journal=lost.journal,
            publication_sha256=digest(lost.item.publication.publication),
            suite=lost.item.suite,
            pulses={},
            current_block=lost.item.round.reveal_block,
        )
    encoded = canonical_json_bytes(lost.evidence)
    with pytest.raises(ValueError, match="version"):
        VoidEvaluationEvidence.model_validate_json(
            encoded.replace(b"void-evidence/2", b"void-evidence/1")
        )


@pytest.mark.parametrize(
    "change",
    [
        "missing_signature",
        "foreign_signature",
        "duplicate_signature",
        "round",
        "order",
        "claim",
        "deadline",
        "early",
        "late",
        "same_release",
    ],
)
async def test_repair_rejects_changed_scope_signatures_and_windows(lost, change):
    repair = lost.repair
    body = repair.amendment
    if change.endswith("signature"):
        signatures = (
            repair.signatures[:-1]
            if change == "missing_signature"
            else (
                repair.signatures[0],
                repair.signatures[0]
                if change == "duplicate_signature"
                else sign_object(body, wallet("Eve")),
            )
        )
        repair = repair.model_copy(update={"signatures": signatures})
    else:
        update = {}
        if change in ("round", "order"):
            update[change + "_sha256"] = "00" * 32
        if change == "claim":
            update["unavailable"] = (lost.claim.model_copy(update={"claim_sha256": "00" * 32}),)
        if change == "deadline":
            update["unavailable"] = (lost.claim.model_copy(update={"deadline_block": 0}),)
        if change in ("early", "late"):
            update["observed"] = boundary(
                lost.claim.deadline_block
                if change == "early"
                else lost.item.round.valid_through_block
            )
        if change == "same_release":
            update["successor_release_identity_sha256"] = body.predecessor_release_identity_sha256
        body = body.model_copy(update=update)
        repair = SignedDispatchRepair.model_construct(
            amendment=body, signatures=tuple(sign_object(body, w) for w in lost.signers)
        )
    with pytest.raises(ValueError):
        validate_local_repair(
            repair,
            journal=lost.journal,
            evaluator_hotkey=lost.incumbent.job.evaluator_hotkey,
            **{k: v for k, v in lost.context.items() if k != "suite"},
        )


async def test_repair_package_cannot_be_relabelled_as_original_worker(lost, release_identity):
    evidence = _evidence(((lost.item.signed_submission, lost.evidence),))
    _verify_repair_release(evidence, release_identity)
    with pytest.raises(ValueError, match="successor release"):
        _verify_repair_release(
            evidence, release_identity.model_copy(update={"umi_revision": "00" * 20})
        )


async def test_completed_claim_cannot_be_voided_as_unavailable(lost):
    complete_key = lost.first.dispatches[0].assignment_key
    with pytest.raises(ValueError, match="original uncertain claim"):
        retained_claim(lost.journal, complete_key)


async def test_repair_signing_requires_current_owned_capture_and_original_claim(lost):
    from umi.competition_dispatch_repair import sign_dispatch_repair

    from .test_competition_evaluator import Provider

    arguments = dict(
        signed_order=lost.order,
        policy=lost.item.policy,
        legacy=lost.item.legacy_policy,
        journal=lost.journal,
        evaluator_hotkey=lost.incumbent.job.evaluator_hotkey,
        wallet=lost.signers[0],
    )
    capture = await Provider(lost.item.round.reveal_block).collect()
    signature = sign_dispatch_repair(lost.body, capture=capture, **arguments)
    from umi.open_competition import verify_signature

    verify_signature(lost.body, signature)
    late = await Provider(lost.item.round.public_schedule.evidence_cutoff_block + 1).collect()
    with pytest.raises(ValueError, match="cutoff"):
        sign_dispatch_repair(lost.body, capture=late, **arguments)
    changed = lost.body.model_copy(
        update={"unavailable": (lost.claim.model_copy(update={"claim_sha256": "00" * 32}),)}
    )
    with pytest.raises(ValueError, match="original local claim"):
        sign_dispatch_repair(changed, capture=capture, **arguments)


@pytest.mark.parametrize("authorization", [173], indirect=True)
async def test_full_174_roster_repair_preserves_other_173_and_replays_new_release_package(
    lost,
    tmp_path,
    release_identity,
    package_limits,
    replay_limits,
):
    from fractions import Fraction
    from pathlib import Path

    from umi.competition_evidence import (
        EvaluatorRunRecord,
        IndependentEvaluationEvidence,
        SignedEvaluatorRunRecord,
        sign_evaluator_run,
    )
    from umi.competition_outcomes import outcome_binding
    from umi.competition_package import load_competition_package, prepare_competition_package
    from umi.competition_publication import (
        SignedCutoffPublication,
        SignedSettlementPublication,
        build_cutoff_publication,
        build_settlement_publication,
        sign_cutoff_publication,
        sign_settlement_publication,
    )
    from umi.competition_settlement import (
        CompetitionSettlement,
        EvidenceCutoffSchedule,
        PromotionHeadBinding,
    )
    from umi.open_competition import (
        AttestedResult,
        Registration,
        RegistrationSnapshot,
        project_weights,
    )

    from .test_open_competition import result_for

    item = lost.item
    round_ = item.round

    def snap(block):
        return RegistrationSnapshot(
            network="finney",
            netuid=78,
            block=block,
            block_hash="0x" + f"{block:064x}",
            registrations=tuple(
                Registration(uid=i, hotkey=s.submission.hotkey)
                for i, s in enumerate(item.submissions)
            ),
        )

    unaffected = []
    for signed in item.submissions:
        if signed == item.signed_submission:
            continue
        result = result_for(signed, round_, item.suite, baseline="hello").result.model_copy(
            update={"finished_block": round_.evaluation_close_block}
        )
        attested = AttestedResult(
            result=result, signatures=tuple(sign_object(result, w) for w in lost.signers)
        )
        runs = []
        for signer in lost.signers:
            run = EvaluatorRunRecord(
                schema="umi-competition-evaluator-run/1",
                evaluator_hotkey=signer.hotkey.ss58_address,
                policy_sha256=digest(item.policy),
                round_sha256=digest(round_),
                submission_sha256=digest(signed.submission),
                common_result_sha256=digest(result),
                suite_sha256=digest(item.suite),
                model_revision=signed.submission.model_revision,
                incumbent_model_sha256=round_.incumbent_model_sha256,
                runtime_sha256=round_.runtime_sha256,
                started_block=round_.submission_close_block + 1,
                finished_block=result.finished_block,
                candidate=result.candidate,
                incumbent=result.incumbent,
                execution_evidence_sha256=digest(result),
            )
            runs.append(
                SignedEvaluatorRunRecord(run=run, signature=sign_evaluator_run(run, signer))
            )
        unaffected.append(
            (
                signed,
                IndependentEvaluationEvidence(
                    schema="umi-competition-independent-evaluation/1",
                    attested_result=attested,
                    evaluator_runs=tuple(runs),
                ),
            )
        )
    originals = {digest(s.submission): canonical_json_bytes(e) for s, e in unaffected}
    pairs = tuple(
        sorted(
            (*unaffected, (item.signed_submission, lost.evidence)),
            key=lambda p: digest(p[0].submission),
        )
    )
    cutoff_block = round_.public_schedule.evidence_cutoff_block
    schedule = EvidenceCutoffSchedule(
        schema="umi-competition-evidence-cutoff/1",
        policy_sha256=digest(item.policy),
        round_sha256=digest(round_),
        evidence_cutoff_block=cutoff_block,
    )
    cutoff_body = build_cutoff_publication(
        round_=round_,
        cutoff_schedule=schedule,
        registration_snapshot=snap(round_.submission_close_block),
        submissions=item.submissions,
        policy=item.policy,
        limits=replay_limits,
    )
    cutoff = SignedCutoffPublication(
        publication=cutoff_body,
        signatures=tuple(sign_cutoff_publication(cutoff_body, w) for w in lost.signers),
    )
    contributor = unaffected[0][0].submission.hotkey
    projection = project_weights(
        policy=item.policy,
        round_=round_,
        suite=item.suite,
        evaluations=tuple((s, e.attested_result) for s, e in unaffected),
        voids=(lost.evidence,),
        snapshot=snap(cutoff_block),
        current_block=cutoff_block,
        promoted_model_sha256=round_.incumbent_model_sha256,
        promoted_hotkey=contributor,
    )
    settlement = CompetitionSettlement(
        schema="umi-competition-settlement/2",
        policy_sha256=digest(item.policy),
        round_sha256=digest(round_),
        cutoff_schedule=schedule,
        roster=round_.roster,
        results=tuple(
            outcome_binding(digest(s.submission), e, round_.reveal_block) for s, e in pairs
        ),
        suite=item.suite,
        registration_snapshot=snap(cutoff_block),
        promotion_head=PromotionHeadBinding(
            sequence=0,
            promotion_sha256="aa" * 32,
            model_sha256=round_.incumbent_model_sha256,
            contributor_hotkey=contributor,
        ),
        projection=projection,
        observed_block=cutoff_block,
    )
    body = build_settlement_publication(
        cutoff_certificate=cutoff,
        retained_settlement=settlement,
        submissions=item.submissions,
        evidence=pairs,
        policy=item.policy,
        limits=replay_limits,
    )
    certificate = SignedSettlementPublication(
        publication=body,
        signatures=tuple(sign_settlement_publication(body, w) for w in lost.signers),
    )
    prepared = prepare_competition_package(
        policy=item.policy,
        cutoff_certificate=cutoff,
        settlement_certificate=certificate,
        retained_settlement=settlement,
        roster=item.submissions,
        evidence=pairs,
        replay_limits=replay_limits,
        release_identity=release_identity,
        destination_root=tmp_path / "packages",
        limits=package_limits,
    )
    try:
        verified = load_competition_package(
            Path(prepared.package_path),
            expected_package_sha256=prepared.package_sha256,
            expected_policy_sha256=digest(item.policy),
            observed_release=release_identity,
            limits=package_limits,
        )
        assert len(verified.retained_settlement.roster) == 174
        assert verified.retained_settlement.roster == round_.roster
        assert sum(hasattr(b, "void_evidence_sha256") for b in settlement.results) == 1
        for entry in verified.evidence.entries:
            key = digest(entry.submission.submission)
            if key in originals:
                assert canonical_json_bytes(entry.evidence) == originals[key]
        assert len(originals) == 173
        assert not verified.chain_submission_authorized
        assert (
            sum(Fraction(int(a.numerator), int(a.denominator)) for a in projection.allocations) == 1
        )
        assert len(projection.allocations) == 173
        _assert_repaired_public_export(tmp_path, item, settlement, pairs)
        with pytest.raises(ValueError):
            build_settlement_publication(
                cutoff_certificate=cutoff,
                retained_settlement=settlement,
                submissions=item.submissions,
                evidence=pairs[:-1],
                policy=item.policy,
                limits=replay_limits,
            )
    finally:
        Path(prepared.package_path).chmod(0o700)


def _assert_repaired_public_export(tmp_path, item, settlement, pairs):
    """Replay the new evidence format through the independently merged publisher."""
    import sqlite3
    from contextlib import closing

    from umi.competition_outcomes import binding_ids, outcome_storage
    from umi.competition_public_results_directory import (
        PublicResultsDirectory,
        discover_source,
        publish_scores,
    )
    from umi.competition_public_results_export import export_round
    from umi.competition_settlement import competition_settlement_digest

    # Populate only the publisher's read contract with the signed synthetic
    # package above. This fixture is not a native intake migration or receipt.
    database = tmp_path / "export.sqlite3"
    rid = digest(item.round)
    with closing(sqlite3.connect(database)) as db, db:
        for table, key in (
            ("rounds", "digest"),
            ("submissions", "digest"),
            ("evidence_cutoff_schedules", "round"),
        ):
            db.execute(f"CREATE TABLE {table} ({key} TEXT, body BLOB)")
        db.execute("CREATE TABLE competition_settlements (round TEXT, digest TEXT, body BLOB)")
        for table, decision in (
            ("independent_evaluation_evidence", "result"),
            ("void_evaluation_evidence", "decision"),
        ):
            db.execute(
                f"CREATE TABLE {table} (digest TEXT, round TEXT, submission TEXT, "
                f"{decision} TEXT, first_observed_block INTEGER, body BLOB)"
            )
        db.execute("INSERT INTO rounds VALUES (?,?)", (rid, canonical_json_bytes(item.round)))
        db.execute(
            "INSERT INTO evidence_cutoff_schedules VALUES (?,?)",
            (rid, canonical_json_bytes(settlement.cutoff_schedule)),
        )
        db.execute(
            "INSERT INTO competition_settlements VALUES (?,?,?)",
            (rid, competition_settlement_digest(settlement), canonical_json_bytes(settlement)),
        )
        for (signed, evidence), binding in zip(pairs, settlement.results, strict=True):
            sid = digest(signed.submission)
            assert sid == binding.submission_sha256
            db.execute("INSERT INTO submissions VALUES (?,?)", (sid, canonical_json_bytes(signed)))
            table, _ = outcome_storage(binding)
            decision, eid = binding_ids(binding)
            db.execute(
                f"INSERT INTO {table} VALUES (?,?,?,?,?,?)",
                (
                    eid,
                    rid,
                    sid,
                    decision,
                    binding.first_observed_block,
                    canonical_json_bytes(evidence),
                ),
            )
    scores = export_round(database, rid, policy=item.policy, scoring_policy=item.legacy_policy)
    assert len(scores.items) == 174
    voids = [row for row in scores.items if row.status == "void"]
    assert len(voids) == 1
    assert voids[0].submission_sha256 == digest(item.signed_submission.submission)
    assert voids[0].candidate is voids[0].incumbent is voids[0].score_rank is None
    assert sum(row.status == "scored" for row in scores.items) == 173
    assert scores.certification == scores.rewards == "not_checked"
    assert not scores.chain_submission_authorized
    raw = canonical_json_bytes(scores)
    assert b'"hypothesis"' not in raw and b'"transcript_hex"' not in raw
    directory = PublicResultsDirectory(directory=str(tmp_path / "public"))
    descriptor = publish_scores(directory, scores)
    assert discover_source(directory, rid).artifact_sha256 == descriptor.artifact_sha256
    with closing(sqlite3.connect(database)) as db, db:
        db.execute(
            "UPDATE void_evaluation_evidence SET first_observed_block = first_observed_block - 1"
        )
    with pytest.raises(ValueError, match="observation binding mismatch"):
        export_round(database, rid, policy=item.policy, scoring_policy=item.legacy_policy)


@pytest.mark.parametrize("retirement_crash", [None, "before", "after"])
async def test_native_evaluators_certify_repair_and_recheck_local_settlement(
    lost, tmp_path, monkeypatch, retirement_crash
):
    from pathlib import Path

    from umi.competition_evaluator import VoidEvidenceObservation, execution_slot
    from umi.competition_settlement_signing import IndependentSettlementSigner
    from umi.competition_void import VoidEvaluationEvidence
    from umi.drand import DrandPulse

    from .test_competition_evaluator import exchange, execute, make_driver, put

    drivers = tuple(
        make_driver(
            tmp_path / f"worker-{i}",
            lost.dispatch.config.chain,
            lost.item.policy,
            lost.setup.archive,
            lost.setup.videos,
            w,
            legacy=lost.item.legacy_policy,
            dispatch=lost.journal.path.parent,
        )
        for i, w in enumerate(lost.signers)
    )
    crashes = []

    def with_crash(original):
        seen = False

        def crash_once(*, evidence, suite):
            nonlocal seen
            if retirement_crash and not seen:
                seen = True
                if retirement_crash == "after":
                    original(evidence=evidence, suite=suite)
                crashes.append(retirement_crash)
                raise OSError("synthetic crash around scheduling retirement")
            return original(evidence=evidence, suite=suite)

        return crash_once

    for driver in drivers:
        monkeypatch.setattr(driver.dispatch, "retire_void", with_crash(driver.dispatch.retire_void))

    class Pulses:
        async def fetch(self, number):
            assert number == ROUND
            return DrandPulse(**pulse_record())

    for driver in drivers:
        driver.pulses = Pulses()
        driver.provider.block = lost.item.request.issued_block
        put(Path(driver.config.order_directory) / (digest(lost.order.order) + ".json"), lost.order)
        put(
            Path(driver.config.state_directory)
            / "dispatch-repairs"
            / (digest(lost.order.order) + ".json"),
            lost.repair,
        )
    await execute(drivers)
    for driver in drivers:
        driver.provider.block = lost.item.round.reveal_block
        put(
            Path(driver.config.reveal_directory) / (digest(lost.item.suite) + ".json"),
            lost.item.suite,
        )
    for _ in range(8):
        for driver in drivers:
            await driver.poll_once()
        exchange(drivers)
    completed = []
    for driver in drivers:
        slot = execution_slot(
            lost.item.round, lost.item.signed_submission, driver.config.evaluator_hotkey
        )
        evidence = driver.journal.get(slot, "void", VoidEvaluationEvidence)
        assert evidence is not None
        assert driver.journal.get(slot, "void_observation", VoidEvidenceObservation) is not None
        with driver.dispatch._transaction() as db:
            assert driver.dispatch.retired_claims(db) == {lost.key}
        completed.append(evidence)
        prepared = SimpleNamespace(
            publication=SimpleNamespace(
                round=lost.item.round,
                settlement=SimpleNamespace(
                    suite=lost.item.suite,
                    cutoff_schedule=SimpleNamespace(
                        evidence_cutoff_block=lost.item.round.public_schedule.evidence_cutoff_block
                    ),
                ),
            ),
            evidence=SimpleNamespace(
                entries=(
                    SimpleNamespace(submission=lost.item.signed_submission, evidence=evidence),
                )
            ),
        )
        IndependentSettlementSigner._local_evidence(
            SimpleNamespace(worker=driver), prepared, lost.item.round.reveal_block + 1
        )
        await driver.aclose()
    assert completed[0] == completed[1]
    assert completed[0].certificate.void.reason == "coordinator_outcome_unavailable"
    assert lost.journal.status(lost.key)["state"] == "uncertain_dispatched"
    assert lost.dispatch.miner.translator.calls == 6
    assert crashes == ([retirement_crash] * 2 if retirement_crash else [])


async def test_delivery_release_override_keeps_original_binding_and_requires_exact_identity(
    lost, tmp_path, release_identity
):
    from pathlib import Path

    from umi.competition_settlement_delivery import SettlementQueue

    from .test_competition_evaluator import put

    config = SimpleNamespace(
        state_directory=str(tmp_path / "queue"), release_identity=lost.predecessor
    )
    queue = SimpleNamespace(config=config)
    prepared = SimpleNamespace(
        publication=SimpleNamespace(round_sha256=digest(lost.item.round)),
        evidence=_evidence(((lost.item.signed_submission, lost.evidence),)),
    )
    with pytest.raises(FileNotFoundError):
        SettlementQueue._release_identity(queue, prepared)
    path = Path(config.state_directory) / "repair-releases" / (digest(lost.item.round) + ".json")
    put(path, release_identity)
    assert SettlementQueue._release_identity(queue, prepared) == release_identity
    assert config.release_identity == lost.predecessor
    put(path, lost.predecessor)
    with pytest.raises(ValueError, match="signed release authorization"):
        SettlementQueue._release_identity(queue, prepared)
    config.release_identity = release_identity
    with pytest.raises(ValueError, match="original delivery release binding"):
        SettlementQueue._release_identity(queue, prepared)


async def test_unaffected_transcript_cannot_be_omitted_and_receipt_cannot_be_backdated(lost):
    from umi.competition_dispatch_repair import unavailable_observations
    from umi.competition_outcomes import outcome_binding
    from umi.competition_void import propose_evaluation_void

    changed = lost.first.model_copy(update={"dispatches": lost.first.dispatches[:-1]})
    with pytest.raises(ValueError, match="omits an unaffected dispatch"):
        unavailable_observations(
            changed, lost.item.suite, lost.item.policy, current_block=lost.item.round.reveal_block
        )
    with pytest.raises(ValueError, match="predates"):
        outcome_binding(
            digest(lost.item.signed_submission.submission),
            lost.evidence,
            lost.body.observed.block - 1,
        )
    invalid = lost.first.model_copy(
        update={"repair": lost.repair.model_copy(update={"signatures": lost.repair.signatures[:1]})}
    )
    changed_announcement = announce(invalid, lost.order, lost.signers[0])
    with pytest.raises(ValueError, match="exactly all assigned evaluator signatures"):
        propose_evaluation_void(
            observations=(changed_announcement, lost.observations[1]), **lost.context
        )


@pytest.mark.parametrize("mutation", ["origin", "nonobject"])
async def test_repair_keeps_original_transcript_origin_bound(lost, mutation):
    import json

    from umi.competition_dispatch_repair import unavailable_observations

    dispatch = lost.first.dispatches[0]
    body = json.loads(bytes.fromhex(dispatch.transcript_hex))
    if mutation == "origin":
        body["origin_block"] = lost.item.round.valid_through_block
    else:
        body = []
    altered = dispatch.model_copy(update={"transcript_hex": canonical_json_bytes(body).hex()})
    evidence = lost.first.model_copy(update={"dispatches": (altered, *lost.first.dispatches[1:])})
    with pytest.raises(ValueError, match=r"origin observation|must be an object"):
        unavailable_observations(
            evidence, lost.item.suite, lost.item.policy, current_block=lost.item.round.reveal_block
        )
