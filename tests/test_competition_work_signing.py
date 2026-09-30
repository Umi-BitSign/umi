from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_work_plans as plans
from umi import competition_work_signing as signing
from umi.competition_artifacts import preserve_bundle
from umi.competition_authorization import SignedEndpointAuthorization, validate_publication
from umi.competition_dispatch_capacity import DispatchTimingBudget, DispatchTimingLimits
from umi.competition_evaluator import SignedEvaluationOrder, validate_order
from umi.competition_execution import execution_boundary
from umi.competition_publication import PublicationReplayLimits, sign_cutoff_publication
from umi.competition_review_history import EvaluatorReviewStore
from umi.competition_rounds import (
    CutoffEndorsement,
    LocalCutoffProof,
    RoundJournal,
    RoundProposal,
    SignedLocalCutoffProof,
)
from umi.competition_scheduling import AssignmentPublicationJournal
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_evaluator import Provider, make_driver
from .test_competition_evaluator import chain_config as chain_config
from .test_competition_work_plans import policy as policy
from .test_competition_work_plans import runtime as runtime
from .test_competition_work_plans import setup as work_fixture
from .test_competition_work_plans import sign_publications
from .test_open_competition import wallet

work = work_fixture


class Transport:
    def __init__(self, work):
        self.head = work.options["issuance"]
        self.blocks = (work.options["announcement"], self.head)
        self.calls = []

    async def verified_blocks(self, heights=()):
        self.calls.append(heights)
        return self.head, self.blocks


@pytest.fixture
def setup(work, tmp_path, monkeypatch, chain_config):
    clock = SimpleNamespace(now=work.options["now_ms"])
    monkeypatch.setattr(signing.time, "time_ns", lambda: clock.now * 1_000_000)
    proposal = RoundProposal(
        schema="umi-round-proposal/1",
        cutoff=work.plan.cutoff.publication,
        submissions=work.plan.submissions,
        signing_close_block=work.plan.cutoff.publication.round.submission_close_block + 1,
    )
    workers, signers = [], []
    for index, hotkey in enumerate(work.signers):
        provider = Provider(work.options["issuance"].height)

        async def boundary(provider=provider):
            return execution_boundary(await provider.collect())

        worker = SimpleNamespace(
            config=SimpleNamespace(
                state_directory=str(tmp_path / f"worker-{index}"),
                evaluator_hotkey=hotkey.hotkey.ss58_address,
                maximum_orders=1024,
                maximum_journal_bytes=1024**3,
            ),
            policy=work.policy,
            wallet=hotkey,
            provider=provider,
            boundary=boundary,
            dispatch=AssignmentPublicationJournal(
                tmp_path / f"dispatch-{index}",
                work.policy,
                work.item.legacy_policy,
                maximum_bytes=16 * 1024**3,
            ),
        )
        native = make_driver(
            tmp_path / f"worker-{index}",
            chain_config,
            work.policy,
            tmp_path / "archive",
            tmp_path / "videos",
            hotkey,
            legacy=work.item.legacy_policy,
            dispatch=tmp_path / f"dispatch-{index}",
        )
        worker.config = native.config
        worker.journal, worker.executions = native.journal, native.executions
        worker.legacy, worker.review_store = native.legacy, None
        inbox = tmp_path / f"inbox-{index}"
        inbox.mkdir(mode=0o700)
        worker.dispatch.configure_dispatch(
            evaluator_hotkey=hotkey.hotkey.ss58_address,
            limits=DispatchTimingLimits(
                maximum_concurrency=4,
                page_size=32,
                poll_seconds=1,
                discovery_grace_seconds=5,
                request_timeout_seconds=1,
            ),
            budget=DispatchTimingBudget(
                proof_collection_ms=1,
                origin_collection_ms=1,
                publication_ingestion_ms=1,
                local_cycle_ms=1,
                publication_delay_ms=0,
                block_advance_numerator=1,
                block_advance_denominator_ms=12000,
                finality_headroom_blocks=0,
                measurement_sha256="99" * 32,
            ),
            publication_directory=inbox,
        )
        cutoff = RoundJournal(tmp_path / f"cutoff-{index}", {"worker": index})
        cutoff.put("intent", str(proposal.cutoff.round.sequence), proposal)
        cutoff.put("suite", proposal.cutoff.round.suite_sha256, {"proposal": digest(proposal)})
        cutoff.put(
            "vote",
            str(proposal.cutoff.round.sequence),
            CutoffEndorsement(
                proposal_sha256=digest(proposal),
                signature=sign_cutoff_publication(proposal.cutoff, hotkey),
            ),
        )
        workers.append(worker)
        signers.append(
            signing.IndependentWorkSigner(
                worker,
                cutoff,
                legacy=work.item.legacy_policy,
                transport_provider=Transport(work),
                minimum_issue_ms=1000,
            )
        )
    authorization = plans.endpoint_proposals(**work.options)[0]
    orders = plans.evaluation_order_proposals(
        plan=work.plan,
        policy=work.policy,
        legacy=work.item.legacy_policy,
        publications=sign_publications(work, (authorization,)),
    )

    def statement(body):
        return (
            None
            if body is None
            else signing.WorkStatement(schema="umi-work-statement/1", plan=work.plan, body=body)
        )

    return SimpleNamespace(
        work=work,
        clock=clock,
        workers=workers,
        signers=signers,
        authorization=statement(authorization),
        model=statement(
            next((o for o in orders if o.submission.submission.track == "model"), None)
        ),
        endpoint=statement(next(o for o in orders if o.submission.submission.track == "endpoint")),
    )


@pytest.mark.asyncio
async def test_separate_signing_limits_survive_reopen_and_refuse_underprovisioning(setup):
    from umi.competition_evaluator import EvaluatorJournalLimits
    from umi.competition_rounds import RoundSigningClient

    worker, original = setup.workers[0], setup.signers[0]
    worker.config = worker.config.model_copy(
        update={
            "maximum_journal_bytes": 12 * 1024**3,
            "journal_limits": EvaluatorJournalLimits(
                execution=2 * 1024**3,
                round_signing=1024**3,
                work_signing=1024**3,
                work_admission=1024**3,
            ),
        }
    )
    assert RoundSigningClient(worker, "https://rounds.example").journal.maximum_bytes == 1024**3

    def reopen():
        return signing.IndependentWorkSigner(
            worker,
            original.cutoffs,
            minimum_issue_ms=original.minimum_issue_ms,
            transport_provider=original.transport_provider,
            legacy=original.legacy,
        )

    signer = reopen()
    vote = await signer.endorse(setup.authorization)
    assert signer.journal.maximum_bytes == signer.admission.journal.maximum_bytes == 1024**3
    assert await reopen().endorse(setup.authorization) == vote
    worker.config = worker.config.model_copy(
        update={
            "journal_limits": worker.config.journal_limits.model_copy(update={"work_signing": 1024})
        }
    )
    with pytest.raises(ValueError, match="capacity"):
        reopen().journal.put("diagnostic", "over-capacity", {"value": "bounded"})
    worker.config = worker.config.model_copy(
        update={
            "journal_limits": worker.config.journal_limits.model_copy(
                update={"work_signing": 1024**3}
            )
        }
    )
    assert await reopen().endorse(setup.authorization) == vote


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", [None, "snapshot", "unowned", "elapsed", "reservation"])
async def test_work_signer_records_only_its_independently_checked_cutoff(setup, tmp_path, fault):
    s = setup
    signer, worker = s.signers[0], s.workers[0]
    plan = s.work.plan
    limits = PublicationReplayLimits(
        maximum_roster_bytes=16 * 1024**2,
        maximum_certificate_bytes=16 * 1024**2,
        maximum_evidence_bytes=16 * 1024**2,
    )
    archive = tmp_path / "review-archive"
    preserve_bundle(plan.incumbent, tmp_path / "incumbent", archive, s.work.policy)
    worker.review_store = EvaluatorReviewStore(tmp_path / "reviews", s.work.policy, limits=limits)
    worker.review_store.initialize_baseline(plan.incumbent, archive)
    calls = []

    async def collect_at(height):
        calls.append(height)
        capture = await Provider(height).collect()
        snap = plan.cutoff.publication.registration_snapshot
        if fault == "snapshot":
            snap = snap.model_copy(update={"registrations": ()})
        provenance = {
            **capture.provenance,
            "snapshot_sha256": digest(snap),
            "block_hash": snap.block_hash,
        }
        if fault == "elapsed":
            worker.provider.block = plan.cutoff.publication.round.evaluation_close_block
        return replace(capture, snapshot=snap, provenance={} if fault == "unowned" else provenance)

    worker.provider.collect_at = collect_at
    if fault == "reservation":
        with signer.cutoffs.transaction() as db:
            db.execute("DELETE FROM records WHERE kind='vote'")
    if fault is not None:
        with pytest.raises(ValueError):
            await signer.endorse(s.authorization)
        assert not worker.review_store.submissions()
        assert signer.journal.get("vote", signing.statement_slot(s.model)) is None
    else:
        vote = await signer.endorse(s.authorization)
        assert calls == [plan.cutoff.publication.registration_snapshot.block]
        entries = worker.review_store.submissions()
        assert len(entries) == len(plan.submissions)
        assert all(e["receipt"]["first_observed_block"] == worker.provider.block for e in entries)
        assert await signer.endorse(s.authorization) == vote
        assert worker.review_store.submissions() == entries


@pytest.mark.asyncio
async def test_independent_signatures_authorize_both_tracks(setup):
    for statement in (setup.authorization, setup.model, setup.endpoint):
        votes = [await s.endorse(statement) for s in setup.signers]
        assert all(v.statement_sha256 == digest(statement) for v in votes)
        if statement == setup.authorization:
            result = SignedEndpointAuthorization(
                publication=statement.body, signatures=tuple(v.signature for v in votes)
            )
            validate_publication(result, setup.work.policy, setup.work.item.legacy_policy)
        else:
            result = SignedEvaluationOrder(
                order=statement.body, signatures=tuple(v.signature for v in votes)
            )
            validate_order(result, setup.work.policy, setup.work.item.legacy_policy)
        assert b'"references"' not in canonical_json_bytes(statement)
        assert statement.chain_submission_authorized is False
    assert all(len(s.transport_provider.calls) == 2 for s in setup.signers)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [None, "tamper", "wrong_signer", "wrong_proposal", "expired", "missing_vote", "stale_head"],
)
async def test_retained_owned_cutoff_proof_survives_historical_age_not_current_checks(
    setup, tmp_path, fault
):
    s = setup
    signer, worker = s.signers[0], s.workers[0]
    plan = s.work.plan
    limits = PublicationReplayLimits(
        maximum_roster_bytes=16 * 1024**2,
        maximum_certificate_bytes=16 * 1024**2,
        maximum_evidence_bytes=16 * 1024**2,
    )
    archive = tmp_path / "proof-review-archive"
    preserve_bundle(plan.incumbent, tmp_path / "incumbent", archive, s.work.policy)
    worker.review_store = EvaluatorReviewStore(
        tmp_path / "proof-reviews", s.work.policy, limits=limits
    )
    worker.review_store.initialize_baseline(plan.incumbent, archive)
    slot = str(plan.cutoff.publication.round.sequence)
    proposal = RoundProposal.model_validate_json(
        canonical_json_bytes(signer.cutoffs.get("intent", slot))
    )
    snap = plan.cutoff.publication.registration_snapshot
    capture = await Provider(snap.block).collect()
    capture = replace(
        capture,
        snapshot=snap,
        provenance={
            **capture.provenance,
            "snapshot_sha256": digest(snap),
            "block_hash": snap.block_hash,
        },
    )
    proof = LocalCutoffProof(
        schema="umi-local-cutoff-proof/1",
        proposal_sha256=digest(proposal),
        registration=execution_boundary(capture),
        observed=execution_boundary(capture),
    )
    if fault == "wrong_proposal":
        proof = proof.model_copy(update={"proposal_sha256": "ab" * 32})
    key = wallet("Eve") if fault == "wrong_signer" else worker.wallet
    signed = SignedLocalCutoffProof(proof=proof, signature=sign_object(proof, key))
    if fault == "tamper":
        signed = signed.model_copy(
            update={"proof": proof.model_copy(update={"proposal_sha256": "cd" * 32})}
        )
    signer.cutoffs.put("owned-proof", slot, signed)
    if fault == "missing_vote":
        with signer.cutoffs.transaction() as db:
            db.execute("DELETE FROM records WHERE kind='vote'")
    if fault == "expired":
        worker.provider.block = plan.cutoff.publication.round.evaluation_close_block
    if fault == "stale_head":

        async def stale_head():
            raise ValueError("owned finalized head is stale")

        worker.boundary = stale_head

    async def expired_historical_read(height):
        pytest.fail("retained independently signed cutoff must not be recollected as a fresh head")

    worker.provider.collect_at = expired_historical_read
    if fault is not None:
        with pytest.raises(ValueError):
            await signer.endorse(s.authorization)
        assert signer.journal.get("vote", signing.statement_slot(s.model)) is None
        assert not worker.review_store.submissions()
    else:
        vote = await signer.endorse(s.authorization)
        assert worker.review_store.submissions()
        restarted = signing.IndependentWorkSigner(
            worker,
            signer.cutoffs,
            legacy=s.work.item.legacy_policy,
            transport_provider=signer.transport_provider,
            minimum_issue_ms=1000,
        )
        assert await restarted.endorse(s.authorization) == vote


@pytest.mark.asyncio
async def test_model_work_needs_no_endpoint_transport_provider(setup):
    signer = setup.signers[0]
    await signer.endorse(setup.authorization)
    signer.transport_provider = None
    assert await signer.endorse(setup.model)
    setup.signers[1].transport_provider = None
    with pytest.raises(ValueError, match="owned transport"):
        await setup.signers[1].endorse(setup.authorization)
    assert (
        setup.signers[1].journal.get("intent", signing.statement_slot(setup.authorization)) is None
    )


@pytest.mark.asyncio
async def test_lost_ack_retry_after_restart_keeps_exact_original_signature(setup, monkeypatch):
    signer = setup.signers[0]
    vote = await signer.endorse(setup.authorization)
    setup.clock.now += 24 * 3600 * 1000
    setup.workers[0].provider.block = setup.authorization.body.round.evaluation_close_block + 1
    restarted = signing.IndependentWorkSigner(
        setup.workers[0],
        signer.cutoffs,
        transport_provider=signer.transport_provider,
        legacy=setup.work.item.legacy_policy,
        minimum_issue_ms=1000,
    )

    def never_sign(*_):
        pytest.fail("a retained endorsement must not be signed again")

    monkeypatch.setattr(signing, "sign_object", never_sign)
    assert await restarted.endorse(setup.authorization) == vote
    assert len(signer.transport_provider.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("statement", ["authorization", "endpoint"])
async def test_delayed_first_endorsement_keeps_original_open_window(setup, statement):
    signer = setup.signers[0]
    body = getattr(setup, statement)
    before = canonical_json_bytes(body)
    setup.clock.now += 90_000
    signer.transport_provider.head = replace(
        signer.transport_provider.head,
        height=signer.transport_provider.head.height + 8,
        timestamp_ms=setup.clock.now,
    )
    vote = await signer.endorse(body)
    assert vote is not None
    assert canonical_json_bytes(body) == before
    assert signer.transport_provider.blocks[1] == setup.work.options["issuance"]


@pytest.mark.asyncio
@pytest.mark.parametrize("statement", ["model", "authorization", "endpoint"])
async def test_expired_first_signing_is_rejected_without_reservation(setup, statement):
    statement = getattr(setup, statement)
    setup.workers[0].provider.block = statement.body.round.evaluation_close_block
    signer = setup.signers[0]
    with pytest.raises(ValueError, match="outside its execution window"):
        await signer.endorse(statement)
    assert signer.journal.get("intent", signing.statement_slot(statement)) is None


@pytest.mark.asyncio
async def test_expiry_during_transport_collection_prevents_signature(setup):
    signer = setup.signers[0]
    original = signer.transport_provider.verified_blocks

    async def advance(heights):
        result = await original(heights)
        setup.workers[0].provider.block = setup.authorization.body.round.evaluation_close_block
        return result

    signer.transport_provider.verified_blocks = advance
    with pytest.raises(ValueError, match="outside its execution window"):
        await signer.endorse(setup.authorization)
    assert signer.journal.get("intent", signing.statement_slot(setup.authorization)) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["intent", "vote", "suite"])
async def test_missing_cutoff_reservation_is_not_authority_to_sign(setup, kind):
    signer = setup.signers[0]
    with signer.cutoffs.transaction() as db:
        db.execute("DELETE FROM records WHERE kind=?", (kind,))
    with pytest.raises(ValueError, match=r"cutoff|suite reservation"):
        await signer.endorse(setup.model)
    assert signer.journal.get("intent", signing.statement_slot(setup.model)) is None


@pytest.mark.asyncio
async def test_held_cutoff_blocks_even_previously_signed_work(setup):
    signer = setup.signers[0]
    await signer.endorse(setup.authorization)
    await signer.endorse(setup.model)
    with pytest.raises(ValueError, match="conflict"):
        signer.cutoffs.put("suite", setup.model.body.round.suite_sha256, {"proposal": "ff" * 32})
    with pytest.raises(ValueError, match="conflict held"):
        await signer.endorse(setup.model)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["intent", "suite"])
async def test_missing_work_reservation_blocks_retained_vote(setup, kind):
    signer = setup.signers[0]
    await signer.endorse(setup.authorization)
    await signer.endorse(setup.model)
    with signer.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind=?", (kind,))
    with pytest.raises(ValueError, match="missing its original reservations"):
        await signer.endorse(setup.model)


@pytest.mark.asyncio
@pytest.mark.parametrize("offset", [-60_001, 5_001])
async def test_stale_or_future_owned_transport_head_is_rejected(setup, offset):
    signer = setup.signers[0]
    signer.transport_provider.head = replace(
        signer.transport_provider.head, timestamp_ms=setup.clock.now + offset
    )
    with pytest.raises(ValueError, match="transport head"):
        await signer.endorse(setup.authorization)


@pytest.mark.asyncio
async def test_transport_data_cannot_be_promoted_from_remote_json(setup):
    signer = setup.signers[0]
    signer.transport_provider.head = {"height": setup.work.options["issuance"].height}
    with pytest.raises(TypeError, match="process-owned"):
        await signer.endorse(setup.authorization)


@pytest.mark.asyncio
async def test_transport_window_must_be_independently_reconstructed(setup):
    signer = setup.signers[0]
    signer.transport_provider.blocks = (
        signer.transport_provider.blocks[0],
        replace(signer.transport_provider.blocks[1], block_hash="0x" + "ab" * 32),
    )
    signer.transport_provider.head = signer.transport_provider.blocks[1]
    with pytest.raises(ValueError, match="independently derived"):
        await signer.endorse(setup.authorization)


@pytest.mark.asyncio
async def test_head_regression_is_not_ignored(setup):
    signer = setup.signers[0]
    await signer.endorse(setup.authorization)
    await signer.endorse(setup.model)
    setup.workers[0].provider.block -= 1
    with pytest.raises(ValueError, match="regressed"):
        await signer.endorse(setup.endpoint)


@pytest.mark.asyncio
async def test_wrong_wallet_cannot_supply_the_configured_endorsement(setup):
    setup.workers[0].wallet = wallet("Eve")
    signer = setup.signers[0]
    with pytest.raises(ValueError, match="configured hotkey"):
        await signer.endorse(setup.authorization)
    assert signer.journal.get("vote", signing.statement_slot(setup.model)) is None


@pytest.mark.asyncio
async def test_concurrent_retry_produces_one_durable_endorsement(setup, monkeypatch):
    calls = []
    original = signing.sign_object

    def count(*args):
        calls.append(1)
        return original(*args)

    monkeypatch.setattr(signing, "sign_object", count)
    first, second = await asyncio.gather(
        setup.signers[0].endorse(setup.authorization), setup.signers[0].endorse(setup.authorization)
    )
    assert first == second and calls == [1]


@pytest.mark.asyncio
async def test_retiming_a_signed_statement_holds_the_slot_across_restart(setup):
    signer = setup.signers[0]
    await signer.endorse(setup.authorization)
    changed_body = setup.authorization.body.model_copy(
        update={
            "assignments": tuple(
                a.model_copy(
                    update={
                        "request": a.request.model_copy(
                            update={"issued_block_hash": "0x" + "de" * 32}
                        )
                    }
                )
                for a in setup.authorization.body.assignments
            )
        }
    )
    changed = setup.authorization.model_copy(update={"body": changed_body})
    signing.validate_statement(changed, setup.work.policy, setup.work.item.legacy_policy)
    assert signing.statement_slot(changed) == signing.statement_slot(setup.authorization)
    with pytest.raises(ValueError, match="conflict retained"):
        await signer.endorse(changed)
    restarted = signing.IndependentWorkSigner(
        setup.workers[0],
        signer.cutoffs,
        legacy=setup.work.item.legacy_policy,
        minimum_issue_ms=1000,
    )
    with pytest.raises(ValueError, match="conflict held"):
        await restarted.endorse(setup.authorization)


def test_issue_margin_must_be_explicit_and_bound_to_restarts(setup):
    signer = setup.signers[0]
    with pytest.raises(TypeError, match="minimum_issue_ms"):
        signing.IndependentWorkSigner(setup.workers[0], signer.cutoffs)
    with pytest.raises(ValueError, match="configuration changed"):
        signing.IndependentWorkSigner(
            setup.workers[0],
            signer.cutoffs,
            legacy=setup.work.item.legacy_policy,
            minimum_issue_ms=5000,
        )
