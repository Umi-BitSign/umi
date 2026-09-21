"""Synthetic full-cohort admission, not inference or production timing qualification.

The cutoff, submissions, work signatures and native reservation receipts are real.
Only the chain source and timing assumptions are synthetic. No model is executed,
no live wallet is opened, and no network request is made.
V4 exercises the full control-request inventory, not quality calibration or settlement.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from umi import competition_work_plans as plans
from umi import competition_work_signing as signing
from umi.competition_dispatch_capacity import DispatchTimingBudget, DispatchTimingLimits
from umi.competition_evaluator import EvaluatorJournal
from umi.competition_execution import ExecutionJournal
from umi.competition_policy_lineage import register_lineage
from umi.competition_publication import (
    PublicationReplayLimits,
    SignedCutoffPublication,
    build_cutoff_publication,
    sign_cutoff_publication,
)
from umi.competition_scheduling import AssignmentPublicationJournal
from umi.competition_settlement import EvidenceCutoffSchedule
from umi.competition_work_queue import WorkQueue
from umi.open_competition import CompetitionPolicy, Registration, RegistrationSnapshot, digest
from umi.protocol import canonical_json_bytes

from .test_competition_authorization import build_authorization_fixture
from .test_competition_dependence import dependence_policy, dependence_suite
from .test_competition_work_signing import chain_config as chain_config
from .test_competition_work_signing import policy as policy
from .test_competition_work_signing import runtime as runtime
from .test_competition_work_signing import setup as _signing_setup
from .test_open_competition import bundle_at, submission

CAPACITY_BYTES = 16 * 1024**3
CASES_PER_ENDPOINT = 6
signing_setup = _signing_setup


@pytest.fixture
def work(policy, runtime, tmp_path, request):
    count, profile = request.param
    incumbent = bundle_at(tmp_path / "incumbent")
    item = build_authorization_fixture(
        policy.model_copy(
            update={
                "schema_": "umi-open-competition-policy/2",
                "evaluation_runtime_sha256": digest(runtime),
            }
        ),
        incumbent_sha256=digest(incumbent),
        case_count=CASES_PER_ENDPOINT,
        single_evaluator=True,
        issue_allowance_seconds=5400,
    )
    # The existing transport fixture supplies owned block/schedule evidence. V4
    # needs a new policy, suite, submissions and cutoff, not relabelled v2 bytes.
    if profile == "v4":
        item.policy = CompetitionPolicy.model_validate_json(
            canonical_json_bytes(
                dependence_policy().model_copy(
                    update={
                        "valid_from_block": item.policy.valid_from_block,
                        "valid_through_block": item.policy.valid_through_block,
                        "evaluation_runtime_sha256": digest(runtime),
                        "evaluators": item.policy.evaluators,
                    }
                )
            )
        )
        item.suite = dependence_suite(item.policy)
        assert len(item.suite.cases) == 27
        assert len(item.suite.matched_swap_pairs) == 12
        assert sum(c.stratum == "fingerspelling" for c in item.suite.cases) == 3
        assert sum(c.stratum == "continuous" and c.role == "scored" for c in item.suite.cases) == 12
    else:
        assert profile in {"v2", "v2-successor"}
    submission_policy = item.policy
    submission_policies = (submission_policy,)
    if profile == "v2-successor":
        intermediate = CompetitionPolicy.model_validate_json(
            canonical_json_bytes(item.policy.model_copy(update={
                "sequence": item.policy.sequence + 1,
                "predecessor_sha256": digest(submission_policy),
                "maximum_inference_ms": item.policy.maximum_inference_ms * 2,
            }))
        )
        item.policy = intermediate.model_copy(update={
            "sequence": intermediate.sequence + 1,
            "predecessor_sha256": digest(intermediate),
        })
        register_lineage(item.policy, (intermediate, submission_policy))
        submission_policies = (submission_policy, intermediate)
        item.suite = item.suite.model_copy(update={"policy_sha256": digest(item.policy)})
    roster = tuple(
        sorted(
            (
                submission(submission_policies[index % len(submission_policies)], name=f"CohortMiner{index}", start=1000, end=1900)
                for index in range(count)
            ),
            key=lambda signed: digest(signed.submission),
        )
    )
    round_ = item.round.model_copy(
        update={
            "policy_sha256": digest(item.policy),
            "suite_sha256": digest(item.suite),
            "roster": tuple(digest(s.submission) for s in roster),
        }
    )
    snapshot = RegistrationSnapshot(
        network="finney",
        netuid=78,
        block=round_.submission_close_block,
        block_hash="0x" + "31" * 32,
        registrations=tuple(
            Registration(uid=index, hotkey=signed.submission.hotkey)
            for index, signed in enumerate(roster)
        ),
    )
    cutoff = build_cutoff_publication(
        round_=round_,
        submissions=roster,
        registration_snapshot=snapshot,
        policy=item.policy,
        cutoff_schedule=EvidenceCutoffSchedule(
            schema="umi-competition-evidence-cutoff/1",
            policy_sha256=digest(item.policy),
            round_sha256=digest(round_),
            evidence_cutoff_block=round_.public_schedule.evidence_cutoff_block,
        ),
        limits=PublicationReplayLimits(
            maximum_roster_bytes=plans.MAX_BYTES,
            maximum_certificate_bytes=plans.MAX_BYTES,
            maximum_evidence_bytes=plans.MAX_BYTES,
        ),
    )
    signers = item.evaluator_wallets
    plan = plans.prepare_work_plan(
        cutoff=SignedCutoffPublication(
            publication=cutoff,
            signatures=tuple(sign_cutoff_publication(cutoff, signer) for signer in signers),
        ),
        submissions=roster,
        suite=item.suite,
        incumbent=incumbent,
        runtime=runtime,
        policy=item.policy,
    )
    issuance = item.finalized_blocks.blocks[item.request.issued_block]
    template_video = item.publication.publication.assignments[0].request.video
    videos = (
        tuple(
            template_video.model_copy(update={"sha256": case.video_sha256, "size_bytes": 1})
            for case in item.suite.cases
        )
        if profile == "v4"
        else tuple(a.request.video for a in item.publication.publication.assignments)
    )
    return SimpleNamespace(
        policy=item.policy,
        item=item,
        plan=plan,
        signers=signers,
        options=dict(
            plan=plan,
            policy=item.policy,
            legacy=item.legacy_policy,
            videos=videos,
            announcement=item.finalized_blocks.blocks[1000],
            issuance=issuance,
            now_ms=issuance.timestamp_ms,
            minimum_issue_ms=1000,
        ),
    )


@pytest.fixture
def cohort(signing_setup, tmp_path):
    setup = signing_setup
    worker, signer = setup.workers[0], setup.signers[0]
    # Deliberately generous logical capacity isolates admission mechanics. These
    # are not release defaults or proof that the corresponding disk space exists.
    worker.config = worker.config.model_copy(
        update={
            "maximum_journal_bytes": CAPACITY_BYTES,
            "scheduling_capacity": worker.config.scheduling_capacity.model_copy(
                update={"maximum_bytes": CAPACITY_BYTES}
            ),
        }
    )
    worker.journal.config = worker.config
    worker.executions.maximum_bytes = CAPACITY_BYTES
    signer.journal.maximum_bytes = CAPACITY_BYTES
    signer.admission.journal.maximum_bytes = CAPACITY_BYTES
    worker.dispatch.configure_dispatch(
        evaluator_hotkey=worker.config.evaluator_hotkey,
        limits=DispatchTimingLimits(
            maximum_concurrency=128,
            page_size=100,
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
            measurement_sha256=digest({"fixture": "full-cohort-admission", "synthetic": True}),
        ),
        publication_directory=tmp_path / "inbox-0",
    )
    setup.queue_arguments = dict(
        root=tmp_path / "queue",
        policy=setup.work.policy,
        provider=worker.provider,
        order_directory=tmp_path / "orders",
        publication_directory=tmp_path / "publications",
        minimum_issue_ms=1000,
        legacy=worker.legacy,
        transport_provider=signer.transport_provider,
        maximum_bytes=CAPACITY_BYTES,
    )
    setup.queue = WorkQueue(**setup.queue_arguments)
    return setup


async def pending_pages(queue, hotkey):
    cursor, pages, seen = 0, 0, set()
    while True:
        next_cursor, statements = await queue.pending(hotkey, after=cursor)
        assert len(statements) <= 4
        if next_cursor == cursor:
            assert not statements
            return pages, seen
        assert next_cursor > cursor
        pages += 1
        for statement in statements:
            statement_id = digest(statement)
            assert statement_id not in seen
            seen.add(statement_id)
        cursor = next_cursor


def reopen_native_stores(setup):
    worker, old = setup.workers[0], setup.signers[0]
    worker.journal = EvaluatorJournal(worker.config)
    worker.executions = ExecutionJournal(
        worker.executions.path.parent,
        worker.policy,
        maximum_jobs=worker.config.maximum_orders,
        maximum_bytes=worker.config.maximum_journal_bytes,
    )
    worker.dispatch = AssignmentPublicationJournal(
        worker.dispatch.path.parent, worker.policy, worker.legacy, maximum_bytes=CAPACITY_BYTES
    )
    signer = signing.IndependentWorkSigner(
        worker,
        old.cutoffs,
        minimum_issue_ms=old.minimum_issue_ms,
        legacy=worker.legacy,
        transport_provider=old.transport_provider,
    )
    setup.signers = [signer]
    setup.queue = WorkQueue(**setup.queue_arguments)
    return signer


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "work",
    [(77, "v2"), (256, "v2"), (77, "v4"), (256, "v2-successor")],
    indirect=True,
    ids=("77-endpoints-six-cases", "256-endpoints-six-cases", "77-endpoints-v4-27-cases", "256-carried-endpoints"),
)
async def test_full_cohort_reserves_before_signing_and_survives_paged_restart(cohort, monkeypatch):
    worker, signer = cohort.workers[0], cohort.signers[0]
    count, batch_id = len(cohort.work.plan.submissions), digest(cohort.work.plan)
    case_count = len(cohort.work.plan.cases)
    await cohort.queue.prepare(cohort.work.plan, videos=cohort.work.options["videos"])
    assert not tuple(cohort.queue.publication_directory.iterdir())
    assert not tuple(cohort.queue.order_directory.iterdir())
    pages, original_ids = await pending_pages(cohort.queue, worker.config.evaluator_hotkey)
    assert pages == (count + 3) // 4 and len(original_ids) == count
    assert digest(cohort.authorization) in original_ids

    original_sign, observed = signing.sign_object, []

    def sign_after_admission(body, key):
        complete = signer.admission.verify(cohort.work.plan)
        assert set(complete["receipts"]) == {"signing", "execution", "evaluator", "dispatch"}
        orders = worker.journal.reservation(batch_id)["orders"]
        assert len(orders) == count and worker.journal.orders() == []
        assert all(worker.executions.status(order["slot"]) is None for order in orders)
        with worker.dispatch._transaction() as db:
            publications = db.execute("SELECT COUNT(*) FROM reservation_publications").fetchone()[0]
            assignments = db.execute("SELECT COUNT(*) FROM reservation_assignments").fetchone()[0]
            row = db.execute("SELECT document FROM reservation_qualifications").fetchone()
            qualification = json.loads(row[0])
        assert publications == count and assignments == count * case_count
        assert qualification["plan"]["assignment_count"] == count * case_count
        assert qualification["plan"]["publication_count"] == count
        assert qualification["plan"]["scan_cycles"] > 1
        observed.append(complete)
        return original_sign(body, key)

    with monkeypatch.context() as patch:
        patch.setattr(signing, "sign_object", sign_after_admission)
        vote = await signer.endorse(cohort.authorization)
    assert len(observed) == 1
    dispatch_receipt = canonical_json_bytes(
        worker.dispatch.reservation(batch_id, evaluator_hotkey=worker.config.evaluator_hotkey)
    )
    restarted = reopen_native_stores(cohort)
    assert restarted.admission.verify(cohort.work.plan) == observed[0]
    assert await restarted.endorse(cohort.authorization) == vote
    assert await pending_pages(cohort.queue, worker.config.evaluator_hotkey) == (
        pages,
        original_ids,
    )
    await cohort.queue.accept(vote)
    assert len(tuple(cohort.queue.publication_directory.glob("*.json"))) == 1
    assert not tuple(cohort.queue.order_directory.iterdir())
    assert (
        canonical_json_bytes(
            worker.dispatch.reservation(batch_id, evaluator_hotkey=worker.config.evaluator_hotkey)
        )
        == dispatch_receipt
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "work",
    [(77, "v2"), (256, "v2")],
    indirect=True,
    ids=("77-endpoints-six-cases", "256-endpoints-six-cases"),
)
async def test_insufficient_full_cohort_capacity_never_signs_and_can_resume(cohort, monkeypatch):
    worker, signer = cohort.workers[0], cohort.signers[0]
    count, batch_id = len(cohort.work.plan.submissions), digest(cohort.work.plan)
    worker.executions.maximum_jobs = count - 1

    def forbidden(*args):
        pytest.fail("work signature escaped before the full native cohort was reserved")

    with monkeypatch.context() as patch:
        patch.setattr(signing, "sign_object", forbidden)
        with pytest.raises(ValueError, match="capacity"):
            await signer.endorse(cohort.authorization)
    slot = signing.statement_slot(cohort.authorization)
    assert signer.journal.get("intent", slot) is None
    assert signer.journal.get("vote", slot) is None
    assert signer.admission.journal.get("complete", batch_id) is None
    assert worker.executions.reservation(batch_id) is None
    assert worker.journal.orders() == []
    assert not tuple(cohort.queue.publication_directory.iterdir())
    before = signer.admission.journal.get("manifest", batch_id)
    assert before is not None
    restarted = reopen_native_stores(cohort)
    vote = await restarted.endorse(cohort.authorization)
    assert restarted.admission.journal.get("manifest", batch_id) == before
    assert len(worker.journal.reservation(batch_id)["orders"]) == count
    assert await restarted.endorse(cohort.authorization) == vote


@pytest.mark.asyncio
@pytest.mark.parametrize("work", [(256, "v4")], indirect=True, ids=("256-endpoints-v4-27-cases",))
async def test_v4_full_roster_timing_rejection_survives_restart(cohort, monkeypatch):
    worker = cohort.workers[0]
    plan = cohort.work.plan
    assert plan.cutoff.publication.round.policy_sha256 == digest(worker.policy)
    assert worker.policy.schema_ == "umi-open-competition-policy/4"
    assert len(plan.submissions) == 256 and len(plan.cases) == 27
    assert worker.legacy.clock.issue_allowance_seconds == 5400
    batch_id = digest(plan)
    slot = signing.statement_slot(cohort.authorization)

    def forbidden(*args):
        pytest.fail("v4 workload exceeded the signed issue window before this signature")

    monkeypatch.setattr(signing, "sign_object", forbidden)
    for restarted in (False, True):
        signer = reopen_native_stores(cohort) if restarted else cohort.signers[0]
        # This is an expected conservative-planner rejection, even with the
        # fastest permitted synthetic timing settings. Do not stretch the signed
        # window or weaken pagination/grace limits to turn it into a passing run.
        with pytest.raises(ValueError, match="cannot fit its original issue window"):
            await signer.endorse(cohort.authorization)
        assert signer.journal.get("intent", slot) is None
        assert signer.journal.get("vote", slot) is None
        assert signer.admission.journal.get("manifest", batch_id) is None
        assert signer.admission.journal.get("complete", batch_id) is None
        assert (
            worker.dispatch.reservation(batch_id, evaluator_hotkey=worker.config.evaluator_hotkey)
            is None
        )
        assert worker.executions.reservation(batch_id) is None
        assert worker.journal.orders() == []
        assert not tuple(cohort.queue.publication_directory.iterdir())
        assert not tuple(cohort.queue.order_directory.iterdir())


@pytest.mark.parametrize("work", [(4, "v2")], indirect=True)
def test_validate_work_plan_memo_returns_an_equal_plan(work) -> None:
    from umi.competition_work_plans import _PLAN_MEMO, validate_work_plan

    _PLAN_MEMO.clear()
    first = validate_work_plan(work.plan, work.policy)
    assert len(_PLAN_MEMO) == 1
    assert validate_work_plan(work.plan, work.policy) == first


@pytest.mark.parametrize("work", [(4, "v2")], indirect=True)
def test_validate_work_plan_memo_does_not_serve_a_different_plan(work) -> None:
    from umi.competition_work_plans import _PLAN_MEMO, validate_work_plan

    _PLAN_MEMO.clear()
    validate_work_plan(work.plan, work.policy)
    # A different plan must miss the memo and be verified on its own merits.
    # Empty evaluators cannot match the canonical selection, so this must raise
    # rather than be served the previously cached plan.
    altered = work.plan.model_copy(update={"evaluators": ()})
    with pytest.raises(ValueError):
        validate_work_plan(altered, work.policy)
    assert len(_PLAN_MEMO) == 1


@pytest.mark.parametrize("work", [(4, "v2")], indirect=True)
def test_endpoint_proposals_memo_returns_identical_publications(work) -> None:
    from umi.competition_work_plans import _PROPOSAL_MEMO, endpoint_proposals

    _PROPOSAL_MEMO.clear()
    first = endpoint_proposals(**work.options)
    assert len(_PROPOSAL_MEMO) == 1
    assert endpoint_proposals(**work.options) == first


@pytest.mark.parametrize("work", [(4, "v2")], indirect=True)
def test_endpoint_proposals_memo_still_rejects_a_stale_caller(work) -> None:
    """A warm memo must not let a caller skip the freshness checks."""
    from umi.competition_work_plans import _PROPOSAL_MEMO, endpoint_proposals

    _PROPOSAL_MEMO.clear()
    endpoint_proposals(**work.options)
    assert len(_PROPOSAL_MEMO) == 1
    stale = dict(work.options)
    stale["now_ms"] = work.options["now_ms"] + 3_600_000
    with pytest.raises(ValueError):
        endpoint_proposals(**stale)
