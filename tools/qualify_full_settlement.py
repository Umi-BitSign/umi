"""Opt-in, synthetic full native settlement qualification; never production inputs.

Run with PYTHONPATH=src:. Python tools/qualify_full_settlement.py ROOT COUNT.
All signing keys derive from public test URIs. Inference observations and owned
registration captures are synthetic; signatures, replay, local journal checks,
publication transport, certificate formation and package retention are native.
"""

from __future__ import annotations

import asyncio
import gc
import hashlib
import json
import os
import resource
import sys
import time
import traceback
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import bittensor as bt
import httpx
import pytest
from fastapi import FastAPI

from tests.test_competition_authorization import build_authorization_fixture
from tests.test_competition_chain import chain_config as chain_fixture
from tests.test_competition_evaluator import signed_order
from tests.test_competition_execution import boundary
from tests.test_competition_runner import runtime as runtime_fixture
from tests.test_competition_void import announce, certify
from tests.test_component_run import response_plaintext
from tests.test_drand import ROUND, pulse_record
from tests.test_open_competition import bundle_at, submission, wallet
from tests.test_open_competition import policy as policy_fixture
from umi.competition_artifacts import preserve_bundle
from umi.competition_authorization import (
    SignedEndpointAuthorization,
    assignment_batch_id,
    assignment_challenge_id,
)
from umi.competition_chain import RegistrationCapture
from umi.competition_endpoint_execution import (
    EndpointDispatchEvidence,
    EndpointPairedEvidence,
    RetainedRevealPulse,
)
from umi.competition_evaluator import (
    EvaluatorConfig,
    EvaluatorJournal,
    IndependentEvidenceObservation,
    VoidEvidenceObservation,
)
from umi.competition_evidence import (
    IndependentEvaluationEvidence,
    SignedEvaluatorRunRecord,
    independent_evidence_digest,
    sign_evaluator_run,
)
from umi.competition_execution import (
    EndpointIncumbentEvidence,
    EndpointIncumbentJob,
    ExecutionCase,
    ExecutionStep,
    ModelEvaluationJob,
    ModelExecutionEvidence,
    common_execution_result,
    execution_boundary,
    execution_slot,
    run_record_from_execution,
)
from umi.competition_package import (
    CompetitionPackageLimits,
    CompetitionReleaseIdentity,
    PreparedCompetitionPackage,
)
from umi.competition_publication import (
    PublicationJournalCapacity,
    PublicationReplayLimits,
    SignedCutoffPublication,
    build_cutoff_publication,
    sign_cutoff_publication,
)
from umi.competition_review_history import EvaluatorReviewStore
from umi.competition_rounds import (
    CutoffEndorsement,
    RoundJournal,
    RoundProposal,
    SettlementDeliveryConfig,
)
from umi.competition_runner import OfflineCaseExecution
from umi.competition_scheduling import assignment_key
from umi.competition_settlement import EvidenceCutoffSchedule
from umi.competition_settlement_delivery import SettlementQueue
from umi.competition_settlement_preparation import (
    SettlementPreparation,
    prepare_retained_settlement,
)
from umi.competition_settlement_transport import SettlementSigningClient, attach_settlement_route
from umi.competition_store import AdmissionCapacity, CompetitionStore
from umi.competition_void import VoidEvaluationEvidence, void_evidence_digest
from umi.competition_worker import CompetitionReplayWorker, CompetitionWorkerCapacity
from umi.config import Limits
from umi.miner import _signed_envelope
from umi.open_competition import (
    AttestedResult,
    BurnDestination,
    CaseOutput,
    CompetitionPolicy,
    Registration,
    RegistrationSnapshot,
    digest,
    sign_object,
)
from umi.policy import ScoringPolicy, scoring_policy_hash, umi_source_tree_sha256
from umi.protocol import canonical_json_bytes
from umi.validator import prepare_request_attempt
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

SOURCE = "4795f42c870b7349d32b050a27605fbfa1a65c08"
REPORT = {}
REPORT_PATH = None


def emit(**event):
    print(json.dumps(event, sort_keys=True), flush=True)


def save():
    REPORT_PATH.write_text(json.dumps(REPORT, indent=2, sort_keys=True) + "\n")


@contextmanager
def phase(name):
    emit(phase=name, state="started")
    wall, cpu = time.perf_counter(), time.process_time()
    try:
        yield
    except BaseException:
        emit(phase=name, state="failed")
        raise
    else:
        value = dict(
            wall_seconds=time.perf_counter() - wall,
            cpu_seconds=time.process_time() - cpu,
            process_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            * (1 if sys.platform == "darwin" else 1024),
        )
        REPORT.setdefault("phases", {})[name] = value
        save()
        emit(phase=name, state="completed", **value)


class SyntheticProvider:
    """Explicit fixture port, not a finality proof or real collector measurement."""

    def __init__(self, registrations, burn, base):
        self.registrations, self.burn, self.base = registrations, burn, base
        self.started = time.monotonic()

    def snapshot(self, block):
        return RegistrationSnapshot(
            network="finney",
            netuid=78,
            block=block,
            block_hash="0x" + f"{block:064x}",
            registrations=self.registrations,
            burn_destination=self.burn,
        )

    async def collect_at(self, block):
        view = self.snapshot(block)
        return RegistrationCapture(
            view,
            {
                "schema": "umi-competition-registration-provenance/1",
                "evidence_class": "verifier_attested_finality",
                "offline_finality_proof": False,
                "chain_submission_authorized": False,
                "snapshot_sha256": digest(view),
                "block": block,
                "block_hash": view.block_hash,
                "state_root": "0x" + "cc" * 32,
                "evidence_sha256": "ee" * 32,
            },
        )

    async def collect(self):
        return await self.collect_at(self.base + int((time.monotonic() - self.started) / 12))


def output_step(job, case, block, role, *, failed=False):
    bundle = job.incumbent if role == "incumbent" else job.submission.submission.model_bundle
    output = CaseOutput(
        case_id=case.case_id,
        status="miner_failure" if failed else "ok",
        hypothesis="",
        elapsed_ms=10,
    )
    return ExecutionStep(
        role=role,
        started=boundary(block),
        finished=boundary(block),
        execution=OfflineCaseExecution(
            schema="umi-offline-case-execution/1",
            model_sha256=digest(bundle),
            runtime_sha256=digest(job.runtime),
            video_sha256=case.video_sha256,
            output=output,
            stdout_hex="" if failed else "0a",
            reason="process_failed" if failed else "ok",
            returncode=1 if failed else 0,
        ),
    )


def endpoint_observation(item, signed, miner, round_, baseline, runtime, healthy):
    signer = item.evaluator_wallets[0]
    ids = dict(
        policy_sha256=digest(item.policy),
        round_sha256=digest(round_),
        submission_sha256=digest(signed.submission),
        evaluator_hotkey=signer.hotkey.ss58_address,
    )
    assignments = tuple(
        a.model_copy(
            update={
                "submission_sha256": ids["submission_sha256"],
                "request": a.request.model_copy(
                    update={
                        "batch_id": assignment_batch_id(**ids),
                        "challenge_id": assignment_challenge_id(**ids, case_sha256=a.case_sha256),
                    }
                ),
            }
        )
        for a in item.publication.publication.assignments
    )
    body = item.publication.publication.model_copy(
        update={
            "policy_sha256": digest(item.policy),
            "round": round_,
            "submissions": (signed,),
            "assignments": assignments,
        }
    )
    publication = SignedEndpointAuthorization(
        publication=body, signatures=(sign_object(body, signer),)
    )
    job = EndpointIncumbentJob(
        schema="umi-endpoint-incumbent-job/1",
        round=round_,
        submission=signed,
        incumbent=baseline,
        runtime=runtime,
        evaluator_hotkey=signer.hotkey.ss58_address,
        cases=tuple(
            ExecutionCase(case_id=c.case_id, video_sha256=c.video_sha256, stratum=c.stratum)
            for c in item.suite.cases
        ),
    )
    incumbent = EndpointIncumbentEvidence(
        schema="umi-endpoint-incumbent-evidence/1",
        job=job,
        steps=tuple(output_step(job, c, item.request.issued_block, "incumbent") for c in job.cases),
    )
    dispatches = []
    for assignment, case in zip(assignments, item.suite.cases, strict=True):
        request = assignment.request
        start = (
            QUICKNET_GENESIS_MS + (request.response_close_round - 1) * QUICKNET_PERIOD_MS
        ) * 1_000_000 - 1_000_000_000
        prepared = prepare_request_attempt(
            request, wallet=signer, miner_hotkey=signed.submission.hotkey, nonce_ns=start
        )
        envelope = signature = None
        if healthy:
            plain = response_plaintext(
                request,
                validator_hotkey=signer.hotkey.ss58_address,
                miner_hotkey=signed.submission.hotkey,
            ).model_copy(
                update={"hypothesis": "hello", "model_revision": signed.submission.model_revision}
            )
            sealing = SimpleNamespace(
                wallet=miner,
                hotkey_ss58=signed.submission.hotkey,
                signature_scheme="sr25519",
                limits=Limits.from_policy(item.legacy_policy),
            )
            with pytest.MonkeyPatch.context() as mp:
                mp.setattr(bt.timelock, "current_round", lambda: ROUND - 10)
                envelope, signature = _signed_envelope(sealing, request, plain)
        key = assignment_key(publication, assignment)
        document = dict(
            schema="umi-endpoint-dispatch-transcript/1",
            assignment_key=key,
            publication_sha256=digest(body),
            case_id=case.case_id,
            origin_evidence_sha256="a7" * 32,
            origin_block=request.issued_block,
            request_hex=prepared.request_bytes.hex(),
            auth_headers=dict(prepared.auth_headers),
            limits=asdict(Limits.from_policy(item.legacy_policy)),
            started_at_unix_ns=str(start),
            finished_at_unix_ns=str(start + 5_000_000),
            received_at_unix_ns=str(start + 5_000_000) if healthy else None,
            envelope_hex=None if envelope is None else envelope.hex(),
            response_signature=signature,
            received_body_prefix_hex=None if envelope is None else envelope.hex(),
            received_bytes_sha256=None
            if envelope is None
            else hashlib.sha256(envelope).hexdigest(),
            failure_code=None if healthy else "transport_timeout",
            no_weight=True,
            evidence_verified=False,
            chain_submission_authorized=False,
        )
        dispatches.append(
            EndpointDispatchEvidence(
                assignment_key=key,
                transcript_hex=canonical_json_bytes(document).hex(),
                reveal_pulse=RetainedRevealPulse(**pulse_record()) if healthy else None,
            )
        )
    return (
        job,
        publication,
        EndpointPairedEvidence(
            schema="umi-endpoint-paired-evidence/1",
            incumbent=incumbent,
            publication=publication,
            legacy_policy=item.legacy_policy,
            dispatches=tuple(dispatches),
        ),
    )


def fixture(root, count):
    assert 2 <= count <= 256
    runtime = runtime_fixture.__wrapped__()
    baseline = bundle_at(root / "baseline")
    candidate = bundle_at(root / "candidate", "candidate", digest(baseline))
    policy = policy_fixture.__wrapped__().model_copy(
        update={
            "schema_": "umi-open-competition-policy/2",
            "evaluation_runtime_sha256": digest(runtime),
            "maximum_snapshot_age_blocks": 1800,
        }
    )
    options = dict(
        case_count=6,
        single_evaluator=True,
        incumbent_sha256=digest(baseline),
        policy_valid_through_block=10000,
        submission_valid_through_block=9000,
    )
    # Pure settlement replay can consume retained transport-policy bytes from
    # another host. This avoids invoking media-tool discovery for a fixture
    # that does not execute video processing or claim runtime qualification.
    if legacy_path := os.environ.get("SETTLEMENT_LEGACY_FIXTURE"):
        options["legacy_policy"] = ScoringPolicy.model_validate_json(Path(legacy_path).read_bytes())
    with pytest.MonkeyPatch.context() as mp:
        now = 1789300000000000000
        mp.setattr(time, "time_ns", lambda: now)
        initial = build_authorization_fixture(policy, **options)
        now += (ROUND - initial.request.reveal_round) * QUICKNET_PERIOD_MS * 1_000_000
        item = build_authorization_fixture(policy, **options)
    assert item.request.reveal_round == ROUND
    burn_wallet = wallet("FullPipelineBurn")
    burn = BurnDestination(uid=255, hotkey=burn_wallet.hotkey.ss58_address)
    item.policy = CompetitionPolicy.model_validate_json(
        canonical_json_bytes(
            item.policy.model_copy(
                update={"schema_": "umi-open-competition-policy/3", "unallocated_model_burn": burn}
            )
        )
    )
    policy = item.policy
    item.suite = item.suite.model_copy(update={"policy_sha256": digest(policy)})
    miners = [wallet(f"FullPipelineMiner{i}") for i in range(count - 1)]
    submissions, by_submission = [], {}
    for i, miner in enumerate(miners):
        signed = submission(policy, name=f"FullPipelineMiner{i}", start=1000, end=9000)
        submissions.append(signed)
        by_submission[digest(signed.submission)] = (miner, i == 0)
    # One miner can offer both tracks; burn remains a separate, nonparticipating UID.
    model = submission(policy, name="FullPipelineMiner0", bundle=candidate, start=1000, end=9000)
    submissions.append(model)
    submissions = tuple(sorted(submissions, key=lambda s: digest(s.submission)))
    cutoff_block = item.round.public_schedule.evidence_cutoff_block
    round_ = item.round.model_copy(
        update={
            "policy_sha256": digest(policy),
            "suite_sha256": digest(item.suite),
            "roster": tuple(digest(s.submission) for s in submissions),
            "eligible_tracks": ("endpoint", "model"),
            "valid_through_block": cutoff_block + 1800,
            "public_schedule": item.round.public_schedule.model_copy(
                update={"round_valid_through_block": cutoff_block + 1800}
            ),
        }
    )
    item.round = round_
    regs = (
        *(Registration(uid=i, hotkey=w.hotkey.ss58_address) for i, w in enumerate(miners)),
        Registration(uid=255, hotkey=burn.hotkey),
    )
    provider = SyntheticProvider(regs, burn, cutoff_block)
    limits = PublicationReplayLimits(
        maximum_roster_bytes=4 * 1024**2,
        maximum_certificate_bytes=4 * 1024**2,
        maximum_evidence_bytes=256 * 1024**2,
    )
    archive = root / "archive"
    preserve_bundle(baseline, root / "baseline", archive, policy)
    preserve_bundle(candidate, root / "candidate", archive, policy)
    capacity = AdmissionCapacity(maximum_records=4096, maximum_bytes=2 * 1024**3)
    store = CompetitionStore(root / "intake", policy, admission_capacity=capacity)
    reviews = EvaluatorReviewStore(
        root / "reviews", policy, limits=limits, admission_capacity=capacity
    )
    for retained in (store, reviews):
        retained.initialize_baseline(baseline, archive)
    for signed in submissions:
        store.admit(signed, provider.snapshot(1000), 1000)
    schedule = EvidenceCutoffSchedule(
        schema="umi-competition-evidence-cutoff/1",
        policy_sha256=digest(policy),
        round_sha256=digest(round_),
        evidence_cutoff_block=cutoff_block,
    )
    close = round_.submission_close_block
    store.fix_evidence_cutoff(round_, schedule, observed_block=close)
    store.close_round(round_, current_block=close)
    signer = item.evaluator_wallets[0]
    cutoff_body = build_cutoff_publication(
        round_=round_,
        cutoff_schedule=schedule,
        registration_snapshot=provider.snapshot(close),
        submissions=submissions,
        policy=policy,
        limits=limits,
    )
    cutoff = SignedCutoffPublication(
        publication=cutoff_body, signatures=(sign_cutoff_publication(cutoff_body, signer),)
    )
    reviews.observe_cutoff(
        cutoff, submissions, snapshot=provider.snapshot(close), observed_block=close
    )
    chain = chain_fixture.__wrapped__(policy, root / "chain-fixture").model_copy(
        update={"collection_timeout_seconds": 10}
    )
    config = EvaluatorConfig(
        schema="umi-evaluator-config/1",
        policy_sha256=digest(policy),
        chain=chain,
        evaluator_hotkey=signer.hotkey.ss58_address,
        wallet_name="fixture",
        hotkey_name="fixture",
        **{
            name: str(root / name)
            for name in (
                "wallet_path",
                "state_directory",
                "order_directory",
                "reveal_directory",
                "peer_directory",
                "outbox_directory",
                "video_directory",
                "dispatch_directory",
            )
        },
        archive_directory=str(archive),
        legacy_policy_sha256=scoring_policy_hash(item.legacy_policy),
        maximum_journal_bytes=2 * 1024**3,
    )
    journal = EvaluatorJournal(config)
    evidence_bytes = 0
    for index, signed in enumerate(submissions):
        if signed.submission.track == "endpoint":
            miner, healthy = by_submission[digest(signed.submission)]
            job, publication, own = endpoint_observation(
                item, signed, miner, round_, baseline, runtime, healthy
            )
        else:
            healthy, publication = False, None
            job = ModelEvaluationJob(
                schema="umi-model-evaluation-job/1",
                round=round_,
                submission=signed,
                incumbent=baseline,
                runtime=runtime,
                evaluator_hotkey=signer.hotkey.ss58_address,
                cases=tuple(
                    ExecutionCase(case_id=c.case_id, video_sha256=c.video_sha256, stratum=c.stratum)
                    for c in item.suite.cases
                ),
            )
            own = ModelExecutionEvidence(
                schema="umi-model-execution-evidence/1",
                job=job,
                steps=tuple(
                    output_step(job, c, item.request.issued_block, role, failed=role == "incumbent")
                    for c in job.cases
                    for role in ("candidate", "incumbent")
                ),
            )
        order = signed_order(job, (signer,), publication=publication)
        announcement = announce(own, order, signer)
        if healthy:
            common = common_execution_result(
                (own,), item.suite, policy, current_block=round_.reveal_block
            )
            run = run_record_from_execution(
                own, common, item.suite, policy, current_block=round_.reveal_block
            )
            evidence = IndependentEvaluationEvidence(
                schema="umi-competition-independent-evaluation/1",
                attested_result=AttestedResult(
                    result=common, signatures=(sign_object(common, signer),)
                ),
                evaluator_runs=(
                    SignedEvaluatorRunRecord(run=run, signature=sign_evaluator_run(run, signer)),
                ),
            )
            kind, receipt_type, sha = (
                "independent",
                IndependentEvidenceObservation,
                independent_evidence_digest(evidence),
            )
            for retained in (store, reviews):
                retained.record_independent_evaluation(
                    signed=signed,
                    evidence=evidence,
                    round_=round_,
                    suite=item.suite,
                    observed_block=round_.reveal_block,
                )
        else:
            context = dict(
                signed_order=order,
                suite=item.suite,
                policy=policy,
                current_block=round_.reveal_block,
                legacy=item.legacy_policy if publication else None,
            )
            evidence = VoidEvaluationEvidence(
                schema="umi-competition-void-evidence/1",
                order=order,
                legacy_policy=context["legacy"],
                certificate=certify(context, (announcement,), (signer,)),
            )
            kind, receipt_type, sha = (
                "void",
                VoidEvidenceObservation,
                void_evidence_digest(evidence),
            )
            for retained in (store, reviews):
                retained.record_void_evaluation(
                    evidence=evidence, suite=item.suite, observed_block=round_.reveal_block
                )
        slot = execution_slot(round_, signed, signer.hotkey.ss58_address)
        journal.admit(order, slot)
        journal.put(slot, "announcement", announcement)
        journal.put(slot, kind, evidence)
        receipt = receipt_type(
            schema="umi-void-evidence-observation/1"
            if not healthy
            else "umi-independent-evidence-observation/1",
            evaluator_hotkey=signer.hotkey.ss58_address,
            policy_sha256=digest(policy),
            round_sha256=digest(round_),
            order_sha256=digest(order.order),
            submission_sha256=digest(signed.submission),
            evidence_sha256=sha,
            observed=boundary(round_.reveal_block),
        )
        journal.put(slot, kind + "_observation", receipt)
        evidence_bytes += len(canonical_json_bytes(evidence))
        if (index + 1) % 16 == 0 or index + 1 == count:
            emit(fixture_retained=index + 1, outcomes=count, evidence_body_bytes=evidence_bytes)
    cutoffs = RoundJournal(root / "cutoff-journal", {"fixture": "full-pipeline"})
    proposal = RoundProposal(
        schema="umi-round-proposal/1",
        cutoff=cutoff_body,
        submissions=submissions,
        signing_close_block=round_.public_schedule.work_signing_close_block,
    )
    cutoffs.put("intent", str(round_.sequence), proposal)
    cutoffs.put("suite", round_.suite_sha256, {"proposal": digest(proposal)})
    cutoffs.put(
        "vote",
        str(round_.sequence),
        CutoffEndorsement(proposal_sha256=digest(proposal), signature=cutoff.signatures[0]),
    )
    provider.started = time.monotonic()

    async def current():
        return execution_boundary(await provider.collect())

    worker = SimpleNamespace(
        config=config,
        policy=policy,
        wallet=signer,
        provider=provider,
        boundary=current,
        journal=journal,
        legacy=item.legacy_policy,
    )
    REPORT["fixture"] = dict(
        outcomes=count,
        scored=1,
        void=count - 1,
        endpoint_void=count - 2,
        model_void=1,
        cases=6,
        evaluator_groups=1,
        evidence_body_bytes=evidence_bytes,
        snapshot_age_blocks=1800,
        artificial_finality=True,
        artificial_inference=True,
        real_signature_and_replay_checks=True,
    )
    return SimpleNamespace(
        store=store,
        reviews=reviews,
        worker=worker,
        cutoffs=cutoffs,
        cutoff=cutoff,
        suite=item.suite,
        limits=limits,
        provider=provider,
        policy=policy,
        round=round_,
    )


async def pipeline(root, count):
    with phase("fixture_generation_and_native_retention"):
        s = fixture(root, count)
    gc.collect()
    pipeline_start = time.perf_counter()
    with phase("prepare_retained_settlement"):
        result = await prepare_retained_settlement(
            store=s.store,
            provider=s.provider,
            cutoff=s.cutoff,
            suite=s.suite,
            limits=s.limits,
            output_directory=root / "proposals",
        )
        assert result == "prepared"
    path = root / "proposals" / (digest(s.round) + ".settlement-proposal.json")
    REPORT["preparation_bytes"] = path.stat().st_size
    prepared = SettlementPreparation.model_validate_json(path.read_bytes())
    package_limits = CompetitionPackageLimits(
        maximum_manifest_bytes=65536,
        maximum_policy_bytes=1024**2,
        maximum_cutoff_certificate_bytes=4 * 1024**2,
        maximum_settlement_certificate_bytes=4 * 1024**2,
        maximum_settlement_bytes=4 * 1024**2,
        maximum_roster_bytes=4 * 1024**2,
        maximum_evidence_bytes=256 * 1024**2,
        maximum_replay_limits_bytes=4096,
        maximum_release_identity_bytes=4096,
        maximum_aggregate_bytes=320 * 1024**2,
    )
    release = CompetitionReleaseIdentity(
        schema="umi-competition-replay-release-identity/1",
        umi_revision=SOURCE,
        release_manifest_sha256="ab" * 32,
        release_bundle_sha256="cd" * 32,
        target_triple="aarch64-apple-darwin",
    )
    config = SettlementDeliveryConfig(
        state_directory=str(root / "delivery"),
        certificate_directory=str(root / "certificates"),
        package_directory=str(root / "packages"),
        package_limits=package_limits,
        release_identity=release,
    )
    queue = SettlementQueue(
        config, s.store, s.provider, limits=s.limits, maximum_rounds=10, maximum_bytes=2 * 1024**3
    )
    with phase("delivery_prepare"):
        assert await queue.prepare(prepared) is None
    del prepared
    gc.collect()
    app = FastAPI()
    attach_settlement_route(app, queue)
    client = SettlementSigningClient(
        s.worker,
        "https://rounds.example",
        s.cutoffs,
        s.reviews,
        limits=s.limits,
        transport=httpx.ASGITransport(app=app),
    )
    with phase("authenticated_proposal_query"):
        reply = await client.query(after=0)
        assert len(reply.proposals) == 1
    with phase("independent_review_and_signature"):
        vote = await client.signer.endorse(reply.proposals[0])
    del reply
    gc.collect()
    with phase("vote_delivery_certificate_and_package"):
        reply = await client.query(vote=vote)
        assert reply.accepted_publication_sha256 == vote.publication_sha256
    packages = list((root / "certificates").glob("*.package.json"))
    assert len(packages) == 1
    package = PreparedCompetitionPackage.model_validate_json(packages[0].read_bytes())
    REPORT["signed_package_wall_seconds"] = time.perf_counter() - pipeline_start
    REPORT["package_bytes"] = sum(p.stat().st_size for p in Path(package.package_path).iterdir())
    REPORT["package_sha256"] = package.package_sha256
    capacity = CompetitionWorkerCapacity(
        maximum_receipts=20,
        maximum_bytes=1024**3,
        publication_journal=PublicationJournalCapacity(
            maximum_certificates=20, maximum_bytes=512 * 1024**2
        ),
    )
    with phase("wallet_free_package_replay_and_retention"):
        result = CompetitionReplayWorker(
            root / "package-replay", package_limits=package_limits, capacity=capacity
        ).run(
            Path(package.package_path),
            expected_package_sha256=package.package_sha256,
            expected_policy_sha256=digest(s.policy),
            observed_release=release,
        )
        assert result.receipt.status == "replayed_no_weight"
        assert (
            result.current_status.settlement_certificate_retained and not result.current_status.held
        )
    REPORT["status"] = "complete_synthetic_full_pipeline"
    REPORT["pipeline_wall_seconds"] = time.perf_counter() - pipeline_start
    REPORT["settlement_certificate_retained"] = True
    REPORT["chain_submission_authorized"] = False
    save()
    emit(status=REPORT["status"], pipeline_wall_seconds=REPORT["pipeline_wall_seconds"])


if __name__ == "__main__":
    os.umask(0o077)
    root = Path(sys.argv[1]).resolve()
    root.mkdir(parents=True, exist_ok=False)
    REPORT_PATH = root / "metrics.json"
    REPORT.update(
        source=os.environ.get("SETTLEMENT_CONTROL_REVISION", SOURCE),
        producer_source_tree_sha256=umi_source_tree_sha256(),
        replay_fixture_revision=SOURCE,
        python=sys.version.split()[0],
        platform=sys.platform,
        status="running",
        release_identity_note=(
            "Manifest/bundle digests are synthetic fixture pins, not runtime attestation"
        ),
    )
    save()
    try:
        asyncio.run(pipeline(root, int(sys.argv[2])))
    except BaseException as exc:
        REPORT["status"] = "failed"
        REPORT["exception_type"] = type(exc).__name__
        save()
        traceback.print_tb(exc.__traceback__)
        emit(
            status="failed",
            exception_type=type(exc).__name__,
            message=str(exc)[:200]
            if not hasattr(exc, "errors")
            else "validation error (payload omitted)",
        )
        sys.exit(1)
