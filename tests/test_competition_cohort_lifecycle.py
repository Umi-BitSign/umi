"""Recurring native admission and phase control, with synthetic finality/HTTPS."""

import asyncio
import hashlib
import sqlite3
from collections import Counter
from types import SimpleNamespace

import httpx
import pytest

from umi.competition_artifacts import preserve_bundle
from umi.competition_cohort_admission_journal import (
    CohortAdmissionJournal,
    CohortAdmissionSignerConfig,
)
from umi.competition_cohort_admission_queue import CohortAdmissionQueue
from umi.competition_cohort_admission_signer import CohortAdmissionSigner
from umi.competition_cohort_admission_worker import CohortAdmissionWorker
from umi.competition_cohort_coordinator import CohortDecisionInput
from umi.competition_cohort_history import CohortRecoveryHistory
from umi.competition_cohort_intake import CohortIntakePublisher, history_tip
from umi.competition_cohort_intake_phase import CohortIntakePhaseObserver
from umi.competition_cohort_intake_review import IntakeProgressReviewer, NativeIntakeProgressSource
from umi.competition_cohort_lifecycle import CohortLifecycleService, CohortPhaseDriver
from umi.competition_cohort_order_signer import CohortOrderHistory, CohortOrderParticipant
from umi.competition_cohort_participation import (
    CohortParticipationRequest,
    SignedCohortParticipationConsent,
)
from umi.competition_cohort_preparation import PreparedCohortRound
from umi.competition_cohort_preparation_owner import CohortPreparation
from umi.competition_cohort_preparation_phase import NativePreparationProgressSource
from umi.competition_cohort_preparation_publisher import CohortPreparationPublisher
from umi.competition_cohort_preparation_review import PreparationProgressReviewer
from umi.competition_cohort_progress_signer import (
    CertifiedPhaseObserver,
    CohortProgressSigner,
    CohortProgressSignerConfig,
)
from umi.competition_cohort_readiness import LiveIntakePhaseObserver, intake_readiness
from umi.competition_cohort_recovery import (
    SignedCohortRecoveryAuthority,
    StandingCohortRecoveryAuthority,
    admit_recoverable_cohort,
)
from umi.competition_cohort_recovery_store import CohortRecoveryStore
from umi.competition_cohort_service_queue import ServiceWorkQueue, ServiceWorkQueueConfig
from umi.competition_cohort_service_work import (
    PrecommittedServiceWorkCatalog,
    ServiceWorkClaim,
    SignedServiceWorkCatalog,
    SignedServiceWorkClaim,
)
from umi.competition_execution import execution_boundary
from umi.competition_reward_decisions import StandingRewardSeries
from umi.competition_reward_manifest import (
    RewardReplayRequirement,
    StandingRewardManifest,
    verify_reward_manifest,
)
from umi.competition_store import CompetitionStore
from umi.concurrency import run_owned_thread
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.open_competition import digest, sign_object
from umi.private_files import read_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_consumers import scenario as legacy_scenario  # noqa: F401
from .test_competition_cohort_consumers import transition
from .test_competition_cohort_intake import capture_at, request_for
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures
from .test_open_competition import bundle_at, submission, wallet
from .test_open_competition import policy as policy


@pytest.fixture
def scenario(request):
    old = request.getfixturevalue("legacy_scenario")
    plan = old["intake_history"].plan
    body = StandingCohortRecoveryAuthority(
        schema="umi-cohort-recovery-authority/2",
        policy_sha256=digest(old["policy"]),
        cohort_sha256s=(digest(plan),),
        issued_at_block=150,
        lifetime="until_completed_or_revoked",
        closure_rule="quorum_certified_phase_completion",
        timing_rule="targets_without_extension_signatures",
    )
    authority = SignedCohortRecoveryAuthority(authority=body, signatures=signatures(body))
    genesis, _ = admit_recoverable_cohort(plan, authority, old["policy"], admitted_at_block=160)
    history = CohortRecoveryHistory(
        schema="umi-cohort-recovery-history/1",
        plan=plan,
        authority=authority,
        genesis=genesis,
        genesis_signatures=signatures(genesis),
        transitions=(),
    )
    consent = old["consent"].consent.model_copy(update={"authority_sha256": digest(body)})
    return dict(
        old,
        intake_history=history,
        consent=old["consent"].model_copy(
            update={"consent": consent, "signature": sign_object(consent, wallet("Alice"))}
        ),
    )


@pytest.fixture
def lifecycle_before_intake(request):
    """Optional initialization before the lifecycle owner consumes any consent."""
    return getattr(request, "param", None)


@pytest.fixture
def lifecycle(intake, scenario, tmp_path, lifecycle_before_intake):
    history, policy = scenario["intake_history"], scenario["policy"]
    h = SimpleNamespace(
        intake=intake,
        history=history,
        cohort=digest(history.plan),
        block=240,
        ready=True,
        offline=False,
        calls=Counter(),
        fail=set(),
        paused_signers={},
        prepared=None,
        factories=[],
        request_entered=asyncio.Event(),
        reports=[],
        request_for=request_for,
    )
    metadata = b"fixture-metadata"
    archives = {}

    def capture(block):
        base = capture_at(block)
        # Native archive storage/identity is exercised. Proof verification is
        # the explicit synthetic Provider port below, not a real chain proof.
        raw = canonical_json_bytes(
            {
                "schema": "umi-competition-registration-evidence/1",
                "snapshot": base.snapshot.model_dump(mode="json", by_alias=True),
                "finality": {"fixture": True},
                "runtime_version": {},
                "runtime_metadata_sha256": hashlib.sha256(metadata).hexdigest(),
                "storage_batches": [
                    {
                        "state_root": base.provenance["state_root"],
                        "claims": [{"key": f"0x{i:02x}", "value": "0x00"}],
                        "proof": [],
                    }
                    for i in range(3)
                ],
            }
        )
        archives[block] = raw, metadata
        return base.__class__(
            base.snapshot,
            {
                **base.provenance,
                "evidence_sha256": hashlib.sha256(raw).hexdigest(),
            },
        )

    h.capture = capture
    h.queue = CohortAdmissionQueue(intake)
    if lifecycle_before_intake is not None:
        lifecycle_before_intake(h)
    for sequence, block in ((1, 210), (2, 240)):
        receipt = intake.retain(
            h.request_for(scenario, sequence=sequence, block=block), capture(block)
        )
        h.queue.attach_evidence(
            h.cohort, receipt["proposed_admission"]["consent_sha256"], *archives[block]
        )
    promotion = CompetitionStore(tmp_path / "promotion", policy)
    bundle = bundle_at(tmp_path / "model")
    preserve_bundle(bundle, tmp_path / "model", tmp_path / "archive", policy)
    promotion.initialize_baseline(bundle, tmp_path / "archive")
    owner = CohortPreparation(h.queue, promotion)
    h.owner = owner

    class Provider:
        def __init__(self):
            self.policy = policy

        def ensure_observer_running(self):
            if h.offline:
                raise OSError("finality offline")

        async def collect(self):
            self.ensure_observer_running()
            return capture(h.block)

        async def retained_archive(self, observation):
            capture(observation.block)
            return archives[observation.block]

        async def review_archive(self, observation, raw, metadata):
            capture(observation.block)
            assert (raw, metadata) == archives[observation.block]
            return SimpleNamespace(
                original=observation,
                snapshot=capture_at(observation.block).snapshot,
                replayed_at=SimpleNamespace(block_number=h.block),
            )

    provider = h.provider = Provider()
    h.output = tmp_path / "rounds" / (h.cohort + ".json")
    publisher = CohortPreparationPublisher(owner, provider, h.output.parent)

    async def signer(name, body):
        phase = getattr(body, "phase", "admission")
        if (name, phase) in h.fail:
            raise OSError("peer unavailable")
        if (name, phase) in h.paused_signers:
            entered, release = h.paused_signers[(name, phase)]
            entered.set()
            await release.wait()
        h.calls[(name, digest(body))] += 1
        return sign_object(body, wallet(name))

    def phase_signers(source, reviewer_type):
        result = []
        for name in ("Charlie", "Dave"):
            reviewer = reviewer_type(source, Provider(), provider.retained_archive)
            cfg = CohortProgressSignerConfig(
                schema="umi-cohort-progress-signer-config/1",
                directory=str(tmp_path / "progress" / name),
                policy_sha256=digest(policy),
                signer=wallet(name).hotkey.ss58_address,
                cohorts=intake.config.cohorts,
            )

            async def sign(body, name=name):
                return await signer(name, body)

            result.append(CohortProgressSigner(cfg, reviewer, sign))
        return tuple(result)

    async def ready(request):
        value = intake_readiness(
            intake,
            h.cohort,
            capture(h.block),
            nonce=request.url.params["nonce"],
            archive_available=h.ready,
        )
        return httpx.Response(
            200, content=canonical_json_bytes(value), headers={"content-type": "application/json"}
        )

    async def intake_driver():
        h.factories.append("intake")
        source = NativeIntakeProgressSource(intake)
        live = LiveIntakePhaseObserver(
            CohortIntakePhaseObserver(intake),
            "https://intake.example",
            transport=httpx.MockTransport(ready),
        )
        h.live = live
        return CohortPhaseDriver(
            CertifiedPhaseObserver(live, phase_signers(source, IntakeProgressReviewer), policy),
            sample_service=live.sample_service,
        )

    async def preparation_driver():
        h.factories.append("preparation")
        source = NativePreparationProgressSource(owner)
        return CohortPhaseDriver(
            CertifiedPhaseObserver(
                source.sample, phase_signers(source, PreparationProgressReviewer), policy
            ),
            publisher.publish_history,
        )

    async def requests_driver():
        h.factories.append("requests")
        h.prepared = read_private_model(h.output, PreparedCohortRound, maximum_bytes=64 * 1024**2)
        current = intake.history(h.cohort)
        assert h.prepared == owner.retained(
            h.cohort, expected_tip_sha256=history_tip(current), current_block=h.block
        )
        h.request_entered.set()
        # The request execution dependency is intentionally unavailable. Never
        # certify a missing round or silently skip the request phase.
        raise FileNotFoundError("request execution unavailable")

    h.db = sqlite3.connect(tmp_path / "control.sqlite3")
    h.store = CohortRecoveryStore(h.db)
    h.store.admit(history.plan, history.authority, policy, admitted_at_block=160)

    async def decision(cohort, key):
        return h.store.source(cohort, key, CohortDecisionInput)

    def reopen(**kwargs):
        return CohortLifecycleService(
            h.store,
            h.cohort,
            policy,
            history.genesis_signatures,
            provider,
            CohortIntakePublisher(intake, provider.collect, decision),
            {
                "intake": intake_driver,
                "preparation": preparation_driver,
                "requests": requests_driver,
            },
            **kwargs,
        )

    h.reopen = reopen
    h.admissions = []
    for name in ("Charlie", "Dave"):
        config = CohortAdmissionSignerConfig(
            schema="umi-cohort-admission-signer-config/1",
            directory=str(tmp_path / "admissions" / name),
            policy_sha256=digest(policy),
            signer=wallet(name).hotkey.ss58_address,
            cohorts=intake.config.cohorts,
        )

        async def source(cohort):
            return await run_owned_thread(h.queue.history, cohort)

        async def sign(body, name=name):
            return await signer(name, body)

        h.admissions.append(
            CohortAdmissionWorker(
                h.queue,
                CohortAdmissionSigner(
                    CohortAdmissionJournal(config, policy), Provider(), source, sign
                ),
            )
        )
    try:
        yield h
    finally:
        h.db.close()


def precommit_service_inventory(
    h,
    *,
    service_terms_sha256="a1" * 32,
    service_reference_sha256="93" * 32,
    service_video_sha256="92" * 32,
):
    """Select fixed inventory without reading a roster, promotion or future block."""
    assert h.intake.export_records(h.cohort, maximum_bytes=1024**2, maximum_records=8) == ()
    assert not h.intake.history(h.cohort).transitions
    policy = h.intake.policy
    body = PrecommittedServiceWorkCatalog(
        schema="umi-cohort-service-work-catalog/2",
        policy_sha256=digest(policy),
        cohort_sha256=h.cohort,
        authority_sha256=digest(h.history.authority.authority),
        service_terms_sha256=service_terms_sha256,
        work=(
            {
                "case_id": "91" * 32,
                "video_sha256": service_video_sha256,
                "reference_sha256": service_reference_sha256,
                "stratum": "fingerspelling",
            },
        ),
        selection_rule="global_fifo_no_identity_quota",
        credit_rule="verified_terminal_work_only",
    )
    histories = sorted(
        (h.intake.history(b.cohort_sha256) for b in h.intake.config.cohorts),
        key=lambda value: value.plan.sequence,
    )
    catalogs = tuple(
        SignedServiceWorkCatalog(catalog=value, signatures=signatures(value))
        for value in (
            body.model_copy(update={"cohort_sha256": digest(history.plan)}) for history in histories
        )
    )
    catalog = catalogs[0]
    manifest = StandingRewardManifest(
        schema="umi-standing-reward-manifest/1",
        policy_sha256=digest(policy),
        cohorts=tuple(
            RewardReplayRequirement(
                cohort_sha256=value.catalog.cohort_sha256,
                terms_sha256=body.service_terms_sha256,
                catalog_sha256s=(digest(value.catalog),),
            )
            for value in catalogs
        ),
    )
    series = StandingRewardSeries(
        schema="umi-standing-reward-series/1",
        genesis_hash=FINNEY_GENESIS_HASH,
        netuid=78,
        policy_sha256=digest(policy),
        policy_epoch=1,
        manifest_sha256=digest(manifest),
        control_hotkey=wallet("Ferdie").hotkey.ss58_address,
        recovery=h.history.authority,
        cohorts=tuple(history.plan for history in histories),
        validators=(wallet("Charlie").hotkey.ss58_address,),
        maximum_proof_lag_blocks=2,
        maximum_transaction_lifetime_blocks=128,
        lifetime="until_superseded_or_revoked",
    )
    h.precommitted = catalog, manifest, series
    h.catalogs = catalogs
    h.precommitted_bytes = tuple(canonical_json_bytes(v) for v in h.precommitted)
    assert verify_reward_manifest(h.precommitted_bytes[1], series, policy) == manifest


@pytest.mark.parametrize("lifecycle_before_intake", [precommit_service_inventory], indirect=True)
@pytest.mark.parametrize(
    "late_participant,preparation_delay,change_incumbent",
    [(False, 0, False), (True, 0, False), (False, 100000, False), (False, 0, True)],
    ids=["original", "late-participant", "late-preparation", "different-incumbent"],
)
async def test_precommitted_inventory_survives_native_intake_and_preparation(
    lifecycle, scenario, tmp_path, late_participant, preparation_delay, change_incumbent
):
    h, policy = lifecycle, lifecycle.intake.policy
    catalog, manifest, series = h.precommitted
    frozen = h.precommitted_bytes
    service = h.reopen()
    await service.tick()
    assert h.store.status(h.cohort)[0].phase == "intake"
    if late_participant:
        # Bob arrives after the first native intake sample and after commitment.
        h.block += 5
        signed = submission(policy, name="Bob")
        consent = scenario["consent"].consent.model_copy(
            update={
                "hotkey": signed.submission.hotkey,
                "submission_sha256": digest(signed.submission),
                "signed_at_block": h.block,
            }
        )
        request = CohortParticipationRequest(
            signed_submission=signed,
            consent=SignedCohortParticipationConsent(
                consent=consent, signature=sign_object(consent, wallet("Bob"))
            ),
        )
        capture = h.capture(h.block)
        receipt = h.intake.retain(request, capture)
        h.queue.attach_evidence(
            h.cohort,
            receipt["proposed_admission"]["consent_sha256"],
            *await h.provider.retained_archive(execution_boundary(capture)),
        )
    for worker in h.admissions:
        await worker.poll_once()
    for _ in range(100):
        if h.store.status(h.cohort)[0].phase != "intake":
            break
        h.block += 5
        await service.tick()
    assert h.store.status(h.cohort)[0].phase == "preparation"

    incumbent = h.owner.promotion.reviewed_promotion_head(h.cohort, maximum_bytes=16 * 1024**2)
    if change_incumbent:
        # Select a different real baseline store before preparation first runs.
        bundle = bundle_at(tmp_path / "later-model", marker="selected-after-precommit")
        archive = tmp_path / "later-archive"
        preserve_bundle(bundle, tmp_path / "later-model", archive, policy)
        promotion = CompetitionStore(tmp_path / "later-promotion", policy)
        promotion.initialize_baseline(bundle, archive)
        h.owner.promotion = promotion
        assert digest(bundle) != incumbent.model_sha256
        incumbent = promotion.reviewed_promotion_head(h.cohort, maximum_bytes=16 * 1024**2)
    h.block += preparation_delay
    preparation_block = h.block
    await service.tick()
    assert h.store.status(h.cohort)[0].phase == "requests"
    with pytest.raises(FileNotFoundError, match="request execution unavailable"):
        await service.tick()
    prepared = h.prepared
    round_ = prepared.roster.round
    assert round_.prepared_at_block == prepared.observation.block == preparation_block
    assert round_.incumbent_model_sha256 == incumbent.model_sha256
    assert prepared.roster.intake_seal.record_count == 2 + late_participant
    assert len(round_.participants) == 1 + late_participant
    assert tuple(canonical_json_bytes(v) for v in h.precommitted) == frozen
    assert verify_reward_manifest(frozen[1], series, policy) == manifest

    history = h.intake.history(h.cohort)
    assert [t.transition.phase for t in history.transitions] == ["intake", "preparation"]
    source = CohortOrderHistory(
        history=history,
        decisions=tuple(
            h.store.source(h.cohort, t.transition.evidence_sha256, CohortDecisionInput)
            for t in history.transitions
        ),
    )
    config = ServiceWorkQueueConfig(
        schema="umi-cohort-service-work-queue-config/1",
        directory=str(tmp_path / "precommitted-service"),
        policy_sha256=digest(policy),
        catalog_sha256=manifest.requirement(h.cohort).catalog_sha256s[0],
        service_terms_sha256=manifest.requirement(h.cohort).terms_sha256,
    )
    queue = ServiceWorkQueue(config, policy)
    capture = await h.provider.collect()
    tip = history_tip(history)
    with pytest.raises(ValueError, match="preparation"):
        queue.install(
            catalog,
            round_.model_copy(update={"prepared_at_block": preparation_block + 1}),
            source,
            capture,
            expected_tip_sha256=tip,
        )
    queue.install(catalog, round_, source, capture, expected_tip_sha256=tip)
    name = "Bob" if late_participant else "Alice"
    member = next(
        p
        for p in prepared.roster.participants
        if p.record.request.signed_submission.submission.hotkey == wallet(name).hotkey.ss58_address
    )
    signed = member.record.request.signed_submission
    participant = CohortOrderParticipant(
        consent=member.record.request.consent,
        admission=member.admission,
        admission_snapshot=member.record.snapshot,
    )
    claim_body = ServiceWorkClaim(
        schema="umi-cohort-service-work-claim/1",
        catalog_sha256=config.catalog_sha256,
        hotkey=signed.submission.hotkey,
        submission_sha256=digest(signed.submission),
        nonce="94" * 32,
    )
    claim = SignedServiceWorkClaim(
        claim=claim_body, signature=sign_object(claim_body, wallet(name))
    )
    admitted = queue.admit(claim, signed, participant, source, capture, expected_tip_sha256=tip)
    assignment = queue.assignment(claim)
    assert assignment.round == round_
    assert canonical_json_bytes(assignment.catalog) == frozen[0]
    assert assignment.admission == admitted
    assert admitted.ordinal == 1 and admitted.observation.block == h.block
    if preparation_delay:
        assert admitted.observation.block > signed.submission.valid_through_block
        assert admitted.observation.block > policy.valid_through_block

    h.offline = True
    h.block += 100000
    with pytest.raises(OSError, match="finality offline"):
        await h.provider.collect()
    reopened = ServiceWorkQueue(config, policy)
    # Exact install/admission retries recover with no current history or capture.
    reopened.install(catalog, round_, None, None, expected_tip_sha256=tip)
    assert (
        reopened.admit(claim, signed, participant, None, None, expected_tip_sha256=tip) == admitted
    )
    assert reopened.lookup(claim) == admitted
    assert canonical_json_bytes(reopened.assignment(claim)) == canonical_json_bytes(assignment)
    assert reopened.entries() == (admitted,)
    assert tuple(canonical_json_bytes(v) for v in h.precommitted) == frozen
    assert h.store.status(h.cohort)[0].phase == "requests"
    assert max(h.calls.values()) == 1


async def test_native_lifecycle_runs_intake_admission_and_preparation(lifecycle):
    h = lifecycle
    stop = asyncio.Event()

    async def admit():
        while not stop.is_set():
            for worker in h.admissions:
                await worker.poll_once()
            await asyncio.sleep(0.01)

    def report(value):
        h.reports.append(value)
        if value.get("phase") == "intake":
            h.block += 5

    service = h.reopen()
    tasks = [
        asyncio.create_task(service.run(stop, poll_seconds=0.01, report=report)),
        asyncio.create_task(admit()),
    ]
    try:
        await asyncio.wait_for(h.request_entered.wait(), 60)
    finally:
        stop.set()
        await asyncio.gather(*tasks)
    current = h.intake.history(h.cohort)
    assert [t.transition.phase for t in current.transitions] == ["intake", "preparation"]
    assert all(t.transition.operation == "close_phase" for t in current.transitions)
    assert h.prepared.roster.intake_seal.record_count == 2
    assert len(h.prepared.roster.participants) == 1
    assert h.factories[:3] == ["intake", "preparation", "requests"]
    assert h.store.status(h.cohort)[0].phase == "requests"
    assert max(h.calls.values()) == 1


async def test_lifecycle_recovers_partial_preparation_vote_and_publication(lifecycle, monkeypatch):
    from umi import competition_cohort_preparation_publisher as module

    h = lifecycle
    for worker in h.admissions:
        await worker.poll_once()
    service = h.reopen()
    while h.store.status(h.cohort)[0].phase == "intake":
        await service.tick()
        h.block += 5
    h.fail.add(("Dave", "preparation"))
    with pytest.raises(ValueError, match="evaluator quorum"):
        await service.tick()
    prepared = h.owner.retained(
        h.cohort, expected_tip_sha256=history_tip(h.intake.history(h.cohort)), current_block=h.block
    )
    before = Counter(h.calls)
    original = module.publish_private_model
    lost = []

    def publish(*args, **kwargs):
        original(*args, **kwargs)
        if not lost:
            lost.append(True)
            raise OSError("publication acknowledgement lost")

    monkeypatch.setattr(module, "publish_private_model", publish)
    h.block += 100000
    h.fail.clear()
    with pytest.raises(OSError, match="acknowledgement lost"):
        await h.reopen().tick()
    assert h.store.status(h.cohort)[0].phase == "requests"
    assert "requests" not in h.factories
    with pytest.raises(FileNotFoundError, match="request execution unavailable"):
        await h.reopen().tick()
    assert h.prepared == prepared
    assert all(h.calls[k] == v for k, v in before.items())
    assert max(h.calls.values()) == 1


async def test_revoked_lifecycle_starts_no_phase_runtime(lifecycle):
    h = lifecycle
    revoked = transition(h.history, h.intake.policy, "revoke", h.block)
    h.store.publish_history(revoked, h.intake.policy, current_block=h.block)
    result = await h.reopen().run(asyncio.Event(), poll_seconds=0.01)
    assert result["status"] == "revoked"
    assert not h.factories and not h.calls


async def test_shutdown_drains_pending_phase_factory(lifecycle):
    h = lifecycle
    service = h.reopen()
    started, drained, stop = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def unavailable():
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(0.01)
            drained.set()

    service.factories["intake"] = unavailable
    task = asyncio.create_task(service.run(stop, poll_seconds=0.01))
    await asyncio.wait_for(started.wait(), timeout=5)
    stop.set()
    assert (await asyncio.wait_for(task, timeout=5))["status"] == "stopped"
    assert drained.is_set()
    assert not h.calls and not service.drivers


async def test_missing_prepared_publication_recovers_without_process_restart(lifecycle):
    h = lifecycle
    for worker in h.admissions:
        await worker.poll_once()
    service = h.reopen()
    while h.store.status(h.cohort)[0].phase != "requests":
        await service.tick()
        h.block += 5
    original, calls = h.output.read_bytes(), Counter(h.calls)
    h.output.unlink()
    with pytest.raises(FileNotFoundError, match="request execution unavailable"):
        await service.tick()
    assert h.output.read_bytes() == original
    assert h.calls == calls


async def test_recurring_lifecycle_resumes_after_long_finality_outage(lifecycle):
    h = lifecycle
    for worker in h.admissions:
        await worker.poll_once()
    before = Counter(h.calls)
    h.offline = True
    retries = 0
    stop = asyncio.Event()

    def report(value):
        nonlocal retries
        if h.offline:
            assert value["status"] == "cohort_lifecycle_retry"
            assert value["error_type"] == "OSError"
            assert value["stage"] == "history_publication"
            assert h.store.status(h.cohort)[0].phase == "intake"
            assert h.calls == before
            retries += 1
            if retries == 2:
                h.block += 100000
                h.offline = False
        elif h.request_entered.is_set():
            assert value["status"] == "cohort_lifecycle_retry"
            assert value["error_type"] == "FileNotFoundError"
            stop.set()
        else:
            # Native availability credits adjacent observations only within
            # its ten-block gap. Unknown intervals remain unavailable.
            h.block += 5

    result = await asyncio.wait_for(h.reopen().run(stop, poll_seconds=0.01, report=report), 60)
    assert result["status"] == "stopped"
    assert retries == 2
    assert h.prepared.roster.intake_seal.record_count == 2
    assert h.store.status(h.cohort)[0].phase == "requests"
    assert all(
        t.transition.operation == "close_phase" for t in h.intake.history(h.cohort).transitions
    )
    assert max(h.calls.values()) == 1


async def test_service_sampling_continues_while_progress_signing_is_slow(lifecycle):
    h = lifecycle
    for worker in h.admissions:
        await worker.poll_once()
    entered, release, stop = asyncio.Event(), asyncio.Event(), asyncio.Event()
    h.paused_signers[("Charlie", "intake")] = entered, release
    samples = []

    def sampled(value):
        if (
            value["status"] == "service_sample_retained"
            and entered.is_set()
            and not release.is_set()
        ):
            samples.append(h.block)
            h.block += 5
            if h.block >= 360:
                release.set()

    def report(value):
        if h.request_entered.is_set():
            assert value["status"] == "cohort_lifecycle_retry"
            stop.set()

    service = h.reopen()
    result = await asyncio.wait_for(
        service.run(
            stop, poll_seconds=0.01, sample_seconds=0.01, report=report, sample_report=sampled
        ),
        60,
    )
    assert result["status"] == "stopped"
    assert samples[-1] - samples[0] >= 100
    assert h.prepared.roster.intake_seal.observation.block <= 360
    # Only the initial unobserved interval was unavailable. Delayed review
    # did not consume the healthy service window or reset its epoch.
    with h.intake._connection() as (_, store):
        from umi.competition_cohort_availability import CohortServiceAvailability

        last = CohortServiceAvailability(store, h.intake.policy)._last(h.cohort, "intake")
    assert last.unavailable_blocks == 40
    assert max(h.calls.values()) == 1


async def test_shutdown_drains_sampler_and_blocked_signer(lifecycle):
    h = lifecycle
    entered, release, sampling, drained, stop = (asyncio.Event() for _ in range(5))
    h.paused_signers[("Charlie", "intake")] = entered, release
    service = h.reopen()
    factory = service.factories["intake"]

    async def driver():
        native = await factory()

        async def sample(state, capture):
            sampling.set()
            try:
                await asyncio.Event().wait()
            finally:
                await asyncio.sleep(0.01)
                drained.set()

        return CohortPhaseDriver(native.observer, sample_service=sample)

    service.factories["intake"] = driver
    task = asyncio.create_task(service.run(stop, poll_seconds=0.01, sample_seconds=0.01))
    try:
        await asyncio.wait_for(asyncio.gather(entered.wait(), sampling.wait()), 10)
    finally:
        stop.set()
        result = await asyncio.wait_for(task, 10)
    assert result["status"] == "stopped"
    assert drained.is_set()
    assert not release.is_set()
    # A cancelled in-flight vote leaves its original intent and releases the
    # signer mutex; a host can safely close/reopen its resources after run().
    journal = service.drivers["intake"].observer.signers[0].journal
    with journal.locked():
        pass


async def test_timed_phase_without_sampler_cannot_start(lifecycle):
    h = lifecycle
    service = h.reopen()
    factory = service.factories["intake"]

    async def incomplete():
        driver = await factory()
        return CohortPhaseDriver(driver.observer)

    service.factories["intake"] = incomplete
    with pytest.raises(ValueError, match="independent service sampling"):
        await service.tick()
    assert not h.calls
    assert not service.drivers


async def test_sampler_records_readiness_failures_and_unknown_gaps(lifecycle):
    h = lifecycle
    service = h.reopen()
    await service.tick()
    calls = Counter(h.calls)
    h.block += 5
    healthy = await service.sample_service()
    assert healthy["status"] == "service_sample_retained" and healthy["serving"]
    assert healthy["observed_at_block"] == h.block
    h.ready = False
    h.block += 5
    failed = await service.sample_service()
    assert not failed["serving"]
    assert failed["unavailable_blocks"] == healthy["unavailable_blocks"] + 5
    h.ready = True
    h.block += 5
    resumed = await service.sample_service()
    assert resumed["unavailable_blocks"] == failed["unavailable_blocks"] + 5
    h.offline = True
    with pytest.raises(OSError, match="finality offline"):
        await service.sample_service()
    h.offline = False
    h.block += 10000
    late = await service.sample_service()
    assert late["unavailable_blocks"] == resumed["unavailable_blocks"] + 10000
    assert h.calls == calls
    assert h.store.status(h.cohort)[0].phase == "intake"


async def test_sampling_keeps_captures_ordered_without_locking_vote_review(lifecycle):
    h = lifecycle
    service = h.reopen()
    entered, release, sampled = asyncio.Event(), asyncio.Event(), asyncio.Event()
    factory = service.factories["intake"]

    async def driver():
        native = await factory()
        observe = native.observer.observe

        async def slow_observation(state, capture):
            entered.set()
            await release.wait()
            return await observe(state, capture)

        async def sample(state, capture):
            sampled.set()
            return await native.sample_service(state, capture)

        native.observer.observe = slow_observation
        return CohortPhaseDriver(native.observer, sample_service=sample)

    service.factories["intake"] = driver
    control = asyncio.create_task(service.tick())
    sampler = None
    try:
        await asyncio.wait_for(entered.wait(), 5)
        h.block += 5
        sampler = asyncio.create_task(service.sample_service())
        await asyncio.sleep(0.02)
        # The coordinator owns an earlier capture. Recording a newer sample
        # here would make its original observation regress native finality.
        assert not sampled.is_set()
        release.set()
        progress, sample = await asyncio.wait_for(asyncio.gather(control, sampler), 10)
    finally:
        release.set()
        for task in (control, sampler):
            if task is not None:
                task.cancel()
        await asyncio.gather(
            *(t for t in (control, sampler) if t is not None), return_exceptions=True
        )
    assert progress["status"] == "waiting_phase_progress"
    assert sample["observed_at_block"] == h.block
    assert sample["unavailable_blocks"] == 40
    assert sampled.is_set()


@pytest.mark.parametrize("lifecycle_before_intake", [precommit_service_inventory], indirect=True)
async def test_selected_request_start_gate_survives_lifecycle_restart(lifecycle, tmp_path):
    from umi.competition_cohort_request_start import RequestStartConfig, SeriesRequestStart

    h = lifecycle
    series = h.precommitted[2]
    h.timestamp = 1_000_000
    h.provider.config = SimpleNamespace(maximum_head_age_ms=120_000, maximum_future_skew_ms=30_000)
    original = h.provider.collect

    async def collect():
        value = await original()
        return value.__class__(value.snapshot, dict(value.provenance, timestamp_ms=h.timestamp))

    h.provider.collect = collect
    config = RequestStartConfig(
        schema="umi-cohort-request-start-config/1",
        directory=str(tmp_path / "request-start"),
        first_cohort_not_before_unix_ms=2_000_000,
    )

    async def history(cohort):
        return await run_owned_thread(h.queue.history, cohort)

    def restart():
        return h.reopen(request_start=SeriesRequestStart(config, series, h.provider, history))

    service = restart()
    for worker in h.admissions:
        await worker.poll_once()
    for _ in range(100):
        if h.store.status(h.cohort)[0].phase != "intake":
            break
        h.block += 5
        await service.tick()
    assert h.store.status(h.cohort)[0].phase == "preparation"
    signatures = dict(h.calls)
    for _ in range(2):
        value = await service.tick()
        assert value["status"] == "waiting_request_rest"
        assert h.store.status(h.cohort)[0].phase == "preparation"
        assert not h.request_entered.is_set()
        assert dict(h.calls) == signatures
        service = restart()
    h.offline = True
    h.timestamp = config.first_cohort_not_before_unix_ms + h.provider.config.maximum_future_skew_ms
    with pytest.raises(OSError, match="finality offline"):
        await service.tick()
    assert h.store.status(h.cohort)[0].phase == "preparation"
    h.offline = False
    await service.tick()
    assert h.store.status(h.cohort)[0].phase == "requests"
    with pytest.raises(FileNotFoundError, match="request execution unavailable"):
        await service.tick()
    assert h.request_entered.is_set()
    assert max(h.calls.values()) == 1
