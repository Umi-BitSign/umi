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
from umi.competition_store import CompetitionStore
from umi.concurrency import run_owned_thread
from umi.open_competition import digest, sign_object
from umi.private_files import read_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_consumers import scenario as legacy_scenario  # noqa: F401
from .test_competition_cohort_consumers import transition
from .test_competition_cohort_intake import capture_at, request_for
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures
from .test_open_competition import bundle_at, wallet
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
def lifecycle(intake, scenario, tmp_path):
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
        prepared=None,
        factories=[],
        request_entered=asyncio.Event(),
        reports=[],
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

    h.queue = CohortAdmissionQueue(intake)
    for sequence, block in ((1, 210), (2, 240)):
        receipt = intake.retain(
            request_for(scenario, sequence=sequence, block=block), capture(block)
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
        return CohortPhaseDriver(
            CertifiedPhaseObserver(live, phase_signers(source, IntakeProgressReviewer), policy)
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

    def reopen():
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
