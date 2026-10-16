"""Normal issuance uses native original ledgers, R2 bytes and signing journals.

RPC/finality, R2 and keys are fixture ports. No production signing occurs.
"""

import asyncio
import sqlite3
from collections import Counter
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_history_http import (
    CohortHistoryExporter,
    CohortHistoryHTTPClient,
    CohortHistoryReader,
    cohort_history_routes,
)
from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_legacy_model_selection import LegacyModelStorageSourceConfig
from umi.competition_cohort_lifecycle import PHASES, CohortLifecycleService
from umi.competition_cohort_model_delivery_api import (
    ROOT,
    ModelDeliveryAdoptionCommit,
    ModelDeliveryAdoptionOwner,
    ModelDeliveryAdoptionPrepare,
    ModelDeliveryAdoptionProposal,
    ModelDeliveryAdoptionReviewer,
    ModelDeliveryAdoptionVotePeer,
    assemble_model_delivery_adoption,
    model_delivery_adoption_owner_routes,
    model_delivery_adoption_vote_routes,
)
from umi.competition_cohort_model_delivery_candidate import (
    ModelDeliveryAdoptionCandidate,
    ModelDeliveryAdoptionCandidateConfig,
)
from umi.competition_cohort_model_delivery_census import census_model_delivery
from umi.competition_cohort_model_delivery_reservation import (
    ModelDeliveryReservationExporter,
    ModelDeliveryReservationReader,
    ModelDeliveryReservationRequest,
    model_delivery_reservation_routes,
)
from umi.competition_cohort_model_upload import CohortModelUploads, ModelUploadConfig
from umi.competition_cohort_progress_signer import CohortProgressSigner, CohortProgressSignerConfig
from umi.competition_cohort_recovery import ModelDeliveryProfile
from umi.competition_cohort_recovery_store import CohortRecoveryStore
from umi.competition_cohort_request_rule import prepare_request_tail_adoption_at_block
from umi.competition_reward_decisions import StandingRewardSeries
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.open_competition import digest, sign_object
from umi.private_files import ensure_private_directory, publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_chunked_model_backup import Remote
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_legacy_model_storage import base_policy as base_policy
from .test_competition_cohort_legacy_model_storage import case as case
from .test_competition_cohort_legacy_model_storage import legacy_scenario as legacy_scenario
from .test_competition_cohort_legacy_model_storage import policy as policy
from .test_competition_cohort_legacy_model_storage import prepared as prepared
from .test_competition_cohort_legacy_model_storage import receipt_scenario as receipt_scenario
from .test_competition_cohort_legacy_model_storage import recovery as recovery
from .test_competition_cohort_legacy_model_storage import runtime as runtime
from .test_competition_cohort_model_acceptance import certify
from .test_competition_cohort_request_rule_api import post
from .test_open_competition import wallet

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
]


@pytest.fixture
def issuance(case, tmp_path):
    c = case
    root = tmp_path / "adoption-originals"
    ensure_private_directory(root)
    ensure_private_directory(root / "objects")
    for key, raw in c.objects.items():
        path = root / "objects" / (key + ".json")
        path.write_bytes(raw)
        path.chmod(0o600)
    publish_private_model(root / "legacy-inventory.json", c.legacy)
    publish_private_model(root / "preservation-inventory.json", c.preservation)
    objects = {}
    for bundle, path in (
        (c.subs[0].model_bundle, c.owner.archive / c.subs[0].model_revision / "model"),
        (c.baseline, tmp_path / "separate-baseline"),
    ):
        objects.update(
            {"chunks/sha256/" + f.sha256: (path / f.path).read_bytes() for f in bundle.files}
        )
    remote = Remote(objects)
    config = ModelDeliveryAdoptionCandidateConfig(
        schema="umi-model-delivery-adoption-candidate/1",
        source=LegacyModelStorageSourceConfig(
            schema="umi-legacy-model-storage-source/1",
            cohort_sha256=c.cohort,
            directory=str(root),
            baseline_model_sha256=digest(c.baseline),
        ),
        delivery=ModelDeliveryProfile(
            schema="umi-model-delivery-profile/1",
            mechanism="direct_r2_multipart_v1",
            part_size_bytes=5 * 1024**2,
            maximum_concurrent_parts=4,
            capability_ttl_seconds=3600,
        ),
        r2_credentials_file=str(tmp_path / "unused-credentials"),
        r2_bucket=remote.signer.bucket,
        verification_directory=str(tmp_path / "byte-receipts"),
    )
    candidate = ModelDeliveryAdoptionCandidate(config, c.policy, multipart=remote)
    uploads = CohortModelUploads(
        ModelUploadConfig(
            directory=str(tmp_path / "original-uploads"), maximum_reserved_bytes=1024**3
        ),
        c.owner.intake,
        c.owner.archive,
    )
    for request in c.requests:
        uploads.reserve(request.record.request, capture_at(220))
    transition = candidate.prepare(c.history, 221)
    return SimpleNamespace(
        case=c,
        config=config,
        candidate=candidate,
        uploads=uploads,
        transition=transition,
        root=root,
        remote=remote,
    )


def census(i, *, reserve=False):
    return census_model_delivery(
        i.case.owner.intake, i.uploads, i.transition, i.candidate, reserve=reserve
    )


def test_exact_census_preserves_originals_and_reserves_once(issuance):
    i = issuance
    raw = {
        key: i.uploads.journal.get_raw("upload", key) for key in i.uploads.journal.keys("upload")
    }
    assert census(i).legacy == i.case.legacy
    assert i.case.owner.intake.pending_policy_adoption(i.case.cohort) is None
    assert census(i, reserve=True).legacy == i.case.legacy
    assert census(i, reserve=True).legacy == i.case.legacy
    assert i.case.owner.intake.pending_policy_adoption(i.case.cohort) == i.transition
    assert {key: i.uploads.journal.get_raw("upload", key) for key in raw} == raw
    assert i.uploads.reserve(i.case.requests[0].record.request, None) == digest(
        i.case.requests[0].record.request
    )


@pytest.mark.parametrize(
    "fault", ["omitted_request", "omitted_intent", "omitted_certificate", "changed_copy"]
)
def test_census_refuses_omission_or_rewritten_original(issuance, fault):
    i = issuance
    legacy, preservation = i.case.legacy, i.case.preservation
    if fault == "changed_copy":
        entry = legacy.entries[0]
        (i.root / "objects" / (entry.request_raw_sha256 + ".json")).write_bytes(b"{}")
    else:
        entries = legacy.entries
        if fault == "omitted_request":
            entries = entries[1:]
        else:
            # Remove signed fields from metadata while retaining owner originals.
            selected = next(e for e in entries if e.certificate_raw_sha256 is not None)
            fields = {"certificate_raw_sha256": None}
            if fault == "omitted_intent":
                fields["intent_raw_sha256"] = None
            entries = tuple(e.model_copy(update=fields) if e == selected else e for e in entries)
        legacy = legacy.model_copy(update={"entries": entries})
        preservation = preservation.model_copy(update={"legacy_inventory_sha256": digest(legacy)})
        (i.root / "legacy-inventory.json").write_bytes(canonical_json_bytes(legacy))
        (i.root / "preservation-inventory.json").write_bytes(canonical_json_bytes(preservation))
        i.transition = i.candidate.prepare(i.case.history, 221)
    with pytest.raises(ValueError):
        census(i, reserve=True)
    assert i.case.owner.intake.pending_policy_adoption(i.case.cohort) is None


def test_late_acceptance_publication_stops_at_fence_but_old_retry_survives(issuance):
    i, c = issuance, issuance.case
    second = certify(
        c.owner, c.cohort, c.subs[1], c.owner.intent(c.cohort, digest(c.subs[1])).inputs
    )
    census(i, reserve=True)
    with pytest.raises(OSError, match="reserved model delivery"):
        c.owner.publish(second, capture_at(221))
    original = c.owner.retained(c.cohort, digest(c.subs[0]))
    assert c.owner.publish(original, capture_at(221)) == original
    assert census(i).legacy == c.legacy


async def test_r2_review_is_checkpointed_across_restart_and_detects_changed_bytes(issuance):
    i = issuance
    await i.candidate.verify(i.case.history, i.transition)
    reads = tuple(i.remote.reads)
    restarted = ModelDeliveryAdoptionCandidate(i.config, i.case.policy, multipart=i.remote)
    await restarted.verify(i.case.history, i.transition)
    assert tuple(i.remote.reads) == reads
    changed = next(iter(i.remote.objects))
    i.remote.etags[changed] = "new-generation"
    i.remote.objects[changed] = b"x" * len(i.remote.objects[changed])
    with pytest.raises(ValueError):
        await restarted.verify(i.case.history, i.transition)


@pytest.fixture
def owner_api(issuance, tmp_path):
    i, c = issuance, issuance.case
    db = sqlite3.connect(tmp_path / "control.sqlite3")
    store = CohortRecoveryStore(db)
    store.publish_history(c.history, c.policy, current_block=221)
    series = StandingRewardSeries(
        schema="umi-standing-reward-series/1",
        genesis_hash=FINNEY_GENESIS_HASH,
        netuid=78,
        policy_sha256=digest(c.policy),
        policy_epoch=1,
        manifest_sha256="aa" * 32,
        control_hotkey=wallet("Charlie").hotkey.ss58_address,
        recovery=c.history.authority,
        cohorts=(c.history.plan,),
        validators=(wallet("Charlie").hotkey.ss58_address,),
        maximum_proof_lag_blocks=100,
        maximum_transaction_lifetime_blocks=100,
        lifetime="until_superseded_or_revoked",
    )

    async def sign(body):
        return sign_object(body, wallet("Charlie"))

    async def current_block():
        return 221

    async def unused():
        pytest.fail("explicit held adoption must not run an automatic lifecycle stage")

    async def publish(history):
        c.owner.intake.publish(history, capture_at(221))

    provider = SimpleNamespace(policy=c.policy, current_finalized_block=current_block)
    node = CohortLifecycleService(
        store,
        c.cohort,
        c.policy,
        c.history.genesis_signatures,
        provider,
        publish,
        {phase: unused for phase in PHASES},
    )
    host = SimpleNamespace(
        config=SimpleNamespace(
            model_delivery_adoption_candidates=(i.config,),
            automatic_progression_hold_cohorts=(c.cohort,),
        ),
        service=SimpleNamespace(
            config=SimpleNamespace(
                series=series,
                admission_owner=SimpleNamespace(owner_hotkey=wallet("Charlie").hotkey.ss58_address),
            ),
            intake=c.owner.intake,
            uploads=i.uploads,
        ),
        nodes={c.cohort: node},
        policy=c.policy,
        provider=provider,
        timeout_seconds=30,
        sign=sign,
        model_delivery_candidates={c.cohort: i.candidate},
        model_delivery_serial=asyncio.Lock(),
    )
    app = FastAPI()
    app.include_router(model_delivery_adoption_owner_routes(host, token="o" * 32))
    app.include_router(model_delivery_reservation_routes(host, token="h" * 32))
    app.include_router(
        cohort_history_routes(
            CohortHistoryExporter(c.owner.intake, wallet("Charlie").hotkey.ss58_address, sign),
            token="h" * 32,
        )
    )
    yield SimpleNamespace(i=i, host=host, app=app, series=series, store=store, node=node)
    db.close()


async def test_normal_owner_routes_review_quorum_commit_and_repeat(owner_api, tmp_path):
    a, i = owner_api, owner_api.i
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=a.app), base_url="https://owner.example"
    ) as client:
        prepare = ModelDeliveryAdoptionPrepare(
            schema="umi-model-delivery-adoption-prepare/1",
            series_sha256=digest(a.series),
            cohort_sha256=i.case.cohort,
            predecessor_sha256=history_tip(i.case.history),
        )
        assert (await post(client, ROOT + "/prepare", prepare, token="h" * 32)).status_code == 401
        result = await post(client, ROOT + "/prepare", prepare)
        assert result.status_code == 200, result.text
        p = ModelDeliveryAdoptionProposal.model_validate_json(result.content)
        assert (await post(client, ROOT + "/reserve", p)).status_code == 200
        assert (await post(client, ROOT + "/reserve", p)).status_code == 200
        history = CohortHistoryReader(
            wallet("Charlie").hotkey.ss58_address,
            CohortHistoryHTTPClient(client, "https://owner.example", token="h" * 32),
        )
        reviewer = SimpleNamespace(
            policy=i.case.policy,
            cohorts=i.case.owner.intake.config.cohorts,
            model_delivery_adoption=ModelDeliveryAdoptionReviewer(
                a.series,
                i.case.policy,
                a.host.provider,
                history,
                ModelDeliveryReservationReader(
                    client,
                    "https://owner.example",
                    token="h" * 32,
                    owner=wallet("Charlie").hotkey.ss58_address,
                ),
                candidates={i.case.cohort: i.candidate},
            ),
        )
        votes, signers = [], []
        for name in ("Charlie", "Dave"):

            async def sign(body, name=name):
                return sign_object(body, wallet(name))

            signer = CohortProgressSigner(
                CohortProgressSignerConfig(
                    schema="umi-cohort-progress-signer-config/1",
                    directory=str(tmp_path / name),
                    policy_sha256=digest(i.case.policy),
                    signer=wallet(name).hotkey.ss58_address,
                    cohorts=i.case.owner.intake.config.cohorts,
                ),
                reviewer,
                sign,
            )
            signers.append(signer)
            app = FastAPI()
            app.include_router(
                model_delivery_adoption_vote_routes(signer, a.series, token="v" * 32)
            )
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as peer_client:
                peer = ModelDeliveryAdoptionVotePeer(
                    peer_client,
                    "https://review.example",
                    signer=signer.config.signer,
                    token="v" * 32,
                )
                votes.append(await peer.certify(p))
                assert await peer.certify(p) == votes[-1]
        certificate = assemble_model_delivery_adoption(p, votes, i.case.policy)
        other = prepare_request_tail_adoption_at_block(i.case.history, i.case.policy, 221)
        with pytest.raises(ValueError, match="reserved for another body"):
            await signers[0].certify_request_tail_adoption(other)
        commit = ModelDeliveryAdoptionCommit(
            schema="umi-model-delivery-adoption-commit/1",
            series_sha256=digest(a.series),
            certificate=certificate,
        )
        assert (await post(client, ROOT + "/commit", commit)).status_code == 200
        assert (await post(client, ROOT + "/commit", commit)).status_code == 200
        assert i.case.owner.intake.pending_policy_adoption(i.case.cohort) is None
        assert i.case.owner.intake.history(i.case.cohort).plan == i.case.history.plan
        assert i.case.cohort in a.host.config.automatic_progression_hold_cohorts


async def test_explicit_held_owner_initialization_does_not_tick(owner_api):
    a, i = owner_api, owner_api.i
    calls = []
    a.host.nodes.clear()

    async def node(cohort):
        calls.append(cohort)
        a.host.nodes[cohort] = a.node
        return a.node

    a.host.node = node
    request = ModelDeliveryAdoptionPrepare(
        schema="umi-model-delivery-adoption-prepare/1",
        series_sha256=digest(a.series),
        cohort_sha256=i.case.cohort,
        predecessor_sha256=history_tip(i.case.history),
    )
    await ModelDeliveryAdoptionOwner(a.host, "prepare").respond(request)
    assert calls == [i.case.cohort]
    assert a.store.status(i.case.cohort)[1] is None
    assert a.host.config.automatic_progression_hold_cohorts == (i.case.cohort,)


async def test_challenge_proof_requires_dual_reservation_and_refuses_replay(owner_api):
    a, i = owner_api, owner_api.i
    request = ModelDeliveryReservationRequest(
        schema="umi-model-delivery-reservation-request/1",
        transition=i.transition,
        challenge="12" * 32,
    )
    exporter = ModelDeliveryReservationExporter(a.host)
    census(i, reserve=True)
    with pytest.raises(ValueError, match="both owner journals"):
        await exporter.respond(request)
    a.store.reserve_exact(i.transition)
    raw = await exporter.respond(request)
    reader = ModelDeliveryReservationReader(
        None, "https://owner.example", token="h" * 32, owner=wallet("Charlie").hotkey.ss58_address
    )
    reader._verify(raw, request, i.case.history)
    with pytest.raises(ValueError, match="challenge"):
        reader._verify(raw, request.model_copy(update={"challenge": "13" * 32}), i.case.history)


def replace_candidate_inventory(i, legacy):
    preservation = i.case.preservation.model_copy(
        update={"legacy_inventory_sha256": digest(legacy)}
    )
    (i.root / "legacy-inventory.json").write_bytes(canonical_json_bytes(legacy))
    (i.root / "preservation-inventory.json").write_bytes(canonical_json_bytes(preservation))
    i.transition = i.candidate.prepare(i.case.history, 221)


def test_uncertified_participation_cannot_publish_admission_during_fence(issuance):
    from umi.competition_cohort_admission_journal import CohortAdmissionVote
    from umi.competition_cohort_admission_queue import CohortAdmissionQueue

    i, c = issuance, issuance.case
    request = c.requests[1]
    consent = request.record.proposed_admission.consent_sha256
    # Start from a supported fixture state: retained participation, quorum votes,
    # no published admission and therefore no acceptance intent yet.
    with c.owner.intake._connection() as (db, _):
        db.execute("DELETE FROM cohort_admission_certificates WHERE consent=?", (consent,))
        db.execute(
            "DELETE FROM cohort_model_acceptance_intents WHERE cohort=? AND submission=?",
            (c.cohort, digest(c.subs[1])),
        )
    legacy = c.legacy.model_copy(
        update={
            "entries": tuple(
                e.model_copy(update={"admission_raw_sha256": None, "intent_raw_sha256": None})
                if e.request_sha256 == digest(request.record.request)
                else e
                for e in c.legacy.entries
            )
        }
    )
    replace_candidate_inventory(i, legacy)
    census(i, reserve=True)
    vote = CohortAdmissionVote(
        admission=request.admission.admission, signature=request.admission.signatures[0]
    )
    with pytest.raises(OSError, match="reserved model delivery"):
        CohortAdmissionQueue(c.owner.intake).publish_vote(vote, capture_at(221))
    assert census(i).legacy == legacy


def test_unadmitted_upload_is_part_of_complete_census(issuance):
    i, c = issuance, issuance.case
    request = c.requests[1]
    consent = request.record.proposed_admission.consent_sha256
    with c.owner.intake._connection() as (db, _):
        db.execute(
            "DELETE FROM cohort_model_acceptance_intents WHERE cohort=? AND submission=?",
            (c.cohort, digest(c.subs[1])),
        )
        db.execute("DELETE FROM cohort_admission_certificates WHERE consent=?", (consent,))
        db.execute("DELETE FROM cohort_consents WHERE consent=?", (consent,))
    legacy = c.legacy.model_copy(
        update={
            "entries": tuple(
                e.model_copy(
                    update={
                        "participation_raw_sha256": None,
                        "admission_raw_sha256": None,
                        "intent_raw_sha256": None,
                    }
                )
                if e.request_sha256 == digest(request.record.request)
                else e
                for e in c.legacy.entries
            )
        }
    )
    replace_candidate_inventory(i, legacy)
    assert census(i).legacy == legacy
    replace_candidate_inventory(
        i,
        legacy.model_copy(
            update={
                "entries": tuple(
                    e for e in legacy.entries if e.request_sha256 != digest(request.record.request)
                )
            }
        ),
    )
    with pytest.raises(ValueError, match="omits or adds original upload"):
        census(i, reserve=True)
    assert c.owner.intake.pending_policy_adoption(c.cohort) is None


async def test_partial_dual_reservation_recovers_exact_intake_bytes(owner_api, monkeypatch):
    a, i = owner_api, owner_api.i
    proposal = ModelDeliveryAdoptionProposal(
        schema="umi-model-delivery-adoption-proposal/1",
        series_sha256=digest(a.series),
        transition=i.transition,
    )
    reserve = a.store.reserve_exact

    def interrupted(_):
        raise OSError("fixture control reservation interrupted after intake commit")

    monkeypatch.setattr(a.store, "reserve_exact", interrupted)
    with pytest.raises(OSError, match="interrupted after intake"):
        await ModelDeliveryAdoptionOwner(a.host, "reserve").respond(proposal)
    assert i.case.owner.intake.pending_policy_adoption(i.case.cohort) == i.transition
    assert a.store.status(i.case.cohort)[1] is None
    monkeypatch.setattr(a.store, "reserve_exact", reserve)
    raw = await ModelDeliveryAdoptionOwner(a.host, "reserve").respond(proposal)
    assert raw == canonical_json_bytes(proposal)
    assert a.store.status(i.case.cohort)[1] == i.transition


async def test_committed_control_republishes_same_certificate_after_lost_ack(owner_api):
    from .test_competition_cohort_recovery import signed_transition

    a, i = owner_api, owner_api.i
    census(i, reserve=True)
    a.store.reserve_exact(i.transition)
    commit = ModelDeliveryAdoptionCommit(
        schema="umi-model-delivery-adoption-commit/1",
        series_sha256=digest(a.series),
        certificate=signed_transition(i.transition),
    )
    publish = a.node.publish_history

    async def interrupted(_):
        raise OSError("fixture publication interrupted")

    a.node.publish_history = interrupted
    with pytest.raises(OSError, match="publication interrupted"):
        await ModelDeliveryAdoptionOwner(a.host, "commit").respond(commit)
    assert a.store.status(i.case.cohort)[0].tip_sha256 == digest(i.transition)
    assert i.case.owner.intake.pending_policy_adoption(i.case.cohort) == i.transition
    a.node.publish_history = publish
    await ModelDeliveryAdoptionOwner(a.host, "commit").respond(commit)
    await ModelDeliveryAdoptionOwner(a.host, "commit").respond(commit)
    assert i.case.owner.intake.history(i.case.cohort).transitions[-1] == commit.certificate


async def test_interrupted_remote_review_resumes_completed_files(issuance):
    i = issuance
    # Fail the final file of the first distinct model after prior files complete.
    first_model = sorted(i.case.preservation.models, key=lambda m: m.model_sha256)[0]
    bundle = (
        i.case.baseline
        if first_model.model_sha256 == digest(i.case.baseline)
        else i.case.subs[0].model_bundle
    )
    i.remote.fail = "chunks/sha256/" + bundle.files[-1].sha256
    with pytest.raises(OSError, match="interrupted fixture"):
        await i.candidate.verify(i.case.history, i.transition)
    completed = tuple(i.remote.reads)
    i.remote.fail = None
    restarted = ModelDeliveryAdoptionCandidate(i.config, i.case.policy, multipart=i.remote)
    await restarted.verify(i.case.history, i.transition)
    assert completed
    expected = Counter(
        "chunks/sha256/" + file.sha256
        for model in (i.case.baseline, i.case.subs[0].model_bundle)
        for file in model.files
    )
    assert Counter(i.remote.reads) == expected
    reads = tuple(i.remote.reads)
    await restarted.verify(i.case.history, i.transition)
    assert tuple(i.remote.reads) == reads


def test_missing_inventory_reports_repair_with_progress_and_no_new_reservation(issuance, caplog):
    import json

    from umi.competition_cohort_legacy_model_storage import LegacyModelStorageRepairRequired

    i = issuance
    caplog.set_level("INFO", logger="umi.competition.progress")
    (i.root / "preservation-inventory.json").unlink()
    with pytest.raises(LegacyModelStorageRepairRequired, match="requires repair"):
        census(i, reserve=True)
    reports = [
        json.loads(record.message)
        for record in caplog.records
        if record.message.startswith('{"schema":"umi-transport-work-progress/1"')
    ]
    repair = next(report for report in reports if report["status"] == "repair_required")
    assert repair["stage"] == "model_delivery_adoption_metadata"
    assert repair["completed_units"] == 1 and repair["total_units"] == 2
    assert "eta_basis" in repair and "elapsed_seconds" in repair
    assert i.case.owner.intake.pending_policy_adoption(i.case.cohort) is None


def test_owner_candidate_requires_explicit_private_configuration(owner_api):
    from umi.competition_cohort_model_delivery_api import selected_owner_candidate

    a, i = owner_api, owner_api.i
    a.host.model_delivery_candidates.clear()
    selected = selected_owner_candidate(a.host, i.case.cohort)
    assert selected.config == i.config
    assert selected.authenticate(i.case.history, i.transition).legacy == i.case.legacy
    a.host.model_delivery_candidates.clear()
    a.host.config.model_delivery_adoption_candidates = ()
    with pytest.raises(ValueError, match="privately selected candidate"):
        selected_owner_candidate(a.host, i.case.cohort)


@pytest.mark.parametrize(
    "schema", ["umi-recoverable-cohort-plan/2", "umi-recoverable-cohort-plan/4"]
)
async def test_actual_lifecycle_initialization_recovers_model_reservation_for_old_and_tail_plans(
    issuance, tmp_path, schema
):
    from umi.competition_cohort_intake import CohortIntake, CohortIntakeBinding, CohortIntakeConfig
    from umi.competition_cohort_lifecycle_host import LifecycleHost
    from umi.competition_cohort_model_transport import prepare_model_delivery_adoption
    from umi.competition_cohort_order_signer import CohortOrderHistory
    from umi.competition_cohort_recovery import RecoverableCohortPlan, cohort_model_delivery

    from .test_competition_cohort_recovery import signatures
    from .test_competition_cohort_standing_phases import standing

    i, policy = issuance, issuance.case.policy
    body = i.case.history.plan.model_dump(by_alias=True)
    body["schema"] = schema
    body["eligible_tracks"] = ("model",)
    body["service_pool_bps"] = 0
    if schema.endswith("/4"):
        body["model_delivery"] = cohort_model_delivery(i.case.history.plan).model_dump(
            by_alias=True
        )
        body["request_tail_rule"] = "original_request_12h_with_completed_miner/1"
    plan = RecoverableCohortPlan.model_validate(body)
    authority, genesis, _ = standing(plan, policy, model_rewards=True)
    history = i.case.history.model_copy(
        update={
            "plan": plan,
            "authority": authority,
            "genesis": genesis,
            "genesis_signatures": signatures(genesis),
            "transitions": (),
        }
    )
    cohort = digest(plan)
    intake = CohortIntake(
        CohortIntakeConfig(
            directory=str(tmp_path / "restart-intake"),
            cohorts=(
                CohortIntakeBinding(
                    cohort_sha256=cohort, authority_sha256=digest(authority.authority)
                ),
            ),
        ),
        policy,
        eligible_tracks=("model",),
        initialize=True,
    )
    intake.publish(history, capture_at(221))
    # Start at the exact durable partial-reservation boundary. No reviewer vote
    # or transport authority is asserted by these unsigned fixture inventories.
    proposal = prepare_model_delivery_adoption(
        history,
        policy,
        expected_tip_sha256=history_tip(history),
        current_block=221,
        delivery=i.config.delivery,
        legacy_inventory_sha256="31" * 32,
        preservation_inventory_sha256="32" * 32,
    )
    with intake._connection() as (_, store):
        store.reserve_exact(proposal)
    db = sqlite3.connect(tmp_path / "restart-control.sqlite3")
    store = CohortRecoveryStore(db)
    store.publish_history(history, policy, current_block=221)

    async def original(_):
        return CohortOrderHistory(history=history, decisions=())

    async def unused(*_):
        pytest.fail("owner initialization must not run automatic phase work")

    host = SimpleNamespace(
        nodes={},
        stores={cohort: store},
        policy=policy,
        forecast_ledger=None,
        service=SimpleNamespace(
            history=original,
            intake=intake,
            config=SimpleNamespace(
                series=SimpleNamespace(cohorts=(plan,), recovery=authority),
                admission_owner=SimpleNamespace(phase_review_budget=None),
            ),
        ),
        provider=SimpleNamespace(collect=unused),
        decision=unused,
        gate=None,
        _intake=unused,
        _preparation=unused,
        _requests=unused,
    )
    try:
        node = await LifecycleHost.node(host, cohort)
        assert node.controller.store.status(cohort)[1] == proposal
        assert intake.pending_policy_adoption(cohort) == proposal
        assert node.drivers == {}
    finally:
        db.close()


@pytest.mark.parametrize("failure", ["unavailable", "regressed"])
async def test_independent_review_rechecks_owned_finality_after_remote_work(owner_api, failure):
    a, i = owner_api, owner_api.i
    census(i, reserve=True)
    a.store.reserve_exact(i.transition)
    calls = []

    async def current_block():
        calls.append(1)
        if len(calls) > 1:
            if failure == "unavailable":
                raise OSError("fixture finality lost after remote work")
            return 220
        return 221

    provider = SimpleNamespace(policy=i.case.policy, current_finalized_block=current_block)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=a.app)) as client:
        history = CohortHistoryReader(
            wallet("Charlie").hotkey.ss58_address,
            CohortHistoryHTTPClient(client, "https://owner.example", token="h" * 32),
        )
        reviewer = ModelDeliveryAdoptionReviewer(
            a.series,
            i.case.policy,
            provider,
            history,
            ModelDeliveryReservationReader(
                client,
                "https://owner.example",
                token="h" * 32,
                owner=wallet("Charlie").hotkey.ss58_address,
            ),
            candidates={i.case.cohort: i.candidate},
        )
        with pytest.raises((OSError, ValueError), match=r"after remote work|regressed"):
            await reviewer(i.transition)
    assert len(calls) == 2 and i.remote.reads


def test_model_adoption_complete_exchange_includes_selected_remote_budget(owner_api):
    from umi.competition_cohort_review_budget import PhaseReviewBudget

    a, i = owner_api, owner_api.i
    budget = PhaseReviewBudget(
        schema="umi-cohort-phase-review-budget/1",
        policy_sha256=digest(i.case.policy),
        evaluation_runtime_sha256=i.case.policy.evaluation_runtime_sha256,
        maximum_aggregate_evidence_bytes=1024**3,
        export_seconds=30,
        replay_seconds=10000,
        authority_seconds=20,
        signing_seconds=300,
        transport_seconds=60,
        vote_queue_seconds=40,
        export_queue_slots=2,
    )
    a.host.service.config.admission_owner.phase_review_budget = budget
    owner = ModelDeliveryAdoptionOwner(a.host, "reserve")
    assert owner.timeout_seconds == 10050
    peer = ModelDeliveryAdoptionVotePeer(
        None,
        "https://review.example",
        signer=wallet("Charlie").hotkey.ss58_address,
        token="v" * 32,
        budget=budget,
        policy=i.case.policy,
    )
    assert peer.timeout_seconds == budget.vote_exchange_seconds("adoption") + 10020


@pytest.mark.parametrize("migration", [False, True], ids=["shared", "old_root_import"])
async def test_candidate_to_committed_reader_reuses_account_byte_facts(
    issuance, tmp_path, migration
):
    from umi.competition_cohort_legacy_model_readers import LegacyModelStorageReaders
    from umi.competition_cohort_legacy_model_storage import authenticate_legacy_storage_inventories
    from umi.competition_cohort_model_transport_selection import CommittedModelDeliveryHistory
    from umi.competition_model_byte_store import ModelByteStoreConfig

    from .test_competition_cohort_recovery import signed_transition

    i, c = issuance, issuance.case
    shared = ModelByteStoreConfig(
        schema="umi-model-byte-verification-store/1", directory=str(tmp_path / "shared-byte-facts")
    )
    source = (
        i.config.source
        if migration
        else i.config.source.model_copy(update={"shared_byte_store": shared})
    )
    config = ModelDeliveryAdoptionCandidateConfig.model_validate_json(
        canonical_json_bytes(i.config.model_copy(update={"source": source}))
    )
    candidate = ModelDeliveryAdoptionCandidate(config, c.policy, multipart=i.remote)
    await candidate.verify(c.history, i.transition)
    if migration:
        shared = shared.model_copy(
            update={"imports": await candidate.export_completed(c.history, i.transition)}
        )
    i.remote.reads.clear()
    history = c.history.model_copy(update={"transitions": (signed_transition(i.transition),)})
    committed = CommittedModelDeliveryHistory(
        schema="umi-committed-model-delivery-history/1",
        history=history,
        committed_tip_sha256=digest(i.transition),
        observed_at_block=221,
    )
    authenticated = authenticate_legacy_storage_inventories(
        canonical_json_bytes(c.legacy),
        canonical_json_bytes(c.preservation),
        selection=committed,
        policy=c.policy,
        expected_baseline_sha256=digest(c.baseline),
        expected_incumbent_sha256s=(),
    )
    consumer = LegacyModelStorageReaders(
        {c.cohort: authenticated},
        policy=c.policy,
        load_original=candidate.originals,
        multipart=i.remote,
        verification_root=tmp_path / "committed-role-root",
        byte_stores={c.cohort: shared},
    )
    for _ in range(2):
        for selector in (
            {"baseline": True},
            {"request_sha256": digest(c.requests[0].record.request)},
        ):
            resolution = consumer.resolve(c.cohort, **selector)
            reader = consumer.reader(resolution)
            snapshot = await reader.verify(
                document_paths=tuple(
                    r.path
                    for r in resolution.selection.bundle.files
                    if r.role in {"license", "provenance"}
                )
            )
            reader.require_verified(snapshot)
    assert not i.remote.reads
    assert c.owner.intake.pending_policy_adoption(c.cohort) is None
