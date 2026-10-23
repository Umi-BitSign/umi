"""Actual sandbox leases consume authenticated /1 models through bounded R2 cache.

Final CPU execution and R2 are inert ports. Native retained intake records,
transport adoption, storage resolution, byte verification, cache and sandbox
selection are real; this does not grant independent review or execution authority.
"""

import asyncio
import json
import logging
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.competition_artifacts import verify_preserved_bundle
from umi.competition_cohort_direct_model_review import (
    DirectModelArtifactReviewer,
    DirectModelReviewSourceConfig,
)
from umi.competition_cohort_execution import RecoverableExecutionJob
from umi.competition_cohort_execution_journal import CohortExecutionAttempt, case_role_model
from umi.competition_cohort_legacy_model_cache import LegacyCohortModelCache
from umi.competition_cohort_legacy_model_readers import LegacyModelStorageReaders
from umi.competition_cohort_legacy_model_storage import (
    LegacyModelIncumbent,
    LegacyModelStorageRepairRequired,
)
from umi.competition_cohort_model_static_review import StandingModelReviewPolicy
from umi.competition_cohort_sandbox import DirectCohortCpuSandbox
from umi.competition_execution import ExecutionCase
from umi.competition_model_cache_space import BootDiskModelCache, BootDiskModelCacheConfig
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes, sha256_hex

from .test_competition_chunked_model_backup import Remote
from .test_competition_cohort_legacy_model_storage import authenticated, backup, retain
from .test_competition_cohort_legacy_model_storage import base_policy as base_policy
from .test_competition_cohort_legacy_model_storage import case as case
from .test_competition_cohort_legacy_model_storage import legacy_scenario as legacy_scenario
from .test_competition_cohort_legacy_model_storage import policy as policy
from .test_competition_cohort_legacy_model_storage import prepared as prepared
from .test_competition_cohort_legacy_model_storage import receipt_scenario as receipt_scenario
from .test_competition_cohort_legacy_model_storage import recovery as recovery
from .test_competition_cohort_legacy_model_storage import runtime as runtime
from .test_competition_execution import boundary
from .test_open_competition import bundle_at, wallet

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
]


@pytest.fixture
def installed(case, tmp_path, receipt_scenario, runtime, request):
    prefix = "preservation/v1/" if getattr(request, "param", None) == "prefixed" else ""
    incumbent = bundle_at(tmp_path / "execution-incumbent", "different-certified-winner")
    incumbent_pin = LegacyModelIncumbent(
        model_sha256=digest(incumbent),
        manifest_raw_sha256=retain(case.objects, incumbent),
    )
    legacy = case.legacy.model_copy(update={"incumbents": (incumbent_pin,)})
    if getattr(request, "param", None) == "new_acceptance":
        # Synthetic adoption census for an already admitted original that had
        # no acceptance yet. No original model/request/admission bytes change.
        selected = digest(case.requests[0].record.request)
        legacy = legacy.model_copy(
            update={
                "entries": tuple(
                    entry.model_copy(
                        update={"intent_raw_sha256": None, "certificate_raw_sha256": None}
                    )
                    if entry.request_sha256 == selected
                    else entry
                    for entry in legacy.entries
                )
            }
        )
    preservation = case.preservation.model_copy(
        update={
            "legacy_inventory_sha256": digest(legacy),
            "models": tuple(
                sorted(
                    (*case.preservation.models, backup(case.objects, incumbent, case.policy)),
                    key=lambda m: m.model_sha256,
                )
            ),
        }
    )
    if prefix:
        preservation = preservation.model_copy(
            update={
                "models": tuple(
                    model.model_copy(update={"object_key_prefix": prefix})
                    for model in preservation.models
                )
            }
        )
    auth = authenticated(
        case, legacy=legacy, preservation=preservation, incumbents=(digest(incumbent),)
    )
    remote_objects = {}
    candidate = case.subs[0].model_bundle
    for bundle, root in (
        (candidate, case.owner.archive / digest(candidate) / "model"),
        (case.baseline, tmp_path / "separate-baseline"),
        (incumbent, tmp_path / "execution-incumbent"),
    ):
        for file in bundle.files:
            remote_objects[prefix + "chunks/sha256/" + file.sha256] = (
                root / file.path
            ).read_bytes()
    remote = Remote(remote_objects)
    verification = tmp_path / "durable-byte-results"
    sources = LegacyModelStorageReaders(
        {case.cohort: auth},
        policy=case.policy,
        load_original=case.objects.__getitem__,
        multipart=remote,
        verification_root=verification,
    )
    config = DirectModelReviewSourceConfig(
        schema="umi-direct-model-review-source/2",
        r2_credentials_file=str(tmp_path / "unused-test-credentials"),
        r2_bucket=remote.signer.bucket,
        maximum_materialized_bytes=1024**2,
        materialization_free_space_reserve_bytes=64 * 1024**2,
        materialization_protected_roots=(str(case.owner.archive),),
        materialization_boot_disk_cache=BootDiskModelCacheConfig(
            schema="umi-boot-disk-model-cache/1",
            directory=str(tmp_path / "bounded-cache"),
            maximum_allocated_bytes=2 * 1024**2,
        ),
        standing_review_policy=StandingModelReviewPolicy(
            schema="umi-standing-model-artifact-review-policy/1",
            competition_policy_sha256=digest(case.policy),
            contribution_terms_sha256=case.policy.contribution_terms_sha256,
            standing_approval_record_sha256="ef" * 32,
            approved_by="fixture-independent-reviewer@example.test",
            approved_at_utc="2026-10-02T12:00:00Z",
            complete_declared_bundle_rights_approved=True,
            licenses_and_notices_reviewed=True,
            public_redistribution_and_evaluation_approved=True,
        ),
    )
    artifacts = DirectModelArtifactReviewer(
        config, case.policy, None, multipart=remote, verification_root=verification
    )
    request = case.requests[0]
    round_ = receipt_scenario["round_"].model_copy(
        update={"cohort_sha256": case.cohort, "incumbent_model_sha256": digest(case.baseline)}
    )
    job = RecoverableExecutionJob(
        schema="umi-recoverable-execution-job/1",
        mode="paired_model",
        round=round_,
        preparation_closure_sha256="ac" * 32,
        submission=request.record.request.signed_submission,
        incumbent=case.baseline,
        runtime=runtime,
        evaluator_hotkey=wallet("Charlie").hotkey.ss58_address,
        cases=tuple(
            ExecutionCase(case_id=c.case_id, video_sha256=c.video_sha256, stratum=c.stratum)
            for c in receipt_scenario["suite"].cases
        ),
    )
    return SimpleNamespace(
        case=case,
        job=job,
        incumbent=incumbent,
        artifacts=artifacts,
        sources=sources,
        remote=remote,
        object_key_prefix=prefix,
        verification=verification,
        root=tmp_path,
        request=request,
    )


def sandbox(installed):
    return DirectCohortCpuSandbox(
        installed.case.policy,
        archive=installed.case.owner.archive,
        videos=installed.root / "videos",
        workspace=Path(installed.artifacts.config.materialization_boot_disk_cache.directory)
        / "cpu",
        artifacts=installed.artifacts,
        request=lambda _: installed.request,
        legacy_artifacts=LegacyCohortModelCache(installed.artifacts, installed.sources),
    )


def attempt(job, step=0, number=1):
    return CohortExecutionAttempt(
        schema="umi-cohort-execution-attempt/1",
        job_sha256=digest(job),
        step_index=step,
        number=number,
        predecessor_sha256=None,
        started=boundary(1500),
        history_sha256="ab" * 32,
    )


def cpu_readback(port, installed, monkeypatch):
    seen = []

    async def invoke(job, selected, archive):
        _, role, bundle = case_role_model(job, selected.step_index)
        assert archive in (port.cache / "archive", port.cache / "standby")
        assert archive != port.archive
        assert verify_preserved_bundle(bundle, archive, installed.case.policy) == digest(bundle)
        root = archive / digest(bundle) / "model"
        for file in bundle.files:
            assert (root / file.path).read_bytes() == installed.remote.objects[
                installed.object_key_prefix + "chunks/sha256/" + file.sha256
            ]
        seen.append((role, digest(bundle)))
        return "inert-cpu-result"

    monkeypatch.setattr(port, "_invoke", invoke)
    return seen


@pytest.mark.parametrize("installed", [None, "prefixed"], indirect=True)
async def test_candidate_baseline_and_explicit_incumbent_use_actual_bounded_sandbox(
    installed, monkeypatch, caplog
):
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    originals = dict(installed.case.objects)
    port = sandbox(installed)
    seen = cpu_readback(port, installed, monkeypatch)
    job = installed.job
    assert await port.invoke(job, attempt(job)) == "inert-cpu-result"
    assert await port.invoke(job, attempt(job, 1)) == "inert-cpu-result"
    winner_job = job.model_copy(
        update={
            "incumbent": installed.incumbent,
            "round": job.round.model_copy(
                update={"incumbent_model_sha256": digest(installed.incumbent)}
            ),
        }
    )
    await port.invoke(winner_job, attempt(winner_job, 1))
    assert seen == [
        ("candidate", installed.case.subs[0].model_revision),
        ("incumbent", digest(installed.case.baseline)),
        ("incumbent", digest(installed.incumbent)),
    ]
    assert installed.case.objects == originals
    assert installed.request.acceptance.schema_ == "umi-cohort-model-artifact-acceptance/1"
    assert installed.request.direct_artifact is None
    assert port.active_candidate_invocations == 0
    root = port.cache / "archive"
    assert [p.name for p in root.iterdir() if p.is_dir()] == [digest(installed.incumbent)]
    config = installed.artifacts.config
    budget = BootDiskModelCache(config.materialization_boot_disk_cache, reserve_bytes=0)
    assert budget._allocation()[0] < budget.maximum_bytes
    events = [
        json.loads(record.message) for record in caplog.records if record.message.startswith("{")
    ]
    stages = {event.get("stage") for event in events}
    assert {
        "legacy_model_cache_space_preparation",
        "chunked_model_materialization",
        "chunked_model_local_cache_inventory",
        "model_cache_local_space",
        "model_cache_eviction",
    } <= stages
    for event in events:
        assert {"elapsed_seconds", "eta_seconds", "eta_basis"} <= event.keys()


async def test_restart_keeps_current_cache_without_get_and_eviction_keeps_durable_results(
    installed, monkeypatch
):
    job = installed.job
    port = sandbox(installed)
    cpu_readback(port, installed, monkeypatch)
    await port.invoke(job, attempt(job))
    reads = tuple(installed.remote.reads)
    durable = {p.relative_to(installed.verification) for p in installed.verification.rglob("*")}
    assert durable
    restarted = sandbox(installed)
    cpu_readback(restarted, installed, monkeypatch)
    await restarted.invoke(job, attempt(job))
    assert tuple(installed.remote.reads) == reads
    await restarted.invoke(job, attempt(job, 1))
    assert durable <= {
        p.relative_to(installed.verification) for p in installed.verification.rglob("*")
    }
    assert (restarted.cache / "archive" / installed.case.subs[0].model_revision).exists()
    before = len(installed.remote.reads)
    await restarted.invoke(job, attempt(job))
    assert len(installed.remote.reads) == before


async def test_alternating_pair_keeps_both_models_without_repeated_remote_reads(
    installed, monkeypatch
):
    port = sandbox(installed)
    seen = cpu_readback(port, installed, monkeypatch)
    job = installed.job
    await port.invoke(job, attempt(job))
    await port.invoke(job, attempt(job, 1))
    reads = tuple(installed.remote.reads)
    for number in (2, 3):
        await port.invoke(job, attempt(job, number=number))
        await port.invoke(job, attempt(job, 1, number=number))
    assert len(seen) == 6 and tuple(installed.remote.reads) == reads
    assert (port.cache / "archive" / digest(job.submission.submission.model_bundle)).is_dir()
    assert (port.cache / "standby" / digest(job.incumbent)).is_dir()
    restarted = sandbox(installed)
    cpu_readback(restarted, installed, monkeypatch)
    await restarted.invoke(job, attempt(job, number=4))
    await restarted.invoke(job, attempt(job, 1, number=4))
    assert tuple(installed.remote.reads) == reads


async def test_pair_capacity_releases_only_idle_managed_slot(installed, monkeypatch):
    port = sandbox(installed)
    cpu_readback(port, installed, monkeypatch)
    job = installed.job
    await port.invoke(job, attempt(job))
    config = installed.artifacts.config
    budget = BootDiskModelCache(config.materialization_boot_disk_cache, reserve_bytes=0)
    archive = port.cache / "standby"
    allocated, unit = budget._allocation()
    expected = budget._metadata_bytes(job.incumbent, unit) + sum(
        ((f.size_bytes + unit - 1) // unit) * unit for f in job.incumbent.files
    )
    # Leave enough space for the new model alone but not its current peer.
    sentinel = budget.root / "unrelated-consumer"
    sentinel.write_bytes(b"preserve")
    sentinel.chmod(0o600)
    sentinel_size = (budget.maximum_bytes - expected - allocated // 2) // unit * unit
    with sentinel.open("r+b") as stream:
        stream.truncate(sentinel_size)
    assert not budget.fits_materialization(job.incumbent, archive)
    await port.invoke(job, attempt(job, 1))
    assert not (port.cache / "archive").exists()
    assert (archive / digest(job.incumbent)).is_dir()
    assert sentinel.stat().st_size == sentinel_size
    assert sentinel.read_bytes()[:8] == b"preserve"
    assert budget._allocation()[0] < budget.maximum_bytes


async def test_interrupted_materialization_resumes_completed_files(installed, monkeypatch):
    bundle = installed.case.subs[0].model_bundle
    installed.remote.fail = "chunks/sha256/" + bundle.files[-1].sha256
    port = sandbox(installed)
    cpu_readback(port, installed, monkeypatch)
    with pytest.raises(OSError, match="interrupted fixture"):
        await port.invoke(installed.job, attempt(installed.job))
    completed = tuple(installed.remote.reads)
    assert completed and len(completed) < len(bundle.files)
    assert port.active_candidate_invocations == 0
    installed.remote.fail = None
    restarted = sandbox(installed)
    cpu_readback(restarted, installed, monkeypatch)
    await restarted.invoke(installed.job, attempt(installed.job))
    assert installed.remote.reads[: len(completed)] == list(completed)
    assert not set(completed) & set(installed.remote.reads[len(completed) :])


async def test_reference_switch_waits_until_all_candidate_cpu_leases_finish(installed, monkeypatch):
    port = sandbox(installed)
    entered, release, reference = asyncio.Event(), asyncio.Event(), asyncio.Event()
    active = 0

    async def invoke(job, selected, archive):
        nonlocal active
        _, role, bundle = case_role_model(job, selected.step_index)
        verify_preserved_bundle(bundle, archive, installed.case.policy)
        if role == "candidate":
            active += 1
            if active == 2:
                entered.set()
            await release.wait()
            assert (archive / digest(bundle)).is_dir()
        else:
            reference.set()
        return "inert"

    monkeypatch.setattr(port, "_invoke", invoke)
    job = installed.job
    first = asyncio.create_task(port.invoke(job, attempt(job)))
    second = asyncio.create_task(port.invoke(job, attempt(job, number=2)))
    await asyncio.wait_for(entered.wait(), 10)
    other = asyncio.create_task(port.invoke(job, attempt(job, 1)))
    for _ in range(100):
        await asyncio.sleep(0)
    assert not reference.is_set() and not other.done()
    assert port.active_candidate_invocations == 2
    release.set()
    await asyncio.wait_for(asyncio.gather(first, second, other), 10)
    assert reference.is_set() and port.active_candidate_invocations == 0


@pytest.mark.parametrize("changed", ["acceptance", "admission", "original", "missing_original"])
async def test_candidate_changes_cannot_fall_back_to_existing_local_archive(
    installed, monkeypatch, changed
):
    port = sandbox(installed)
    cpu_readback(port, installed, monkeypatch)
    request = installed.request
    if changed == "acceptance":
        installed.request = request.model_copy(
            update={"acceptance": request.acceptance.model_copy(update={"accepted_at_block": 219})}
        )
    elif changed == "admission":
        installed.request = request.model_copy(
            update={"admission": request.admission.model_copy(update={"signatures": ()})}
        )
    else:
        original = next(
            x
            for x in installed.sources.authenticated[installed.case.cohort].legacy.entries
            if x.request_sha256 == digest(request.record.request)
        )
        if changed == "original":
            installed.case.objects[original.intent_raw_sha256] += b"\n"
        else:
            installed.case.objects.pop(original.intent_raw_sha256)
    with pytest.raises((ValueError, LegacyModelStorageRepairRequired)):
        await port.invoke(installed.job, attempt(installed.job))
    assert not installed.remote.reads


async def test_unknown_incumbent_cannot_fall_back_to_local_archive(installed, monkeypatch):
    port = sandbox(installed)
    cpu_readback(port, installed, monkeypatch)
    candidate = installed.case.subs[0].model_bundle
    job = installed.job.model_copy(
        update={
            "incumbent": candidate,
            "round": installed.job.round.model_copy(
                update={"incumbent_model_sha256": digest(candidate)}
            ),
        }
    )
    with pytest.raises(ValueError, match="incumbent"):
        await port.invoke(job, attempt(job, 1))
    assert not installed.remote.reads


async def test_legacy_receipts_must_remain_outside_disposable_boot_cache(installed):
    port = sandbox(installed)
    installed.sources.verification_root = port.cache / "results"
    with pytest.raises(ValueError, match="overlaps the disposable cache"):
        await port.invoke(installed.job, attempt(installed.job))
    assert not installed.remote.reads


@pytest.mark.parametrize(
    "field,value", [("provenance_sha256", "ff" * 32), ("object_key_prefix", "preservation/v1/")]
)
def test_reader_rejects_unselected_inventory_provenance(installed, field, value):
    source = installed.sources.resolve(installed.case.cohort, baseline=True)
    changed = source.selection.model_copy(
        update={"binding": source.selection.binding.model_copy(update={field: value})}
    )
    with pytest.raises(ValueError, match="outside its authenticated inventories"):
        installed.sources.reader(replace(source, selection=changed))
    assert canonical_json_bytes(installed.request) == canonical_json_bytes(
        installed.case.requests[0]
    )


async def test_restart_restores_only_missing_file_and_leaves_original_archive_intact(
    installed, monkeypatch
):
    job = installed.job
    port = sandbox(installed)
    cpu_readback(port, installed, monkeypatch)
    await port.invoke(job, attempt(job))
    bundle = installed.case.subs[0].model_bundle
    missing = bundle.files[-1]
    cached = port.cache / "archive" / digest(bundle) / "model" / missing.path
    cached.unlink()
    before = len(installed.remote.reads)
    restarted = sandbox(installed)
    cpu_readback(restarted, installed, monkeypatch)
    await restarted.invoke(job, attempt(job))
    assert installed.remote.reads[before:] == ["chunks/sha256/" + missing.sha256]
    assert verify_preserved_bundle(
        bundle, installed.case.owner.archive, installed.case.policy
    ) == digest(bundle)


async def test_exhausted_shared_cache_retries_without_evicting_unrelated_consumer(installed):
    port = sandbox(installed)
    config = installed.artifacts.config.materialization_boot_disk_cache
    unrelated = Path(config.directory) / "another-consumer"
    with unrelated.open("wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.truncate(config.maximum_allocated_bytes - 80 * 1024)
    with pytest.raises(OSError, match="capacity"):
        await port.invoke(installed.job, attempt(installed.job))
    assert unrelated.stat().st_size == config.maximum_allocated_bytes - 80 * 1024
    assert not installed.remote.reads and port.active_candidate_invocations == 0


def test_reader_does_not_accept_another_self_consistent_package_under_same_provenance(installed):
    source = installed.sources.resolve(installed.case.cohort, baseline=True)
    selected = source.selection
    first = selected.package.files[0]
    changed_file = first.model_copy(
        update={"chunks": (first.chunks[0].model_copy(update={"sha256": "ff" * 32}),)}
    )
    package = selected.package.model_copy(
        update={"files": (changed_file, *selected.package.files[1:])}
    )
    package_hash = sha256_hex(canonical_json_bytes(package))
    association = selected.association.model_copy(
        update={
            "package_sha256": package_hash,
            "package_key": f"packages/{digest(selected.bundle)}/{package_hash}.json",
        }
    )
    replacement = selected.model_copy(
        update={
            "package": package,
            "association": association,
            "binding": selected.binding.model_copy(
                update={"association_sha256": sha256_hex(canonical_json_bytes(association))}
            ),
        }
    )
    with pytest.raises(ValueError, match="outside its authenticated inventories"):
        installed.sources.reader(replace(source, selection=replacement))
    assert not installed.remote.reads


@pytest.mark.parametrize("installed", ["new_acceptance"], indirect=True)
@pytest.mark.parametrize("accepted_at", [220, 221, 222])
async def test_original_admission_without_old_intent_can_use_new_post_adoption_acceptance(
    installed, monkeypatch, accepted_at
):
    originals = dict(installed.case.objects)
    installed.request = installed.request.model_copy(
        update={
            "acceptance": installed.request.acceptance.model_copy(
                update={"accepted_at_block": accepted_at}
            )
        }
    )
    port = sandbox(installed)
    cpu_readback(port, installed, monkeypatch)
    if accepted_at < 221:
        with pytest.raises(ValueError, match="predates its committed storage adoption"):
            await port.invoke(installed.job, attempt(installed.job))
        assert not installed.remote.reads
    else:
        assert await port.invoke(installed.job, attempt(installed.job)) == "inert-cpu-result"
    assert installed.case.objects == originals
    assert installed.request.acceptance.schema_ == "umi-cohort-model-artifact-acceptance/1"
    assert installed.request.direct_artifact is None


@pytest.mark.parametrize("authorized", [True, False, "damaged_receipt"])
async def test_new_reference_requires_explicit_independent_baseline_authority(
    installed, monkeypatch, authorized
):
    from umi.competition_cohort_sandbox import CohortCpuSandbox

    port = sandbox(installed)
    bundle = installed.case.subs[0].model_bundle
    job = installed.job.model_copy(
        update={
            "incumbent": bundle,
            "round": installed.job.round.model_copy(
                update={"incumbent_model_sha256": digest(bundle)}
            ),
        }
    )
    references, calls = [], []

    def authorize(selected, model):
        assert selected == job and model == bundle
        calls.append(digest(model))
        if authorized == "damaged_receipt":
            raise ValueError("certified baseline receipt needs repair")
        return authorized

    port.legacy_artifacts.reference_authorized = authorize
    if authorized is True:
        # Publishing a baseline did not provision these canonical local bytes.
        # The supported sandbox must recover from its authenticated R2 source.
        import shutil

        shutil.rmtree(port.archive / digest(bundle))
        cpu_readback(port, installed, monkeypatch)

    async def native_reference(self, selected, invocation):
        assert self is port and selected == job
        assert invocation.step_index == 1
        verify_preserved_bundle(bundle, port.archive, installed.case.policy)
        references.append(digest(bundle))
        return "native-preserved-reference"

    monkeypatch.setattr(CohortCpuSandbox, "invoke", native_reference)
    if authorized is True:
        assert await port.invoke(job, attempt(job, 1)) == "inert-cpu-result"
        assert not references
        assert not (port.archive / digest(bundle)).exists()
        first_reads = list(installed.remote.reads)
        reopened = sandbox(installed)
        reopened.legacy_artifacts.reference_authorized = authorize
        cpu_readback(reopened, installed, monkeypatch)
        assert await reopened.invoke(job, attempt(job, 1, 2)) == "inert-cpu-result"
        assert installed.remote.reads == first_reads
    else:
        with pytest.raises(ValueError, match=r"incumbent|repair"):
            await port.invoke(job, attempt(job, 1))
        assert not references
    assert calls == [digest(bundle)] * (2 if authorized is True else 1)
    if authorized is not True:
        assert not installed.remote.reads


async def test_certified_reference_missing_original_requires_repair(installed, monkeypatch):
    port = sandbox(installed)
    bundle = installed.case.subs[0].model_bundle
    job = installed.job.model_copy(
        update={
            "incumbent": bundle,
            "round": installed.job.round.model_copy(
                update={"incumbent_model_sha256": digest(bundle)}
            ),
        }
    )
    port.legacy_artifacts.reference_authorized = lambda *_: True
    selected = next(
        e
        for e in installed.sources.authenticated[installed.case.cohort].legacy.entries
        if e.model_sha256 == digest(bundle) and e.payload_state == "preserved"
    )
    del installed.case.objects[selected.request_raw_sha256]
    with pytest.raises((ValueError, KeyError), match=r"original|repair|[0-9a-f]{64}"):
        await port.invoke(job, attempt(job, 1))
    assert not installed.remote.reads
