"""Exercise inherited direct-reference restoration with native materializers.

The independent baseline reader is an inert authority port here. The retained
request/intent parsing, R2 byte checks, bounded cache and reopening are real;
applied-baseline authority is separately covered by native store/boot tests.
"""

import asyncio
from types import SimpleNamespace

import pytest

from umi import competition_artifacts
from umi.competition_cohort_model_acceptance import ModelAcceptanceIntent
from umi.competition_cohort_reference_cache import CohortReferenceModelCache
from umi.competition_cohort_sandbox import DirectCohortCpuSandbox
from umi.open_competition import digest


async def check_inherited_direct_reference(verifier, request, inputs, archive, monkeypatch):
    acceptance = request.acceptance.model_copy(
        update={
            "rights_evidence_sha256": digest(inputs.rights_evidence),
            "reconstruction_evidence_sha256": digest(inputs.reconstruction_evidence),
        }
    )
    request = request.model_copy(update={"acceptance": acceptance})
    submission = request.record.request.signed_submission.submission
    bundle = submission.model_bundle
    review = SimpleNamespace(
        source_cohort_sha256=acceptance.cohort_sha256,
        target_cohort_sha256="f0" * 32,
        target_sequence=7,
        policy_sha256=acceptance.policy_sha256,
        model=bundle,
        candidate=SimpleNamespace(
            model_sha256=digest(bundle),
            submission_sha256=digest(submission),
            contributor_hotkey=submission.hotkey,
        ),
    )
    job = SimpleNamespace(
        incumbent=bundle,
        round=SimpleNamespace(
            cohort_sha256=review.target_cohort_sha256,
            sequence=review.target_sequence,
            policy_sha256=review.policy_sha256,
            incumbent_model_sha256=digest(bundle),
        ),
    )
    slot = review.source_cohort_sha256 + ":" + digest(submission)
    intent = ModelAcceptanceIntent(acceptance=acceptance, inputs=inputs)
    records = {("model_request", slot): request, ("model_intent", slot): intent}
    journal = SimpleNamespace(get=lambda kind, key: records.get((kind, key)))

    def create(reference=lambda *_: review, metadata=None):
        return CohortReferenceModelCache(
            verifier,
            legacy=None,
            journal=journal,
            reference=reference,
            metadata=metadata,
        )

    cache = create()
    source = cache.execution_source(job, "incumbent", bundle)
    assert source.selection == request and source.legacy is False
    assert not archive.exists()
    await cache.materialize(source, archive)
    assert await cache.materialized(source, archive)
    before = verifier.multipart.ranges_read
    reopened = create()
    source = reopened.execution_source(job, "incumbent", bundle)
    assert await reopened.materialized(source, archive)
    await reopened.materialize(source, archive)
    assert verifier.multipart.ranges_read == before
    assert create(lambda *_: None).execution_source(job, "incumbent", bundle) is None
    for kind in ("model_request", "model_intent"):
        removed = records.pop((kind, slot))
        with pytest.raises(ValueError, match="retained-journal repair"):
            create().execution_source(job, "incumbent", bundle)
        records[kind, slot] = removed
    bad_round = SimpleNamespace(
        round=SimpleNamespace(
            **{
                **vars(job.round),
                "incumbent_model_sha256": "f1" * 32,
            }
        )
    )
    with pytest.raises(ValueError, match="frozen execution"):
        create().execution_source(bad_round, "incumbent", bundle)
    original = records.copy()
    records.clear()
    fetched = []

    async def metadata(selected, baseline):
        await asyncio.sleep(0)
        assert selected is job and baseline is review
        fetched.append(1)
        return request

    fallback = create(metadata=metadata)
    port = object.__new__(DirectCohortCpuSandbox)
    port.legacy_artifacts = fallback
    port.artifacts = verifier
    plan = await port._source_plan(job, "incumbent")
    assert fetched == [1] and plan.request.selection == request
    assert plan.identity == cache.cache_identity(source)
    assert plan.materializer is fallback

    def forbidden(*args, **kwargs):
        raise AssertionError("metadata fallback must reuse completed model byte verification")

    with monkeypatch.context() as patch:
        patch.setattr(competition_artifacts, "verify_bundle_directory", forbidden)
        await plan.materializer.materialize(plan.request, archive)
        assert await plan.materializer.materialized(plan.request, archive)
    assert records == {}  # Restored metadata must not pretend to be local reviewer history.
    records.update(original)
    assert verifier.multipart.ranges_read == before
