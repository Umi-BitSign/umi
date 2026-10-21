"""Exercise inherited direct-reference restoration with native materializers.

The independent baseline reader is an inert authority port here. The retained
request/intent parsing, R2 byte checks, bounded cache and reopening are real;
applied-baseline authority is separately covered by native store/boot tests.
"""

from types import SimpleNamespace

import pytest

from umi.competition_cohort_model_acceptance import ModelAcceptanceIntent
from umi.competition_cohort_reference_cache import CohortReferenceModelCache
from umi.open_competition import digest


async def check_inherited_direct_reference(verifier, request, inputs, archive):
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
        round=SimpleNamespace(
            cohort_sha256=review.target_cohort_sha256,
            sequence=review.target_sequence,
            policy_sha256=review.policy_sha256,
            incumbent_model_sha256=digest(bundle),
        )
    )
    slot = review.source_cohort_sha256 + ":" + digest(submission)
    intent = ModelAcceptanceIntent(acceptance=acceptance, inputs=inputs)
    records = {("model_request", slot): request, ("model_intent", slot): intent}
    journal = SimpleNamespace(get=lambda kind, key: records.get((kind, key)))

    def create(reference=lambda *_: review):
        return CohortReferenceModelCache(
            verifier,
            legacy=None,
            journal=journal,
            reference=reference,
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
    assert verifier.multipart.ranges_read == before
