"""Independent /1 approval survives authenticated R2 storage selection."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.competition_cohort_admission_queue import CohortAdmissionQueue
from umi.competition_cohort_model_acceptance import (
    ModelAcceptanceIntent,
    ModelArtifactReviewInputs,
    check_model_vote,
)
from umi.competition_cohort_model_review import ModelArtifactReviewer, ModelReviewConfig
from umi.open_competition import digest, sign_object
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_legacy_model_sandbox import base_policy as base_policy
from .test_competition_cohort_legacy_model_sandbox import case as case
from .test_competition_cohort_legacy_model_sandbox import installed as installed
from .test_competition_cohort_legacy_model_sandbox import legacy_scenario as legacy_scenario
from .test_competition_cohort_legacy_model_sandbox import policy as policy
from .test_competition_cohort_legacy_model_sandbox import prepared as prepared
from .test_competition_cohort_legacy_model_sandbox import receipt_scenario as receipt_scenario
from .test_competition_cohort_legacy_model_sandbox import recovery as recovery
from .test_competition_cohort_legacy_model_sandbox import runtime as runtime
from .test_open_competition import wallet

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
]


@pytest.fixture
def review(installed, tmp_path):
    i = installed
    selected = i.sources.resolve(i.case.cohort, request_sha256=digest(i.request.record.request))
    intent = ModelAcceptanceIntent.model_validate_json(
        i.sources.load_original(selected.originals.intent_raw_sha256)
    )
    config = ModelReviewConfig(
        schema="umi-cohort-model-review-config/1",
        directory=str(tmp_path / "independent-review-journal"),
        approvals_directory=str(tmp_path / "independent-review-approvals"),
        archive_directory=str(i.case.owner.archive),
        policy_sha256=digest(i.case.policy),
        signer=wallet("Dave").hotkey.ss58_address,
        cohorts=i.case.owner.intake.config.cohorts,
    )
    approval = Path(config.approvals_directory) / (i.request.acceptance.model_sha256 + ".json")
    publish_private_model(approval, intent.inputs)
    state = SimpleNamespace(online=True, signatures=[], refuse_sign=False)

    async def capture():
        assert state.online, "completed review must reuse its own signed result"
        return capture_at(230)

    async def history(cohort):
        assert state.online, "completed review must reuse its original history"
        return CohortAdmissionQueue(i.case.owner.intake).history(cohort)

    async def sign(body):
        if state.refuse_sign:
            raise OSError("fixture signer interruption")
        state.signatures.append(body)
        return sign_object(body, wallet("Dave"))

    def create():
        return ModelArtifactReviewer(
            config,
            i.case.policy,
            capture,
            history,
            sign,
            legacy_readers=i.sources,
        )

    # Keep the original archive directory binding and protected root in place,
    # but make its payload unavailable. Only authenticated R2 can supply bytes.
    model = i.case.owner.archive / i.request.acceptance.model_sha256
    model.rename(tmp_path / "retained-offline-original")
    return SimpleNamespace(
        installed=i,
        config=config,
        approval=approval,
        inputs=intent.inputs,
        state=state,
        create=create,
    )


async def test_private_legacy_review_uses_r2_without_changing_rights_or_signed_vote(review):
    r, i = review, review.installed
    original = canonical_json_bytes(i.request)
    reviewer = r.create()
    vote = await reviewer.attest(i.request)
    check_model_vote(vote, i.request.acceptance, i.case.policy, signer=r.config.signer)
    assert canonical_json_bytes(i.request) == original
    assert vote.acceptance.schema_ == "umi-cohort-model-artifact-acceptance/1"
    assert vote.acceptance.direct_artifact is None
    slot = i.case.cohort + ":" + i.request.acceptance.submission_sha256
    retained = reviewer.journal.get("model_intent", slot)
    assert canonical_json_bytes(retained) == canonical_json_bytes(
        ModelAcceptanceIntent(acceptance=i.request.acceptance, inputs=r.inputs)
    )
    assert len(i.remote.reads) == len(i.case.subs[0].model_bundle.files)
    reads = tuple(i.remote.reads)
    r.state.online = False
    r.approval.unlink()
    i.remote.objects.clear()
    assert await r.create().attest(i.request) == vote
    assert tuple(i.remote.reads) == reads and len(r.state.signatures) == 1


@pytest.mark.parametrize("fault", ["missing", "different_rights", "different_reconstruction"])
async def test_r2_storage_does_not_substitute_for_private_approval(review, fault):
    r, i = review, review.installed
    if fault == "missing":
        r.approval.unlink()
    else:
        inputs = ModelArtifactReviewInputs(
            model_sha256=r.inputs.model_sha256,
            rights_evidence={"unreviewed": True}
            if fault == "different_rights"
            else r.inputs.rights_evidence,
            reconstruction_evidence={"unreviewed": True}
            if fault == "different_reconstruction"
            else r.inputs.reconstruction_evidence,
        )
        r.approval.unlink()
        publish_private_model(r.approval, inputs)
    with pytest.raises((ValueError, FileNotFoundError)):
        await r.create().attest(i.request)
    assert not i.remote.reads and not r.state.signatures


async def test_interrupted_signing_reuses_original_private_intent_and_remote_byte_checks(review):
    r, i = review, review.installed
    r.state.refuse_sign = True
    with pytest.raises(OSError, match="signer interruption"):
        await r.create().attest(i.request)
    reads = tuple(i.remote.reads)
    assert reads
    r.approval.unlink()
    i.remote.objects.clear()
    r.state.refuse_sign = False
    vote = await r.create().attest(i.request)
    assert vote.acceptance == i.request.acceptance
    assert tuple(i.remote.reads) == reads and len(r.state.signatures) == 1


async def test_missing_authenticated_original_refuses_instead_of_using_archive(review):
    r, i = review, review.installed
    selected = i.sources.resolve(i.case.cohort, request_sha256=digest(i.request.record.request))
    i.case.objects.pop(selected.originals.intent_raw_sha256)
    with pytest.raises(ValueError, match="missing; repair required"):
        await r.create().attest(i.request)
    assert not i.remote.reads and not r.state.signatures
