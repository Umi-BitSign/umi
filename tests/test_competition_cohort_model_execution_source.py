"""Certified native model metadata survives another reviewer's absence and restart."""

from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi import competition_cohort_model_execution_source as sources
from umi.competition_cohort_model_acceptance import (
    CertifiedModelArtifactAcceptance,
    ModelArtifactAcceptance,
    ModelReviewRequest,
)
from umi.competition_round_journal import RoundJournal
from umi.open_competition import digest, model_content_digest

from .test_competition_cohort_executor import (
    base_policy as base_policy,
)
from .test_competition_cohort_executor import (
    execution as execution,
)
from .test_competition_cohort_executor import (
    harness as harness,
)
from .test_competition_cohort_executor import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_executor import (
    policy as policy,
)
from .test_competition_cohort_executor import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_executor import (
    recovery as recovery,
)
from .test_competition_cohort_executor import (
    relay as relay,
)
from .test_competition_cohort_executor import (
    runtime as runtime,
)
from .test_competition_cohort_executor import (
    scenario as scenario,
)
from .test_competition_cohort_recovery import signatures

pytestmark = [
    pytest.mark.parametrize("scenario", ["paired_model"], indirect=True),
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
]


@pytest.fixture
async def certified(execution, tmp_path):
    e = execution
    participant = e.r.h.batch["roster"].participants[0]
    sub = participant.record.request.signed_submission.submission
    policy = e.r.h.batch["policy"]
    source = e.r.h.source
    acceptance = ModelArtifactAcceptance(
        schema="umi-cohort-model-artifact-acceptance/1",
        policy_sha256=digest(policy),
        cohort_sha256=e.job.round.cohort_sha256,
        authority_sha256=digest(source.history.authority.authority),
        submission_sha256=digest(sub),
        model_sha256=digest(sub.model_bundle),
        content_sha256=model_content_digest(sub.model_bundle),
        recipient_hotkey=sub.hotkey,
        rights_evidence_sha256="ab" * 32,
        reconstruction_evidence_sha256="ac" * 32,
        accepted_at_block=220,
        accepted_ordinal=1,
        rights_and_reconstruction_passed=True,
    )
    request = ModelReviewRequest(
        schema="umi-cohort-model-review-request/1",
        acceptance=acceptance,
        record=participant.record,
        admission=participant.admission,
    )
    certificate = CertifiedModelArtifactAcceptance(
        acceptance=acceptance, signatures=signatures(acceptance)
    )
    value = sources.CertifiedModelExecutionSource(
        request=request, certificate=certificate, history=source
    )
    n = SimpleNamespace(e=e, value=value, reads=0, unavailable=False)

    def retained(cohort, submission):
        assert cohort == e.job.round.cohort_sha256 and submission == digest(sub)
        n.reads += 1
        if n.unavailable:
            raise OSError("owner offline")
        return SimpleNamespace(certificate=n.value.certificate)

    app = FastAPI()
    app.include_router(
        sources.model_execution_source_routes(
            SimpleNamespace(retained=retained, review_request=lambda *args: n.value.request),
            lambda _: n.value.history,
            token="owner-token" * 4,
        )
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://owner.example"
    ) as client:
        n.journal = lambda: RoundJournal(
            tmp_path / "sources",
            {"evaluator": e.box.config.signer},
            maximum_record_bytes=sources.MAX_BYTES,
        )
        n.reader = lambda: sources.CertifiedModelExecutionSources(
            client,
            "https://owner.example",
            token="owner-token" * 4,
            policy=policy,
            cohorts=e.executor().journal.cohorts,
            journal=n.journal(),
            timeout_seconds=30,
        )
        yield n


async def test_authenticated_source_and_durable_restart_need_no_local_vote(certified, monkeypatch):
    n = certified
    first = n.reader()
    assert await first.request(n.e.job) == n.value.request
    assert n.reads == 1
    n.unavailable = True

    def no_replay(*args):
        raise AssertionError("unchanged certified source must reuse durable verification")

    monkeypatch.setattr(sources, "verify_execution_model_source", no_replay)
    assert await n.reader().request(n.e.job) == n.value.request
    assert n.reads == 1
    slot = n.e.job.round.cohort_sha256 + ":" + digest(n.e.job.submission.submission)
    assert n.journal().get("model_request", slot) is None
    assert n.journal().get("model_vote", slot) is None


@pytest.mark.parametrize("damage", ["certificate", "submission", "clock"])
async def test_changed_or_uncertified_source_cannot_be_checkpointed(certified, damage):
    n = certified
    if damage == "certificate":
        n.value = n.value.model_copy(
            update={
                "certificate": n.value.certificate.model_copy(
                    update={"signatures": n.value.certificate.signatures[:1]}
                )
            }
        )
    elif damage == "submission":
        changed = n.value.request.record.request.signed_submission.model_copy(
            update={"signature": n.value.certificate.signatures[0]}
        )
        record = n.value.request.record.model_copy(
            update={
                "request": n.value.request.record.request.model_copy(
                    update={"signed_submission": changed}
                )
            }
        )
        n.value = n.value.model_copy(
            update={"request": n.value.request.model_copy(update={"record": record})}
        )
    else:
        changed = n.value.request.acceptance.model_copy(update={"accepted_at_block": 1000000})
        n.value = n.value.model_copy(
            update={
                "request": n.value.request.model_copy(update={"acceptance": changed}),
                "certificate": n.value.certificate.model_copy(
                    update={"acceptance": changed, "signatures": signatures(changed)}
                ),
            }
        )
    with pytest.raises(ValueError):
        await n.reader().request(n.e.job)
    slot = n.e.job.round.cohort_sha256 + ":" + digest(n.e.job.submission.submission)
    assert n.journal().get("model_execution_source_verified", slot) is None


async def test_missing_completed_receipt_requires_repair_without_network(certified):
    n = certified
    slot = n.e.job.round.cohort_sha256 + ":" + digest(n.e.job.submission.submission)
    n.journal().put("model_execution_source", slot, n.value)
    with pytest.raises(ValueError, match="repair required"):
        await n.reader().request(n.e.job)
    assert n.reads == 0
