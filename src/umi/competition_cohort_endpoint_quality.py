"""Content-quality replay of complete endpoint archives after reference reveal.

Metrics deliberately carry no invented elapsed time. They are inputs for the
future service-credit consumer, not legacy timed scores or reward eligibility.
Full-roster closure binding, service-clock proof and allocation remain separate.
"""

from __future__ import annotations

from collections.abc import Callable
from fractions import Fraction
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_endpoint_archive import (
    EndpointObjectSource,
    EndpointReplayArchive,
    endpoint_archive_cases,
    endpoint_archive_header,
)
from .competition_cohort_endpoint_selection import selected_request
from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_orders import verify_recoverable_order
from .competition_endpoint_content import decrypt_endpoint_content
from .competition_endpoint_execution import RetainedRevealPulse
from .competition_scoring import score_single_reference
from .config import Limits
from .open_competition import (
    BURN_POLICY_SCHEMA,
    DEPENDENCE_POLICY_SCHEMA,
    TWO_TASK_POLICY_SCHEMA,
    CompetitionPolicy,
    EvaluationSuite,
    Hotkey,
    digest,
    validate_suite_profile,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .scoring import score_cer, score_wer
from .validator import validate_response_envelope


class EndpointCaseQuality(StrictProtocolModel):
    case_id: Hex32
    review_sha256: Hex32
    response_sha256: Hex32
    status: Literal["ok", "miner_failure"]
    reason_code: Annotated[str, Field(max_length=128)] | None
    hypothesis: Annotated[str, Field(max_length=4096)]
    numerator: Annotated[str, Field(pattern=r"^[0-9]+$", max_length=4096)]
    denominator: Annotated[str, Field(pattern=r"^[1-9][0-9]*$", max_length=4096)]
    # Retrieval timestamps are never an inference duration, including zero.
    elapsed_ms: None = None
    original_receipt_timing_proven: Literal[False] = False


class EndpointArchiveQuality(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-content-quality/1"] = Field(alias="schema")
    archive_sha256: Hex32
    policy_sha256: Hex32
    suite_sha256: Hex32
    round_sha256: Hex32
    submission_sha256: Hex32
    evaluator_hotkey: Hotkey
    cases: Annotated[tuple[EndpointCaseQuality, ...], Field(min_length=3, max_length=2048)]
    timing_class: Literal["original_timing_unverified"] = "original_timing_unverified"
    service_credit_authorized: Literal[False] = False
    chain_submission_authorized: Literal[False] = False


def replay_endpoint_archive_quality(
    archive: EndpointReplayArchive,
    source: EndpointObjectSource,
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
    history: CohortRecoveryHistory,
    *,
    pulses: Callable[[int], RetainedRevealPulse],
    expected_tip_sha256: str,
    current_block: int,
) -> EndpointArchiveQuality:
    """Finish every authenticated case before returning a quality report.

    Missing evidence/pulses and invalid authority raise; they cannot become a
    zero. Signed miner errors remain zeros. This does not apply latency gates,
    dependence gates, promotion rules, or certify full-roster request closure.
    """
    archive = EndpointReplayArchive.model_validate_json(canonical_json_bytes(archive))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    assignment, _, job = endpoint_archive_header(archive, source, policy)
    participant = assignment.participant
    verify_recoverable_order(
        assignment.certificate,
        policy,
        participant.consent,
        participant.admission,
        participant.admission_snapshot,
        history,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    view = verify_cohort_history(
        history, policy, expected_tip_sha256=expected_tip_sha256, current_block=current_block
    )
    opened = view.closure("preparation").observed_at_block
    closed = view.closure("requests").observed_at_block
    if not opened < closed < view.closure("reference_reveal").observed_at_block <= current_block:
        raise ValueError("endpoint quality requires certified request closure and reveal")
    if view.state.phase == "revoked":
        raise ValueError("endpoint quality authority is revoked")
    validate_suite_profile(suite, policy)
    if (
        digest(suite) != job.round.suite_sha256
        or suite.policy_sha256 != digest(policy)
        or [(c.case_id, c.video_sha256, c.stratum) for c in suite.cases]
        != [(c.case_id, c.video_sha256, c.stratum) for c in job.cases]
    ):
        raise ValueError("endpoint quality suite differs from the complete assignment")
    outputs = []
    reviews = endpoint_archive_cases(archive, source, policy, request_interval=(opened, closed))
    for case, review in zip(suite.cases, reviews, strict=True):
        request = selected_request(review.selection, case.case_id)
        retained = review.recovered.response
        pulse = RetainedRevealPulse.model_validate_json(
            canonical_json_bytes(pulses(request.reveal_round))
        ).verified()
        envelope, sealed = validate_response_envelope(
            bytes.fromhex(retained.envelope_hex),
            retained.signature,
            request=request,
            validator_hotkey=job.evaluator_hotkey,
            miner_hotkey=job.submission.submission.hotkey,
        )
        content = decrypt_endpoint_content(
            request=request,
            envelope=envelope,
            sealed_bytes=sealed.portable_bytes,
            pulse=pulse,
            model_revision=job.submission.submission.model_revision,
            maximum_output_bytes=policy.maximum_output_bytes,
            limits=Limits.from_policy(review.selection.transport_policy),
            resource_errors_pending=True,
        )
        quality = Fraction(0)
        if content.status == "ok":
            if policy.schema_ in {
                TWO_TASK_POLICY_SCHEMA,
                BURN_POLICY_SCHEMA,
                DEPENDENCE_POLICY_SCHEMA,
            }:
                quality = score_single_reference(
                    "cer" if case.stratum == "fingerspelling" else "wer",
                    content.hypothesis,
                    case.references[0],
                )
            else:
                score = score_cer if case.stratum == "fingerspelling" else score_wer
                quality = score(content.hypothesis, case.references)
        outputs.append(
            EndpointCaseQuality(
                case_id=case.case_id,
                review_sha256=digest(review),
                response_sha256=review.retirement.retirement.receipt.response_sha256,
                status=content.status,
                reason_code=content.reason_code,
                hypothesis=content.hypothesis,
                numerator=str(quality.numerator),
                denominator=str(quality.denominator),
            )
        )
    return EndpointArchiveQuality(
        schema="umi-cohort-endpoint-content-quality/1",
        archive_sha256=digest(archive),
        policy_sha256=digest(policy),
        suite_sha256=digest(suite),
        round_sha256=digest(job.round),
        submission_sha256=digest(job.submission.submission),
        evaluator_hotkey=job.evaluator_hotkey,
        cases=tuple(outputs),
    )
