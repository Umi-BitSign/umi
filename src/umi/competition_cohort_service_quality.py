"""Replay exact paid-work quality after certified request closure and reveal.

The caller supplies independently selected terms, catalogs and queue seals.
This consumer establishes observations for certification, not chain authority.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_coordinator import CohortDecisionInput
from .competition_cohort_endpoint_archive import read_endpoint_object
from .competition_cohort_history import verify_cohort_history
from .competition_cohort_quality import ExactQuality, exact_quality
from .competition_cohort_service_closure import verify_certified_service_request_closure
from .competition_cohort_service_grant import ServiceMinerGrant
from .competition_cohort_service_terminal import SignedServiceTerminal
from .competition_endpoint_content import decrypt_endpoint_content
from .competition_endpoint_execution import RetainedRevealPulse
from .competition_scoring import score_single_reference
from .config import Limits
from .endpoint_response_recovery import RecoveredEndpointResponse
from .open_competition import EvaluationSuite, Hotkey, digest, validate_suite_profile
from .policy import scoring_policy_hash
from .protocol import (
    Hex32,
    StrictProtocolModel,
    canonical_json_bytes,
    normalized_grapheme_count,
    normalized_token_count,
)
from .validator import validate_response_envelope

ServiceStratum = Literal["fingerspelling", "continuous"]


class ServiceTerms(StrictProtocolModel):
    schema_: Literal["umi-cohort-service-terms/1"] = Field(alias="schema")
    policy_sha256: Hex32
    transport_policy_sha256: Hex32
    service_pool_bps: Annotated[int, Field(ge=0, le=10_000)]
    stratum_weights: dict[ServiceStratum, Annotated[int, Field(ge=1, le=1_000_000)]]
    total_raw_weight: Literal[65535] = 65535
    quality_rule: Literal["single_reference_cer_wer"] = "single_reference_cer_wer"
    credit_rule: Literal["one_unit_times_quality"] = "one_unit_times_quality"
    miner_failure_rule: Literal["signed_miner_failure_zero"] = "signed_miner_failure_zero"
    unavailable_evidence_rule: Literal["pending"] = "pending"
    rounding_order: Literal["pool_stratum_work_hotkey_uid"] = "pool_stratum_work_hotkey_uid"

    @model_validator(mode="after")
    def strata(self):
        if set(self.stratum_weights) != {"fingerspelling", "continuous"}:
            raise ValueError("service terms require both task strata")
        return self


class ServiceReference(StrictProtocolModel):
    schema_: Literal["umi-cohort-service-reference/1"] = Field(alias="schema")
    case_id: Hex32
    video_sha256: Hex32
    stratum: ServiceStratum
    salt: Hex32
    reference: Annotated[str, Field(min_length=1, max_length=4096)]

    @model_validator(mode="after")
    def nonempty(self):
        count = (
            normalized_grapheme_count
            if self.stratum == "fingerspelling"
            else normalized_token_count
        )
        if count(self.reference) == 0:
            raise ValueError("service reference must contain normalized scoring units")
        return self


class CatalogReferences(StrictProtocolModel):
    catalog_sha256: Hex32
    references: Annotated[tuple[Hex32, ...], Field(min_length=1, max_length=8192)]


class ServiceReferenceReveal(StrictProtocolModel):
    schema_: Literal["umi-cohort-service-reference-reveal/1"] = Field(alias="schema")
    policy_sha256: Hex32
    request_closure_sha256: Hex32
    benchmark_suite_sha256: Hex32
    catalogs: Annotated[tuple[CatalogReferences, ...], Field(min_length=1, max_length=64)]


def _committed_references(catalogs, objects):
    references = {}
    for catalog in catalogs:
        for item in catalog.catalog.work:
            ref = ServiceReference.model_validate_json(
                read_endpoint_object(objects, item.reference_sha256)
            )
            if (ref.case_id, ref.video_sha256, ref.stratum) != (
                item.case_id,
                item.video_sha256,
                item.stratum,
            ):
                raise ValueError("service reference belongs to another committed input")
            references[item.reference_sha256] = ref
    return references


def build_service_reference_reveal(
    closure,
    roster,
    suite,
    objects,
    policy,
    history,
    transport,
    *,
    expected_catalogs,
    expected_seals,
    decision_source,
    intake_records,
    expected_tip_sha256,
    current_block,
) -> ServiceReferenceReveal:
    """Reveal the complete committed inventory after certified request closure.

    The host independently selects history, catalogs, owner seals and original
    finality. Missing evidence raises before a reveal can be signed. References
    remain private until the enclosing publication service releases them.
    """
    view = verify_cohort_history(
        history, policy, expected_tip_sha256=expected_tip_sha256, current_block=current_block
    )
    if view.state.phase != "reference_reveal":
        raise ValueError("reference publication requires the reference-reveal phase")
    if current_block <= view.closure("requests").observed_at_block:
        raise ValueError("reference publication must follow certified request closure")
    closure = verify_certified_service_request_closure(
        closure,
        roster,
        objects,
        policy,
        history,
        transport,
        expected_catalogs=expected_catalogs,
        expected_seals=expected_seals,
        decision_source=decision_source,
        intake_records=intake_records,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    validate_suite_profile(suite, policy)
    if digest(suite) != roster.round.suite_sha256 or suite.policy_sha256 != digest(policy):
        raise ValueError("revealed suite differs from certified preparation")
    _committed_references(expected_catalogs, objects)
    return ServiceReferenceReveal(
        schema="umi-cohort-service-reference-reveal/1",
        policy_sha256=digest(policy),
        request_closure_sha256=digest(closure),
        benchmark_suite_sha256=digest(suite),
        catalogs=tuple(
            CatalogReferences(
                catalog_sha256=digest(c.catalog),
                references=tuple(w.reference_sha256 for w in c.catalog.work),
            )
            for c in expected_catalogs
        ),
    )


class ServiceWorkQuality(StrictProtocolModel):
    work_sha256: Hex32
    terminal_sha256: Hex32
    reference_sha256: Hex32
    recipient_hotkey: Hotkey
    stratum: ServiceStratum
    units: Literal[1] = 1
    status: Literal["ok", "miner_failure"]
    reason_code: Annotated[str, Field(max_length=128)] | None
    hypothesis_sha256: Hex32
    quality: ExactQuality
    credit: ExactQuality
    # Response retrieval does not measure original inference latency.
    elapsed_ms: None = None


class ClosedServiceQuality(StrictProtocolModel):
    schema_: Literal["umi-cohort-service-quality/1"] = Field(alias="schema")
    terms_sha256: Hex32
    request_closure_sha256: Hex32
    reference_reveal_sha256: Hex32
    work: Annotated[tuple[ServiceWorkQuality, ...], Field(max_length=524288)]
    chain_submission_authorized: Literal[False] = False


def replay_closed_service_quality(
    closure,
    roster,
    objects,
    policy,
    history,
    transport,
    terms,
    reveal,
    *,
    expected_catalogs,
    expected_seals,
    expected_terms_sha256,
    decision_source,
    intake_records,
    pulses,
    expected_tip_sha256,
    current_block,
):
    """All accepted work must replay; missing objects/pulses remain pending.

    References are salted commitments in the original pre-admission catalogs.
    The native reference-reveal phase must certify this exact complete manifest.
    A response or quality JSON by itself cannot supply a credit entitlement.
    """
    terms = ServiceTerms.model_validate_json(canonical_json_bytes(terms))
    if (
        digest(terms) != expected_terms_sha256
        or terms.policy_sha256 != digest(policy)
        or terms.transport_policy_sha256 != scoring_policy_hash(transport)
        or any(c.catalog.service_terms_sha256 != digest(terms) for c in expected_catalogs)
    ):
        raise ValueError("service quality differs from selected scoring terms")
    closure = verify_certified_service_request_closure(
        closure,
        roster,
        objects,
        policy,
        history,
        transport,
        expected_catalogs=expected_catalogs,
        expected_seals=expected_seals,
        decision_source=decision_source,
        intake_records=intake_records,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    reveal = ServiceReferenceReveal.model_validate_json(canonical_json_bytes(reveal))
    view = verify_cohort_history(
        history, policy, expected_tip_sha256=expected_tip_sha256, current_block=current_block
    )
    revealed = view.closure("reference_reveal")
    decision = CohortDecisionInput.model_validate_json(
        canonical_json_bytes(decision_source(revealed.evidence_sha256))
    )
    if (
        not closure.observation.block < revealed.observed_at_block <= current_block
        or digest(decision) != revealed.evidence_sha256
        or decision.progress.progress.phase_result_sha256 != digest(reveal)
        or reveal.policy_sha256 != digest(policy)
        or reveal.request_closure_sha256 != digest(closure)
        or reveal.benchmark_suite_sha256 != roster.round.suite_sha256
        or tuple(r.catalog_sha256 for r in reveal.catalogs)
        != tuple(c.catalog_sha256 for c in closure.catalogs)
    ):
        raise ValueError("service references differ from certified complete reveal")
    for declared, catalog in zip(reveal.catalogs, expected_catalogs, strict=True):
        if declared.references != tuple(w.reference_sha256 for w in catalog.catalog.work):
            raise ValueError("service reveal substituted its committed reference inventory")
    references = _committed_references(expected_catalogs, objects)
    outcomes = []
    for catalog_closure in closure.catalogs:
        for key in catalog_closure.terminals:
            terminal = SignedServiceTerminal.model_validate_json(
                read_endpoint_object(objects, key)
            ).terminal
            grant = ServiceMinerGrant.model_validate_json(
                read_endpoint_object(objects, terminal.grant_sha256)
            )
            admission = grant.body.assignment.admission
            item = grant.body.assignment.catalog.catalog.work[admission.ordinal - 1]
            retained = RecoveredEndpointResponse.model_validate_json(
                read_endpoint_object(objects, terminal.response_sha256)
            )
            request = grant.body.request
            pulse = RetainedRevealPulse.model_validate_json(
                canonical_json_bytes(pulses(request.reveal_round))
            ).verified()
            envelope, sealed = validate_response_envelope(
                bytes.fromhex(retained.envelope_hex),
                retained.signature,
                request=request,
                validator_hotkey=grant.body.evaluator_hotkey,
                miner_hotkey=admission.submission.submission.hotkey,
            )
            content = decrypt_endpoint_content(
                request=request,
                envelope=envelope,
                sealed_bytes=sealed.portable_bytes,
                pulse=pulse,
                model_revision=admission.submission.submission.model_revision,
                maximum_output_bytes=policy.maximum_output_bytes,
                limits=Limits.from_policy(transport),
                resource_errors_pending=True,
            )
            quality = Fraction(0)
            if content.status == "ok":
                quality = score_single_reference(
                    "cer" if item.stratum == "fingerspelling" else "wer",
                    content.hypothesis,
                    references[item.reference_sha256].reference,
                )
            outcomes.append(
                ServiceWorkQuality(
                    work_sha256=admission.work_sha256,
                    terminal_sha256=key,
                    reference_sha256=item.reference_sha256,
                    recipient_hotkey=admission.submission.submission.hotkey,
                    stratum=item.stratum,
                    status=content.status,
                    reason_code=content.reason_code,
                    hypothesis_sha256=digest(content.hypothesis),
                    quality=exact_quality(quality),
                    credit=exact_quality(item.units * quality),
                )
            )
    return ClosedServiceQuality(
        schema="umi-cohort-service-quality/1",
        terms_sha256=digest(terms),
        request_closure_sha256=digest(closure),
        reference_reveal_sha256=digest(reveal),
        work=tuple(outcomes),
    )
