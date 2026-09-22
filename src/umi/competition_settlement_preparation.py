"""Prepare complete retained settlements using the coordinator's owned head.

The output is a proposal for independent review and signing. It contains the
revealed suite and never belongs in the pre-reveal discovery feed. It grants
no signing or weight authority and cannot substitute for promotion review.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from .competition_execution import execution_boundary
from .competition_package import (
    CompetitionPackageEvidence,
    CompetitionPackageEvidenceEntry,
    CompetitionPackageRoster,
)
from .competition_publication import (
    SettlementPublication,
    SignedCutoffPublication,
    build_settlement_publication,
    independent_evidence_set_digest,
    verify_cutoff_publication,
)
from .competition_settlement import CompetitionSettlement
from .competition_settlement_capacity import settlement_capacity
from .competition_void import VoidEvaluationEvidence
from .open_competition import (
    DEPENDENCE_POLICY_SCHEMA,
    AttestedDependenceCalibration,
    StrictProtocolModel,
    digest,
    validate_dependence_calibration,
)
from .private_files import MAX_PRIVATE_BYTES
from .private_files import publish_private_model as _publish
from .protocol import canonical_json_bytes

# Existing publication consumers also use this smaller bound for promotion
# history. Complete proposals include the whole cohort's evidence instead.
MAX_BYTES = 16 * 1024**2
MAX_PREPARATION_BYTES = MAX_PRIVATE_BYTES


class SettlementPreparation(StrictProtocolModel):
    schema_: Literal["umi-settlement-preparation/1"] = Field(alias="schema")
    cutoff: SignedCutoffPublication
    publication: SettlementPublication
    roster: CompetitionPackageRoster
    evidence: CompetitionPackageEvidence
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def bindings(self):
        if self.cutoff.publication.round != self.publication.round or (
            tuple(digest(s.submission) for s in self.roster.submissions)
            != self.publication.round.roster
            or tuple(e.submission for e in self.evidence.entries) != self.roster.submissions
        ):
            raise ValueError("settlement preparation round or roster binding mismatch")
        return self


def validate_preparation(prepared, policy, limits):
    raw = canonical_json_bytes(prepared)
    if len(raw) > settlement_capacity(limits).preparation_bytes:
        raise ValueError("settlement preparation exceeds the transport byte bound")
    prepared = SettlementPreparation.model_validate_json(raw)
    calibration = prepared.publication.settlement.dependence_calibration
    if policy.schema_ == DEPENDENCE_POLICY_SCHEMA:
        if calibration is None:
            raise ValueError("dependence settlement lacks its positive control")
        validate_dependence_calibration(
            calibration,
            prepared.publication.settlement.suite,
            policy,
            latest_block=prepared.publication.round.evaluation_close_block,
        )
    elif calibration is not None:
        raise ValueError("legacy settlement cannot carry a dependence calibration")
    publication = build_settlement_publication(
        cutoff_certificate=prepared.cutoff,
        retained_settlement=prepared.publication.settlement,
        submissions=prepared.roster.submissions,
        evidence=tuple((e.submission, e.evidence) for e in prepared.evidence.entries),
        policy=policy,
        limits=limits,
    )
    if publication != prepared.publication:
        raise ValueError("settlement preparation replay differs")
    return prepared


async def prepare_retained_settlement(
    *,
    store,
    provider,
    cutoff,
    suite,
    limits,
    output_directory,
    dependence_calibration: AttestedDependenceCalibration | None = None,
):
    """Publish an unsigned review package, preserving exact retries across restart."""
    policy = store.policy
    round_ = cutoff.publication.round
    if digest(suite) != round_.suite_sha256:
        raise ValueError("settlement preparation suite differs from its closed round")
    capture = await provider.collect()
    head = execution_boundary(capture).block
    if head < cutoff.publication.cutoff_schedule.evidence_cutoff_block:
        return "waiting"
    if head > round_.valid_through_block:
        return "expired"
    material = store.settlement_material(round_, limits=limits)
    verify_cutoff_publication(
        cutoff, policy=policy, submissions=material["submissions"], limits=limits
    )
    if cutoff.publication.cutoff_schedule != material["cutoff_schedule"]:
        raise ValueError("settlement cutoff differs from the retained schedule")
    independent_evidence_set_digest(
        material["evidence"], maximum_bytes=limits.maximum_evidence_bytes
    )
    existing = material["retained_settlement"]
    # No network caller supplies this snapshot. For a new record use a fresh
    # collection after loading evidence; retries preserve the original record.
    capture = await provider.collect()
    current = execution_boundary(capture).block
    if current < head:
        raise ValueError("settlement finalized head regressed")
    if current > round_.valid_through_block:
        return "expired"
    snapshot = capture.snapshot if existing is None else existing.registration_snapshot
    settlement = CompetitionSettlement.model_validate_json(
        canonical_json_bytes(
            store.settle(
                round_=round_,
                suite=suite,
                evidence=material["evidence"],
                snapshot=snapshot,
                current_block=current,
                dependence_calibration=dependence_calibration,
            )
        )
    )
    # Re-read conflict status and evidence bindings after the settlement commit.
    # Publishing this proposal still requires independent current review later.
    retained = store.settlement_material(round_, limits=limits)
    if retained["retained_settlement"] != settlement:
        raise ValueError("settlement changed before preparation publication")
    prepared = SettlementPreparation(
        schema="umi-settlement-preparation/1",
        cutoff=cutoff,
        publication=build_settlement_publication(
            cutoff_certificate=cutoff,
            retained_settlement=settlement,
            submissions=retained["submissions"],
            evidence=retained["evidence"],
            policy=policy,
            limits=limits,
        ),
        roster=CompetitionPackageRoster(
            schema="umi-competition-replay-roster/1", submissions=retained["submissions"]
        ),
        evidence=CompetitionPackageEvidence(
            schema=(
                "umi-competition-replay-evidence/2"
                if any(isinstance(e, VoidEvaluationEvidence) for _, e in retained["evidence"])
                else "umi-competition-replay-evidence/1"
            ),
            entries=tuple(
                CompetitionPackageEvidenceEntry(submission=s, evidence=e)
                for s, e in retained["evidence"]
            ),
        ),
    )
    validate_preparation(prepared, policy, limits)
    _publish(
        Path(output_directory) / (digest(round_) + ".settlement-proposal.json"),
        prepared,
        maximum_bytes=settlement_capacity(limits).preparation_bytes,
    )
    return "prepared"
