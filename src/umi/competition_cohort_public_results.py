"""Bounded public projections of retained native cohort results.

This module does not replay evidence, sign certificates or authorize weights.
The publisher authenticates private native metadata before calling these pure
projections. Public model release follows original signed contribution terms
and artifact acceptance; reward rank and activation are deliberately unrelated.
"""

from __future__ import annotations

from collections import defaultdict
from fractions import Fraction
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_model_acceptance import (
    CertifiedModelArtifactAcceptance,
    verify_model_acceptance,
)
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_cohort_roster import RecoverableRosterEvidence, RecoverableRosterParticipant
from .competition_cohort_service_allocation import allocate_service_quality
from .competition_cohort_service_certification import CertifiedServiceAllocation
from .competition_cohort_service_quality import ClosedServiceQuality, ServiceTerms
from .competition_work_progress import WorkProgress
from .open_competition import CompetitionPolicy, Hotkey, ModelBundle, digest, identity
from .protocol import Hex32, StrictProtocolModel

# Original signed terms permit redistribution subject to the retained rights
# review and notices. New terms require an explicit reviewed implementation.
PUBLIC_RELEASE_TERMS = frozenset(
    {
        "451b8ccf3c592fa4336bcf062594321a0e14f2443613a80f33dc6ee4acb5a0e0",  # v3
        "01e1e3b5953d41cf07ac5f70ff5caae5b223d70c3219d4eeca259fff036996a1",  # v4
    }
)
Count = Annotated[int, Field(ge=0)]


class PublicCredit(StrictProtocolModel):
    numerator: Annotated[str, Field(pattern=r"^(0|[1-9][0-9]*)$", max_length=1000)]
    denominator: Annotated[str, Field(pattern=r"^[1-9][0-9]*$", max_length=1000)]

    @classmethod
    def from_fraction(cls, value: Fraction):
        return cls(numerator=str(value.numerator), denominator=str(value.denominator))


class PublicPaidMiner(StrictProtocolModel):
    uid: Annotated[int, Field(ge=0, le=255)]
    hotkey: Hotkey
    paid_completed: Count
    paid_miner_failed: Count
    positive_credit_items: Count
    quality_credit: PublicCredit
    service_raw_weight: Annotated[int, Field(ge=0, le=65535)]


class PublicPaidResults(StrictProtocolModel):
    schema_: Literal["umi-public-cohort-paid-results/2"] = Field(alias="schema")
    cohort_sha256: Hex32
    policy_sha256: Hex32
    round_sha256: Hex32
    quality_sha256: Hex32
    service_certificate_sha256: Hex32
    roster_sha256: Hex32
    certification: Literal["quorum_certified_service_results"]
    reward_activation: Literal["not_verified_live"] = "not_verified_live"
    chain_submission_authorized: Literal[False] = False
    uid_source: Literal["retained_cohort_admission_snapshots"]
    skipped_unassigned_work: Count
    service_budget_raw_weight: Annotated[int, Field(ge=0, le=65535)]
    service_burn_raw_weight: Annotated[int, Field(ge=0, le=65535)]
    items: Annotated[tuple[PublicPaidMiner, ...], Field(max_length=512)]

    @model_validator(mode="after")
    def complete(self):
        keys = [(r.uid, identity(r.hotkey)) for r in self.items]
        if keys != sorted(set(keys)) or len({k[1] for k in keys}) != len(keys):
            raise ValueError("public paid miners must be sorted with one row per hotkey")
        if sum(r.service_raw_weight for r in self.items) + self.service_burn_raw_weight != (
            self.service_budget_raw_weight
        ):
            raise ValueError("public service weights do not conserve the certified budget")
        return self


def retained_uid(participant: RecoverableRosterParticipant, cohort: str) -> int:
    sub = participant.record.request.signed_submission.submission
    a = participant.admission.admission
    if (
        a != participant.record.proposed_admission
        or a.cohort_sha256 != cohort
        or a.submission_sha256 != digest(sub)
        or a.snapshot_sha256 != digest(participant.record.snapshot)
        or a.consent_sha256 != digest(participant.record.request.consent.consent)
        or not any(
            r.uid == a.uid and identity(r.hotkey) == identity(sub.hotkey)
            for r in participant.record.snapshot.registrations
        )
    ):
        raise ValueError("public UID differs from retained cohort admission")
    return a.uid


def project_paid_results(
    quality: ClosedServiceQuality,
    terms: ServiceTerms,
    certificate: CertifiedServiceAllocation,
    roster: RecoverableRosterEvidence,
    policy: CompetitionPolicy,
) -> PublicPaidResults:
    """Reuse the native quality result, checking only signatures and arithmetic."""
    statement = certificate.statement
    if (
        statement.policy_sha256 != digest(policy)
        or statement.round_sha256 != digest(roster.round)
        or statement.allocation != allocate_service_quality(quality, terms)
    ):
        raise ValueError("cached service quality differs from its certified allocation")
    verify_recovery_quorum(statement, certificate.signatures, policy)
    workers = {identity(w.recipient_hotkey) for w in quality.work}
    if workers & {identity(s.hotkey) for s in certificate.signatures}:
        raise ValueError("paid workers cannot certify their own service allocation")
    members = {}
    for p in roster.participants:
        sub = p.record.request.signed_submission.submission
        uid = retained_uid(p, roster.round.cohort_sha256)
        key = identity(sub.hotkey)
        if key in members and members[key][0] != uid:
            raise ValueError("one retained hotkey has conflicting cohort UIDs")
        members[key] = (uid, sub.hotkey)
    if not workers <= members.keys():
        raise ValueError("service work names a recipient outside the retained roster")
    counts = defaultdict(lambda: [0, 0, 0, Fraction()])
    with WorkProgress("public_paid_projection", len(quality.work), unit="work_items") as progress:
        for w in quality.work:
            row = counts[identity(w.recipient_hotkey)]
            credit = Fraction(int(w.credit.numerator), int(w.credit.denominator))
            row[0] += w.status == "ok"
            row[1] += w.status == "miner_failure"
            row[2] += credit > 0
            row[3] += credit
            progress.advance()
    weights = {identity(r.hotkey): r.raw_weight for r in statement.allocation.recipients}
    rows = tuple(
        PublicPaidMiner(
            uid=uid,
            hotkey=hotkey,
            paid_completed=counts[key][0],
            paid_miner_failed=counts[key][1],
            positive_credit_items=counts[key][2],
            quality_credit=PublicCredit.from_fraction(counts[key][3]),
            service_raw_weight=weights.get(key, 0),
        )
        for key, (uid, hotkey) in sorted(members.items(), key=lambda i: (i[1][0], i[0]))
    )
    return PublicPaidResults(
        schema="umi-public-cohort-paid-results/2",
        cohort_sha256=roster.round.cohort_sha256,
        policy_sha256=digest(policy),
        round_sha256=digest(roster.round),
        quality_sha256=digest(quality),
        service_certificate_sha256=digest(certificate),
        roster_sha256=digest(roster),
        certification="quorum_certified_service_results",
        uid_source="retained_cohort_admission_snapshots",
        skipped_unassigned_work=len(quality.skipped_work),
        service_budget_raw_weight=statement.allocation.service_budget,
        service_burn_raw_weight=statement.allocation.burn_weight,
        items=rows,
    )


class PublicModelEntry(StrictProtocolModel):
    submission_sha256: Hex32
    model_sha256: Hex32
    uid: Annotated[int, Field(ge=0, le=255)]
    hotkey: Hotkey
    accepted_terms_sha256: Hex32
    license_id: str
    file_count: Count
    total_bytes: Count
    release: Literal[
        "public_release_authorized", "artifact_acceptance_pending", "terms_review_required"
    ]
    acceptance_sha256: Hex32 | None


class PublicModelCatalog(StrictProtocolModel):
    schema_: Literal["umi-public-cohort-models/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    policy_sha256: Hex32
    inventory_sha256: Hex32
    inventory_scope: Literal["all_admitted_model_submissions", "sealed_roster"]
    chain_submission_authorized: Literal[False] = False
    items: Annotated[tuple[PublicModelEntry, ...], Field(max_length=65536)]

    @model_validator(mode="after")
    def unique(self):
        keys = [r.submission_sha256 for r in self.items]
        if keys != sorted(set(keys)):
            raise ValueError("public model submissions must be sorted and unique")
        return self


class PublicModelInventory(StrictProtocolModel):
    """Owner-exported admitted entries; retain revisions, not just award candidates."""

    schema_: Literal["umi-native-public-model-inventory/1"] = Field(alias="schema")
    scope: Literal["all_admitted_model_submissions", "sealed_roster"]
    policy: CompetitionPolicy
    history: CohortRecoveryHistory
    participants: Annotated[tuple[RecoverableRosterParticipant, ...], Field(max_length=65536)]
    acceptances: Annotated[tuple[CertifiedModelArtifactAcceptance, ...], Field(max_length=65536)]


def project_models(
    inventory: PublicModelInventory,
) -> tuple[PublicModelCatalog, dict[str, ModelBundle]]:
    policy, history = inventory.policy, inventory.history
    cohort = digest(history.plan)
    acceptances = {c.acceptance.submission_sha256: c for c in inventory.acceptances}
    if len(acceptances) != len(inventory.acceptances):
        raise ValueError("public inventory repeats artifact acceptance")
    rows, bundles, seen = [], {}, set()
    with WorkProgress(
        "public_model_projection", len(inventory.participants), unit="entries"
    ) as progress:
        for p in inventory.participants:
            sub = p.record.request.signed_submission.submission
            key = digest(sub)
            if key in seen:
                raise ValueError("public inventory repeats an admitted submission")
            seen.add(key)
            uid = retained_uid(p, cohort)
            if (
                sub.policy_sha256 != digest(policy)
                or sub.accepted_terms_sha256 != policy.contribution_terms_sha256
            ):
                raise ValueError("public inventory changes signed submission policy or terms")
            verify_recovery_quorum(p.admission.admission, p.admission.signatures, policy)
            if sub.track == "model":
                cert = acceptances.get(key)
                if cert is not None:
                    verify_model_acceptance(
                        cert,
                        p.record,
                        history,
                        policy,
                        maximum_block=cert.acceptance.accepted_at_block,
                    )
                release = (
                    "terms_review_required"
                    if sub.accepted_terms_sha256 not in PUBLIC_RELEASE_TERMS
                    else "artifact_acceptance_pending"
                    if cert is None
                    else "public_release_authorized"
                )
                bundle = sub.model_bundle
                rows.append(
                    PublicModelEntry(
                        submission_sha256=key,
                        model_sha256=digest(bundle),
                        uid=uid,
                        hotkey=sub.hotkey,
                        accepted_terms_sha256=sub.accepted_terms_sha256,
                        license_id=bundle.license_id,
                        file_count=len(bundle.files),
                        total_bytes=sum(f.size_bytes for f in bundle.files),
                        release=release,
                        acceptance_sha256=None if cert is None else digest(cert),
                    )
                )
                if release == "public_release_authorized":
                    bundles[digest(bundle)] = bundle
            progress.advance()
    if not acceptances.keys() <= seen:
        raise ValueError("public inventory includes an unadmitted artifact acceptance")
    return PublicModelCatalog(
        schema="umi-public-cohort-models/1",
        cohort_sha256=cohort,
        policy_sha256=digest(policy),
        inventory_sha256=digest(inventory),
        inventory_scope=inventory.scope,
        items=tuple(sorted(rows, key=lambda row: row.submission_sha256)),
    ), bundles
