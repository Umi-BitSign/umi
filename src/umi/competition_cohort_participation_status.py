"""Bounded, advisory participation lookup in one owned read-only snapshot.

This reports retained intake and verified admission certificates, not a seal's
selection or permission to replace a running miner's bound configuration. A
fresh observation is not a reservation against a concurrent intake seal.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, TypeAdapter

from .competition_chain import RegistrationCapture
from .competition_cohort_admission_queue import CohortAdmissionQueue
from .competition_cohort_coordinator import CohortDecisionInput, replay_cohort_decisions
from .competition_cohort_intake_records import read_participation, replay_participation
from .competition_cohort_participation import CohortAdmissionStatus
from .competition_cohort_recovery import Block, Phase
from .competition_execution import ExecutionBoundary, execution_boundary
from .open_competition import Hotkey, Track, digest, identity
from .protocol import Hex32, StrictProtocolModel

Nonce = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
Sequence = Annotated[int, Field(ge=1, le=2**32 - 1)]


class RetainedParticipationStatus(StrictProtocolModel):
    sequence: Sequence
    model_revision: Hex32
    consent_sha256: Hex32
    submission_sha256: Hex32
    retained_at_block: Block
    admission: CohortAdmissionStatus


class CohortParticipationStatus(StrictProtocolModel):
    schema_: Literal["umi-cohort-participation-status/1"] = Field(alias="schema")
    nonce: Nonce
    policy_sha256: Hex32
    cohort_sha256: Hex32
    authority_sha256: Hex32
    recovery_tip_sha256: Hex32
    observation: ExecutionBoundary
    hotkey: Hotkey
    track: Track
    phase: Phase | Literal["complete", "revoked"]
    intake_fenced: bool
    pending_policy_adoption: Literal["adopt_model_delivery", "adopt_request_tail_rule"] | None
    latest: RetainedParticipationStatus | None
    requested_consent_sha256: Hex32 | None
    requested_consent_status: Literal["not_requested", "not_retained", "latest", "superseded"]
    requested: RetainedParticipationStatus | None
    minimum_next_sequence: Sequence | None
    # Policy/sequence lower bound only; capacity, registration, transport and
    # current readiness must still pass, and intake can close at any time.
    submission_not_before_block: Block
    advisory_only: Literal[True] = True
    sealed_selection_verified: Literal[False] = False
    runtime_migration_authorized: Literal[False] = False
    chain_submission_authorized: Literal[False] = False


def participation_status(
    queue: CohortAdmissionQueue,
    cohort: str,
    hotkey: str,
    track: Track,
    capture: RegistrationCapture,
    *,
    nonce: str,
    consent: str | None = None,
) -> CohortParticipationStatus:
    """Read at most two bounded participation rows; never reconstruct a roster."""
    intake = queue.intake
    intake._allowed(cohort)
    hotkey = TypeAdapter(Hotkey).validate_python(hotkey)
    track = TypeAdapter(Track).validate_python(track)
    nonce = TypeAdapter(Nonce).validate_python(nonce)
    if consent is not None:
        consent = TypeAdapter(Hex32).validate_python(consent)
    account = identity(hotkey)
    observation = execution_boundary(capture)
    with intake._connection(prefer_history=True) as (db, store):
        history = store.published_history(cohort)
        state, _, _ = replay_cohort_decisions(
            history, intake.policy, lambda key: store.source(cohort, key, CohortDecisionInput)
        )
        if observation.block < state.observed_at_block:
            raise ValueError("participation observation predates the published history")
        _, pending = store.status(cohort)
        adoption = pending.operation if pending is not None and pending.is_policy_adoption else None
        # Existence is enough to report a fence. Do not deserialize a seal or
        # claim the latest entry is selected without replaying its whole roster.
        fenced = (
            adoption is not None
            or db.execute(
                "SELECT 1 FROM cohort_intake_seals WHERE cohort=? AND tip=?",
                (cohort, state.tip_sha256),
            ).fetchone()
            is not None
        )

        def decode(row):
            if row is None:
                return None
            key, seq, observed, tip, raw = row
            record = read_participation(raw)
            sub = record.request.signed_submission.submission
            admission = replay_participation(record, history, intake.policy)
            if (
                key != admission.consent_sha256
                or cohort != admission.cohort_sha256
                or account != identity(sub.hotkey)
                or track != sub.track
                or seq != sub.sequence
                or observed != admission.admitted_at_block
                or tip != admission.recovery_tip_sha256
                or admission.admitted_at_block > observation.block
            ):
                raise ValueError(
                    "retained participation index differs from its body or observation"
                )
            certificate = queue._certificate(db, record)
            return RetainedParticipationStatus(
                sequence=sub.sequence,
                model_revision=sub.model_revision,
                consent_sha256=key,
                submission_sha256=admission.submission_sha256,
                retained_at_block=observed,
                admission=CohortAdmissionStatus(
                    schema="umi-cohort-admission-status/1",
                    policy_sha256=digest(intake.policy),
                    cohort_sha256=cohort,
                    consent_sha256=key,
                    status="pending_attestation" if certificate is None else "admission_certified",
                    certificate=certificate,
                ),
            )

        columns = "consent,sequence,observed,recovery_tip,substr(body,1,4194305)"
        latest = decode(
            db.execute(
                f"SELECT {columns} FROM cohort_consents "
                "WHERE cohort=? AND hotkey=? AND track=? ORDER BY sequence DESC LIMIT 1",
                (cohort, account, track),
            ).fetchone()
        )
        requested = None
        relation = "not_requested"
        if consent is not None:
            if latest is not None and consent == latest.consent_sha256:
                requested, relation = latest, "latest"
            else:
                requested = decode(
                    db.execute(
                        f"SELECT {columns} FROM cohort_consents "
                        "WHERE consent=? AND cohort=? AND hotkey=? AND track=?",
                        (consent, cohort, account, track),
                    ).fetchone()
                )
                if requested is not None and (
                    latest is None or requested.sequence >= latest.sequence
                ):
                    raise ValueError("requested participation contradicts latest retained sequence")
                relation = "not_retained" if requested is None else "superseded"
        next_sequence = 1 if latest is None else latest.sequence + 1
        return CohortParticipationStatus(
            schema="umi-cohort-participation-status/1",
            nonce=nonce,
            policy_sha256=digest(intake.policy),
            cohort_sha256=cohort,
            authority_sha256=state.authority_sha256,
            recovery_tip_sha256=state.tip_sha256,
            observation=observation,
            hotkey=hotkey,
            track=track,
            phase=state.phase,
            intake_fenced=fenced,
            pending_policy_adoption=adoption,
            latest=latest,
            requested_consent_sha256=consent,
            requested_consent_status=relation,
            requested=requested,
            minimum_next_sequence=next_sequence if next_sequence < 2**32 else None,
            submission_not_before_block=max(
                state.not_before_block,
                0
                if latest is None
                else (latest.retained_at_block + intake.policy.minimum_submission_interval_blocks),
            ),
        )
