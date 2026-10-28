"""Retained local admission scheduling; never changes signed cohort clocks."""

from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_cohort_direct_model_upload import SignedDirectModelUploadReservation
from .open_competition import digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class OperatorAdmissionDeadline(StrictProtocolModel):
    schema_: Literal["umi-cohort-operator-admission-deadline/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    authority_sha256: Hex32
    authorized_history_tip_sha256: Hex32
    close_new_admissions_at_unix_ms: Annotated[int, Field(ge=1, le=2**63 - 1)]
    source_sha256: Hex32
    operator_plan_sha256: Hex32
    reason: Annotated[str, Field(min_length=8, max_length=1024)]
    legacy_reservations_before_unix_ms: Annotated[int, Field(ge=1, le=2**63 - 1)] | None = None
    ingress_cutoff_receipt_sha256: Hex32 | None = None

    @model_serializer(mode="wrap")
    def omit_absent_bridge(self, handler):
        value = handler(self)
        if self.legacy_reservations_before_unix_ms is None:
            value.pop("legacy_reservations_before_unix_ms", None)
            value.pop("ingress_cutoff_receipt_sha256", None)
        return value

    @model_validator(mode="after")
    def bridge_evidence(self):
        if (self.legacy_reservations_before_unix_ms is None) != (
            self.ingress_cutoff_receipt_sha256 is None
        ):
            raise ValueError("legacy admission bridge needs exact retained ingress evidence")
        if self.legacy_reservations_before_unix_ms is not None and (
            self.legacy_reservations_before_unix_ms < self.close_new_admissions_at_unix_ms
            or self.ingress_cutoff_receipt_sha256 == "0" * 64
        ):
            raise ValueError("legacy admission bridge cannot precede its announced deadline")
        return self


def retain_deadline(db, selection, history):
    """The root-owned selected host config supplies local operator authority."""
    selection = OperatorAdmissionDeadline.model_validate_json(canonical_json_bytes(selection))
    tips = {digest(history.genesis), *(digest(v.transition) for v in history.transitions)}
    if (
        selection.cohort_sha256 != digest(history.plan)
        or selection.authority_sha256 != digest(history.authority.authority)
        or selection.authorized_history_tip_sha256 not in tips
        or selection.source_sha256 == "0" * 64
        or selection.operator_plan_sha256 == "0" * 64
    ):
        raise ValueError("admission deadline differs from its retained operator authority")
    raw = canonical_json_bytes(selection)
    prior = db.execute(
        "SELECT body FROM cohort_admission_deadlines WHERE cohort=?",
        (selection.cohort_sha256,),
    ).fetchone()
    if prior is not None:
        if prior[0] != raw:
            raise ValueError("retained admission deadline cannot be replaced")
        return
    db.execute(
        "INSERT INTO cohort_admission_deadlines VALUES (?,?)",
        (selection.cohort_sha256, raw),
    )


def retained_deadline(db, cohort):
    row = db.execute(
        "SELECT body FROM cohort_admission_deadlines WHERE cohort=?", (cohort,)
    ).fetchone()
    return None if row is None else OperatorAdmissionDeadline.model_validate_json(row[0])


def reservation_precedes_deadline(reservation, request, deadline, policy):
    """Authenticate old direct reservations, including a pre-restart generation."""
    signed = SignedDirectModelUploadReservation.model_validate_json(
        canonical_json_bytes(reservation)
    )
    body, sub = signed.reservation, request.signed_submission.submission
    if (
        sub.track != "model"
        or body.cohort_sha256 != deadline.cohort_sha256
        or body.cohort_sha256 != request.consent.consent.cohort_sha256
        or body.payload.upload_sha256 != digest(request)
        or body.payload.model_sha256 != sub.model_revision
        or identity(body.hotkey) != identity(sub.hotkey)
        or identity(signed.signature.hotkey) not in {identity(e.hotkey) for e in policy.evaluators}
        or body.created_at_unix_ms
        >= (deadline.legacy_reservations_before_unix_ms or deadline.close_new_admissions_at_unix_ms)
    ):
        raise ValueError("reservation does not authorize admission after the deadline")


class PendingReservedAdmissions(OSError):
    """Accepted uploads still need preservation and first participation."""

    def __init__(self, inventory):
        self.inventory = inventory
        self.submission_sha256 = None
        super().__init__("accepted pre-deadline uploads are still awaiting participation")
