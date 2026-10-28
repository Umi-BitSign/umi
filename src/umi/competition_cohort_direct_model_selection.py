"""One bounded projection of already authorized, actually issued model uploads.

This is scheduling metadata, not admission or replacement signed evidence. The
owner retained authorization before issuing the original reservation. Reuse
those immutable bindings; do not repeat signatures, payload hashing or replay.
"""

from dataclasses import dataclass
from typing import Annotated

from pydantic import Field

from .competition_cohort_participation import CohortParticipationRequest
from .open_competition import digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

SCHEDULING_HOLD_REASONS = frozenset(
    ("direct_model_submission_superseded", "direct_model_reservation_after_cutoff")
)


class IssuedModelUpload(StrictProtocolModel):
    upload: Hex32
    consent: Hex32
    hotkey: Hex32
    sequence: Annotated[int, Field(ge=0)]
    created_ms: Annotated[int, Field(ge=0)]


@dataclass(frozen=True)
class ModelUploadSelection:
    issued: dict[str, IssuedModelUpload]
    selected: tuple[IssuedModelUpload, ...]
    superseded: frozenset[str]
    ineligible: frozenset[str]


def select_issued_model_uploads(owner, cohort, *, deadline=None, permitted=(), db=None):
    # Local import avoids making owner construction depend on admission drain.
    from .competition_cohort_direct_model_owner import DirectModelUploadPending

    args = {} if db is None else {"db": db}
    uploads = owner.journal.keys("direct-request", **args)
    if len(uploads) > owner.config.maximum_uploads:
        raise ValueError("retained upload count exceeds its configured metadata bound")
    cutoff = (
        None
        if deadline is None
        else deadline.legacy_reservations_before_unix_ms or deadline.close_new_admissions_at_unix_ms
    )
    if deadline is not None and deadline.cohort_sha256 != cohort:
        raise ValueError("upload selection deadline differs from its cohort")
    latest, issued, eligible, ineligible = {}, {}, set(), set()
    for upload in uploads:
        request = CohortParticipationRequest.model_validate_json(
            canonical_json_bytes(owner.journal.get("direct-request", upload, **args))
        )
        sub = request.signed_submission.submission
        if (
            digest(request) != upload
            or request.consent.consent.cohort_sha256 != cohort
            or sub.track != "model"
        ):
            raise ValueError("retained upload request differs from its cohort identity")
        try:
            reservation = owner.admission_reservation(request, **args).reservation
        except DirectModelUploadPending as error:
            if str(error) != "original direct reservation is incomplete":
                raise ValueError("issued upload reservation metadata needs repair") from error
            # Authorization or provider intent alone is not an issued upload.
            continue
        if (
            reservation.cohort_sha256 != cohort
            or reservation.payload.upload_sha256 != upload
            or reservation.payload.model_sha256 != sub.model_revision
            or identity(reservation.hotkey) != identity(sub.hotkey)
        ):
            raise ValueError("issued upload reservation identity differs")
        item = IssuedModelUpload(
            upload=upload,
            consent=digest(request.consent.consent),
            hotkey=identity(sub.hotkey),
            sequence=sub.sequence,
            created_ms=reservation.created_at_unix_ms,
        )
        issued[upload] = item
        if cutoff is not None and item.created_ms >= cutoff and upload not in permitted:
            ineligible.add(upload)
            continue
        eligible.add(upload)
        prior = latest.get(item.hotkey, [])
        if not prior or item.sequence > prior[0].sequence:
            latest[item.hotkey] = [item]
        elif item.sequence == prior[0].sequence:
            # Exact retry/consent siblings and conflicting equal sequences stay
            # visible. Only native admission can resolve them, not this hint.
            prior.append(item)
    selected = tuple(
        sorted((item for items in latest.values() for item in items), key=lambda item: item.upload)
    )
    return ModelUploadSelection(
        issued=issued,
        selected=selected,
        superseded=frozenset(eligible - {item.upload for item in selected}),
        ineligible=frozenset(ineligible),
    )
