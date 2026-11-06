"""Local operator upload-completion bounds anchored to the retained intake cutoff."""

from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_admission_deadline import OperatorAdmissionDeadline
from .protocol import Hex32, StrictProtocolModel


class OperatorUploadCompletionPolicy(StrictProtocolModel):
    schema_: Literal["umi-operator-upload-completion-policy/1"] = Field(alias="schema")
    admission_deadline: OperatorAdmissionDeadline
    grace_seconds: Annotated[int, Field(ge=1, le=24 * 60 * 60)]
    source_sha256: Hex32
    operator_plan_sha256: Hex32
    reason: Annotated[str, Field(min_length=8, max_length=1024)]

    @property
    def close_completion_at_unix_ms(self):
        return self.admission_deadline.close_new_admissions_at_unix_ms + self.grace_seconds * 1000

    @model_validator(mode="after")
    def retained_decision(self):
        if (
            self.source_sha256 == "0" * 64
            or self.operator_plan_sha256 == "0" * 64
            or self.close_completion_at_unix_ms > 2**63 - 1
            or self.close_completion_at_unix_ms
            <= (self.admission_deadline.legacy_reservations_before_unix_ms or 0)
        ):
            raise ValueError("upload completion policy lacks its bounded operator decision")
        return self


class DirectUploadCompletionClosed(RuntimeError):
    """The retained operator policy closed an unfinished upload."""


class DirectUploadExpiryIntent(StrictProtocolModel):
    schema_: Literal["umi-direct-upload-expiry-intent/1"] = Field(alias="schema")
    policy_sha256: Hex32
    reservation_sha256: Hex32
    attempt_id: Hex32
    upload_sha256: Hex32
    object_key_sha256: Hex32
    provider_upload_id_sha256: Hex32
    completion_sha256: Hex32 | None = None
    created_at_unix_ms: Annotated[int, Field(ge=0, le=2**63 - 1)]


class DirectUploadExpiryReceipt(StrictProtocolModel):
    schema_: Literal["umi-direct-upload-expiry-receipt/1"] = Field(alias="schema")
    intent_sha256: Hex32
    reservation_sha256: Hex32
    expired_at_unix_ms: Annotated[int, Field(ge=0, le=2**63 - 1)]
