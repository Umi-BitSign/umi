"""Shared durable admission cutoff; no completed work or quorum is implied."""

from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_request_tail import RequestTailObservation
from .private_files import Directory
from .protocol import Hex32, StrictProtocolModel


class ServiceTailFenceBinding(StrictProtocolModel):
    schema_: Literal["umi-private-service-tail-fence-binding/1"] = Field(alias="schema")
    directory: Directory
    cohort_sha256: Hex32
    policy_sha256: Hex32


class ServiceTailAdmissionFence(StrictProtocolModel):
    schema_: Literal["umi-private-service-tail-admission-fence/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    policy_sha256: Hex32
    recovery_tip_sha256: Hex32
    catalog_sha256s: Annotated[tuple[Hex32, ...], Field(min_length=1, max_length=64)]
    tail: RequestTailObservation

    @model_validator(mode="after")
    def original_catalogs(self):
        if self.catalog_sha256s != tuple(sorted(set(self.catalog_sha256s))):
            raise ValueError("tail admission fence catalogs must be unique and ordered")
        return self
