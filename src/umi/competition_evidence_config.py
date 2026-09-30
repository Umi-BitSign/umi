"""Explicit, versioned evidence settings for authenticated worker and host inputs."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .competition_evidence_store import EvidenceBudget
from .competition_evidence_worker import EvidenceWorkerProfile
from .protocol import StrictProtocolModel


class EvidenceStorageConfig(StrictProtocolModel):
    schema_: Literal["umi-weight-evidence-storage-config/1"] = Field(alias="schema")
    maximum_stored_bytes: Annotated[int, Field(gt=0, le=16 * 1024**3)]
    maximum_expanded_bytes: Annotated[int, Field(gt=0, le=128 * 1024**3)]
    maximum_records: Annotated[int, Field(gt=0, le=65536)]
    maximum_objects: Annotated[int, Field(gt=0, le=2000000)]
    recovery_observations: Annotated[int, Field(ge=1, le=32)]
    maximum_database_bytes: Annotated[int, Field(ge=1024**2, le=16 * 1024**3)]

    def profile(self) -> EvidenceWorkerProfile:
        return EvidenceWorkerProfile(
            EvidenceBudget(
                self.maximum_stored_bytes,
                self.maximum_expanded_bytes,
                self.maximum_records,
                self.maximum_objects,
            ),
            self.recovery_observations,
        )

    @model_validator(mode="after")
    def capacity(self) -> Self:
        self.profile()
        if self.maximum_stored_bytes + 1024**2 > self.maximum_database_bytes:
            raise ValueError("evidence database needs room beyond the payload ceiling")
        return self

    def worker_options(self) -> dict:
        return {
            "evidence_profile": self.profile(),
            "maximum_database_bytes": self.maximum_database_bytes,
        }
