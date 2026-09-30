"""Bounded root-seal records; these data models alone grant no authority."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from typing_extensions import Self

from .protocol import Hex32, StrictProtocolModel


class EvidenceMigrationSeal(StrictProtocolModel):
    schema_: Literal["umi-weight-evidence-migration-seal/1"] = Field(alias="schema")
    compatibility_sha256: Hex32
    original_receipt_hex: Annotated[
        str, Field(min_length=2, max_length=64 * 1024, pattern=r"^(?:[0-9a-f]{2})+$")
    ]
    original_worker_limits_hex: Annotated[
        str, Field(min_length=2, max_length=64 * 1024, pattern=r"^(?:[0-9a-f]{2})+$")
    ]
    predecessor_state_hex: Annotated[
        str, Field(min_length=2, max_length=64 * 1024, pattern=r"^(?:[0-9a-f]{2})+$")
    ]
    preparation_receipt_hex: Annotated[
        str, Field(min_length=2, max_length=32 * 1024, pattern=r"^(?:[0-9a-f]{2})+$")
    ]
    retained_history_sha256: Hex32
    source_root: Annotated[str, Field(min_length=2, max_length=4096)]
    candidate_root: Annotated[str, Field(min_length=2, max_length=4096)]
    source_database_sha256: Hex32
    candidate_database_sha256: Hex32
    migration_finalized_block: Annotated[int, Field(gt=0, le=2**53 - 1)]
    service_uid: Annotated[int, Field(gt=0)]
    chain_submission_authorized: Literal[False] = False

    @field_validator("source_root", "candidate_root")
    @classmethod
    def absolute_path(cls, value):
        path = Path(value)
        if not path.is_absolute() or str(path) != value or ".." in path.parts or path == Path("/"):
            raise ValueError("migration paths must be normalized absolute directories")
        return value

    @model_validator(mode="after")
    def distinct_roots(self) -> Self:
        source, candidate = Path(self.source_root), Path(self.candidate_root)
        if source.is_relative_to(candidate) or candidate.is_relative_to(source):
            raise ValueError("migration needs disjoint source and candidate roots")
        return self
