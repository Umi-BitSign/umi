"""Exact committed service answers, independent of closure and scoring replay."""

from typing import Annotated, Literal

from pydantic import Field, model_validator

from .protocol import (
    Hex32,
    StrictProtocolModel,
    normalized_grapheme_count,
    normalized_token_count,
)

ServiceStratum = Literal["fingerspelling", "continuous"]


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
