"""Large cohort documents use the same protocol domain without output buffers."""

import rfc8785
from pydantic import model_validator
from typing_extensions import Self

from .aggregate_json import validate_aggregate_json
from .canonical_aggregate import AggregateStreamModel
from .canonical_stream import canonical_json_size
from .protocol import StrictProtocolModel


class AggregateProtocolModel(StrictProtocolModel, AggregateStreamModel):
    @classmethod
    def model_validate_json(
        cls, json_data, *, strict=None, extra=None, context=None, by_alias=None, by_name=None
    ):
        return validate_aggregate_json(
            cls,
            json_data,
            super().model_validate_json,
            strict=strict,
            extra=extra,
            context=context,
            by_alias=by_alias,
            by_name=by_name,
        )

    @model_validator(mode="after")
    def validate_canonical_json_domain(self) -> Self:
        """Preserve the inherited domain check, including every invalid value."""
        try:
            canonical_json_size(self)
        except rfc8785.CanonicalizationError as error:
            raise ValueError("protocol model is outside the RFC 8785 JSON domain") from error
        return self
