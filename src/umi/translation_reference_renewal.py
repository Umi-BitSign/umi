"""Explicit rolling authorization windows for newly signed reference directives.

Renewal issues a successor; it never changes an existing signed interval or a
cohort clock. Current native approval remains required for each signature.
"""

from typing import Annotated, Literal

from pydantic import Field, model_validator

from .protocol import StrictProtocolModel


class ReferenceDirectiveRenewal(StrictProtocolModel):
    schema_: Literal["umi-reference-directive-renewal/1"] = Field(alias="schema")
    lifetime_blocks: Annotated[int, Field(ge=2, le=2**53 - 1)]
    renew_before_blocks: Annotated[int, Field(ge=1, le=2**53 - 1)]

    @model_validator(mode="after")
    def bounded_margin(self):
        if self.renew_before_blocks >= self.lifetime_blocks:
            raise ValueError("reference renewal margin must be shorter than its lifetime")
        return self

    def through_block(self, block: int) -> int:
        if type(block) is not int or not 1 <= block <= 2**53 - 1 - self.lifetime_blocks:
            raise ValueError("reference renewal requires a bounded current native block")
        return block + self.lifetime_blocks
