"""Portable exact quality fractions without execution or storage dependencies."""

from typing import Annotated

from pydantic import Field

from .protocol import StrictProtocolModel


class ExactQuality(StrictProtocolModel):
    numerator: Annotated[str, Field(pattern=r"^[0-9]+$", max_length=4096)]
    denominator: Annotated[str, Field(pattern=r"^[1-9][0-9]*$", max_length=4096)]
