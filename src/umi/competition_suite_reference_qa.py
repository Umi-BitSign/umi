"""Private annotation/alignment qualification, not automatic ASL translation proof."""

from typing import Annotated, Literal

from pydantic import Field, model_validator

from .protocol import Hex32, StrictProtocolModel

Index = Annotated[int, Field(strict=True, ge=0, le=2**53 - 1)]
Positive = Annotated[int, Field(strict=True, ge=1, le=2**53 - 1)]


class SuiteReferenceInterval(StrictProtocolModel):
    kind: Literal["publisher_labeled_clip", "source_milliseconds", "source_frames"]
    start: Index | None = None
    end: Positive | None = None
    fps_numerator: Positive | None = None
    fps_denominator: Positive | None = None
    fps_evidence_sha256: Hex32 | None = None

    @model_validator(mode="after")
    def exact_interval(self):
        bounds = self.start is not None and self.end is not None and self.start < self.end
        fps = all(
            v is not None
            for v in (self.fps_numerator, self.fps_denominator, self.fps_evidence_sha256)
        )
        any_fps = any(
            v is not None
            for v in (self.fps_numerator, self.fps_denominator, self.fps_evidence_sha256)
        )
        if self.kind == "publisher_labeled_clip":
            valid = self.start is None and self.end is None and not any_fps
        elif self.kind == "source_milliseconds":
            valid = bounds and not any_fps
        else:
            valid = bounds and fps
        if not valid:
            raise ValueError(
                "reference interval requires exact source bounds and evidenced actual FPS"
            )
        return self


class SuiteReferenceQA(StrictProtocolModel):
    schema_: Literal["umi-suite-reference-qa/1"] = Field(alias="schema")
    case_sha256: Hex32
    source_group_sha256: Hex32
    signer_group_sha256: Hex32
    provenance_sha256: Hex32
    reference_sha256: Hex32
    annotation_source_sha256: Hex32
    reference_basis: Literal["publisher_annotation", "independent_reference_review"]
    annotation_source: Annotated[str, Field(min_length=1, max_length=4096)]
    interval: SuiteReferenceInterval
    reference_and_interval_checked: Literal[True]
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=1024)], ...], Field(max_length=64)
    ] = ()
