"""Trusted cold-bundle cache observation; never a claim of a cold machine."""

from typing import Annotated, Literal

from pydantic import Field, model_validator

from .protocol import Hex32, StrictProtocolModel

BUNDLE_CACHE_RULE = "verified_bundle_pagecache_eviction/1"


class CpuBundleCacheEvidence(StrictProtocolModel):
    schema_: Literal["umi-cpu-bundle-cache-evidence/1"] = Field(alias="schema")
    rule: Literal["verified_bundle_pagecache_eviction/1"] = BUNDLE_CACHE_RULE
    model_sha256: Hex32
    invocation_sha256: Hex32
    file_count: Annotated[int, Field(ge=1, le=4096)]
    total_bytes: Annotated[int, Field(ge=0, le=2**53 - 1)]
    total_pages: Annotated[int, Field(ge=0, le=2**53 - 1)]
    page_size: Annotated[int, Field(ge=4096, le=65536)]
    resident_pages: Literal[0] = 0
    started_monotonic_us: Annotated[int, Field(ge=1, le=2**63 - 1)]
    finished_monotonic_us: Annotated[int, Field(ge=1, le=2**63 - 1)]

    @property
    def elapsed_ms(self):
        return (self.finished_monotonic_us - self.started_monotonic_us + 999) // 1000

    @model_validator(mode="after")
    def geometry(self):
        if (
            self.page_size & (self.page_size - 1)
            or self.finished_monotonic_us < self.started_monotonic_us
            or not (self.total_bytes + self.page_size - 1) // self.page_size
            <= self.total_pages
            <= self.total_bytes // self.page_size + self.file_count
        ):
            raise ValueError("bundle cache receipt has inconsistent timing or page geometry")
        return self


def validate_bundle_cache_evidence(value, *, model_sha256, invocation_sha256, measured_start_us):
    if (
        type(value) is not CpuBundleCacheEvidence
        or value.model_sha256 != model_sha256
        or value.invocation_sha256 != invocation_sha256
        or value.finished_monotonic_us > measured_start_us
    ):
        raise ValueError("CPU timing lacks its original cold-bundle observation")
    return value
