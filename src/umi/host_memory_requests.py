"""Explicit, measured C5 request-stage policy; no inferred operation capacity."""

from typing import Annotated, Literal

from pydantic import Field, model_validator

from .host_memory_admission import (
    MINIMUM_AVAILABLE_BYTES,
    HostMemoryFile,
    HostMemorySlot,
    _absolute,
)
from .protocol import Hex32, StrictProtocolModel

C5 = "5dab3bfb836a91898f010bd229115e3e1c0406c3e17498d3b3b1975adab71428"
RequestOperation = Literal[
    "requests_source",
    "requests_lifecycle",
    "requests_seal_fenced",
    "requests_observe",
    "requests_sample",
    "requests_review",
    "requests_decision",
    "requests_export",
    "requests_publish",
    "preparation_republish",
]
OPERATIONS = {
    "requests_source": (None, "requests"),
    "requests_lifecycle": (None, "requests"),
    "requests_seal_fenced": ("transient", "requests"),
    "requests_observe": ("transient", "requests"),
    "requests_sample": ("transient", "requests"),
    "requests_review": ("transient", "requests"),
    "requests_decision": ("transient", "requests"),
    "requests_export": ("owner_export", "requests"),
    "requests_publish": ("transient", "requests"),
    "preparation_republish": ("transient", "preparation"),
}
Positive = Annotated[int, Field(gt=0, strict=True)]


class RequestStageBounds(StrictProtocolModel):
    """Qualified input shape, checked before retaining/decode at native read sites."""

    maximum_records: Annotated[int, Field(gt=0, le=65536, strict=True)]
    maximum_objects: Annotated[int, Field(gt=0, le=65536, strict=True)]
    maximum_services: Annotated[int, Field(gt=0, le=262144, strict=True)]
    maximum_orders: Annotated[int, Field(gt=0, le=65536, strict=True)]
    maximum_inventory_entries: Annotated[int, Field(gt=0, le=65536, strict=True)]
    maximum_participants: Annotated[int, Field(gt=0, le=65536, strict=True)]
    maximum_catalogs: Annotated[int, Field(gt=0, le=64, strict=True)]
    maximum_input_bytes: Positive
    maximum_object_bytes: Annotated[int, Field(gt=0, le=16 * 1024**2, strict=True)]
    maximum_declaration_bytes: Positive
    maximum_json_values: Positive
    maximum_json_depth: Annotated[int, Field(gt=0, le=256, strict=True)]


class RequestsStageMemoryPolicy(StrictProtocolModel):
    schema_: Literal["umi-c5-requests-memory-admission/1"] = Field(alias="schema")
    host_identity_sha256: Hex32
    directory: str
    directory_device: Annotated[int, Field(ge=0, strict=True)]
    directory_inode: Positive
    group_id: Positive
    minimum_available_bytes: Annotated[int, Field(ge=MINIMUM_AVAILABLE_BYTES, strict=True)]
    incremental_budget_bytes: Positive
    background_reservation_bytes: Positive
    maximum_aggregate_bytes: Annotated[int, Field(ge=1024, strict=True)]
    qualification_sha256: Hex32
    cohort_sha256: Literal[C5]
    protocol_policy_sha256: Hex32
    series_sha256: Hex32
    authority_sha256: Hex32
    preparation_result_sha256: Hex32
    operations: Annotated[tuple[RequestOperation, ...], Field(min_length=1, max_length=10)]
    bounds: RequestStageBounds
    slots: Annotated[tuple[HostMemorySlot, ...], Field(min_length=2, max_length=64)]
    transaction_lock: HostMemoryFile

    @model_validator(mode="after")
    def bindings(self):
        _absolute(self.directory)
        if set(slot.lane for slot in self.slots) != {"owner_export", "transient"}:
            raise ValueError("requests stage requires only measured owner and transient lanes")
        if any(slot.settlement_role is not None for slot in self.slots):
            raise ValueError("requests stage cannot reserve settlement replicas")
        if (
            len(set(self.operations)) != len(self.operations)
            or "preparation_republish" not in self.operations
        ):
            raise ValueError(
                "requests stage needs unique operations and retained preparation publication"
            )
        files = (*self.slots, self.transaction_lock)
        if len({item.name for item in files}) != len(files) or len(
            {(item.device, item.inode) for item in files}
        ) != len(files):
            raise ValueError("requests stage files must have distinct names and inodes")
        for lane in {slot.lane for slot in self.slots}:
            if len({slot.reservation_bytes for slot in self.slots if slot.lane == lane}) != 1:
                raise ValueError("each requests lane needs its measured reservation")
        if self.reserved_bytes > self.incremental_budget_bytes:
            raise ValueError("requests stage reservations exceed its qualified incremental budget")
        if (
            self.bounds.maximum_input_bytes > self.maximum_aggregate_bytes
            or self.bounds.maximum_declaration_bytes > self.bounds.maximum_input_bytes
            or self.bounds.maximum_object_bytes > self.bounds.maximum_input_bytes
        ):
            raise ValueError("requests stage shape exceeds its aggregate qualification")
        return self

    @property
    def reserved_bytes(self):
        return sum(slot.reservation_bytes for slot in self.slots)
