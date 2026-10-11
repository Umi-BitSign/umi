"""Private files for aggregate cohort evidence, with a dedicated runtime budget."""

from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

from .canonical_stream import canonical_json_matches
from .competition_cohort_capacity import check_aggregate_evidence_bytes
from .private_files import _publish_bounded_private_model, _read_bounded_private_bytes

_Model = TypeVar("_Model", bound=BaseModel)


def read_aggregate_model(path: Path, model: type[_Model], *, maximum_bytes: int) -> _Model:
    raw = _read_bounded_private_bytes(
        path, maximum_bytes=check_aggregate_evidence_bytes(maximum_bytes)
    )
    value = model.model_validate_json(raw)
    if not canonical_json_matches(value, raw):
        raise ValueError("evaluator input must have stable canonical bytes")
    return value


def publish_aggregate_model(path: Path, value: BaseModel, *, maximum_bytes: int) -> None:
    _publish_bounded_private_model(
        path, value, maximum_bytes=check_aggregate_evidence_bytes(maximum_bytes)
    )
