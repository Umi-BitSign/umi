"""Generate a ~400 KB signed synthetic void; never use production inputs.

Invoke explicitly with pytest (this file is outside default test discovery):
UMI_SYNTHETIC_VOID_OUTPUT=<task-root>/fixture.json PYTHONPATH=src:. \
    python -m pytest -q tools/export_canonical_reuse_fixture.py \
    --basetemp=<task-root>/pytest -o cache_dir=<task-root>/cache
The output includes public synthetic signatures, never signing keys.
"""

import os
from pathlib import Path

import pytest

from tests.test_canonical_reuse_memory import base_setup as base_setup
from tests.test_canonical_reuse_memory import setup as setup
from tests.test_competition_execution import policy as policy
from tests.test_competition_execution import runtime as runtime
from tests.test_competition_void import attempts as attempts
from tests.test_competition_void_reuse import native_void as native_void
from umi.protocol import canonical_json_bytes


@pytest.mark.parametrize("base_setup", ["umi-open-competition-policy/2"], indirect=True)
@pytest.mark.parametrize("setup", [66], indirect=True)
async def test_export_synthetic_fixture(native_void):
    evidence, context = native_void
    fixture = {
        "schema": "umi-synthetic-void-replay-benchmark/1",
        "evidence": evidence.model_dump(mode="json", by_alias=True),
        "policy": context["policy"].model_dump(mode="json", by_alias=True),
        "suite": context["suite"].model_dump(mode="json", by_alias=True),
        "current_block": context["current_block"],
    }
    path = Path(os.environ["UMI_SYNTHETIC_VOID_OUTPUT"])
    path.write_bytes(canonical_json_bytes(fixture))
