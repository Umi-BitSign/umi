"""Service entry modules must load before the command registry is initialized."""

import subprocess
import sys

import pytest


@pytest.mark.parametrize(
    "module",
    [
        "umi.competition_service",
        "umi.competition_evaluator",
        "umi.competition_dispatch",
        "umi.competition_rounds",
        "umi.competition_exchange",
        "umi.competition_cli",
    ],
)
def test_service_cold_import(module):
    result = subprocess.run(
        [sys.executable, "-c", f"import {module}; import umi.competition_cli"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
