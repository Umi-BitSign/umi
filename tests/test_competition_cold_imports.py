"""Service entry modules must load before the command registry is initialized."""

import subprocess
import sys
from pathlib import Path

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
        "umi.competition_commands.cohort_baseline",
        "umi.competition_cohort_review_config",
        "umi.competition_public_results_cli",
    ],
)
def test_service_cold_import(module):
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import importlib,sys; from pathlib import Path; "
            "sys.path.insert(0,sys.argv[1]); "
            "module=importlib.import_module(sys.argv[2]); "
            "assert Path(module.__file__).resolve().is_relative_to(Path(sys.argv[1])); "
            "import umi.competition_cli",
            str(Path(__file__).resolve().parents[1] / "src"),
            module,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
