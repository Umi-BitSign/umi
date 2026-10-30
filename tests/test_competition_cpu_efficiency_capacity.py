"""Bounded allocation transport with synthetic compact evidence, no inference."""

from fractions import Fraction
from types import SimpleNamespace

import pytest

from umi.competition_cohort_reward_allocation import (
    MAX_REWARD_ALLOCATION_BYTES,
    CohortRewardAllocation,
    derive_effective_reward_allocation,
)
from umi.competition_cpu_efficiency_evidence import CpuEfficiencyRun, combine_cpu_efficiency_runs
from umi.competition_geometric_rewards import cohort_reward_parameters
from umi.competition_reward_files import StandingRewardFiles
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_geometric_rewards import package_boundary
from .test_open_competition import wallet


def large_cpu_package():
    """Forty candidates with 64 evaluators exceed the former 1 MiB file limit."""
    who = wallet("Alice").hotkey.ss58_address
    package = package_boundary(
        [Fraction(595000 - index, 1000000) for index in range(40)],
        baseline=Fraction(3, 5),
        hotkeys=[who] * 40,
    )
    contract = {"measurement_contract": "allocation-file-capacity-fixture"}
    original = package.allocation.model_award
    candidates = []
    for index, candidate in enumerate(original.candidates):
        runs = tuple(
            CpuEfficiencyRun(
                evaluator_identity=f"{evaluator + 1:064x}",
                terminal_sha256=digest(["terminal", index, evaluator]),
                profile_sha256="34" * 32,
                observations_sha256=digest(["observations", index, evaluator]),
                slowdown_numerator="1",
                slowdown_denominator="1",
                candidate_failed_cases=0,
                case_count=16,
            )
            for evaluator in range(64)
        )
        candidates.append(
            candidate.model_copy(
                update={
                    "cpu_efficiency": combine_cpu_efficiency_runs(digest(contract), runs),
                }
            )
        )
    package.allocation = package.allocation.model_copy(
        update={
            "model_award": original.model_copy(
                update={
                    "candidates": tuple(candidates),
                    "cpu_efficiency_adoption_sha256": digest(contract),
                }
            )
        }
    )
    package.inputs.roster = SimpleNamespace(
        round=SimpleNamespace(cpu_efficiency_adoption=SimpleNamespace(adoption=contract))
    )
    return package


@pytest.fixture
def large_cpu_allocation():
    return derive_effective_reward_allocation(large_cpu_package(), cohort_reward_parameters(8))


def test_allocation_envelope_covers_bounded_schema_without_quantizing_quality():
    schema = CohortRewardAllocation.model_json_schema()
    definitions = schema["$defs"]
    award = definitions["GeometricModelAward"]["properties"]
    assert award["candidates"]["maxItems"] == award["credits"]["maxItems"] == 512
    assert award["acceptances"]["maxItems"] == 512
    assert schema["properties"]["recipients"]["maxItems"] == 65535
    assert definitions["CpuEfficiencySummary"]["properties"]["runs"]["maxItems"] == 64
    for field in ("case_count", "candidate_failed_cases"):
        assert definitions["CpuEfficiencyRun"]["properties"][field]["maximum"] == 2048
    for field in ("slowdown_numerator", "slowdown_denominator"):
        assert definitions["CpuEfficiencyRun"]["properties"][field]["maxLength"] <= 20
    for field in ("numerator", "denominator"):
        assert definitions["ExactQuality"]["properties"][field]["maxLength"] == 4096
    # Conservative component ceilings documented beside the shared constant.
    envelope = 512 * (64 * 512 + 17 * 1024 + 17 * 1024 + 40 * 1024)
    envelope += 65535 * 128 + 1024**2
    assert envelope == 65_011_584
    assert envelope < MAX_REWARD_ALLOCATION_BYTES == 64 * 1024**2


def test_native_allocation_files_above_old_limit_survive_restart(tmp_path, large_cpu_allocation):
    value = large_cpu_allocation
    raw = canonical_json_bytes(value)
    assert 1024**2 < len(raw) < MAX_REWARD_ALLOCATION_BYTES
    options = dict(maximum_package_bytes=1024**2, maximum_witness_bytes=1024**2)
    files = StandingRewardFiles(tmp_path / "files", **options)
    files.retain_allocation(value)
    reopened = StandingRewardFiles(files.root, **options)
    assert canonical_json_bytes(reopened.allocation(digest(value))) == raw
    reopened.retain_allocation(value)
    # An oversized sparse input is rejected from metadata before parsing; the
    # larger supported envelope does not remove the bounded reader.
    path = files.root / "allocations" / ("ff" * 32 + ".json")
    with path.open("wb") as stream:
        stream.truncate(MAX_REWARD_ALLOCATION_BYTES + 1)
    path.chmod(0o600)
    with pytest.raises((ValueError, OSError)):
        reopened.allocation("ff" * 32)
