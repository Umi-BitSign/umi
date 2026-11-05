"""Read an immutable authority selection only when creating new C8+ work."""

from pathlib import Path

from .competition_cpu_efficiency_adoption import MAX_CPU_ADOPTION_BYTES
from .competition_cpu_efficiency_policy import (
    CURRENT_CPU_MEASUREMENT,
    LEGACY_CPU_MEASUREMENT,
    SignedCohortCpuEfficiencyAdoption,
    cpu_adoption_slot,
    verify_cpu_efficiency_adoption_selection,
)
from .open_competition import digest
from .private_files import read_private_model


def selected_cpu_efficiency_adoption(
    *, directory, inline, policy, authority, plan, runtime_adoption
):
    # Historical C7 cannot acquire a new contract by changing local selection.
    if plan.sequence < 8:
        return None
    selected = inline
    if directory is not None:
        for semantics in (CURRENT_CPU_MEASUREMENT, LEGACY_CPU_MEASUREMENT):
            path = Path(directory) / (cpu_adoption_slot(digest(authority), semantics) + ".json")
            if not path.exists() and not path.is_symlink():
                continue
            delivered = read_private_model(
                path, SignedCohortCpuEfficiencyAdoption, maximum_bytes=MAX_CPU_ADOPTION_BYTES
            )
            if delivered.adoption.measurement_semantics != semantics:
                raise ValueError("CPU efficiency selection uses another measurement slot")
            if inline is not None and inline != delivered:
                raise ValueError("CPU efficiency inline and delivered selections disagree")
            selected = delivered
            break
    if selected is None or plan.sequence < selected.adoption.first_cohort_sequence:
        return None
    runtime = runtime_adoption
    if runtime is not None and plan.sequence < runtime.adoption.first_cohort_sequence:
        runtime = None
    verify_cpu_efficiency_adoption_selection(
        selected,
        policy=policy,
        authority=authority,
        runtime_sha256=(
            policy.evaluation_runtime_sha256
            if runtime is None
            else digest(runtime.adoption.runtime)
        ),
    )
    return selected
