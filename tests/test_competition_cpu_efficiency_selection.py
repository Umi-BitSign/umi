"""Selected signed contract reaches first new work without rewriting old rounds."""

from types import SimpleNamespace

import pytest

from umi.competition_cohort_preparation_owner import CohortPreparation
from umi.competition_cpu_efficiency_selection import selected_cpu_efficiency_adoption
from umi.open_competition import digest
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_preparation import run
from .test_competition_cpu_efficiency_policy import (
    adoption as adoption,
)
from .test_competition_cpu_efficiency_policy import (
    base_policy as base_policy,
)
from .test_competition_cpu_efficiency_policy import (
    intake as intake,
)
from .test_competition_cpu_efficiency_policy import (
    original_runtime as original_runtime,
)
from .test_competition_cpu_efficiency_policy import (
    policy as policy,
)
from .test_competition_cpu_efficiency_policy import (
    preparation as preparation,
)
from .test_competition_cpu_efficiency_policy import (
    recovery as recovery,
)
from .test_competition_cpu_efficiency_policy import (
    runtime as runtime,
)
from .test_competition_cpu_efficiency_policy import (
    runtime_adoption as runtime_adoption,
)
from .test_competition_cpu_efficiency_policy import (
    scenario as scenario,
)


def test_first_preparation_consumes_delivered_contract_without_restart(
    preparation, adoption, runtime_adoption, tmp_path
):
    h = preparation
    h.certify()
    directory = tmp_path / "cpu-selection"
    h.owner = CohortPreparation(
        h.queue,
        h.store,
        runtime_adoption=runtime_adoption,
        cpu_efficiency_adoptions_directory=str(directory),
    )
    with pytest.raises(ValueError, match="cpu_efficiency_measurement_policy_missing"):
        run(h)
    path = directory / (adoption.adoption.authority_sha256 + ".json")
    publish_private_model(path, adoption)
    prepared = run(h)
    assert prepared.roster.round.cpu_efficiency_adoption == adoption
    original = canonical_json_bytes(prepared)
    path.unlink()
    # Once prepared, both restart and repeat retain the original signed bytes;
    # dynamic selection is consulted only for a new round.
    restarted = CohortPreparation(
        h.queue,
        h.store,
        runtime_adoption=runtime_adoption,
        cpu_efficiency_adoptions_directory=str(directory),
    )
    assert canonical_json_bytes(run(h, owner=restarted)) == original


@pytest.mark.parametrize("recovery", [7], indirect=True)
def test_c7_does_not_read_future_contract_file(preparation, adoption, tmp_path):
    h = preparation
    h.certify()
    directory = tmp_path / "cpu-selection"
    directory.mkdir(mode=0o700)
    path = directory / (adoption.adoption.authority_sha256 + ".json")
    path.write_bytes(b"invalid CPU selection must not affect C7")
    h.owner = CohortPreparation(h.queue, h.store, cpu_efficiency_adoptions_directory=str(directory))
    round_ = run(h).roster.round
    assert round_.sequence == 7
    assert round_.cpu_efficiency_adoption is None


def test_selection_rejects_runtime_and_inline_delivery_disagreement(
    scenario, policy, adoption, runtime_adoption, tmp_path
):
    directory = tmp_path / "selection"
    publish_private_model(directory / (adoption.adoption.authority_sha256 + ".json"), adoption)
    kwargs = dict(
        directory=str(directory),
        inline=None,
        policy=policy,
        authority=scenario["history"].authority.authority,
        plan=scenario["history"].plan,
        runtime_adoption=runtime_adoption,
    )
    assert selected_cpu_efficiency_adoption(**kwargs) == adoption
    with pytest.raises(ValueError, match="runtime"):
        selected_cpu_efficiency_adoption(**{**kwargs, "runtime_adoption": None})
    changed = adoption.model_copy(update={"signatures": tuple(reversed(adoption.signatures))})
    with pytest.raises(ValueError, match="disagree"):
        selected_cpu_efficiency_adoption(**{**kwargs, "inline": changed})


async def test_operator_start_uses_the_same_delivered_policy(
    preparation, adoption, runtime_adoption, tmp_path
):
    from umi.competition_cohort_lifecycle_host import LifecycleHost

    h = preparation
    directory = tmp_path / "selection"
    publish_private_model(directory / (adoption.adoption.authority_sha256 + ".json"), adoption)
    h.owner = CohortPreparation(
        h.queue,
        h.store,
        runtime_adoption=runtime_adoption,
        cpu_efficiency_adoptions_directory=str(directory),
    )
    shell = SimpleNamespace(
        policy=h.intake.policy,
        service=SimpleNamespace(
            preparation=h.owner,
            intake=SimpleNamespace(tracks=("model",)),
            config=SimpleNamespace(
                series=SimpleNamespace(cohorts=(h.history.plan,), recovery=h.history.authority),
                runtime_adoption=runtime_adoption,
            ),
        ),
    )
    result = await LifecycleHost._operator_request_start_selection(shell, h.cohort, 330)
    assert result["cpu_efficiency_adoption_sha256"] == digest(adoption.adoption)
    assert result["evaluation_runtime_sha256"] == adoption.adoption.runtime_sha256
