from __future__ import annotations

import json

import pytest

from umi import competition_worker_cli as cli
from umi.competition_evidence_config import EvidenceStorageConfig
from umi.competition_host_activation import (
    SuccessorWorkerExecutionLimits,
    _validate_worker_execution_bindings,
)
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_host_activation import _weight_rollover
from .test_competition_host_activation import activation_case as activation_case
from .test_competition_package import package_case as package_case
from .test_competition_package import package_limits as package_limits
from .test_competition_package import release_identity as release_identity
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_recovery import explicit as explicit
from .test_competition_recovery import limits as limits
from .test_competition_recovery import trusted_ports as trusted_ports
from .test_competition_supervisor import successor_release as successor_release
from .test_competition_weights import weight_case as weight_case
from .test_competition_worker import worker_capacity as worker_capacity
from .test_competition_worker_cli import inputs as inputs
from .test_competition_worker_cli import weight_inputs as weight_inputs
from .test_open_competition import policy as policy


def storage_config():
    return EvidenceStorageConfig(
        schema="umi-weight-evidence-storage-config/1",
        maximum_stored_bytes=2 * 1024**3,
        maximum_expanded_bytes=64 * 1024**3,
        maximum_records=10000,
        maximum_objects=2000000,
        recovery_observations=16,
        maximum_database_bytes=12 * 1024**3,
    )


def test_explicit_v2_preserves_v1_canonical_bytes(weight_inputs):
    old = weight_inputs.inputs.worker_execution_config
    original = canonical_json_bytes(old)
    assert "evidence_storage" not in json.loads(original)["weights"]
    body = json.loads(original)
    body["weights"]["evidence_storage"] = storage_config().model_dump(mode="json", by_alias=True)
    with pytest.raises(ValueError, match="explicit execution"):
        cli.SuccessorWorkerExecutionConfig.model_validate(body)
    body["schema"] = "umi-successor-worker-execution-config/2"
    selected = cli.SuccessorWorkerExecutionConfig.model_validate(body)
    assert selected.weights.evidence_storage == storage_config()
    del body["weights"]["evidence_storage"]
    with pytest.raises(ValueError, match="explicit execution"):
        cli.SuccessorWorkerExecutionConfig.model_validate(body)
    assert (
        canonical_json_bytes(cli.SuccessorWorkerExecutionConfig.model_validate_json(original))
        == original
    )


async def test_cli_uses_selected_profile_after_authentication(weight_inputs, monkeypatch):
    inputs = weight_inputs.inputs
    old = inputs.worker_execution_config
    storage = storage_config()
    inputs.worker_execution_config = old.model_copy(
        update={
            "schema_": "umi-successor-worker-execution-config/2",
            "weights": old.weights.model_copy(update={"evidence_storage": storage}),
        }
    )
    original = cli.CompetitionWeightWorker
    selected = []

    class CandidatePort(original):
        def __init__(self, path, **kwargs):
            assert kwargs.pop("evidence_profile") == storage.profile()
            assert kwargs.pop("maximum_database_bytes") == storage.maximum_database_bytes
            selected.append(True)
            super().__init__(path, **kwargs)

    monkeypatch.setattr(cli, "ContentAddressedWeightWorker", CandidatePort)
    assert (await cli.run_worker("competition_weights")).exact_row_currently_applied
    assert selected == [True]
    assert weight_inputs.events.index("activation") < weight_inputs.events.index("worker")


def test_host_requires_exact_root_sealed_storage_profile(activation_case):
    case = activation_case
    rollover = _weight_rollover(case)
    storage = storage_config()
    execution = rollover.execution.model_copy(
        update={
            "schema_": "umi-successor-worker-execution-config/2",
            "weights": rollover.execution.weights.model_copy(update={"evidence_storage": storage}),
        }
    )
    limits_body = case.limits.model_dump(mode="json", by_alias=True)
    assert "weight_evidence_storage" not in limits_body
    limits_body["weight_evidence_storage"] = storage.model_dump(mode="json", by_alias=True)
    with pytest.raises(ValueError, match="versioned"):
        SuccessorWorkerExecutionLimits.model_validate(limits_body)
    limits_body["schema"] = "umi-successor-worker-execution-limits/2"
    limits = SuccessorWorkerExecutionLimits.model_validate(limits_body)
    options = dict(
        execution=execution,
        directive=rollover.directive,
        release_identity=case.release_identity,
        authorization_body=rollover.body,
        limits=limits,
    )
    _validate_worker_execution_bindings(**options)
    for ceiling in (
        case.limits,
        limits.model_copy(
            update={
                "weight_evidence_storage": storage.model_copy(update={"recovery_observations": 15})
            }
        ),
    ):
        with pytest.raises(ValueError, match="sealed installation"):
            _validate_worker_execution_bindings(**(options | {"limits": ceiling}))
