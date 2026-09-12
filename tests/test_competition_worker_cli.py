from __future__ import annotations

import socket
import subprocess
from types import SimpleNamespace

import pytest

from umi import competition_worker_cli as cli
from umi.competition_weights import signed_competition_weight_authorization_digest
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_package import package_case as package_case
from .test_competition_package import package_limits as package_limits
from .test_competition_package import release_identity as release_identity
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_weights import weight_case as weight_case
from .test_competition_worker import worker_capacity as worker_capacity
from .test_open_competition import policy as policy
from .test_open_competition import wallet


@pytest.fixture
def inputs(package_case, package_limits, release_identity, worker_capacity, tmp_path, monkeypatch):
    target = SimpleNamespace(
        limits=package_limits,
        package_sha256=package_case.prepared.package_sha256,
        policy_sha256=package_case.prepared.policy_sha256,
    )
    value = SimpleNamespace(
        profile="competition_replay",
        directive=SimpleNamespace(mode="competition_replay", replay_package=target),
        directive_sha256="55" * 32,
        config_sha256="66" * 32,
        validator_hotkey=wallet("Eve").hotkey.ss58_address,
        release_identity=release_identity,
        worker_execution_config=cli.SuccessorWorkerExecutionConfig(
            schema="umi-successor-worker-execution-config/1",
            replay_capacity=worker_capacity,
            weights=None,
        ),
        authority_hotkeys=(wallet("Ferdie").hotkey.ss58_address,),
        authorization=None,
        rechecks=0,
    )

    def recheck():
        value.rechecks += 1

    value.recheck = recheck
    monkeypatch.setattr(cli, "_load_inputs", lambda: value)
    monkeypatch.setattr(cli.sys, "platform", "linux")
    monkeypatch.setattr(cli, "WORKER_PACKAGE_ROOT", package_case.path)
    monkeypatch.setattr(cli, "WORKER_REPLAY_STATE_ROOT", tmp_path / "cli-replay")
    monkeypatch.setattr(cli, "WORKER_WEIGHTS_STATE_ROOT", tmp_path / "cli-weights")
    return value


def denied(*args, **kwargs):
    pytest.fail("wallet-free replay touched a chain, wallet, subprocess or network port")


async def test_replay_profile_runs_real_replay_without_wallet_or_network(inputs, monkeypatch):
    monkeypatch.setattr(cli, "_load_hotkey", denied)
    monkeypatch.setattr(cli, "_activate", denied)
    monkeypatch.setattr(cli, "FinalizedCompetitionWeightProvider", denied)
    monkeypatch.setattr(cli, "BittensorCompetitionWeightTransport", denied)
    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    result = await cli.run_worker("competition_replay")
    assert result.receipt.status == "replayed_no_weight"
    assert not result.chain_submission_authorized and inputs.rechecks >= 3


async def test_cli_profile_cannot_expand_authenticated_mode(inputs, monkeypatch):
    monkeypatch.setattr(cli, "_load_hotkey", denied)
    monkeypatch.setattr(cli, "FinalizedCompetitionWeightProvider", denied)
    with pytest.raises(ValueError, match="authenticated profile"):
        await cli.run_worker("competition_weights")


async def test_replay_rejects_even_attached_unused_authorization(inputs, monkeypatch):
    inputs.authorization = {"must_not": "expand authority"}
    monkeypatch.setattr(cli, "_load_hotkey", denied)
    with pytest.raises(ValueError, match="cannot carry"):
        await cli.run_worker("competition_replay")


async def test_replay_rechecks_immutable_inputs_after_execution(inputs):
    def changed():
        inputs.rechecks += 1
        if inputs.rechecks == 3:
            raise ValueError("fixture mounted history changed")

    inputs.recheck = changed
    with pytest.raises(ValueError, match="mounted history changed"):
        await cli.run_worker("competition_replay")


@pytest.fixture
def weight_inputs(inputs, weight_case, chain_config, monkeypatch):
    config = chain_config.model_copy(
        update={
            "target_triple": "x86_64-unknown-linux-gnu",
            "finality_pin": chain_config.finality_pin.model_copy(
                update={"release_sha256_by_target": {"x86_64-unknown-linux-gnu": "a2" * 32}}
            ),
            "finality_binary": str(cli.WORKER_FINALITY_BINARY),
            "proof_binary": str(cli.WORKER_PROOF_BINARY),
            "chain_spec": str(cli.WORKER_CHAIN_SPEC),
            "state_directory": str(cli.WORKER_FINALITY_STATE_ROOT),
        }
    )
    inputs.profile = inputs.directive.mode = "competition_weights"
    inputs.directive.chain = SimpleNamespace(chain_pin=config.chain_pin)
    inputs.authorization = weight_case.signed
    inputs.worker_execution_config = cli.SuccessorWorkerExecutionConfig(
        schema="umi-successor-worker-execution-config/1",
        replay_capacity=inputs.worker_execution_config.replay_capacity,
        weights=cli.SuccessorWeightExecutionConfig(
            maximum_attempts=20,
            maximum_evidence_bytes=50_000_000,
            submission_timeout_seconds=10,
            chain=config,
        ),
    )
    events = []
    observation = SimpleNamespace(block=170)
    activation = SimpleNamespace(
        directive_sha256=inputs.directive_sha256,
        config_sha256=inputs.config_sha256,
        validator_hotkey=inputs.validator_hotkey,
        package_sha256=inputs.directive.replay_package.package_sha256,
        authorization_sha256=signed_competition_weight_authorization_digest(inputs.authorization),
    )

    class ChainPort:
        def __init__(self, supplied, policy):
            assert supplied == config
            events.append("observer-created")

        async def start(self):
            events.append("observer-started")

        async def wait_weights_ready(self, hotkey, recipients):
            assert hotkey == inputs.validator_hotkey and len(recipients) == 2
            events.append("owned-observation")
            return observation

        async def aclose(self):
            events.append("observer-closed")

    class WorkerPort:
        def __init__(self, path, **kwargs):
            assert path == cli.WORKER_WEIGHTS_STATE_ROOT
            assert kwargs["maximum_attempts"] == 20

        async def run(self, path, **kwargs):
            assert path == cli.WORKER_PACKAGE_ROOT
            assert kwargs["activation"] is activation
            assert kwargs["authorization"] is inputs.authorization
            assert kwargs["wallet"] is signer
            events.append("worker")
            return SimpleNamespace(exact_row_currently_applied=True)

    signer = wallet("Eve").hotkey

    def activate(verified_inputs, observed):
        assert verified_inputs is inputs
        assert observed is observation and events[-1] == "owned-observation"
        events.append("activation")
        return activation

    def hotkey(value):
        assert value == inputs.validator_hotkey and events[-1] == "activation"
        events.append("hotkey")
        return signer

    # Explicit orchestration ports only. Full proof, journal and exact SDK
    # submission scenarios are exercised in test_competition_weights.py.
    monkeypatch.setattr(cli, "FinalizedCompetitionWeightProvider", ChainPort)
    monkeypatch.setattr(cli, "CompetitionWeightWorker", WorkerPort)
    monkeypatch.setattr(cli, "validate_owned_weight_observation", lambda value: None)
    monkeypatch.setattr(cli, "validate_weight_preflight", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli, "_activate", activate)
    monkeypatch.setattr(cli, "_load_hotkey", hotkey)
    monkeypatch.setattr(cli, "BittensorCompetitionWeightTransport", lambda **kwargs: object())
    return SimpleNamespace(inputs=inputs, events=events, activation=activation, config=config)


async def test_weights_require_owned_observation_before_activation_and_hotkey(weight_inputs):
    result = await cli.run_worker("competition_weights")
    assert result.exact_row_currently_applied
    assert weight_inputs.events == [
        "observer-created",
        "observer-started",
        "owned-observation",
        "activation",
        "hotkey",
        "worker",
        "observer-closed",
    ]


async def test_weights_close_observer_and_do_not_open_key_on_activation_swap(weight_inputs):
    weight_inputs.activation.directive_sha256 = "99" * 32
    with pytest.raises(ValueError, match="changed during observer startup"):
        await cli.run_worker("competition_weights")
    assert weight_inputs.events[-1] == "observer-closed"
    assert "hotkey" not in weight_inputs.events and "worker" not in weight_inputs.events


async def test_weights_close_observer_when_hotkey_cannot_be_loaded(weight_inputs, monkeypatch):
    def failed(*args):
        raise ValueError("fixture unavailable key")

    monkeypatch.setattr(cli, "_load_hotkey", failed)
    with pytest.raises(ValueError, match="unavailable key"):
        await cli.run_worker("competition_weights")
    assert weight_inputs.events[-1] == "observer-closed" and "worker" not in weight_inputs.events


@pytest.mark.parametrize(
    "field", ["finality_binary", "proof_binary", "chain_spec", "state_directory"]
)
def test_execution_config_rejects_arbitrary_absolute_paths(weight_inputs, field):
    value = weight_inputs.inputs.worker_execution_config.model_dump(mode="json", by_alias=True)
    value["weights"]["chain"][field] = "/etc/an-unapproved-file"
    with pytest.raises(ValueError, match="paths or platform"):
        cli.SuccessorWorkerExecutionConfig.model_validate(value)


def test_cli_has_no_path_command_or_context_provider_flags(capsys):
    for option in ("--wallet", "--package", "--config", "--context-provider", "--rpc", "--exec"):
        with pytest.raises(SystemExit) as error:
            cli.run_cli(["competition_weights", option, "unused"])
        assert error.value.code == 2
    capsys.readouterr()


def test_cli_does_not_print_exception_or_secret_material(monkeypatch, capsys):
    async def failed(*args):
        raise ValueError("fixture-private-key-never-print")

    monkeypatch.setattr(cli, "run_worker", failed)
    assert cli.run_cli(["competition_weights"]) == 2
    output = capsys.readouterr()
    assert output.out == "" and "fixture-private-key" not in output.err


def test_hotkey_loader_reads_only_fixed_file_without_prompt(tmp_path, monkeypatch):
    from bittensor.keyfiles import serialized_keypair_to_keyfile_data

    target = tmp_path / "hotkey"
    target.write_bytes(bytes(serialized_keypair_to_keyfile_data(wallet("Eve").hotkey)))
    target.chmod(0o400)
    monkeypatch.setattr(cli, "WORKER_HOTKEY_FILE", target)
    signer = cli._load_hotkey(wallet("Eve").hotkey.ss58_address)
    assert signer.ss58_address == wallet("Eve").hotkey.ss58_address
    with pytest.raises(ValueError, match="installed identity"):
        cli._load_hotkey(wallet("Alice").hotkey.ss58_address)
    target.chmod(0o600)


def test_hotkey_loader_refuses_encryption_without_prompt(tmp_path, monkeypatch):
    import bittensor.keyfiles as keyfiles

    target = tmp_path / "hotkey"
    target.write_bytes(b"fixture-encrypted")
    target.chmod(0o400)
    monkeypatch.setattr(cli, "WORKER_HOTKEY_FILE", target)
    monkeypatch.setattr(keyfiles, "keyfile_data_is_encrypted", lambda body: True)
    monkeypatch.setattr(keyfiles, "deserialize_keypair_from_keyfile_data", denied)
    with pytest.raises(ValueError, match="unlocked by its operator"):
        cli._load_hotkey(wallet("Eve").hotkey.ss58_address)
    target.chmod(0o600)


def test_execution_configuration_requires_explicit_capacities(worker_capacity):
    with pytest.raises(ValueError):
        cli.SuccessorWorkerExecutionConfig.model_validate_json(
            canonical_json_bytes(
                {"schema": "umi-successor-worker-execution-config/1", "weights": None}
            )
        )
