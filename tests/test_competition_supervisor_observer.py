from __future__ import annotations

import asyncio
import hashlib
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_supervisor_observer as observer_module
from umi.competition_chain_state import validate_owned_weight_observation
from umi.competition_supervisor import successor_continuation_bytes
from umi.competition_supervisor_observer import (
    OwnedSuccessorHostObserver,
    SuccessorHostObserverConfig,
    parse_successor_host_observer_config,
    successor_host_observer_config_sha256,
)
from umi.competition_supervisor_runtime import SuccessorWorkerSelection
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import ValidatorSupervisorError

from .test_competition_supervisor import _signed_continuation
from .test_competition_supervisor_adapters import adapter_case as adapter_case
from .test_competition_supervisor_adapters import chain as chain
from .test_competition_supervisor_adapters import chain_config as chain_config
from .test_competition_supervisor_adapters import package_case as package_case
from .test_competition_supervisor_adapters import package_limits as package_limits
from .test_competition_supervisor_adapters import policy as policy
from .test_competition_supervisor_adapters import release_identity as release_identity
from .test_competition_supervisor_adapters import replay_limits as replay_limits
from .test_competition_supervisor_adapters import successor_case as successor_case
from .test_competition_supervisor_adapters import successor_chain as successor_chain
from .test_competition_supervisor_adapters import successor_release as successor_release
from .test_competition_supervisor_adapters import v3_predecessor as v3_predecessor
from .test_competition_supervisor_adapters import weight_case as weight_case
from .test_competition_supervisor_adapters import worker_capacity as worker_capacity


@pytest.fixture
def observer_case(adapter_case, monkeypatch):
    case = adapter_case
    case.select("competition_weights")
    initial = SuccessorHostObserverConfig(
        schema="umi-successor-host-observer-config/1",
        policy=case.item.policy,
        chain=case.item.config,
    )
    case.installation.observer_config = initial

    def validate_installation(value):
        if value is not case.installation or not value.valid:
            raise ValueError("fixture installed capability rejected")

    monkeypatch.setattr(
        observer_module, "validate_authenticated_successor_installation", validate_installation
    )
    case.events, case.providers = [], []
    case.fail_start = case.fail_capture = False
    case.capture_entered = case.capture_release = None

    class Provider:
        # Explicit process/network fixture. The underlying storage proofs and
        # returned owned capability use the real pinned collector fixture.
        def __init__(self, config, selected_policy):
            self.config, self.policy = config, selected_policy
            self.closed = False
            case.providers.append(self)
            case.events.append(("construct", digest(config), digest(selected_policy)))

        async def start(self):
            case.events.append(("start",))
            if case.fail_start:
                raise ValueError("fixture startup failed")

        async def wait_weights_ready(self, hotkey, recipients):
            case.events.append(("capture", hotkey, recipients))
            if case.capture_entered is not None:
                case.capture_entered.set()
                await case.capture_release.wait()
            if case.fail_capture:
                raise ValueError("fixture capture failed")
            provider = case.item.provider
            provider.config, provider.policy = self.config, self.policy
            case.item.finality.config, case.item.finality.policy = self.config, self.policy
            return await provider.collect_weights(hotkey, recipients)

        async def aclose(self):
            self.closed = True
            case.events.append(("close",))

    monkeypatch.setattr(observer_module, "FinalizedCompetitionWeightProvider", Provider)
    case.observer = OwnedSuccessorHostObserver(installation=case.installation)
    return case


async def test_initial_runtime_observation_needs_no_target_fetch(observer_case):
    case = observer_case
    observation = await case.observer.observe()
    validate_owned_weight_observation(observation)
    assert observation.validator_uid == 54 and observation.validator_permit
    assert observation.chain_config_sha256 == digest(case.installation.observer_config.chain)
    assert [event[0] for event in case.events] == ["construct", "start", "capture", "close"]
    assert case.events[2][2] == ()
    assert case.materializations == 0 and case.container.events == []


@pytest.mark.parametrize("different_history", [False, True])
async def test_long_retained_history_keeps_owned_observation_bound_to_runtime(
    observer_case, different_history
):
    case = observer_case
    case.select("competition_replay")
    anchor = case.selection.signed
    records = _signed_continuation(anchor)
    body = successor_continuation_bytes(anchor, records)
    selection = SuccessorWorkerSelection(records[-1], body)
    files = replace(case.files, current_directive_page_bytes=body)
    if different_history:
        files = replace(files, current_directive_page_bytes=case.files.current_directive_page_bytes)
        with pytest.raises(ValueError, match="retained history"):
            await case.observer.observe_for(selection, files)
        assert not case.events
    else:
        observation = await case.observer.observe_for(selection, files)
        validate_owned_weight_observation(observation)
        assert observation.validator_permit
        assert case.providers[-1].closed
    assert not case.materializations and not case.container.events


async def test_expired_initial_policy_does_not_gate_read_only_finality(observer_case):
    case = observer_case
    policy = case.item.policy.model_copy(update={"valid_from_block": 1, "valid_through_block": 100})
    chain = case.item.config.model_copy(update={"policy_sha256": digest(policy)})
    case.installation.observer_config = SuccessorHostObserverConfig(
        schema="umi-successor-host-observer-config/1", policy=policy, chain=chain
    )
    observer = OwnedSuccessorHostObserver(installation=case.installation)
    observation = await observer.observe()
    assert observation.block > policy.valid_through_block
    validate_owned_weight_observation(observation)


async def test_later_target_policy_does_not_require_initial_policy_equality(observer_case):
    case = observer_case
    initial_policy = case.item.policy.model_copy(update={"sequence": 77})
    initial_chain = case.item.config.model_copy(update={"policy_sha256": digest(initial_policy)})
    case.installation.observer_config = SuccessorHostObserverConfig(
        schema="umi-successor-host-observer-config/1", policy=initial_policy, chain=initial_chain
    )
    observer = OwnedSuccessorHostObserver(installation=case.installation)
    first = await observer.observe()
    target_config = case.item.config
    second = await observer.observe_for(case.selection, case.files)
    third = await observer.observe()
    assert first.chain_config_sha256 == third.chain_config_sha256 == digest(initial_chain)
    assert second.chain_config_sha256 == digest(target_config)
    assert first.chain_config_sha256 != second.chain_config_sha256
    assert case.events[6][2] == case.item.recipients
    assert all(provider.closed for provider in case.providers)


async def test_replay_observation_never_creates_weight_capability(observer_case):
    case = observer_case
    case.select("competition_replay")
    observed = await case.observer.observe_for(case.selection, case.files)
    validate_owned_weight_observation(observed)
    assert case.events[2][2] == ()
    assert case.files.authorization_bytes is None and case.materializations == 0


@pytest.mark.parametrize(
    "field", ["finality_binary", "proof_binary", "chain_spec", "state_directory"]
)
def test_initial_observer_rejects_expanded_paths(observer_case, field):
    initial = observer_case.installation.observer_config
    value = initial.model_copy(
        update={"chain": initial.chain.model_copy(update={field: "/tmp/arbitrary-host-file"})}
    )
    with pytest.raises(ValueError, match="fixed Linux"):
        parse_successor_host_observer_config(canonical_json_bytes(value))


def test_initial_observer_parser_and_digest_are_bounded_canonical(observer_case):
    initial = observer_case.installation.observer_config
    raw = canonical_json_bytes(initial)
    assert parse_successor_host_observer_config(raw) == initial
    assert successor_host_observer_config_sha256(initial) == hashlib.sha256(raw).hexdigest()
    for invalid in (b"", raw + b"\n", b"x" * (observer_module.MAX_HOST_OBSERVER_CONFIG_BYTES + 1)):
        with pytest.raises(ValueError):
            parse_successor_host_observer_config(invalid)


async def test_mutated_initial_or_invalid_installation_reject_before_network(observer_case):
    case = observer_case
    case.installation.observer_config = case.installation.observer_config.model_copy(
        update={"chain": case.item.config.model_copy(update={"collection_timeout_seconds": 16})}
    )
    with pytest.raises(ValueError, match="configuration changed"):
        await case.observer.observe()
    case.installation.valid = False
    with pytest.raises(ValueError, match="capability rejected"):
        await case.observer.observe()
    assert case.events == []


@pytest.mark.parametrize("target", ["authorization", "execution", "package", "head"])
async def test_invalid_target_rejected_before_owned_network(observer_case, target):
    case = observer_case
    if target == "authorization":
        files = replace(case.files, authorization_bytes=b"{}")
    elif target == "execution":
        files = replace(
            case.files, worker_execution_bytes=case.files.worker_execution_bytes + b"\n"
        )
    elif target == "package":
        files = replace(case.files, package_path=case.files.package_path.parent / "absent")
    else:
        files = replace(case.files, current_directive_page_bytes=b"{}")
    with pytest.raises((ValueError, OSError, ValidatorSupervisorError)):
        await case.observer.observe_for(case.selection, files)
    assert case.events == []


@pytest.mark.parametrize("failure", ["start", "capture", "cancel"])
async def test_owned_provider_closed_on_error_and_cancellation(observer_case, failure):
    case = observer_case
    if failure == "cancel":
        case.capture_entered, case.capture_release = asyncio.Event(), asyncio.Event()
        task = asyncio.create_task(case.observer.observe())
        await case.capture_entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        setattr(case, "fail_" + failure, True)
        with pytest.raises(ValueError, match="fixture"):
            await case.observer.observe()
    assert len(case.providers) == 1 and case.providers[0].closed


async def test_closed_observer_cannot_create_a_new_provider(observer_case):
    case = observer_case
    await case.observer.aclose()
    with pytest.raises(ValueError, match="closed"):
        await case.observer.observe()
    assert case.events == []


def test_caller_json_is_not_an_installed_capability(observer_case):
    with pytest.raises(ValueError, match="capability rejected"):
        OwnedSuccessorHostObserver(installation=SimpleNamespace(**vars(observer_case.installation)))
