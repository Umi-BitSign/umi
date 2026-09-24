from __future__ import annotations

import os
import shutil
import sqlite3
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_host_activation as host
from umi import competition_supervisor_adapters as adapters
from umi.competition_container import SuccessorContainerStatus
from umi.competition_host_activation import SuccessorWorkerExecutionLimits
from umi.competition_supervisor import (
    SuccessorSupervisorDirectivePage,
    successor_source_config_sha256,
)
from umi.competition_supervisor_runtime import SuccessorWorkerSelection
from umi.competition_weights import sign_competition_weight_authorization
from umi.competition_worker import CompetitionReplayWorker
from umi.competition_worker_cli import (
    WORKER_CHAIN_SPEC,
    WORKER_FINALITY_BINARY,
    WORKER_FINALITY_STATE_ROOT,
    WORKER_PROOF_BINARY,
    SuccessorWeightExecutionConfig,
    SuccessorWorkerExecutionConfig,
)
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import ValidatorSupervisorError

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_package import package_case as package_case
from .test_competition_package import package_limits as package_limits
from .test_competition_package import release_identity as release_identity
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_supervisor import (
    _consent,
    _directive,
    _signed,
    _signed_authorization_target,
    _signed_continuation,
    authority_wallets,
)
from .test_competition_supervisor import successor_case as successor_case
from .test_competition_supervisor import successor_chain as successor_chain
from .test_competition_supervisor import successor_release as successor_release
from .test_competition_supervisor import v3_predecessor as v3_predecessor
from .test_competition_weights import _advance, _run
from .test_competition_weights import weight_case as weight_case
from .test_competition_worker import _record_cutoff_conflict
from .test_competition_worker import worker_capacity as worker_capacity
from .test_open_competition import policy as policy


class Container:
    def __init__(self, config):
        self.config = config
        self.events = []
        self.current = SuccessorContainerStatus("absent")
        self.fail_stop = False

    def stage_release(self, path, target):
        self.events.append("stage_release")
        return SimpleNamespace(path=path, target=target)

    async def prepare_image(self, release):
        self.events.append("prepare_image")

    async def stop(self):
        self.events.append("stop")
        if self.fail_stop:
            raise ValueError("container still running")
        if self.current.phase == "running":
            self.current = replace(self.current, phase="failed", exit_code=137)
        return self.current

    async def status(self):
        return self.current

    async def remove_stopped(self):
        assert self.current.phase != "running"
        self.events.append("remove")
        self.current = SuccessorContainerStatus("absent")

    async def launch(self, activation, release):
        self.events.append("launch")
        self.current = SuccessorContainerStatus("running", "ab" * 32, activation.directive_sha256)
        return self.current


@pytest.fixture
def adapter_case(
    weight_case, successor_case, worker_capacity, package_limits, tmp_path, monkeypatch, request
):
    item, source = weight_case, successor_case
    config = source.predecessor.config.model_copy(
        update={
            "validator_hotkey": item.hotkey,
            "state_root": str(tmp_path / "host-state"),
            "worker_state_root": str(tmp_path / "worker-state"),
        }
    )
    Path(config.state_root).mkdir(mode=0o700)
    predecessor = SimpleNamespace(**vars(source.predecessor))
    predecessor.config = config
    consent = _consent(predecessor)
    ceiling = SuccessorWorkerExecutionLimits(
        schema="umi-successor-worker-execution-limits/1",
        replay_capacity_ceiling=worker_capacity,
        maximum_weight_attempts=20,
        maximum_weight_evidence_bytes=50_000_000,
        maximum_submission_timeout_seconds=30,
    )
    installation = SimpleNamespace(
        config=config,
        config_sha256=successor_source_config_sha256(config),
        receipt_sha256="dd" * 32,
        checkpoint_sha256=item.context.checkpoint_sha256,
        checkpoint_finalized_block=160,
        operator_consent=consent,
        worker_execution_limits=ceiling,
        valid=True,
    )

    def verify_installation(value):
        if value is not installation or not value.valid:
            raise ValueError("fixture installation invalid")

    # Explicit host/OS fixture ports. Package, signed directive/authority,
    # replay, owned proof collector and private durable journals remain real.
    monkeypatch.setattr(
        adapters, "validate_authenticated_successor_installation", verify_installation
    )
    monkeypatch.setattr(host, "validate_authenticated_successor_installation", verify_installation)
    container = Container(config)
    activation = SimpleNamespace()

    def validate_activation(value, **bindings):
        if value is not activation or getattr(value, "invalid", False):
            raise ValueError("fixture activation invalid")
        assert value.directive_sha256 == bindings["directive_sha256"]
        assert value.package_sha256 == bindings["package_sha256"]

    monkeypatch.setattr(
        adapters, "validate_authenticated_successor_activation", validate_activation
    )
    result = SimpleNamespace(
        item=item,
        source=source,
        predecessor=predecessor,
        config=config,
        consent=consent,
        installation=installation,
        container=container,
        activation=activation,
        files=None,
        materializations=0,
    )

    class Materializer:
        async def fetch(self, selection):
            return result.files

        async def retire_redundant(self, retained):
            assert result.adapter._stopped
            assert all(
                item.phase in adapters._TERMINAL for item in result.adapter._attempts().values()
            )
            result.retired_records = set(retained)
            return 0

        async def activate(self, selection, files, *, owned_observation):
            assert result.adapter._stopped and result.adapter._recovered is not None
            assert selection.directive_sha256 in result.adapter._records()
            result.materializations += 1
            activation.directive_sha256 = selection.directive_sha256
            activation.package_sha256 = selection.signed.directive.replay_package.package_sha256
            activation.worker_execution_config = SuccessorWorkerExecutionConfig.model_validate_json(
                files.worker_execution_bytes
            )
            return activation

    class Observer:
        async def observe(self):
            return await item.provider.collect_weights(item.hotkey, item.recipients)

        async def observe_for(self, selection, files):
            return await item.provider.collect_weights(item.hotkey, item.recipients)

    result.materializer, result.observer = Materializer(), Observer()
    result.adapter = adapters.ProductionSuccessorRuntimeAdapter(
        installation=installation,
        materializer=result.materializer,
        observer=result.observer,
        container=container,
        limits=adapters.SuccessorAdapterLimits(*getattr(request, "param", (20, 4 * 1024**2))),
    )
    new_weight_root = Path(config.worker_state_root) / "competition" / "weights"
    new_weight_root.parent.mkdir(parents=True, mode=0o700)
    item.worker.state_root.rename(new_weight_root)
    item.worker.state_root = new_weight_root
    item.worker.path = new_weight_root / "competition-weights.sqlite3"
    item.worker.lock_path = new_weight_root / "competition-weights.lock"
    item.worker.replay_worker = CompetitionReplayWorker(
        new_weight_root.parent / "replay",
        package_limits=package_limits,
        capacity=worker_capacity,
    )
    result.select = lambda mode="competition_replay": _select(result, mode, worker_capacity)
    result.select()
    return result


def _select(case, mode, capacity):
    item = case.item
    authorization = None
    if mode == "competition_weights":
        config = item.provider.config.model_copy(
            update={
                "target_triple": "x86_64-unknown-linux-gnu",
                "finality_pin": item.provider.config.finality_pin.model_copy(
                    update={
                        "bootstrap_block_number": 100,
                        "release_sha256_by_target": {"x86_64-unknown-linux-gnu": "a2" * 32},
                    }
                ),
                "finality_binary": str(WORKER_FINALITY_BINARY),
                "proof_binary": str(WORKER_PROOF_BINARY),
                "chain_spec": str(WORKER_CHAIN_SPEC),
                "state_directory": str(WORKER_FINALITY_STATE_ROOT),
            }
        )
        # Owned synthetic proof adapter only; no binary or live path is opened.
        item.provider.config = item.config = config
        body = item.body.model_copy(
            update={
                "predecessor_directive_sha256": case.predecessor.state.accepted_directive_sha256,
                "required_finality_verifier_sha256_by_target": {
                    "x86_64-unknown-linux-gnu": "a2" * 32
                },
                "required_storage_proof_verifier_sha256_by_target": {
                    "x86_64-unknown-linux-gnu": "a3" * 32
                },
            }
        )
        item.body = body
        item.signed = authorization = sign_competition_weight_authorization(
            body, authority_wallets()[0]
        )
        item.context.authority_hotkeys = (authorization.signature.hotkey,)
        weights = SuccessorWeightExecutionConfig.model_construct(
            maximum_attempts=20,
            maximum_evidence_bytes=50_000_000,
            submission_timeout_seconds=10,
            chain=config,
        )
    else:
        weights = None
    chain = case.source.chain.model_copy(update={"chain_pin": item.config.chain_pin})
    changes = (
        {}
        if authorization is None
        else {"chain_authorization": _signed_authorization_target(authorization)}
    )
    directive = _directive(
        case.predecessor,
        case.source.target,
        case.source.release,
        chain,
        case.consent,
        mode=mode,
        issued_at_block=160,
        valid_from_block=170,
        valid_through_block=190,
        **changes,
    )
    selection = SuccessorWorkerSelection(_signed(directive))
    page = SuccessorSupervisorDirectivePage(
        schema="umi-validator-supervisor-directive-page/4",
        after_version=4,
        after_sequence=selection.signed.directive.sequence,
        after_directive_sha256=selection.directive_sha256,
        directives=[],
        more=False,
        head=selection.signed,
    )
    execution = SuccessorWorkerExecutionConfig.model_construct(
        schema_="umi-successor-worker-execution-config/1",
        replay_capacity=capacity,
        weights=weights,
    )
    case.selection = selection
    case.files = adapters.SuccessorArtifactFiles(
        release_bundle_path=case.item.case.path.parent / "inert-bundle",
        package_path=case.item.case.path,
        worker_execution_bytes=canonical_json_bytes(execution),
        current_directive_page_bytes=canonical_json_bytes(page),
        authorization_bytes=None if authorization is None else canonical_json_bytes(authorization),
    )
    return selection


async def _stopped(case):
    await case.adapter.stop_worker()
    observation = await case.item.provider.collect_weights(case.item.hotkey, case.item.recipients)
    await case.adapter.recover_stopped_transactions(observation)
    return observation


def _retain_weight_renewals(case, count=12, *, bad_authorization=False):
    from umi.competition_supervisor import successor_continuation_bytes

    case.select("competition_weights")
    anchor = case.selection.signed
    case.adapter._retain(case.adapter._verify(case.selection, case.files))
    previous, records = anchor, []
    for index in range(count):
        body = case.item.body.model_copy(update={
            "authorization_id": f"{index + 500:064x}",
            "predecessor_directive_sha256": previous.directive_sha256,
        })
        authorization = sign_competition_weight_authorization(body, authority_wallets()[0])
        directive = previous.directive.model_copy(update={
            "sequence": previous.directive.sequence + 1,
            "predecessor_version": 4,
            "previous_directive_sha256": previous.directive_sha256,
            "chain_authorization": _signed_authorization_target(authorization),
        })
        signed = _signed(directive)
        records.append(signed)
        files = replace(
            case.files,
            current_directive_page_bytes=successor_continuation_bytes(anchor, records),
            authorization_bytes=canonical_json_bytes(
                case.item.signed if bad_authorization and index == count - 1 else authorization
            ),
        )
        case.adapter._retain(SimpleNamespace(
            selection=SuccessorWorkerSelection(signed), files=files,
        ))
        previous = signed


async def test_recovery_replays_unchanged_package_once_but_checks_every_renewal(
    adapter_case, monkeypatch
):
    from umi import competition_recovery_packages as recovery

    case = adapter_case
    _retain_weight_renewals(case)
    replay, authorize = recovery.load_bound_successor_replay_package, (
        adapters.verify_bound_successor_chain_authorization
    )
    calls = {"replay": 0, "authorize": 0}

    def replayed(*args, **kwargs):
        calls["replay"] += 1
        return replay(*args, **kwargs)

    def authorized(*args, **kwargs):
        calls["authorize"] += 1
        return authorize(*args, **kwargs)

    monkeypatch.setattr(recovery, "load_bound_successor_replay_package", replayed)
    monkeypatch.setattr(adapters, "verify_bound_successor_chain_authorization", authorized)
    await _stopped(case)
    assert calls == {"replay": 1, "authorize": 13}
    assert case.adapter._recovered is not None
    await _stopped(case)
    assert calls == {"replay": 2, "authorize": 26}  # No reuse across audits.
    assert not case.item.encoded


async def test_recovery_reused_package_does_not_accept_wrong_renewal_authority(
    adapter_case,
):
    case = adapter_case
    _retain_weight_renewals(case, count=2, bad_authorization=True)
    with pytest.raises(
        ValidatorSupervisorError, match="successor_chain_authorization_digest_mismatch"
    ):
        await _stopped(case)
    assert case.adapter._recovered is None
    assert not case.item.encoded


async def test_recovery_reuse_detects_sealed_package_change_between_authorizations(
    adapter_case, monkeypatch
):
    case = adapter_case
    _retain_weight_renewals(case, count=2)
    original = adapters.verify_bound_successor_chain_authorization
    touched = []

    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        if not touched:
            path = case.files.package_path / "manifest.json"
            raw = path.read_bytes()
            path.chmod(0o600)
            path.write_bytes(raw)  # Even equal bytes cannot hide a new file identity.
            path.chmod(0o400)
            touched.append(True)
        return result

    monkeypatch.setattr(adapters, "verify_bound_successor_chain_authorization", changed)
    with pytest.raises(ValueError, match="package changed"):
        await _stopped(case)
    assert case.adapter._recovered is None
    assert not case.item.encoded


@pytest.mark.parametrize("changed", ["target", "release"])
def test_recovery_reuse_rechecks_changed_binding_with_the_same_package_path(adapter_case, changed):
    from umi.competition_recovery_packages import RecoveryPackageReplay

    case = adapter_case
    cache = RecoveryPackageReplay()
    directive = case.selection.signed.directive
    cache.load(case.files.package_path, directive=directive)
    if changed == "target":
        directive = directive.model_copy(update={
            "replay_package": directive.replay_package.model_copy(update={
                "projection_sha256": "ff" * 32,
            }),
        })
    else:
        directive = directive.model_copy(update={
            "release": directive.release.model_copy(update={
                "umi_git_revision": "f" * 40,
                "replay_release_identity": directive.release.replay_release_identity.model_copy(
                    update={"umi_revision": "f" * 40}
                ),
            }),
        })
    with pytest.raises((ValueError, ValidatorSupervisorError)):
        cache.load(case.files.package_path, directive=directive)


async def test_staging_full_replay_does_not_select_current_or_load_image(adapter_case):
    case = adapter_case
    await case.adapter.stage(case.selection)
    assert case.materializations == 0
    assert case.container.events == ["stage_release"]
    assert case.adapter._records() == {}


@pytest.mark.parametrize("slow_phase", ["preflight", "image_prepare", "after_recovery"])
async def test_slow_work_refreshes_proof_without_extending_old_authority(
    adapter_case, monkeypatch, slow_phase
):
    from umi.competition_chain_state import validate_owned_weight_observation

    case = adapter_case
    await case.adapter.stage(case.selection)
    observation = await _stopped(case)
    monotonic_ns = time.monotonic_ns
    shift = [0]
    monkeypatch.setattr(time, "monotonic_ns", lambda: monotonic_ns() + shift[0])
    if slow_phase == "preflight":
        replay = case.adapter._replay

        def slow_replay(prepared):
            value = replay(prepared)
            shift[0] = 121_000_000_000
            return value

        monkeypatch.setattr(case.adapter, "_replay", slow_replay)
        await case.adapter.preflight(case.selection, observation)
    elif slow_phase == "image_prepare":
        prepare = case.container.prepare_image

        async def slow_prepare(release):
            await prepare(release)
            shift[0] = 121_000_000_000

        monkeypatch.setattr(case.container, "prepare_image", slow_prepare)
        await case.adapter.start_replay(case.selection)
        assert case.container.current.phase == "running"
    else:
        shift[0] = 121_000_000_000
        await case.adapter.start_replay(case.selection)
        assert case.container.current.phase == "running"
    with pytest.raises(ValueError, match="owned proof"):
        validate_owned_weight_observation(observation)
    fresh = case.adapter._preflight[case.selection.directive_sha256]
    validate_owned_weight_observation(fresh)
    assert fresh.captured_monotonic_ns > observation.expires_monotonic_ns


async def test_preflight_rejects_already_expired_floor(adapter_case, monkeypatch):
    case = adapter_case
    observation = await case.item.provider.collect_weights(case.item.hotkey, case.item.recipients)
    monkeypatch.setattr(time, "monotonic_ns", lambda: observation.expires_monotonic_ns + 1)
    with pytest.raises(ValueError, match="owned proof"):
        await case.adapter.preflight(case.selection, observation)
    assert case.container.events == []


async def test_many_renewals_evict_only_reconstructible_memory(adapter_case):
    case = adapter_case
    original = case.selection
    await case.adapter.stage(original)
    case.container.current = SuccessorContainerStatus(
        "running", "ab" * 32, original.directive_sha256
    )
    prior = original
    for sequence in range(3, 10):
        directive = prior.signed.directive.model_copy(
            update={
                "sequence": sequence,
                "predecessor_version": 4,
                "previous_directive_sha256": prior.directive_sha256,
            }
        )
        selected = SuccessorWorkerSelection(_signed(directive))
        page = SuccessorSupervisorDirectivePage(
            schema="umi-validator-supervisor-directive-page/4",
            after_version=4,
            after_sequence=prior.signed.directive.sequence,
            after_directive_sha256=prior.directive_sha256,
            directives=[selected.signed],
            more=False,
            head=selected.signed,
        )
        case.files = replace(case.files, current_directive_page_bytes=canonical_json_bytes(page))
        await case.adapter.stage(selected)
        observed = await case.item.provider.collect_weights(case.item.hotkey, case.item.recipients)
        await case.adapter.preflight(selected, observed)
        assert len(case.adapter._staged) <= 4 and len(case.adapter._preflight) <= 4
        assert original.directive_sha256 in case.adapter._staged
        prior = selected
    assert case.adapter._records() == {} and not case.materializations


async def test_replay_start_requires_stop_recovery_and_retains_intent_before_launch(adapter_case):
    case = adapter_case
    await case.adapter.stage(case.selection)
    with pytest.raises(ValueError, match="stopped recovery"):
        await case.adapter.start_replay(case.selection)
    await _stopped(case)
    await case.adapter.start_replay(case.selection)
    assert case.materializations == 1
    assert case.container.events[-3:] == ["prepare_image", "remove", "launch"]
    assert await case.adapter.worker_is_healthy(case.selection)


@pytest.mark.parametrize("fault", ["missing_receipt", "corrupt_receipt", "held_receipt"])
async def test_exit_zero_requires_matching_durable_worker_receipt(adapter_case, fault):
    case = adapter_case
    await case.adapter.stage(case.selection)
    case.container.current = SuccessorContainerStatus(
        "completed", "ab" * 32, case.selection.directive_sha256, 0
    )
    if fault != "missing_receipt":
        replay = case.item.worker.replay_worker
        replay.run(
            case.files.package_path,
            expected_package_sha256=case.item.package.package_sha256,
            expected_policy_sha256=case.item.package.manifest.policy_sha256,
            observed_release=case.item.context.release_identity,
        )
        if fault == "corrupt_receipt":
            with sqlite3.connect(replay.path) as db:
                db.execute("UPDATE runs SET receipt=?", (b"{}",))
        else:
            with sqlite3.connect(replay.path) as db:
                db.execute("UPDATE runs SET status='rejected'")
    with pytest.raises(ValueError):
        await case.adapter.worker_is_healthy(case.selection)


async def test_valid_replay_receipt_can_complete_without_restarting(adapter_case):
    case = adapter_case
    await case.adapter.stage(case.selection)
    case.item.worker.replay_worker.run(
        case.files.package_path,
        expected_package_sha256=case.item.package.package_sha256,
        expected_policy_sha256=case.item.package.manifest.policy_sha256,
        observed_release=case.item.context.release_identity,
    )
    case.container.current = SuccessorContainerStatus(
        "completed", "ab" * 32, case.selection.directive_sha256, 0
    )
    assert await case.adapter.worker_is_healthy(case.selection)


async def test_changed_artifact_control_rejects_before_current_selection(adapter_case):
    case = adapter_case
    case.files = replace(case.files, worker_execution_bytes=b"{}")
    with pytest.raises(ValueError):
        await case.adapter.stage(case.selection)
    assert not case.container.events and not case.materializations


async def test_publication_conflict_blocks_launch(adapter_case, replay_limits):
    case = adapter_case
    await case.adapter.stage(case.selection)
    worker = CompetitionReplayWorker(
        case.adapter.root / "preflight-replay",
        package_limits=case.selection.signed.directive.replay_package.limits,
        capacity=case.installation.worker_execution_limits.replay_capacity_ceiling,
    )
    _record_cutoff_conflict(worker, case.item.case, case.item.policy, replay_limits)
    with pytest.raises(ValueError, match="held"):
        await case.adapter.preflight(
            case.selection,
            await case.item.provider.collect_weights(case.item.hotkey, case.item.recipients),
        )
    assert case.materializations == 0


async def test_failed_stop_cannot_mint_recovery_or_start(adapter_case):
    case = adapter_case
    case.container.fail_stop = True
    with pytest.raises(ValueError):
        await case.adapter.stop_worker()
    with pytest.raises(ValueError, match="confirmed stopped"):
        await case.adapter.recover_stopped_transactions(
            await case.item.provider.collect_weights(case.item.hotkey, case.item.recipients)
        )


@pytest.mark.parametrize("fault", ["unknown", "expired", "consumed_other_row", "applied"])
async def test_wallet_free_stopped_recovery_uses_real_attempt_and_owned_proof(adapter_case, fault):
    case = adapter_case
    case.select("competition_weights")
    await case.adapter.stage(case.selection)
    case.adapter._retain(case.adapter._staged[case.selection.directive_sha256])
    case.item.behavior = "disconnect"
    with pytest.raises(ConnectionError):
        await _run(case.item)
    if fault == "expired":
        _advance(case.item, 187)
    elif fault == "consumed_other_row":
        _advance(case.item, 187, nonce=5)
    elif fault == "applied":
        _advance(case.item, 171, applied=True)
    await case.adapter.stop_worker()
    observation = await case.item.provider.collect_weights(case.item.hotkey, case.item.recipients)
    if fault in {"unknown", "consumed_other_row"}:
        with pytest.raises(ValueError, match="unknown"):
            await case.adapter.recover_stopped_transactions(observation)
        assert case.adapter._recovered is None
    else:
        await case.adapter.recover_stopped_transactions(observation)
        assert case.adapter._recovered is not None
        expected = "expired_unconsumed_nonce" if fault == "expired" else "recovered_effect"
        assert next(iter(case.adapter._attempts().values())).phase == expected
    assert len(case.item.encoded) == 1


@pytest.mark.parametrize(
    ("history", "slow_phase"),
    [
        ("empty", "attempt_audit"),
        ("terminal", "target"),
        ("pending", "target"),
        ("pending", "worker_package"),
        ("pending", "worker_journal"),
        ("pending", "attempt_audit"),
    ],
)
async def test_stopped_recovery_refreshes_after_slow_retained_history(
    adapter_case, monkeypatch, history, slow_phase
):
    from umi import competition_weights as weights
    from umi.competition_chain_state import validate_owned_weight_observation

    case = adapter_case
    if history != "empty":
        case.select("competition_weights")
        await case.adapter.stage(case.selection)
        case.adapter._retain(case.adapter._staged[case.selection.directive_sha256])
        if history == "pending":
            case.item.behavior = "disconnect"
            with pytest.raises(ConnectionError):
                await _run(case.item)
            _advance(case.item, 187)
        else:
            await _run(case.item)
    await case.adapter.stop_worker()
    initial = await case.item.provider.collect_weights(case.item.hotkey, case.item.recipients)
    now = time.monotonic_ns
    elapsed = [0]
    monkeypatch.setattr(time, "monotonic_ns", lambda: now() + elapsed[0])
    target, name = {
        "attempt_audit": (case.adapter, "_attempts"),
        "target": (case.adapter, "_verify"),
        "worker_package": (weights, "load_competition_package"),
        "worker_journal": (weights.CompetitionWeightWorker, "_audit_evidence"),
    }[slow_phase]
    original = getattr(target, name)

    def slow(*args, **kwargs):
        result = original(*args, **kwargs)
        elapsed[0] += 121 * 10**9
        return result

    monkeypatch.setattr(target, name, slow)
    await case.adapter.recover_stopped_transactions(initial)
    with pytest.raises(ValueError, match="owned proof"):
        validate_owned_weight_observation(initial)
    current = case.adapter._recovered
    validate_owned_weight_observation(current)
    assert current.captured_monotonic_ns > initial.expires_monotonic_ns
    assert len(case.item.encoded) == (0 if history == "empty" else 1)
    if history == "pending":
        assert next(iter(case.adapter._attempts().values())).phase == "expired_unconsumed_nonce"


async def test_stopped_recovery_rejects_an_expired_entry_proof(adapter_case, monkeypatch):
    case = adapter_case
    await case.adapter.stop_worker()
    initial = await case.item.provider.collect_weights(case.item.hotkey, case.item.recipients)
    monkeypatch.setattr(time, "monotonic_ns", lambda: initial.expires_monotonic_ns + 1)
    monkeypatch.setattr(case.adapter, "_records", lambda: pytest.fail("audited an expired floor"))
    with pytest.raises(ValueError, match="owned proof"):
        await case.adapter.recover_stopped_transactions(initial)
    assert case.adapter._recovered is None and not case.item.encoded


@pytest.mark.parametrize(
    "fault", ["registry", "package", "journal", "running", "expired", "forged", "rollback"]
)
async def test_stopped_adapter_rechecks_inputs_after_final_capture(
    adapter_case, monkeypatch, fault
):
    case = adapter_case
    await case.adapter.stage(case.selection)
    case.adapter._retain(case.adapter._staged[case.selection.directive_sha256])
    await case.adapter.stop_worker()
    initial = await case.item.provider.collect_weights(case.item.hotkey, case.item.recipients)
    observe = case.observer.observe

    async def changed():
        if fault == "rollback":
            _advance(case.item, initial.block - 1)
        current = await observe()
        if fault in {"registry", "package", "journal"}:
            path = {
                "registry": case.adapter.path,
                "package": case.files.package_path / "manifest.json",
                "journal": case.item.worker.path,
            }[fault]
            info, raw = path.stat(), path.read_bytes()
            path.chmod(0o600)
            path.write_bytes(raw)
            path.chmod(0o400 if fault == "package" else 0o600)
            os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
        elif fault == "running":
            case.container.current = SuccessorContainerStatus(
                "running", "ab" * 32, case.selection.directive_sha256
            )
        elif fault == "expired":
            monkeypatch.setattr(time, "monotonic_ns", lambda: current.expires_monotonic_ns + 1)
        elif fault == "forged":
            current = replace(current, validator_nonce=current.validator_nonce + 1)
        return current

    monkeypatch.setattr(case.observer, "observe", changed)
    with pytest.raises(ValueError):
        await case.adapter.recover_stopped_transactions(initial)
    assert case.adapter._recovered is None and not case.item.encoded


async def test_unretained_attempt_blocks_all_new_runs(adapter_case):
    case = adapter_case
    await _run(case.item)
    with pytest.raises(ValueError, match="retained signed authority"):
        await _stopped(case)


async def test_weight_start_needs_separate_authority_and_fixed_mode(adapter_case):
    case = adapter_case
    case.select("competition_weights")
    await case.adapter.stage(case.selection)
    await _stopped(case)
    with pytest.raises(ValueError, match="fixed profile"):
        await case.adapter.start_replay(case.selection)
    await case.adapter.start_weights(case.selection)
    assert case.container.events[-1] == "launch" and case.materializations == 1
    assert not case.item.encoded  # The host adapter has no signing or broadcast code.


async def test_recovered_failed_worker_is_not_restarted_or_resubmitted(adapter_case):
    case = adapter_case
    case.select("competition_weights")
    await case.adapter.stage(case.selection)
    case.adapter._retain(case.adapter._staged[case.selection.directive_sha256])
    case.item.behavior = "disconnect"
    with pytest.raises(ConnectionError):
        await _run(case.item)
    case.container.current = SuccessorContainerStatus(
        "failed", "ab" * 32, case.selection.directive_sha256, 2
    )
    _advance(case.item, 171, applied=True)
    await _stopped(case)
    await case.adapter.start_weights(case.selection)
    assert await case.adapter.worker_is_healthy(case.selection)
    assert "launch" not in case.container.events and not case.materializations
    assert len(case.item.encoded) == 1


async def test_proven_mortality_unblocks_a_distinct_signed_authority(adapter_case):
    case = adapter_case
    case.select("competition_weights")
    await case.adapter.stage(case.selection)
    case.adapter._retain(case.adapter._staged[case.selection.directive_sha256])
    case.item.behavior = "disconnect"
    with pytest.raises(ConnectionError):
        await _run(case.item)
    _advance(case.item, 187)
    await _stopped(case)
    old = case.item.body.authorization_id
    body = case.item.body.model_copy(
        update={
            "authorization_id": "99" * 32,
            "signed_at_block": 187,
            "valid_from_block": 187,
            "mortality_period": 4,
        }
    )
    signed = sign_competition_weight_authorization(body, authority_wallets()[0])

    class SecondTransport:
        # Exact SDK encoding is covered by the weight transport suite. This
        # fixture proves journal/replay/authority progression after mortality.
        def encode(self, call, authority, observation, signer, *, projection):
            assert authority.authorization_id != old and observation.validator_nonce == 4
            return b"fixture-second-authority"

        async def submit(self, encoded, signer):
            case.item.encoded.append(encoded)
            _advance(case.item, 188, applied=True)

    result = await _run(case.item, authorization=signed, transport=SecondTransport())
    assert result.status == "recovered_effect" and result.exact_row_currently_applied
    assert len(case.item.encoded) == 2
    attempts = case.adapter._attempts()
    assert attempts[old].phase == "expired_unconsumed_nonce"
    assert attempts[body.authorization_id].phase == "recovered_effect"


async def test_lost_weight_journal_after_launch_identity_is_not_empty_state(adapter_case):
    case = adapter_case
    case.select("competition_weights")
    await case.adapter.stage(case.selection)
    case.adapter._retain(case.adapter._staged[case.selection.directive_sha256])
    original = case.item.worker.state_root
    retained = original.with_name("preserved-lost-weights")
    original.rename(retained)
    with pytest.raises(ValueError, match="lost its journal"):
        await _stopped(case)
    assert retained.exists() and not original.exists()


async def test_forged_activation_cannot_launch(adapter_case):
    case = adapter_case
    await case.adapter.stage(case.selection)
    await _stopped(case)
    case.activation.invalid = True
    with pytest.raises(ValueError, match="activation invalid"):
        await case.adapter.start_replay(case.selection)
    assert "launch" not in case.container.events


async def test_registry_corruption_blocks_recovery_without_erasing_history(adapter_case):
    case = adapter_case
    await case.adapter.stage(case.selection)
    case.adapter._retain(case.adapter._staged[case.selection.directive_sha256])
    with sqlite3.connect(case.adapter.path) as db:
        db.execute("UPDATE runs SET body=?", (b"{}",))
    with pytest.raises(ValueError, match="corrupt"):
        await _stopped(case)


async def test_identical_refetch_path_does_not_rewrite_recovery_history(adapter_case):
    case = adapter_case
    await case.adapter.stage(case.selection)
    first = case.adapter._staged[case.selection.directive_sha256]
    case.adapter._retain(first)
    copied = case.files.package_path.with_name("immutable-refetch")
    shutil.copytree(case.files.package_path, copied)
    try:
        case.files = replace(case.files, package_path=copied)
        await case.adapter.stage(case.selection)
        case.adapter._retain(case.adapter._staged[case.selection.directive_sha256])
        assert (
            case.adapter._records()[case.selection.directive_sha256][1].package_path
            == first.files.package_path
        )
    finally:
        copied.chmod(0o700)


def test_shared_registry_history_is_lossless_lazy_and_keeps_legacy_runs(adapter_case, monkeypatch):
    """Storage-only test; this does not simulate successful worker execution."""
    import hashlib
    import json

    from umi.competition_supervisor import successor_continuation_bytes

    case = adapter_case
    anchor = case.selection.signed
    # Keep an old inline-format record unchanged beside the new references.
    old = adapters._record(case.selection, case.files)
    with sqlite3.connect(case.adapter.path) as db:
        db.execute(
            "INSERT INTO runs VALUES (?,?,?)",
            (anchor.directive_sha256, old, hashlib.sha256(old).hexdigest()),
        )
    records = _signed_continuation(anchor, 12)
    bodies = []
    for count, signed in enumerate(records, 1):
        body = successor_continuation_bytes(anchor, records[:count])
        bodies.append(body)
        files = replace(case.files, current_directive_page_bytes=body)
        case.adapter._retain(
            SimpleNamespace(selection=SuccessorWorkerSelection(signed), files=files)
        )
    with sqlite3.connect(case.adapter.path) as db:
        assert db.execute("SELECT COUNT(*) FROM history_nodes").fetchone() == (12,)
        assert db.execute(
            "SELECT body FROM runs WHERE id=?", (anchor.directive_sha256,)
        ).fetchone() == (old,)
        rows = db.execute(
            "SELECT body FROM runs WHERE id!=?", (anchor.directive_sha256,)
        ).fetchall()
        assert all(json.loads(raw)["schema"] == "umi-successor-adapter-run/2" for (raw,) in rows)
    calls = []
    restore = adapters.restore_history

    def observe_restore(*args, **kwargs):
        calls.append(True)
        return restore(*args, **kwargs)

    monkeypatch.setattr(adapters, "restore_history", observe_restore)
    snapshot = case.adapter._records()
    assert len(snapshot) == 13 and calls == []
    assert snapshot[records[-1].directive_sha256][1].current_directive_page_bytes == bodies[-1]
    assert calls == [True]
    assert snapshot[anchor.directive_sha256][1] == case.files


def test_shared_registry_counts_nodes_in_budget_and_rolls_back_failed_retention(
    adapter_case, monkeypatch
):
    from umi.competition_supervisor import successor_continuation_bytes

    case = adapter_case
    records = _signed_continuation(case.selection.signed, 2)
    body = successor_continuation_bytes(case.selection.signed, records)
    prepared = SimpleNamespace(
        selection=SuccessorWorkerSelection(records[-1]),
        files=replace(case.files, current_directive_page_bytes=body),
    )
    # A failed run insertion must roll back the preceding node insertions too.
    with sqlite3.connect(case.adapter.path) as db:
        db.execute(
            "CREATE TRIGGER refuse_run BEFORE INSERT ON runs "
            "BEGIN SELECT RAISE(ABORT, 'injected'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="injected"):
        case.adapter._retain(prepared)
    with sqlite3.connect(case.adapter.path) as db:
        assert db.execute("SELECT COUNT(*) FROM runs").fetchone() == (0,)
        assert db.execute("SELECT COUNT(*) FROM history_nodes").fetchone() == (0,)
        db.execute("DROP TRIGGER refuse_run")
    case.adapter._retain(prepared)
    with sqlite3.connect(case.adapter.path) as db:
        size = db.execute("SELECT SUM(length(body)) FROM runs").fetchone()[0]
        size += db.execute("SELECT SUM(length(body)) FROM history_nodes").fetchone()[0]
    assert case.adapter._records().used_bytes == size
    # Exercise a smaller read ceiling without changing any durable record.
    monkeypatch.setattr(
        case.adapter, "limits", replace(case.adapter.limits, maximum_registry_bytes=size - 1)
    )
    with pytest.raises(adapters.SuccessorAdapterError, match="capacity"):
        case.adapter._records()


def test_shared_registry_checks_missing_nodes_and_head_before_history_expansion(
    adapter_case, monkeypatch
):
    import hashlib
    import json

    from umi.competition_supervisor import successor_continuation_bytes

    case = adapter_case
    records = _signed_continuation(case.selection.signed, 2)
    body = successor_continuation_bytes(case.selection.signed, records)
    case.adapter._retain(
        SimpleNamespace(
            selection=SuccessorWorkerSelection(records[-1]),
            files=replace(case.files, current_directive_page_bytes=body),
        )
    )
    monkeypatch.setattr(
        adapters, "restore_history", lambda *args, **kwargs: pytest.fail("expanded full history")
    )
    assert len(case.adapter._records()) == 1
    with sqlite3.connect(case.adapter.path) as db:
        node = db.execute("SELECT id,body FROM history_nodes ORDER BY id LIMIT 1").fetchone()
        run = db.execute("SELECT id,body,sha FROM runs").fetchone()
        db.execute("DELETE FROM history_nodes WHERE id=?", (node[0],))
    with pytest.raises(ValueError, match="missing"):
        case.adapter._records()
    with sqlite3.connect(case.adapter.path) as db:
        db.execute("INSERT INTO history_nodes VALUES (?,?)", node)
    assert len(case.adapter._records()) == 1
    for field, value in (("count", 1), ("after_directive_sha256", "00" * 32)):
        altered = json.loads(run[1])
        altered["current_directive_page"][field] = value
        raw = canonical_json_bytes(altered)
        with sqlite3.connect(case.adapter.path) as db:
            db.execute(
                "UPDATE runs SET body=?,sha=? WHERE id=?",
                (raw, hashlib.sha256(raw).hexdigest(), run[0]),
            )
        with pytest.raises(ValueError, match="prefix or head"):
            case.adapter._records()
    with sqlite3.connect(case.adapter.path) as db:
        db.execute("UPDATE runs SET body=?,sha=? WHERE id=?", (run[1], run[2], run[0]))
    assert len(case.adapter._records()) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("maximum_retained_runs", True),
        ("maximum_registry_bytes", float("nan")),
        ("maximum_staged_selections", 1.5),
        ("maximum_staged_selections", 1),
    ],
)
def test_adapter_limits_reject_noninteger_unbounded_values(field, value):
    values = dict(maximum_retained_runs=20, maximum_registry_bytes=1024**2)
    values[field] = value
    with pytest.raises(ValueError):
        adapters.SuccessorAdapterLimits(**values)


def test_artifact_controls_require_execution_bytes(adapter_case):
    with pytest.raises(ValueError):
        replace(adapter_case.files, worker_execution_bytes=None)


async def test_slow_start_verification_precedes_fresh_weight_proof(adapter_case, monkeypatch):
    from umi.competition_chain_state import validate_owned_weight_observation

    case = adapter_case
    case.select("competition_weights")
    await case.adapter.stage(case.selection)
    initial = await _stopped(case)
    original_verify = case.adapter._verify
    monotonic_ns = time.monotonic_ns
    shift = [0]
    monkeypatch.setattr(time, "monotonic_ns", lambda: monotonic_ns() + shift[0])

    def slow_verify(*args, **kwargs):
        result = original_verify(*args, **kwargs)
        shift[0] += 121_000_000_000
        return result

    monkeypatch.setattr(case.adapter, "_verify", slow_verify)
    await case.adapter.start_weights(case.selection)
    assert case.container.current.phase == "running"
    assert case.container.events.count("launch") == 1
    assert case.container.current.directive_sha256 == case.selection.directive_sha256
    with pytest.raises(ValueError, match="owned proof"):
        validate_owned_weight_observation(initial)
    fresh = case.adapter._preflight[case.selection.directive_sha256]
    validate_owned_weight_observation(fresh)
    assert fresh.captured_monotonic_ns > initial.expires_monotonic_ns
