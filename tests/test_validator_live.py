from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import umi.validator_live as validator_live_module
from umi.encoding import account_id32
from umi.mirror_readiness import VerifiedLiveMirrorReadiness
from umi.policy import ScoringPolicy, scoring_policy_hash
from umi.protocol import PROTOCOL_VERSION, canonical_json_bytes
from umi.validator_live import (
    FORBIDDEN_WEIGHT_CAPABILITY_NAMES,
    LIVE_SHADOW_MODE,
    LIVE_VALIDATOR_CONFIG_SCHEMA,
    WEIGHT_DISABLED_HOLD_ID,
    LiveRuntimeValidation,
    LiveValidatorConfig,
    LiveValidatorConfigError,
    LiveValidatorPaths,
    LiveValidatorPorts,
    LiveValidatorPrimer,
    LiveValidatorProductionDependencies,
    LiveValidatorRuntimeError,
    PrivateBtauthTranscriptFactory,
    PrivateValidatorManifestSigner,
    ProductionPoolRevealContext,
    build_live_validator,
    build_production_pool_reveal_ports,
    load_live_policy,
    load_live_validator_config,
    run_cli,
)
from umi.validator_live_ports import (
    DEFAULT_DELIVERY_ISSUANCE_PATH,
    DEFAULT_MIRROR_INDEX_PATH,
    MIRROR_DISCOVERY_SCHEMA,
    DurablePoolMirrorSource,
    FinalizedRevealAuditReleaseAdapter,
    MirrorDiscoveryRule,
    QuicknetRevealPulseAdapter,
    QuicknetSelectionPulseAdapter,
    TLERevealDecryptAdapter,
)
from umi.validator_state import (
    STAGE_ORDER,
    PauseScope,
    ValidatorControlPlane,
    WindowPlan,
    WindowStage,
)

from .factories import dev_wallet
from .test_policy import _live_shadow_policy_data, make_policy

TARGET = "aarch64-unknown-linux-musl"


@pytest.fixture(autouse=True)
def _supported_linux_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(validator_live_module.sys, "platform", "linux")
    monkeypatch.setattr(validator_live_module.platform, "machine", lambda: "aarch64")


def _policy() -> ScoringPolicy:
    data = _live_shadow_policy_data()
    pins = data["implementation_pins"]
    for name in ("storage_proof_verifier", "finality_verifier"):
        releases = pins[name]["release_sha256_by_target"]
        releases[TARGET] = releases.pop("aarch64-apple-darwin")
    return ScoringPolicy.model_validate(data)


def _config(tmp_path: Path, policy: ScoringPolicy) -> LiveValidatorConfig:
    policy_path = tmp_path / "policy.json"
    policy_path.write_bytes(canonical_json_bytes(policy))
    return LiveValidatorConfig(
        schema=LIVE_VALIDATOR_CONFIG_SCHEMA,
        protocol=PROTOCOL_VERSION,
        mode=LIVE_SHADOW_MODE,
        translation_weights_active=False,
        policy_path=str(policy_path),
        scoring_policy_sha256=scoring_policy_hash(policy),
        conformance_release_root=str((tmp_path / "release").resolve()),
        state_root=str(tmp_path / "state"),
        validator_hotkey=policy.validator_registry[0].validator_hotkey,
        target_triple=TARGET,
        storage_proof_verifier_binary=str(tmp_path / "proof-verifier"),
        finality_verifier_binary=str(tmp_path / "finality-verifier"),
        finality_chain_spec_path=str(tmp_path / "chain-spec.json"),
        initial_minimum_finalized_block=policy.activation_block - 1,
        signature_scheme="sr25519",
        umi_revision="test-revision",
        maximum_transport_concurrency=8,
        transport_timeout_seconds=2.0,
        stage_port_timeout_seconds=2.0,
        maximum_anchor_advances=4,
        poll_seconds=0.1,
    )


def _runtime_validation(policy: ScoringPolicy) -> LiveRuntimeValidation:
    proof = policy.implementation_pins.storage_proof_verifier
    finality = policy.implementation_pins.finality_verifier
    assert proof is not None and finality is not None
    return LiveRuntimeValidation(
        target_triple=TARGET,
        storage_proof_verifier_sha256=proof.release_sha256_by_target[TARGET],
        finality_verifier_sha256=finality.release_sha256_by_target[TARGET],
        finality_chain_spec_sha256=finality.chain_spec_sha256,
    )


class _Finality:
    def __init__(self, chain_calls: list[str]) -> None:
        self.chain_calls = chain_calls

    async def finalized_head_height(self):
        self.chain_calls.append("finalized_head_height")
        return 0

    async def verified_block_at(self, _height):
        self.chain_calls.append("verified_block_at")
        return None

    def close(self) -> None:
        return None


class _Readiness:
    def __init__(self, chain_calls: list[str]) -> None:
        self.chain_calls = chain_calls

    async def verified_reveal_and_spent(self, _previous):
        self.chain_calls.append("verified_reveal_and_spent")
        return None


class _Anchor:
    def __init__(self, chain_calls: list[str]) -> None:
        self.chain_calls = chain_calls

    def __call__(self, *_args, **_kwargs):
        self.chain_calls.append("anchor_ports")
        raise AssertionError("anchor port must not run during startup")

    async def verify_anchor(self, *_args, **_kwargs):
        self.chain_calls.append("verify_anchor")
        raise AssertionError("anchor verifier must not run during startup")


class _NoWeightCapture:
    def __init__(self, validator_hotkey: str, chain_calls: list[str]) -> None:
        self.validator_account_id32 = account_id32(validator_hotkey)
        self.chain_calls = chain_calls

    async def capture(self, **_kwargs):
        self.chain_calls.append("no_weight_capture")
        raise AssertionError("no-weight capture must not run during startup")


class _BundleVerifier:
    def __init__(self, chain_calls: list[str]) -> None:
        self.chain_calls = chain_calls

    async def verify(self, _root):
        self.chain_calls.append("bundle_verify")
        raise AssertionError("bundle verifier must not run during startup")


def _ports(
    policy: ScoringPolicy,
    chain_calls: list[str],
    *,
    finalized_blocks=None,
) -> LiveValidatorPorts:
    async def unused(*_args, **_kwargs):
        chain_calls.append("stage_port")
        raise AssertionError("stage port must not run during startup")

    def close_resolver(**_kwargs):
        chain_calls.append("weight_close_resolver")
        raise AssertionError("weight close resolver must not run during startup")

    def manifest_signer(_digest):
        chain_calls.append("manifest_signer")
        raise AssertionError("manifest signer must not run during startup")

    return LiveValidatorPorts(
        finalized_blocks=finalized_blocks or _Finality(chain_calls),
        prior_readiness=_Readiness(chain_calls),
        pool_source=unused,
        closing_snapshot=unused,
        selection_pulse=unused,
        delivery_issuance=unused,
        prepared_assignments=unused,
        transcript_plan=unused,
        observe=unused,
        anchor_ports=_Anchor(chain_calls),
        transcript_audit_release=unused,
        transport=unused,
        prepare_retry=unused,
        reveal_pulse=unused,
        decrypt=unused,
        reveal_audit_release=unused,
        weight_schedule=unused,
        weight_snapshot=unused,
        no_weight_capture=_NoWeightCapture(
            policy.validator_registry[0].validator_hotkey,
            chain_calls,
        ),
        weight_close_resolver=close_resolver,
        bundle_verifier=_BundleVerifier(chain_calls),
        incident_bundle_verifier=_BundleVerifier(chain_calls),
        manifest_signer=manifest_signer,
    )


def test_factory_wires_all_seven_stages_without_any_chain_or_signing_action(
    tmp_path: Path,
) -> None:
    policy = _policy()
    config = _config(tmp_path, policy)
    chain_calls: list[str] = []

    runtime = build_live_validator(
        config=config,
        policy=policy,
        runtime_validation=_runtime_validation(policy),
        port_factory=lambda _context: _ports(policy, chain_calls),
    )
    try:
        assert runtime.configured_stages == STAGE_ORDER
        assert chain_calls == []
        observer_owners = {
            runtime._engine._adapters[stage]._receipt_observer_hook.__self__
            for stage in STAGE_ORDER
        }
        assert len(observer_owners) == 1
        assert FORBIDDEN_WEIGHT_CAPABILITY_NAMES.isdisjoint(LiveValidatorPorts.__dataclass_fields__)
        assert FORBIDDEN_WEIGHT_CAPABILITY_NAMES.isdisjoint(
            LiveValidatorProductionDependencies.__dataclass_fields__
        )
        assert not any(hasattr(runtime, name) for name in FORBIDDEN_WEIGHT_CAPABILITY_NAMES)
        weight_control = next(
            item
            for item in runtime.recovery_state().controls
            if item.scope is PauseScope.WEIGHT_SUBMISSION
        )
        assert weight_control.paused
        assert [hold.hold_id for hold in weight_control.active_holds] == [WEIGHT_DISABLED_HOLD_ID]
    finally:
        runtime.close()
    assert chain_calls == []


def test_factory_rejects_a_traversable_preexisting_state_root(tmp_path: Path) -> None:
    policy = _policy()
    config = _config(tmp_path, policy)
    state_root = Path(config.state_root)
    state_root.mkdir(mode=0o755)
    state_root.chmod(0o755)

    with pytest.raises(LiveValidatorConfigError) as raised:
        build_live_validator(
            config=config,
            policy=policy,
            runtime_validation=_runtime_validation(policy),
            port_factory=lambda _context: _ports(policy, []),
        )
    assert raised.value.reason_code == "state_root_unsafe"


def test_factory_restart_recovers_controls_and_does_not_replay_ports(tmp_path: Path) -> None:
    policy = _policy()
    config = _config(tmp_path, policy)
    chain_calls: list[str] = []
    contexts = []

    def factory(context):
        contexts.append(context)
        return _ports(policy, chain_calls)

    first = build_live_validator(
        config=config,
        policy=policy,
        runtime_validation=_runtime_validation(policy),
        port_factory=factory,
    )
    contexts[-1].control_plane.pause(
        PauseScope.WINDOW_INTAKE,
        reason_code="operator_hold",
        operation_id="test-live-restart-hold",
    )
    first.close()

    restarted = build_live_validator(
        config=config,
        policy=policy,
        runtime_validation=_runtime_validation(policy),
        port_factory=factory,
    )
    try:
        controls = {item.scope: item for item in restarted.recovery_state().controls}
        assert controls[PauseScope.WINDOW_INTAKE].paused
        assert [item.hold_id for item in controls[PauseScope.WINDOW_INTAKE].active_holds] == [
            "test-live-restart-hold"
        ]
        assert [item.hold_id for item in controls[PauseScope.WEIGHT_SUBMISSION].active_holds] == [
            WEIGHT_DISABLED_HOLD_ID
        ]
        assert restarted.configured_stages == STAGE_ORDER
        assert chain_calls == []
    finally:
        restarted.close()


@pytest.mark.asyncio
async def test_runtime_supervises_finality_without_touching_stage_ports(tmp_path: Path) -> None:
    policy = _policy()
    config = _config(tmp_path, policy)
    chain_calls: list[str] = []
    started = asyncio.Event()
    contexts = []

    class RunningFinality(_Finality):
        async def run(self, stop_event: asyncio.Event) -> None:
            started.set()
            await stop_event.wait()

    finality = RunningFinality(chain_calls)

    def factory(context):
        contexts.append(context)
        return _ports(policy, chain_calls, finalized_blocks=finality)

    runtime = build_live_validator(
        config=config,
        policy=policy,
        runtime_validation=_runtime_validation(policy),
        port_factory=factory,
    )
    contexts[0].control_plane.pause(
        PauseScope.WINDOW_INTAKE,
        reason_code="test_supervisor_hold",
        operation_id="test-live-supervisor-hold",
    )
    stop = asyncio.Event()
    task = asyncio.create_task(runtime.run(stop, poll_seconds=0.01))
    try:
        await asyncio.wait_for(started.wait(), timeout=1)
        stop.set()
        await asyncio.wait_for(task, timeout=1)
        assert chain_calls == []
    finally:
        stop.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        runtime.close()


def test_config_and_policy_loaders_require_canonical_fully_pinned_bytes(
    tmp_path: Path,
) -> None:
    live = _policy()
    config = _config(tmp_path, live)
    config_path = tmp_path / "validator-live.json"
    config_path.write_bytes(canonical_json_bytes(config))

    loaded = load_live_validator_config(config_path)
    assert loaded == config
    assert load_live_policy(loaded) == live

    config_path.write_bytes(canonical_json_bytes(config) + b"\n")
    with pytest.raises(LiveValidatorConfigError) as noncanonical:
        load_live_validator_config(config_path)
    assert noncanonical.value.reason_code == "config_noncanonical"

    local = make_policy(activation_block=live.activation_block)
    local_path = tmp_path / "local-policy.json"
    local_path.write_bytes(canonical_json_bytes(local))
    local_config = config.model_copy(
        update={
            "policy_path": str(local_path),
            "scoring_policy_sha256": scoring_policy_hash(local),
            "validator_hotkey": local.validator_registry[0].validator_hotkey,
        }
    )
    with pytest.raises(LiveValidatorConfigError) as unpinned:
        load_live_policy(local_config)
    assert unpinned.value.reason_code == "policy_not_fully_pinned"

    active_data = live.model_dump(mode="json", by_alias=True)
    active_data["translation_weights_active"] = True
    active_bytes = canonical_json_bytes(active_data)
    active_path = tmp_path / "active-policy.json"
    active_path.write_bytes(active_bytes)
    active_config = config.model_copy(
        update={
            "policy_path": str(active_path),
            "scoring_policy_sha256": hashlib.sha256(active_bytes).hexdigest(),
        }
    )
    with pytest.raises(LiveValidatorConfigError) as active:
        load_live_policy(active_config)
    assert active.value.reason_code == "policy_invalid"


def test_live_validator_rejects_darwin_even_when_a_policy_names_it(tmp_path: Path) -> None:
    policy = _policy()
    darwin = "aarch64-apple-darwin"
    values = policy.model_dump(mode="json", by_alias=True)
    pins = values["implementation_pins"]
    for name in ("storage_proof_verifier", "finality_verifier"):
        releases = pins[name]["release_sha256_by_target"]
        releases[darwin] = releases[TARGET]
    darwin_policy = ScoringPolicy.model_validate(values)
    policy_path = tmp_path / "darwin-policy.json"
    policy_path.write_bytes(canonical_json_bytes(darwin_policy))
    config = _config(tmp_path, darwin_policy).model_copy(
        update={
            "policy_path": str(policy_path),
            "scoring_policy_sha256": scoring_policy_hash(darwin_policy),
            "target_triple": darwin,
        }
    )

    with pytest.raises(LiveValidatorConfigError) as raised:
        load_live_policy(config)
    assert raised.value.reason_code == "live_validator_target_unsupported"


def test_live_validator_rejects_linux_target_on_a_darwin_host(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy()
    config = _config(tmp_path, policy)
    monkeypatch.setattr(validator_live_module.sys, "platform", "darwin")
    monkeypatch.setattr(validator_live_module.platform, "machine", lambda: "arm64")

    with pytest.raises(LiveValidatorConfigError) as raised:
        load_live_policy(config)
    assert raised.value.reason_code == "live_validator_host_unsupported"


def test_startup_loader_rejects_symlinks_and_group_writable_inputs(tmp_path: Path) -> None:
    policy = _policy()
    config = _config(tmp_path, policy)
    config_path = tmp_path / "validator-live.json"
    config_path.write_bytes(canonical_json_bytes(config))

    link = tmp_path / "validator-live-link.json"
    link.symlink_to(config_path)
    with pytest.raises(LiveValidatorConfigError) as symlinked:
        load_live_validator_config(link)
    assert symlinked.value.reason_code == "config_file_unsafe"

    config_path.chmod(0o620)
    with pytest.raises(LiveValidatorConfigError) as writable:
        load_live_validator_config(config_path)
    assert writable.value.reason_code == "config_file_unsafe"


def test_cli_missing_capability_document_is_complete(tmp_path: Path, capsys) -> None:
    policy = _policy()
    config = _config(tmp_path, policy)
    config_path = tmp_path / "validator-live.json"
    config_path.write_bytes(canonical_json_bytes(config))

    assert run_cli(["--config", str(config_path), "--check"]) == 2
    captured = capsys.readouterr()
    document = json.loads(captured.err)
    assert captured.out == ""
    assert document["reason_code"] == "missing_live_capabilities"
    assert document["translation_weights_active"] is False
    assert document["weight_submission_capability"] is False
    assert document["missing_capabilities"] == list(
        LiveValidatorProductionDependencies().missing_capability_codes()
    )
    assert "missing_weight_schedule_capture" not in document["missing_capabilities"]
    assert "missing_weight_snapshot_capture" not in document["missing_capabilities"]
    assert "missing_transcript_ports_factory" in document["missing_capabilities"]
    assert "missing_validator_capacity_set" in document["missing_capabilities"]
    assert "missing_transcript_observation" not in document["missing_capabilities"]
    assert "missing_transcript_transport" not in document["missing_capabilities"]
    assert "missing_pool_source" not in document["missing_capabilities"]
    assert "missing_selection_pulse" not in document["missing_capabilities"]
    assert "missing_reveal_pulse" not in document["missing_capabilities"]
    assert "missing_reveal_decrypt" not in document["missing_capabilities"]
    assert "missing_reveal_audit_release" not in document["missing_capabilities"]
    assert "missing_mirror_discovery_rule_bytes" in document["missing_capabilities"]
    assert "missing_mirror_request_headers" in document["missing_capabilities"]
    assert "missing_mirror_readiness" in document["missing_capabilities"]
    assert "missing_reveal_audit_release_boundary" not in document["missing_capabilities"]
    assert "missing_prepared_assignments" not in document["missing_capabilities"]
    assert all("submit_weights" not in value for value in document["missing_capabilities"])


class _PrimeFinality:
    def __init__(self, *, head: int) -> None:
        self.head = head
        self.run_count = 0
        self.closed = False

    async def run(self, stop_event: asyncio.Event) -> None:
        self.run_count += 1
        await stop_event.wait()

    def persisted_head(self) -> object:
        return object()

    async def finalized_head_height(self) -> int:
        return self.head

    def close(self) -> None:
        self.closed = True


class _PrimePlanSource:
    def __init__(self, plan: WindowPlan) -> None:
        self.plan = plan
        self.calls = 0

    async def next_plan(self) -> WindowPlan:
        self.calls += 1
        return self.plan


def _prime_plan(policy: ScoringPolicy) -> WindowPlan:
    return WindowPlan(
        window_id="61" * 32,
        window_index=0,
        scoring_policy_hash=scoring_policy_hash(policy),
        announcement_block=10,
        proposal_close_block=20,
        closing_block=30,
        selection_round=40,
        issue_close_round=50,
        response_close_round=60,
        reveal_round=70,
    )


@pytest.mark.asyncio
async def test_primer_records_one_pool_plan_and_never_runs_a_stage(tmp_path: Path) -> None:
    policy = _policy()
    plan = _prime_plan(policy)
    finality = _PrimeFinality(head=plan.proposal_close_block - 1)
    source = _PrimePlanSource(plan)
    control = ValidatorControlPlane(tmp_path / "control.sqlite3")
    protocol_state = SimpleNamespace(closed=False)

    def close_protocol_state() -> None:
        protocol_state.closed = True

    protocol_state.close = close_protocol_state
    primer = LiveValidatorPrimer(
        control_plane=control,
        plan_source=source,  # type: ignore[arg-type]
        finality=finality,  # type: ignore[arg-type]
        protocol_state=protocol_state,  # type: ignore[arg-type]
        paths=LiveValidatorPaths.below(tmp_path / "state"),
        policy_hash=scoring_policy_hash(policy),
    )

    record, created = await primer.prime(asyncio.Event(), poll_seconds=0.05)
    assert created is True
    assert record is not None
    assert record.plan == plan
    assert record.stage is WindowStage.POOL_AND_SELECTION
    assert control.recovery_state().pending_work is not None
    assert control.recovery_state().pending_work.completed_evidence == ()
    assert source.calls == 1
    assert finality.run_count == 1

    same, created_again = await primer.prime(asyncio.Event(), poll_seconds=0.05)
    assert same == record
    assert created_again is False
    assert source.calls == 1
    assert finality.run_count == 2

    primer.close()
    assert protocol_state.closed is True
    assert finality.closed is True
    with pytest.raises(LiveValidatorRuntimeError) as closed:
        await primer.prime(asyncio.Event(), poll_seconds=0.05)
    assert closed.value.reason_code == "primer_closed"


@pytest.mark.asyncio
async def test_primer_rejects_a_closed_proposal_interval_without_recording_window(
    tmp_path: Path,
) -> None:
    policy = _policy()
    plan = _prime_plan(policy)
    finality = _PrimeFinality(head=plan.proposal_close_block)
    source = _PrimePlanSource(plan)
    control = ValidatorControlPlane(tmp_path / "control.sqlite3")
    primer = LiveValidatorPrimer(
        control_plane=control,
        plan_source=source,  # type: ignore[arg-type]
        finality=finality,  # type: ignore[arg-type]
        protocol_state=SimpleNamespace(close=lambda: None),  # type: ignore[arg-type]
        paths=LiveValidatorPaths.below(tmp_path / "state"),
        policy_hash=scoring_policy_hash(policy),
    )

    with pytest.raises(LiveValidatorRuntimeError) as closed:
        await primer.prime(asyncio.Event(), poll_seconds=0.05)
    assert closed.value.reason_code == "prime_proposal_interval_closed"
    assert control.list_windows() == ()
    assert finality.run_count == 1


@pytest.mark.asyncio
async def test_primer_does_not_report_a_stale_existing_pool_window_as_usable(
    tmp_path: Path,
) -> None:
    policy = _policy()
    plan = _prime_plan(policy)
    finality = _PrimeFinality(head=plan.proposal_close_block)
    source = _PrimePlanSource(plan)
    control = ValidatorControlPlane(tmp_path / "control.sqlite3")
    control.start_window(
        plan,
        operation_id="test-prime-existing-window",
        metadata={"source": "verified_window_plan"},
    )
    primer = LiveValidatorPrimer(
        control_plane=control,
        plan_source=source,  # type: ignore[arg-type]
        finality=finality,  # type: ignore[arg-type]
        protocol_state=SimpleNamespace(close=lambda: None),  # type: ignore[arg-type]
        paths=LiveValidatorPaths.below(tmp_path / "state"),
        policy_hash=scoring_policy_hash(policy),
    )

    with pytest.raises(LiveValidatorRuntimeError) as closed:
        await primer.prime(asyncio.Event(), poll_seconds=0.05)
    assert closed.value.reason_code == "prime_proposal_interval_closed"
    assert source.calls == 0


def test_prime_cli_uses_only_live_config_and_reports_the_exact_record(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    policy = _policy()
    plan = _prime_plan(policy)
    record = SimpleNamespace(plan=plan, stage=WindowStage.POOL_AND_SELECTION)
    config = SimpleNamespace(poll_seconds=0.05)
    primer = SimpleNamespace(policy_hash=scoring_policy_hash(policy), closed=False)

    def close_primer() -> None:
        primer.closed = True

    primer.close = close_primer
    monkeypatch.setattr("umi.validator_live.load_live_validator_config", lambda _path: config)
    monkeypatch.setattr(
        "umi.validator_live.build_live_validator_primer",
        lambda *, config: primer,
    )

    async def prime_until_signal(selected, *, poll_seconds):
        assert selected is primer
        assert poll_seconds == 0.05
        return record, True

    monkeypatch.setattr("umi.validator_live._prime_until_signal", prime_until_signal)

    assert run_cli(["--config", "/absolute/live.json", "--prime-next-window"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document == {
        "mirror_readiness_required_for_serving": True,
        "mode": LIVE_SHADOW_MODE,
        "proposal_close_block": plan.proposal_close_block,
        "scoring_policy_sha256": scoring_policy_hash(policy),
        "stage": WindowStage.POOL_AND_SELECTION.value,
        "status": "primed",
        "translation_weights_active": False,
        "weight_submission_capability": False,
        "window_id": plan.window_id,
        "window_index": plan.window_index,
    }
    assert primer.closed is True


def test_prime_cli_rejects_operator_or_injected_runtime_dependencies(capsys) -> None:
    for extra, dependencies in (
        (["--operator-config", "/absolute/operator.json"], None),
        ([], LiveValidatorProductionDependencies()),
    ):
        assert (
            run_cli(
                ["--config", "/absolute/live.json", "--prime-next-window", *extra],
                dependencies=dependencies,
            )
            == 2
        )
        document = json.loads(capsys.readouterr().err)
        assert document["reason_code"] == "prime_requires_live_config_only"
        assert document["weight_submission_capability"] is False


def test_dependency_surface_reports_wrong_production_shapes_without_weight_authority() -> None:
    dependencies = LiveValidatorProductionDependencies(raw_json_rpc=object())
    transcript_factory = PrivateBtauthTranscriptFactory(object())

    assert dependencies.invalid_capability_codes() == ("invalid_raw_json_rpc",)
    assert not hasattr(transcript_factory, "wallet")
    assert FORBIDDEN_WEIGHT_CAPABILITY_NAMES.isdisjoint(
        LiveValidatorProductionDependencies.__dataclass_fields__
    )

    narrowed = LiveValidatorProductionDependencies(
        validator_capacity_set=object(),
        mirror_discovery_rule_bytes=bytearray(b"not-immutable"),
        mirror_request_headers={"Authorization": 123},
        mirror_readiness=object(),
    )
    assert narrowed.invalid_capability_codes() == (
        "invalid_validator_capacity_set",
        "invalid_mirror_discovery_rule_bytes",
        "invalid_mirror_request_headers",
        "invalid_mirror_readiness",
    )
    obsolete = {
        "pool_source",
        "selection_pulse",
        "reveal_pulse",
        "decrypt",
        "reveal_audit_release",
        "prepared_assignments",
        "reveal_audit_release_boundary",
    }
    assert obsolete.isdisjoint(LiveValidatorProductionDependencies.__dataclass_fields__)


def test_private_manifest_signer_is_hotkey_bound_and_self_verifying() -> None:
    wallet = dev_wallet("//ValidatorManifest")
    signer = PrivateValidatorManifestSigner(
        wallet,
        validator_hotkey=wallet.hotkey.ss58_address,
        signature_scheme="sr25519",
    )

    assert len(signer(hashlib.sha256(b"manifest").digest())) == 64
    assert not hasattr(signer, "wallet")
    with pytest.raises(ValueError, match="32-byte"):
        signer(b"short")


def test_pool_reveal_production_context_constructs_only_exact_read_adapters(
    tmp_path: Path,
) -> None:
    initial = _policy()
    discovery = MirrorDiscoveryRule(
        schema=MIRROR_DISCOVERY_SCHEMA,
        protocol=PROTOCOL_VERSION,
        authentication_profile=(initial.implementation_pins.rules.mirror_authentication_profile),
        index_path_template=DEFAULT_MIRROR_INDEX_PATH,
        delivery_issuance_path=DEFAULT_DELIVERY_ISSUANCE_PATH,
        origins=["https://mirror.example"],
        delivery_origins=["https://delivery.example"],
    )
    discovery_bytes = canonical_json_bytes(discovery)
    policy_data = initial.model_dump(mode="json", by_alias=True)
    policy_data["implementation_pins"]["rules"]["mirror_discovery_rule_sha256"] = hashlib.sha256(
        discovery_bytes
    ).hexdigest()
    policy = ScoringPolicy.model_validate(policy_data)
    config = _config(tmp_path, policy)
    paths = LiveValidatorPaths.below(config.state_root)

    class Finality:
        chain_observation = policy.implementation_pins.live_chain
        finality_verifier_sha256 = next(
            iter(policy.implementation_pins.finality_verifier.release_sha256_by_target.values())
        )

        async def finalized_head_height(self):
            raise AssertionError("finality must not run during composition")

        async def verified_block_at(self, _height):
            raise AssertionError("finality must not run during composition")

    async def closing_snapshot(_work):
        raise AssertionError("closing snapshot must not run during composition")

    async def prepared_assignments(_context, _work):
        raise AssertionError("request preparation must not run during composition")

    async def audit_boundary(_work, _reason_code):
        raise AssertionError("release boundary must not run during composition")

    context = ProductionPoolRevealContext(
        policy=policy,
        config=config,
        paths=paths,
        finality=Finality(),
        closing_snapshot=closing_snapshot,
        prepared_assignments=prepared_assignments,
        mirror_discovery_rule_bytes=discovery_bytes,
        mirror_request_headers={"Authorization": "Bearer deployment-token"},
        mirror_readiness=VerifiedLiveMirrorReadiness(
            raw=b"unit-test-readiness",
            readiness=None,  # type: ignore[arg-type]
            expected_pool_manifest_sha256_by_publisher_account={},
            signer_accounts=frozenset(),
        ),
        reveal_audit_release_boundary=audit_boundary,
    )
    ports = build_production_pool_reveal_ports(context)

    assert isinstance(ports.mirror, DurablePoolMirrorSource)
    assert ports.mirror._require_mirror_readiness is True
    assert ports.mirror._mirror_readiness is context.mirror_readiness
    assert isinstance(ports.pool.selection_pulse, QuicknetSelectionPulseAdapter)
    assert isinstance(ports.reveal.reveal_pulse, QuicknetRevealPulseAdapter)
    assert isinstance(ports.reveal.decrypt, TLERevealDecryptAdapter)
    assert isinstance(ports.audit_release, FinalizedRevealAuditReleaseAdapter)
    assert ports.pool.source is ports.mirror
    assert ports.pool.closing_snapshot is closing_snapshot
    assert ports.pool.prepared_assignments is prepared_assignments
    assert ports.reveal.audit_release is ports.audit_release
    assert ports.pool.selection_pulse.client is ports.quicknet
    assert ports.reveal.reveal_pulse.client is ports.quicknet
    assert ports.quicknet.transport is None
    assert ports.mirror._transport is None
    assert ports.mirror._resolver is None
    assert ports.mirror._path == paths.pool_mirror
    assert paths.pool_mirror.is_file()
    assert FORBIDDEN_WEIGHT_CAPABILITY_NAMES.isdisjoint(
        ProductionPoolRevealContext.__dataclass_fields__
    )
