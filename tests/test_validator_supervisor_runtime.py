from __future__ import annotations

import ast
import asyncio
import stat
from pathlib import Path

import pytest

import umi.validator_supervisor as supervisor_models
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import (
    SUPERVISOR_CONFIG_SCHEMA,
    SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
    SUPERVISOR_DIRECTIVE_SCHEMA,
    SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA,
    SupervisorAuthority,
    SupervisorDirective,
    SupervisorDirectiveSignature,
    SupervisorOperatorInputTarget,
    SupervisorReleaseTarget,
    SupervisorWalletBinding,
    ValidatorSupervisorConfig,
    load_supervisor_directive_state,
    parse_canonical_signed_supervisor_directive,
    supervisor_directive_digest,
    supervisor_directive_sha256,
)
from umi.validator_supervisor_runtime import (
    DIRECTIVE_STATE_FILENAME,
    SupervisorReconcileStatus,
    SupervisorWorkerActivation,
    ValidatorSupervisorRuntime,
    ValidatorSupervisorRuntimeError,
)

AUTHORITY_HOTKEY = "5GsPXiSyzpK3rRoeAmjT4F5Cqa1RmP1CyBvNpwNDsDejyNZ4"
VALIDATOR_HOTKEY = "5CaRQtMKLXd35MA7E6igoUbKTe5wyrmTp6RkDzZKaTewofRM"
CHANNEL_ID = "11" * 32
POLICY_SHA256 = "22" * 32
REPOSITORY = "ghcr.io/umi-bitsign/umi-validator"

PROFILE_BY_MODE = {
    "inactive_shadow": "umi-live-shadow-validator/1",
    "bootstrap_service_weights": "umi-bootstrap-weight-validator/2",
    "translation_weights": "umi-translation-validator/1",
}


class FakeDirectiveFetcher:
    def __init__(self, payload: bytes | None) -> None:
        self.payload = payload
        self.error: Exception | None = None
        self.calls = 0
        self.concurrent_calls = 0
        self.maximum_concurrent_calls = 0
        self.delay = 0.0
        self.requested_cursors: list[tuple[int, str | None]] = []

    async def fetch_directive_page(
        self,
        *,
        after_sequence: int,
        after_directive_sha256: str | None,
    ) -> bytes | None:
        self.calls += 1
        self.requested_cursors.append((after_sequence, after_directive_sha256))
        self.concurrent_calls += 1
        self.maximum_concurrent_calls = max(self.maximum_concurrent_calls, self.concurrent_calls)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            if self.error is not None:
                raise self.error
            if self.payload is None:
                return None
            try:
                signed = parse_canonical_signed_supervisor_directive(self.payload)
            except Exception:
                return self.payload
            signed_json = signed.model_dump(mode="json", by_alias=True)
            caught_up = (
                signed.directive.sequence == after_sequence
                and signed.directive_sha256 == after_directive_sha256
            )
            return canonical_json_bytes(
                {
                    "schema": SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
                    "after_sequence": after_sequence,
                    "after_directive_sha256": after_directive_sha256,
                    "directives": [] if caught_up else [signed_json],
                    "more": False,
                    "head": signed_json,
                }
            )
        finally:
            self.concurrent_calls -= 1


class FakeFinalizedBlockReader:
    def __init__(self, height: int) -> None:
        self.height = height
        self.error: Exception | None = None
        self.calls = 0
        self.next_heights: list[int] = []

    async def read_finalized_block(self) -> int:
        self.calls += 1
        if self.error is not None:
            raise self.error
        if self.next_heights:
            height = self.next_heights.pop(0)
            self.height = height + 1
            return height
        height = self.height
        self.height += 1
        return height


class FakeWorkerAdapter:
    def __init__(self) -> None:
        self.active_mode: str | None = None
        self.live_workers = 0
        self.maximum_live_workers = 0
        self.healthy = True
        self.events: list[str] = []
        self.activations: list[SupervisorWorkerActivation] = []
        self.preflight_active_modes: list[str | None] = []
        self.preflight_failure_mode: str | None = None
        self.start_failure_mode: str | None = None
        self.partial_start_failure = False
        self.hold_start_fails = False
        self.stop_fails = False

    async def stop_worker(self) -> None:
        self.events.append(f"stop:{self.active_mode or 'none'}")
        if self.stop_fails:
            raise RuntimeError("private stop detail")
        if self.active_mode is not None:
            self.live_workers -= 1
        self.active_mode = None

    async def worker_is_healthy(self) -> bool:
        self.events.append(f"health:{self.active_mode or 'none'}")
        return self.healthy and self.active_mode is not None

    async def preflight_activation(self, *, activation: SupervisorWorkerActivation) -> None:
        self.events.append(f"preflight:{activation.mode}")
        self.activations.append(activation)
        self.preflight_active_modes.append(self.active_mode)
        if self.preflight_failure_mode == activation.mode:
            raise RuntimeError("private preflight detail")

    async def start_hold(self, *, reason_code: str) -> None:
        self.events.append(f"start:hold:{reason_code}")
        if self.hold_start_fails:
            raise RuntimeError("private hold detail")
        self._start("hold")

    async def start_inactive_shadow(self, *, activation: SupervisorWorkerActivation) -> None:
        await self._start_activation("inactive_shadow", activation)

    async def start_bootstrap_service_weights(
        self, *, activation: SupervisorWorkerActivation
    ) -> None:
        await self._start_activation("bootstrap_service_weights", activation)

    async def start_translation_weights(self, *, activation: SupervisorWorkerActivation) -> None:
        await self._start_activation("translation_weights", activation)

    async def _start_activation(self, mode: str, activation: SupervisorWorkerActivation) -> None:
        assert activation.mode == mode
        self.events.append(f"start:{mode}")
        if self.start_failure_mode == mode:
            if self.partial_start_failure:
                self._start(mode)
            raise RuntimeError("private start detail")
        self._start(mode)

    def _start(self, mode: str) -> None:
        if self.active_mode is not None:
            raise AssertionError("the runtime attempted to start a second worker")
        self.active_mode = mode
        self.live_workers += 1
        self.maximum_live_workers = max(self.maximum_live_workers, self.live_workers)


@pytest.fixture(autouse=True)
def _accept_structurally_valid_test_signatures(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        supervisor_models,
        "verify_response_signature",
        lambda *_args, **_kwargs: True,
    )


def _config(tmp_path: Path) -> ValidatorSupervisorConfig:
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    return ValidatorSupervisorConfig(
        schema=SUPERVISOR_CONFIG_SCHEMA,
        network="finney",
        netuid=78,
        mechanism_id=0,
        validator_hotkey=VALIDATOR_HOTKEY,
        channel_id=CHANNEL_ID,
        signature_threshold=1,
        trusted_authorities=[
            SupervisorAuthority(hotkey=AUTHORITY_HOTKEY, signature_scheme="sr25519")
        ],
        allowed_oci_repositories=[REPOSITORY],
        release_origins=["https://releases.umi.vision"],
        target_platform="linux/amd64",
        state_schema_version=1,
        directive_url="https://releases.umi.vision/supervisor/directive.json",
        poll_seconds=30,
        container_runtime="/usr/bin/podman",
        state_root=str(state_root),
        worker_state_root=str(tmp_path / "worker-state"),
        release_root=str(tmp_path / "releases"),
        operator_input_root=str(tmp_path / "operator-input"),
        finality_verifier_binary=str(tmp_path / "umi-grandpa-finality"),
        finality_verifier_sha256="77" * 32,
        finality_chain_spec_path=str(tmp_path / "finney.json"),
        worker_cpu_millis=8_000,
        worker_memory_bytes=16 * 1024 * 1024 * 1024,
        worker_pids_limit=256,
        worker_uid=2000,
        worker_gid=2000,
        wallet=SupervisorWalletBinding(
            path=str(tmp_path / "wallet"),
            name="validator",
            hotkey="default",
        ),
        allowed_modes=[
            "hold",
            "inactive_shadow",
            "bootstrap_service_weights",
            "translation_weights",
        ],
    )


def _release(mode: str, *, repository: str = REPOSITORY) -> SupervisorReleaseTarget:
    return SupervisorReleaseTarget(
        artifact_type="oci",
        release_bundle_url="https://releases.umi.vision/bundles/release.tar",
        release_bundle_sha256="33" * 32,
        release_bundle_size_bytes=1_024,
        release_manifest_sha256="44" * 32,
        release_authority_hotkey=AUTHORITY_HOTKEY,
        release_authority_signature_scheme="sr25519",
        oci_repository=repository,
        oci_manifest_sha256="55" * 32,
        target_platform="linux/amd64",
        umi_git_revision="66" * 20,
        umi_source_tree_sha256="77" * 32,
        entrypoint_profile=PROFILE_BY_MODE[mode],
        state_schema_minimum=1,
        state_schema_maximum=1,
    )


def _operator_inputs() -> SupervisorOperatorInputTarget:
    return SupervisorOperatorInputTarget(
        artifact_type="canonical_json",
        profile="umi-bootstrap-direct-inputs/2",
        bundle_url="https://releases.umi.vision/bundles/bootstrap-inputs.json",
        bundle_sha256="88" * 32,
        bundle_size_bytes=1_024,
    )


def _signed_directive(
    *,
    sequence: int,
    mode: str,
    valid_from_block: int = 100,
    valid_through_block: int = 200,
    issued_at_block: int = 90,
    predecessor: str | None = None,
    release: SupervisorReleaseTarget | None = None,
) -> tuple[bytes, str]:
    directive = SupervisorDirective(
        schema=SUPERVISOR_DIRECTIVE_SCHEMA,
        channel_id=CHANNEL_ID,
        sequence=sequence,
        previous_directive_sha256=predecessor,
        issued_at_block=issued_at_block,
        valid_from_block=valid_from_block,
        valid_through_block=valid_through_block,
        network="finney",
        netuid=78,
        mechanism_id=0,
        mode=mode,
        validator_hotkeys=[VALIDATOR_HOTKEY],
        policy_sha256=None if mode == "hold" else POLICY_SHA256,
        release=None if mode == "hold" else (release or _release(mode)),
        operator_inputs=_operator_inputs() if mode == "bootstrap_service_weights" else None,
    )
    digest = supervisor_directive_sha256(directive)
    signed = supervisor_models.SignedSupervisorDirective(
        schema=SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA,
        directive=directive,
        directive_sha256=digest,
        directive_digest=supervisor_directive_digest(directive).hex(),
        signatures=[
            SupervisorDirectiveSignature(
                hotkey=AUTHORITY_HOTKEY,
                signature_scheme="sr25519",
                signature="0x" + "88" * 64,
            )
        ],
    )
    return canonical_json_bytes(signed), digest


def _directive_page(
    payloads: list[bytes],
    *,
    after_sequence: int,
    after_directive_sha256: str | None,
    more: bool = False,
    head_payload: bytes | None = None,
) -> bytes:
    signed = [parse_canonical_signed_supervisor_directive(item) for item in payloads]
    if head_payload is not None:
        head = parse_canonical_signed_supervisor_directive(head_payload)
    elif signed:
        head = signed[-1]
    else:
        raise ValueError("an empty test page requires an explicit head")
    return canonical_json_bytes(
        {
            "schema": SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
            "after_sequence": after_sequence,
            "after_directive_sha256": after_directive_sha256,
            "directives": [item.model_dump(mode="json", by_alias=True) for item in signed],
            "more": more,
            "head": head.model_dump(mode="json", by_alias=True),
        }
    )


def _runtime(
    tmp_path: Path,
    *,
    payload: bytes | None,
    height: int,
) -> tuple[
    ValidatorSupervisorRuntime,
    FakeDirectiveFetcher,
    FakeFinalizedBlockReader,
    FakeWorkerAdapter,
    ValidatorSupervisorConfig,
]:
    config = _config(tmp_path)
    fetcher = FakeDirectiveFetcher(payload)
    finality = FakeFinalizedBlockReader(height)
    worker = FakeWorkerAdapter()
    runtime = ValidatorSupervisorRuntime(
        config=config,
        directive_fetcher=fetcher,
        finalized_block_reader=finality,
        worker_adapter=worker,
    )
    return runtime, fetcher, finality, worker, config


async def test_future_directive_is_persisted_and_preflighted_before_activation(
    tmp_path: Path,
) -> None:
    payload, digest = _signed_directive(
        sequence=1,
        mode="bootstrap_service_weights",
        valid_from_block=120,
    )
    runtime, _fetcher, finality, worker, config = _runtime(tmp_path, payload=payload, height=110)

    waiting = await runtime.reconcile()

    assert waiting.status is SupervisorReconcileStatus.WAITING_FOR_ACTIVATION
    assert waiting.active_mode == "hold"
    assert waiting.accepted_sequence == 1
    assert waiting.accepted_directive_sha256 == digest
    assert worker.active_mode == "hold"
    assert worker.events[:4] == [
        "stop:none",
        "start:hold:directive_transition",
        "preflight:bootstrap_service_weights",
        "health:hold",
    ]
    assert worker.preflight_active_modes == ["hold"]
    state_path = Path(config.state_root) / DIRECTIVE_STATE_FILENAME
    persisted = load_supervisor_directive_state(state_path, trust_policy=config.trust_policy())
    assert persisted is not None and persisted.accepted_directive_sha256 == digest
    assert persisted.accepted_mode == "bootstrap_service_weights"
    assert persisted.accepted_oci_manifest_sha256 == "55" * 32
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600

    finality.height = 120
    started = await runtime.reconcile()

    assert started.status is SupervisorReconcileStatus.WORKER_STARTED
    assert started.active_mode == "bootstrap_service_weights"
    assert worker.active_mode == "bootstrap_service_weights"
    assert worker.maximum_live_workers == 1
    assert worker.events[-2:] == ["stop:hold", "start:bootstrap_service_weights"]


async def test_future_hold_is_persisted_but_reported_as_waiting(tmp_path: Path) -> None:
    payload, digest = _signed_directive(
        sequence=1,
        mode="hold",
        valid_from_block=120,
    )
    runtime, _fetcher, _finality, worker, _config_value = _runtime(
        tmp_path, payload=payload, height=110
    )

    result = await runtime.reconcile()

    assert result.status is SupervisorReconcileStatus.WAITING_FOR_ACTIVATION
    assert result.accepted_directive_sha256 == digest
    assert worker.active_mode == "hold"
    assert not any(item.startswith("preflight:") for item in worker.events)


@pytest.mark.parametrize(
    "mode",
    ["inactive_shadow", "bootstrap_service_weights", "translation_weights"],
)
async def test_fixed_mode_dispatch_passes_only_verified_typed_activation(
    tmp_path: Path,
    mode: str,
) -> None:
    payload, digest = _signed_directive(sequence=1, mode=mode)
    runtime, _fetcher, _finality, worker, _config_value = _runtime(
        tmp_path, payload=payload, height=100
    )

    result = await runtime.reconcile()

    assert result.status is SupervisorReconcileStatus.WORKER_STARTED
    assert worker.active_mode == mode
    assert worker.events[-1] == f"start:{mode}"
    assert worker.maximum_live_workers == 1
    activation = worker.activations[-1]
    assert activation.directive_sha256 == digest
    assert activation.valid_from_block == 100
    assert activation.valid_through_block == 200
    assert activation.release.oci_manifest_sha256 == "55" * 32
    assert not hasattr(activation, "argv")
    assert not hasattr(activation, "command")
    assert not hasattr(activation, "environment")


async def test_same_worker_is_health_checked_without_a_second_start(tmp_path: Path) -> None:
    payload, _digest = _signed_directive(sequence=1, mode="inactive_shadow")
    runtime, _fetcher, _finality, worker, _config_value = _runtime(
        tmp_path, payload=payload, height=100
    )
    first = await runtime.reconcile()
    second = await runtime.reconcile()

    assert first.status is SupervisorReconcileStatus.WORKER_STARTED
    assert second.status is SupervisorReconcileStatus.WORKER_HEALTHY
    assert worker.events.count("start:inactive_shadow") == 1
    assert worker.maximum_live_workers == 1


async def test_new_directive_stops_old_chain_worker_before_candidate_preflight(
    tmp_path: Path,
) -> None:
    first_payload, first_digest = _signed_directive(
        sequence=1,
        mode="bootstrap_service_weights",
    )
    runtime, fetcher, _finality, worker, _config_value = _runtime(
        tmp_path, payload=first_payload, height=100
    )
    assert (await runtime.reconcile()).active_mode == "bootstrap_service_weights"

    second_payload, _second_digest = _signed_directive(
        sequence=2,
        mode="translation_weights",
        predecessor=first_digest,
    )
    fetcher.payload = second_payload
    worker.events.clear()
    worker.preflight_active_modes.clear()

    result = await runtime.reconcile()

    assert result.status is SupervisorReconcileStatus.WORKER_STARTED
    assert worker.preflight_active_modes == ["hold"]
    assert worker.events[:3] == [
        "stop:bootstrap_service_weights",
        "start:hold:directive_transition",
        "preflight:translation_weights",
    ]


async def test_preflight_refresh_prevents_start_after_directive_expiry(tmp_path: Path) -> None:
    payload, digest = _signed_directive(
        sequence=1,
        mode="bootstrap_service_weights",
        valid_through_block=101,
    )
    runtime, _fetcher, finality, worker, config = _runtime(tmp_path, payload=payload, height=100)
    finality.next_heights = [100, 102]

    result = await runtime.reconcile()

    assert result.status is SupervisorReconcileStatus.HOLDING
    assert result.reason_code == "directive_expired_after_preflight"
    assert result.finalized_block == 102
    assert result.accepted_directive_sha256 == digest
    assert worker.preflight_active_modes == ["hold"]
    assert worker.active_mode == "hold"
    assert "start:bootstrap_service_weights" not in worker.events
    state = load_supervisor_directive_state(
        Path(config.state_root) / DIRECTIVE_STATE_FILENAME,
        trust_policy=config.trust_policy(),
    )
    assert state is not None and state.accepted_directive_sha256 == digest


async def test_preflight_requires_a_newer_finalized_head_before_worker_start(
    tmp_path: Path,
) -> None:
    payload, digest = _signed_directive(
        sequence=1,
        mode="bootstrap_service_weights",
    )
    runtime, _fetcher, finality, worker, _config_value = _runtime(
        tmp_path, payload=payload, height=100
    )
    finality.next_heights = [100, 100]

    result = await runtime.reconcile()

    assert result.status is SupervisorReconcileStatus.HOLDING
    assert result.reason_code == "finalized_block_refresh_not_advanced"
    assert result.finalized_block == 100
    assert result.accepted_directive_sha256 == digest
    assert worker.active_mode == "hold"
    assert "start:bootstrap_service_weights" not in worker.events


async def test_preflight_requires_two_blocks_of_activation_lease_headroom(
    tmp_path: Path,
) -> None:
    payload, digest = _signed_directive(
        sequence=1,
        mode="bootstrap_service_weights",
        valid_through_block=102,
    )
    runtime, _fetcher, finality, worker, _config_value = _runtime(
        tmp_path, payload=payload, height=100
    )
    finality.next_heights = [100, 101]

    result = await runtime.reconcile()

    assert result.status is SupervisorReconcileStatus.HOLDING
    assert result.reason_code == "directive_activation_headroom_insufficient"
    assert result.finalized_block == 101
    assert result.accepted_directive_sha256 == digest
    assert worker.active_mode == "hold"
    assert "start:bootstrap_service_weights" not in worker.events


async def test_preflighted_future_worker_is_not_started_with_too_little_headroom(
    tmp_path: Path,
) -> None:
    payload, digest = _signed_directive(
        sequence=1,
        mode="bootstrap_service_weights",
        valid_from_block=199,
        valid_through_block=200,
    )
    runtime, _fetcher, finality, worker, _config_value = _runtime(
        tmp_path, payload=payload, height=100
    )

    waiting = await runtime.reconcile()
    assert waiting.status is SupervisorReconcileStatus.WAITING_FOR_ACTIVATION
    assert worker.active_mode == "hold"

    finality.height = 199
    result = await runtime.reconcile()

    assert result.status is SupervisorReconcileStatus.HOLDING
    assert result.reason_code == "directive_activation_headroom_insufficient"
    assert result.finalized_block == 199
    assert result.accepted_directive_sha256 == digest
    assert worker.active_mode == "hold"
    assert "start:bootstrap_service_weights" not in worker.events


async def test_restart_fences_persisted_worker_before_same_directive_resumes(
    tmp_path: Path,
) -> None:
    payload, digest = _signed_directive(sequence=1, mode="translation_weights")
    first_runtime, _fetcher, _finality, first_worker, config = _runtime(
        tmp_path, payload=payload, height=100
    )
    assert (await first_runtime.reconcile()).active_mode == "translation_weights"
    assert first_worker.active_mode == "translation_weights"

    fetcher = FakeDirectiveFetcher(payload)
    finality = FakeFinalizedBlockReader(100)
    restarted_worker = FakeWorkerAdapter()
    restarted_worker.active_mode = "translation_weights"
    restarted_worker.live_workers = 1
    restarted_worker.maximum_live_workers = 1
    restarted = ValidatorSupervisorRuntime(
        config=config,
        directive_fetcher=fetcher,
        finalized_block_reader=finality,
        worker_adapter=restarted_worker,
    )

    fenced = await restarted.reconcile()

    assert fenced.status is SupervisorReconcileStatus.HOLDING
    assert fenced.reason_code == "restart_fence"
    assert fenced.accepted_directive_sha256 == digest
    assert fenced.prior_worker_may_have_chain_effects is True
    assert fetcher.calls == 0
    assert finality.calls == 0
    assert restarted_worker.active_mode == "hold"
    assert restarted_worker.events == [
        "stop:translation_weights",
        "start:hold:restart_fence",
    ]

    resumed = await restarted.reconcile()

    assert resumed.status is SupervisorReconcileStatus.WORKER_STARTED
    assert resumed.active_mode == "translation_weights"
    assert fetcher.calls == 1
    assert finality.calls == 2
    assert restarted_worker.events[-3:] == [
        "preflight:translation_weights",
        "stop:hold",
        "start:translation_weights",
    ]


async def test_inactive_shadow_is_classified_as_may_have_chain_anchor_effects(
    tmp_path: Path,
) -> None:
    payload, _digest = _signed_directive(sequence=1, mode="inactive_shadow")
    runtime, fetcher, _finality, worker, _config_value = _runtime(
        tmp_path, payload=payload, height=100
    )
    assert (await runtime.reconcile()).active_mode == "inactive_shadow"

    fetcher.payload = None
    held = await runtime.reconcile()

    assert held.status is SupervisorReconcileStatus.HOLDING
    assert held.prior_worker_may_have_chain_effects is True
    assert worker.active_mode == "hold"


@pytest.mark.parametrize(
    ("payload", "height", "reason"),
    [
        (None, 100, "directive_missing"),
        (b"not-json", 100, "directive_page_json_invalid"),
    ],
)
async def test_missing_or_malformed_directive_fails_closed_to_hold(
    tmp_path: Path,
    payload: bytes | None,
    height: int,
    reason: str,
) -> None:
    runtime, _fetcher, _finality, worker, _config_value = _runtime(
        tmp_path, payload=payload, height=height
    )

    result = await runtime.reconcile()

    assert result.status is SupervisorReconcileStatus.HOLDING
    assert result.reason_code == reason
    assert worker.active_mode == "hold"
    assert worker.maximum_live_workers == 1


async def test_expired_or_locally_incompatible_directive_is_not_persisted(
    tmp_path: Path,
) -> None:
    payload, _digest = _signed_directive(
        sequence=1,
        mode="inactive_shadow",
        valid_through_block=105,
    )
    runtime, fetcher, finality, worker, config = _runtime(tmp_path, payload=payload, height=106)

    expired = await runtime.reconcile()
    assert expired.reason_code == "directive_expired"
    assert worker.active_mode == "hold"
    assert not (Path(config.state_root) / DIRECTIVE_STATE_FILENAME).exists()

    incompatible = _release("inactive_shadow", repository="ghcr.io/example/untrusted-validator")
    fetcher.payload, _ = _signed_directive(
        sequence=1,
        mode="inactive_shadow",
        release=incompatible,
    )
    finality.height = 100
    rejected = await runtime.reconcile()
    assert rejected.reason_code == "directive_oci_repository_not_allowed"
    assert worker.active_mode == "hold"
    assert not (Path(config.state_root) / DIRECTIVE_STATE_FILENAME).exists()


async def test_offline_runtime_catches_up_expired_history_and_executes_only_current_head(
    tmp_path: Path,
) -> None:
    first_payload, first_digest = _signed_directive(
        sequence=1,
        mode="inactive_shadow",
        valid_from_block=90,
        valid_through_block=92,
    )
    second_payload, second_digest = _signed_directive(
        sequence=2,
        mode="hold",
        predecessor=first_digest,
        valid_from_block=93,
        valid_through_block=95,
    )
    third_payload, third_digest = _signed_directive(
        sequence=3,
        mode="bootstrap_service_weights",
        predecessor=second_digest,
    )
    page = _directive_page(
        [first_payload, second_payload, third_payload],
        after_sequence=0,
        after_directive_sha256=None,
    )
    runtime, fetcher, _finality, worker, config = _runtime(
        tmp_path,
        payload=page,
        height=100,
    )

    result = await runtime.reconcile()

    assert result.status is SupervisorReconcileStatus.WORKER_STARTED
    assert result.accepted_sequence == 3
    assert result.accepted_directive_sha256 == third_digest
    assert worker.active_mode == "bootstrap_service_weights"
    assert [item.sequence for item in worker.activations] == [3]
    assert "start:inactive_shadow" not in worker.events
    assert fetcher.requested_cursors == [(0, None)]
    state = load_supervisor_directive_state(
        Path(config.state_root) / DIRECTIVE_STATE_FILENAME,
        trust_policy=config.trust_policy(),
    )
    assert state is not None and state.accepted_sequence == 3


async def test_continued_catchup_page_persists_each_item_and_remains_in_hold(
    tmp_path: Path,
) -> None:
    first_payload, first_digest = _signed_directive(
        sequence=1,
        mode="inactive_shadow",
        valid_from_block=90,
        valid_through_block=92,
    )
    second_payload, second_digest = _signed_directive(
        sequence=2,
        mode="hold",
        predecessor=first_digest,
        valid_from_block=93,
        valid_through_block=95,
    )
    third_payload, third_digest = _signed_directive(
        sequence=3,
        mode="translation_weights",
        predecessor=second_digest,
    )
    first_page = _directive_page(
        [first_payload, second_payload],
        after_sequence=0,
        after_directive_sha256=None,
        more=True,
    )
    runtime, fetcher, _finality, worker, config = _runtime(
        tmp_path,
        payload=first_page,
        height=100,
    )

    catching_up = await runtime.reconcile()

    assert catching_up.status is SupervisorReconcileStatus.HOLDING
    assert catching_up.reason_code == "directive_catchup_more"
    assert catching_up.accepted_sequence == 2
    assert catching_up.accepted_directive_sha256 == second_digest
    assert worker.active_mode == "hold"
    assert worker.activations == []
    state = load_supervisor_directive_state(
        Path(config.state_root) / DIRECTIVE_STATE_FILENAME,
        trust_policy=config.trust_policy(),
    )
    assert state is not None and state.accepted_sequence == 2

    fetcher.payload = _directive_page(
        [third_payload],
        after_sequence=2,
        after_directive_sha256=second_digest,
    )
    started = await runtime.reconcile()

    assert started.status is SupervisorReconcileStatus.WORKER_STARTED
    assert started.accepted_sequence == 3
    assert started.accepted_directive_sha256 == third_digest
    assert worker.active_mode == "translation_weights"
    assert [item.sequence for item in worker.activations] == [3]
    assert fetcher.requested_cursors == [(0, None), (2, second_digest)]


async def test_invalid_later_page_item_leaves_only_verified_prefix_persisted(
    tmp_path: Path,
) -> None:
    first_payload, first_digest = _signed_directive(
        sequence=1,
        mode="hold",
        valid_from_block=90,
        valid_through_block=92,
    )
    incompatible = _release(
        "translation_weights",
        repository="ghcr.io/example/untrusted-validator",
    )
    second_payload, _second_digest = _signed_directive(
        sequence=2,
        mode="translation_weights",
        predecessor=first_digest,
        release=incompatible,
    )
    page = _directive_page(
        [first_payload, second_payload],
        after_sequence=0,
        after_directive_sha256=None,
    )
    runtime, _fetcher, _finality, worker, config = _runtime(
        tmp_path,
        payload=page,
        height=100,
    )

    result = await runtime.reconcile()

    assert result.status is SupervisorReconcileStatus.HOLDING
    assert result.reason_code == "directive_oci_repository_not_allowed"
    assert result.accepted_sequence == 1
    assert result.accepted_directive_sha256 == first_digest
    assert worker.active_mode == "hold"
    assert worker.activations == []
    state = load_supervisor_directive_state(
        Path(config.state_root) / DIRECTIVE_STATE_FILENAME,
        trust_policy=config.trust_policy(),
    )
    assert state is not None and state.accepted_sequence == 1


async def test_expired_terminal_head_is_not_advanced_or_executed(tmp_path: Path) -> None:
    first_payload, first_digest = _signed_directive(
        sequence=1,
        mode="hold",
        valid_from_block=90,
        valid_through_block=92,
    )
    second_payload, _second_digest = _signed_directive(
        sequence=2,
        mode="translation_weights",
        predecessor=first_digest,
        valid_from_block=93,
        valid_through_block=95,
    )
    page = _directive_page(
        [first_payload, second_payload],
        after_sequence=0,
        after_directive_sha256=None,
    )
    runtime, _fetcher, _finality, worker, config = _runtime(
        tmp_path,
        payload=page,
        height=100,
    )

    result = await runtime.reconcile()

    assert result.status is SupervisorReconcileStatus.HOLDING
    assert result.reason_code == "directive_expired"
    assert result.accepted_sequence == 1
    assert result.accepted_directive_sha256 == first_digest
    assert worker.active_mode == "hold"
    assert worker.activations == []
    state = load_supervisor_directive_state(
        Path(config.state_root) / DIRECTIVE_STATE_FILENAME,
        trust_policy=config.trust_policy(),
    )
    assert state is not None and state.accepted_sequence == 1


async def test_page_cursor_echo_must_match_the_requested_high_water(tmp_path: Path) -> None:
    first_payload, first_digest = _signed_directive(sequence=1, mode="hold")
    stale_page = _directive_page(
        [],
        after_sequence=1,
        after_directive_sha256=first_digest,
        head_payload=first_payload,
    )
    runtime, fetcher, finality, worker, _config_value = _runtime(
        tmp_path,
        payload=stale_page,
        height=100,
    )

    result = await runtime.reconcile()

    assert result.status is SupervisorReconcileStatus.HOLDING
    assert result.reason_code == "directive_page_cursor_mismatch"
    assert result.accepted_sequence is None
    assert fetcher.requested_cursors == [(0, None)]
    assert finality.calls == 0
    assert worker.active_mode == "hold"


async def test_catchup_rejects_a_directive_issued_after_finalized_head(tmp_path: Path) -> None:
    future_payload, _future_digest = _signed_directive(
        sequence=1,
        mode="hold",
        issued_at_block=101,
        valid_from_block=101,
    )
    page = _directive_page(
        [future_payload],
        after_sequence=0,
        after_directive_sha256=None,
        more=True,
    )
    runtime, _fetcher, _finality, worker, config = _runtime(
        tmp_path,
        payload=page,
        height=100,
    )

    result = await runtime.reconcile()

    assert result.status is SupervisorReconcileStatus.HOLDING
    assert result.reason_code == "directive_issued_in_future"
    assert result.accepted_sequence is None
    assert worker.active_mode == "hold"
    assert not (Path(config.state_root) / DIRECTIVE_STATE_FILENAME).exists()


async def test_new_candidate_failure_advances_high_water_then_never_rolls_back(
    tmp_path: Path,
) -> None:
    first_payload, first_digest = _signed_directive(sequence=1, mode="bootstrap_service_weights")
    runtime, fetcher, _finality, worker, config = _runtime(
        tmp_path, payload=first_payload, height=100
    )
    assert (await runtime.reconcile()).active_mode == "bootstrap_service_weights"

    second_payload, second_digest = _signed_directive(
        sequence=2,
        mode="translation_weights",
        predecessor=first_digest,
    )
    fetcher.payload = second_payload
    worker.preflight_failure_mode = "translation_weights"

    failed_candidate = await runtime.reconcile()

    assert failed_candidate.status is SupervisorReconcileStatus.HOLDING
    assert failed_candidate.reason_code == "worker_preflight_failed"
    assert failed_candidate.prior_worker_may_have_chain_effects is True
    assert failed_candidate.accepted_sequence == 2
    assert worker.active_mode == "hold"
    state = load_supervisor_directive_state(
        Path(config.state_root) / DIRECTIVE_STATE_FILENAME,
        trust_policy=config.trust_policy(),
    )
    assert state is not None and state.accepted_directive_sha256 == second_digest

    worker.preflight_failure_mode = None
    fetcher.payload = first_payload
    rollback = await runtime.reconcile()

    assert rollback.status is SupervisorReconcileStatus.HOLDING
    assert rollback.reason_code == "directive_page_schema_invalid"
    assert worker.active_mode == "hold"
    assert worker.events.count("start:bootstrap_service_weights") == 1


async def test_partial_worker_start_is_cleaned_before_fail_closed_hold(tmp_path: Path) -> None:
    payload, _digest = _signed_directive(sequence=1, mode="translation_weights")
    runtime, _fetcher, _finality, worker, _config_value = _runtime(
        tmp_path, payload=payload, height=100
    )
    worker.start_failure_mode = "translation_weights"
    worker.partial_start_failure = True

    result = await runtime.reconcile()

    assert result.status is SupervisorReconcileStatus.HOLDING
    assert result.reason_code == "worker_start_failed"
    assert result.prior_worker_may_have_chain_effects is True
    assert worker.active_mode == "hold"
    assert worker.live_workers == 1
    assert worker.maximum_live_workers == 1
    assert worker.events[-3:] == [
        "stop:translation_weights",
        "stop:none",
        "start:hold:worker_start_failed",
    ]


async def test_concurrent_reconciliations_are_serialized_and_start_one_worker(
    tmp_path: Path,
) -> None:
    payload, _digest = _signed_directive(sequence=1, mode="inactive_shadow")
    runtime, fetcher, _finality, worker, _config_value = _runtime(
        tmp_path, payload=payload, height=100
    )
    fetcher.delay = 0.02

    results = await asyncio.gather(runtime.reconcile(), runtime.reconcile())

    assert {item.status for item in results} == {
        SupervisorReconcileStatus.WORKER_STARTED,
        SupervisorReconcileStatus.WORKER_HEALTHY,
    }
    assert fetcher.maximum_concurrent_calls == 1
    assert worker.events.count("start:inactive_shadow") == 1
    assert worker.maximum_live_workers == 1


async def test_poll_uses_pinned_delay_and_an_injected_interruptible_wait(
    tmp_path: Path,
) -> None:
    payload, _digest = _signed_directive(sequence=1, mode="inactive_shadow")
    config = _config(tmp_path)
    fetcher = FakeDirectiveFetcher(payload)
    finality = FakeFinalizedBlockReader(100)
    worker = FakeWorkerAdapter()
    stop_event = asyncio.Event()
    observed_delays: list[float] = []

    async def stop_after_first_poll(event: asyncio.Event, delay: float) -> None:
        observed_delays.append(delay)
        event.set()

    runtime = ValidatorSupervisorRuntime(
        config=config,
        directive_fetcher=fetcher,
        finalized_block_reader=finality,
        worker_adapter=worker,
        wait=stop_after_first_poll,
    )

    await runtime.poll(stop_event)

    assert fetcher.calls == 1
    assert observed_delays == [30.0]
    assert worker.active_mode == "inactive_shadow"


async def test_corrupt_high_water_is_checked_before_fetch_and_holds(tmp_path: Path) -> None:
    payload, _digest = _signed_directive(sequence=1, mode="inactive_shadow")
    runtime, fetcher, _finality, worker, config = _runtime(tmp_path, payload=payload, height=100)
    state_path = Path(config.state_root) / DIRECTIVE_STATE_FILENAME
    state_path.write_bytes(b"corrupt")
    state_path.chmod(0o600)

    result = await runtime.reconcile()

    assert result.status is SupervisorReconcileStatus.HOLDING
    assert result.reason_code == "state_json_invalid"
    assert fetcher.calls == 0
    assert worker.active_mode == "hold"


async def test_hold_failure_raises_only_a_stable_non_sensitive_error(tmp_path: Path) -> None:
    runtime, _fetcher, _finality, worker, _config_value = _runtime(
        tmp_path, payload=None, height=100
    )
    worker.hold_start_fails = True

    with pytest.raises(ValidatorSupervisorRuntimeError) as captured:
        await runtime.reconcile()

    assert captured.value.reason_code == "fail_closed_hold_start_failed"
    assert "private" not in str(captured.value)
    assert worker.live_workers == 0


def test_runtime_has_no_network_subprocess_or_arbitrary_worker_dispatch() -> None:
    source_path = Path(supervisor_models.__file__).with_name("validator_supervisor_runtime.py")
    source = source_path.read_text()
    tree = ast.parse(source)
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])

    assert not imported_roots.intersection(
        {"bittensor", "http", "httpx", "requests", "socket", "subprocess", "urllib"}
    )
    assert "shell=True" not in source
    assert "create_subprocess" not in source
    assert "start_worker(" not in source
