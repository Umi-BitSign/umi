"""Fail-closed composition for the seven-stage live shadow validator.

This module is deliberately an assembly boundary, not another protocol layer.
It joins the durable stores, the deterministic plan source, all seven existing
stage effects, and the finality supervisor.  Construction performs no network
request and no broadcast.  The only chain mutation admitted by the resulting
service is the existing :class:`BittensorAnchorPorts` adapter, whose public
surface is restricted to the assignment, request, and response commitments.

``LiveValidatorProductionDependencies`` names the narrow external capabilities
assembled by the installed operator command.  The production builder rejects
all missing inputs together with stable reason codes; it never substitutes a
fixture, an unverified node decode, or a generic signer.  In particular,
neither the dependency object nor the runtime has a weight-call builder, weight
signer, weight submitter, or generic extrinsic-submission field.
"""

from __future__ import annotations

import argparse
import asyncio
import errno
import hashlib
import inspect
import os
import platform
import re
import signal
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol

from pydantic import Field, ValidationError, model_validator
from typing_extensions import Self

from .calibration_bundle import (
    STAGE_IDS,
    GrandpaFinalityReplayVerifier,
    calibration_stage_replay_hook_id,
)
from .conformance import (
    ConformanceBinaryPins,
    ConformanceError,
    ConformanceExecution,
    ConformanceExecutionReport,
    ConformanceFixturePaths,
    execute_conformance_suite,
)
from .crypto import verify_response_signature
from .drand import QuicknetClient
from .encoding import account_id32
from .grandpa_finality_supervisor import DurableGrandpaFinalityPort
from .mirror_readiness import VerifiedLiveMirrorReadiness
from .policy import ScoringPolicy, scoring_policy_hash, validate_live_shadow_runtime
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, canonical_json_bytes
from .substrate_proof import SubprocessStorageProofVerifier
from .validator_adapters import JournalStageAdapter
from .validator_anchor_ports import BittensorAnchorPorts, GrandpaQuicknetRoundPort
from .validator_assignment_preparation import FinalizedPreparedAssignmentsAdapter
from .validator_assignments import ValidatorAssignmentStore
from .validator_bundle_ports import build_production_calibration_bundle_verifier
from .validator_chain import (
    BittensorRawJsonRpc,
    FinalizedProofCollector,
    FinalizedRuntimePin,
)
from .validator_chain_scan import FinalizedBlockScanner
from .validator_chain_scan_port import LiveFinalizedBlockScanPort
from .validator_closing_snapshot import ProofBackedClosingSnapshotCollector
from .validator_engine import ValidatorEngine
from .validator_extrinsics import ValidatorExtrinsicJournal
from .validator_incident_observer import (
    ReplayIncidentBundleVerifier,
    ShadowIncidentReceiptObserver,
)
from .validator_journal import ValidatorStageJournal
from .validator_live_ports import (
    AuthenticatedMirrorDeliveryIssuer,
    DurablePoolMirrorSource,
    FinalizedRevealAuditReleaseAdapter,
    ProofBackedRevealAuditReleaseBoundaryPort,
    QuicknetRevealPulseAdapter,
    QuicknetSelectionPulseAdapter,
    RevealAuditReleaseBoundaryPort,
    TLERevealDecryptAdapter,
    build_live_pool_effect_ports,
    build_live_reveal_effect_ports,
)
from .validator_monitoring_state import (
    MonitoringStatePolicy,
    ValidatorMonitoringStateStore,
)
from .validator_no_weight import LiveNoWeightCapturePort
from .validator_plans import DeterministicWindowPlanSource
from .validator_pool_effect import PoolAndSelectionEffect, PoolEffectPorts
from .validator_protocol_state import ValidatorProtocolStateStore
from .validator_readiness import (
    ProofBackedPriorWindowReadiness,
    ReplayPublishedBundleVerifier,
)
from .validator_reveal_effect import (
    RevealEffectPorts,
    RevealTransitionCoordinator,
    ValidatorRevealEffect,
)
from .validator_service import (
    MAX_POLL_SECONDS,
    MIN_POLL_SECONDS,
    ValidatorService,
    start_window_operation_id,
)
from .validator_state import (
    STAGE_ORDER,
    PauseScope,
    ValidatorControlPlane,
    WindowRecord,
    WindowStage,
)
from .validator_terminal_effect import (
    CalibrationNoWeightTerminalEffect,
    ReplayCalibrationBundleVerifier,
)
from .validator_transcript_abort import DurableTranscriptAbortRegistry
from .validator_transcript_effects import (
    AssignmentTranscriptEffect,
    RequestTranscriptEffect,
    SealedResponseTranscriptEffect,
    TranscriptEffectPorts,
)
from .validator_transcript_ports import (
    BoundedHttpTranscriptTransport,
    DurableBtauthNonceStore,
    DurableTranscriptResourceStore,
    FinalizedTranscriptObservationPort,
    LiveBtauthAttemptPort,
    ObservedScheduleAuditReleasePort,
    ProductionTranscriptPorts,
    ReceiptReplayTranscriptResourceBaseline,
    TranscriptPreflightPlanPort,
    VerifiedValidatorCapacitySet,
    build_production_transcript_ports,
)
from .validator_weight_build_effect import (
    ProofBackedWeightBuildCloseResolver,
    ShadowWeightBuildEffect,
    WeightBuildEffectPorts,
)
from .validator_weight_ports import build_live_weight_ports
from .validator_window_material import ValidatorWindowMaterialStore

LIVE_VALIDATOR_CONFIG_SCHEMA = "umi-validator-live-config/1"
LIVE_SHADOW_MODE = "live_shadow_calibration"
SUPPORTED_LIVE_VALIDATOR_TARGETS = frozenset(
    {"aarch64-unknown-linux-musl", "x86_64-unknown-linux-musl"}
)
WEIGHT_DISABLED_HOLD_ID = "umi-live-shadow-weight-disabled-v1"
MAX_STARTUP_DOCUMENT_BYTES = 4 * 1024 * 1024

_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

# Kept as data so an audit can mechanically prove that the production injection
# surface contains none of these capabilities.
FORBIDDEN_WEIGHT_CAPABILITY_NAMES = frozenset(
    {
        "build_weight_call",
        "compose_weight_call",
        "set_weights",
        "sign_weight_call",
        "submit_weights",
        "weight_call_builder",
        "weight_signer",
        "weight_submitter",
    }
)


class LiveValidatorError(RuntimeError):
    """Base error with a stable, non-sensitive startup reason code."""

    def __init__(self, reason_code: str) -> None:
        if not isinstance(reason_code, str) or not reason_code:
            raise ValueError("live-validator reason code must be nonempty")
        self.reason_code = reason_code
        super().__init__(reason_code)


class LiveValidatorConfigError(LiveValidatorError):
    """The canonical startup document or one of its immutable inputs is unsafe."""


class LiveValidatorCompositionError(LiveValidatorError):
    """The requested production service cannot be assembled safely."""


class LiveValidatorMissingCapabilities(LiveValidatorCompositionError):
    """One or more genuine production ports are not available."""

    def __init__(self, missing_codes: Sequence[str]) -> None:
        codes = tuple(missing_codes)
        if not codes or any(not isinstance(item, str) or not item for item in codes):
            raise ValueError("missing capability codes must be nonempty strings")
        self.missing_codes = codes
        super().__init__("missing_live_capabilities")


class LiveValidatorInvalidCapabilities(LiveValidatorCompositionError):
    """One or more supplied production ports have a broader or wrong shape."""

    def __init__(self, invalid_codes: Sequence[str]) -> None:
        codes = tuple(invalid_codes)
        if not codes or any(not isinstance(item, str) or not item for item in codes):
            raise ValueError("invalid capability codes must be nonempty strings")
        self.invalid_codes = codes
        super().__init__("invalid_live_capabilities")


class LiveValidatorRuntimeError(LiveValidatorError):
    """A supervised live service component stopped or failed unexpectedly."""


@dataclass(slots=True)
class LiveValidatorPrimer:
    """Planner-only runtime used before window-scoped mirror readiness exists."""

    control_plane: ValidatorControlPlane
    plan_source: DeterministicWindowPlanSource
    finality: DurableGrandpaFinalityPort
    protocol_state: ValidatorProtocolStateStore
    paths: LiveValidatorPaths
    policy_hash: str
    _closed: bool = False

    async def prime(
        self,
        stop_event: asyncio.Event,
        *,
        poll_seconds: float,
    ) -> tuple[WindowRecord | None, bool]:
        """Record exactly one next plan without executing its first stage."""

        if not isinstance(stop_event, asyncio.Event):
            raise TypeError("stop_event must be an asyncio.Event")
        if self._closed:
            raise LiveValidatorRuntimeError("primer_closed")
        delay = _prime_poll_seconds(poll_seconds)
        existing = self.control_plane.active_window()
        if existing is not None and existing.stage is not WindowStage.POOL_AND_SELECTION:
            raise LiveValidatorRuntimeError("prime_window_already_advanced")

        finality_task = asyncio.create_task(self.finality.run(stop_event))
        try:
            while not stop_event.is_set():
                if finality_task.done():
                    await finality_task
                    raise LiveValidatorRuntimeError("prime_finality_stopped")
                head = await asyncio.to_thread(self.finality.persisted_head)
                if head is not None:
                    if existing is not None:
                        current = self.control_plane.active_window()
                        if current != existing:
                            raise LiveValidatorRuntimeError("prime_window_changed")
                        finalized_height = await self.finality.finalized_head_height()
                        if finalized_height >= existing.plan.proposal_close_block:
                            raise LiveValidatorRuntimeError("prime_proposal_interval_closed")
                        return existing, False
                    plan = await self.plan_source.next_plan()
                    if plan is not None:
                        finalized_height = await self.finality.finalized_head_height()
                        if finalized_height >= plan.proposal_close_block:
                            raise LiveValidatorRuntimeError("prime_proposal_interval_closed")
                        record = self.control_plane.start_window(
                            plan,
                            operation_id=start_window_operation_id(plan),
                            metadata={"source": "verified_window_plan"},
                        )
                        return record, True
                await _wait_for_prime_progress(stop_event, finality_task, delay)
            return None, False
        finally:
            stop_event.set()
            with suppress(asyncio.CancelledError):
                await finality_task

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.protocol_state.close()
        self.finality.close()


class LiveValidatorConfig(StrictProtocolModel):
    """Canonical, restart-stable local configuration for one validator process."""

    schema_: Literal[LIVE_VALIDATOR_CONFIG_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    mode: Literal[LIVE_SHADOW_MODE]
    translation_weights_active: Literal[False]
    policy_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    scoring_policy_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    conformance_release_root: Annotated[str, Field(min_length=1, max_length=4_096)]
    state_root: Annotated[str, Field(min_length=1, max_length=4_096)]
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    target_triple: Annotated[str, Field(min_length=1, max_length=128)]
    storage_proof_verifier_binary: Annotated[str, Field(min_length=1, max_length=4_096)]
    finality_verifier_binary: Annotated[str, Field(min_length=1, max_length=4_096)]
    finality_chain_spec_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    initial_minimum_finalized_block: Annotated[int, Field(ge=0)]
    signature_scheme: Literal["sr25519", "ed25519"]
    umi_revision: Annotated[str, Field(min_length=1, max_length=256)]
    maximum_transport_concurrency: Annotated[int, Field(ge=1, le=1_024)]
    transport_timeout_seconds: Annotated[float, Field(gt=0, le=300)]
    stage_port_timeout_seconds: Annotated[float, Field(gt=0, le=300)] = 30.0
    maximum_anchor_advances: Annotated[int, Field(ge=1, le=16)] = 4
    poll_seconds: Annotated[float, Field(ge=MIN_POLL_SECONDS, le=MAX_POLL_SECONDS)] = 1.0

    @model_validator(mode="after")
    def validate_local_bindings(self) -> Self:
        account_id32(self.validator_hotkey)
        if _TARGET_RE.fullmatch(self.target_triple) is None:
            raise ValueError("target triple is not canonical")
        paths = tuple(
            Path(value)
            for value in (
                self.policy_path,
                self.conformance_release_root,
                self.state_root,
                self.storage_proof_verifier_binary,
                self.finality_verifier_binary,
                self.finality_chain_spec_path,
            )
        )
        if any(not value.is_absolute() for value in paths):
            raise ValueError("all live-validator paths must be absolute")
        if any(value != Path(os.path.normpath(value)) for value in paths):
            raise ValueError("live-validator paths must be lexically normalized")
        if len({os.fspath(value) for value in paths}) != len(paths):
            raise ValueError("live-validator paths must be distinct")
        release_root = paths[1]
        state_root = paths[2]
        if (
            state_root == release_root
            or state_root in release_root.parents
            or release_root in state_root.parents
            or any(state_root in value.parents for value in paths[3:])
            or state_root in paths[0].parents
        ):
            raise ValueError("immutable startup inputs must be outside the state root")
        return self


@dataclass(frozen=True, slots=True)
class LiveRuntimeValidation:
    """Target-specific executable identities copied into every audit bundle."""

    target_triple: str
    storage_proof_verifier_sha256: str
    finality_verifier_sha256: str
    finality_chain_spec_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.target_triple, str) or not self.target_triple:
            raise ValueError("runtime-validation target triple must be nonempty")
        for name in (
            "storage_proof_verifier_sha256",
            "finality_verifier_sha256",
            "finality_chain_spec_sha256",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or _HEX32_RE.fullmatch(value) is None:
                raise ValueError(f"{name} must be lowercase SHA-256 hexadecimal")

    @classmethod
    def from_mapping(cls, value: Mapping[str, str]) -> LiveRuntimeValidation:
        if not isinstance(value, Mapping):
            raise TypeError("runtime validation must be a mapping")
        try:
            return cls(
                target_triple=value["target_triple"],
                storage_proof_verifier_sha256=value["storage_proof_verifier_sha256"],
                finality_verifier_sha256=value["finality_verifier_sha256"],
                finality_chain_spec_sha256=value["finality_chain_spec_sha256"],
            )
        except KeyError as error:
            raise LiveValidatorConfigError("runtime_validation_incomplete") from error

    def software_revisions(self, umi_revision: str) -> dict[str, str]:
        return {
            "finality_chain_spec_sha256": self.finality_chain_spec_sha256,
            "finality_verifier_sha256": self.finality_verifier_sha256,
            "storage_proof_verifier_sha256": self.storage_proof_verifier_sha256,
            "target_triple": self.target_triple,
            "umi": umi_revision,
        }


@dataclass(frozen=True, slots=True)
class LiveValidatorPaths:
    """Fixed, disjoint durable paths below one operator-selected root."""

    root: Path
    control_plane: Path
    stage_journal: Path
    extrinsic_journal: Path
    assignments: Path
    window_material: Path
    protocol_state: Path
    monitoring_state: Path
    reveal_coordinator: Path
    plan_observations: Path
    finality_state: Path
    anchor_sidecars: Path
    transcript_resources: Path
    btauth_nonces: Path
    pool_mirror: Path
    bundles: Path
    incident_bundles: Path

    @classmethod
    def below(cls, root: str | Path) -> LiveValidatorPaths:
        value = Path(root)
        if not value.is_absolute():
            raise LiveValidatorConfigError("state_root_not_absolute")
        return cls(
            root=value,
            control_plane=value / "control-plane.sqlite3",
            stage_journal=value / "stage-journal",
            extrinsic_journal=value / "extrinsic-journal",
            assignments=value / "assignments",
            window_material=value / "window-material",
            protocol_state=value / "protocol-state.sqlite3",
            monitoring_state=value / "monitoring-state.sqlite3",
            reveal_coordinator=value / "reveal-coordinator.sqlite3",
            plan_observations=value / "plan-observations.sqlite3",
            finality_state=value / "grandpa-finality.sqlite3",
            anchor_sidecars=value / "anchor-sidecars",
            transcript_resources=value / "transcript-resources",
            btauth_nonces=value / "btauth-nonces",
            pool_mirror=value / "pool-mirror.sqlite3",
            bundles=value / "calibration-bundles",
            incident_bundles=value / "incident-bundles",
        )


@dataclass(frozen=True, slots=True)
class LiveValidatorPorts:
    """Fully resolved narrow ports consumed by the seven stage effects.

    Tests may supply this object directly. Production callers must use
    :func:`build_production_live_validator`, which constructs the available
    proof-backed ports and enforces their concrete types.
    """

    finalized_blocks: Any
    prior_readiness: Any
    pool_source: Any
    closing_snapshot: Any
    selection_pulse: Any
    delivery_issuance: Any
    prepared_assignments: Any
    transcript_plan: Any
    observe: Any
    anchor_ports: Any
    transcript_audit_release: Any
    transport: Any
    prepare_retry: Any
    reveal_pulse: Any
    decrypt: Any
    reveal_audit_release: Any
    weight_schedule: Any
    weight_snapshot: Any
    no_weight_capture: Any
    weight_close_resolver: Any
    bundle_verifier: Any
    incident_bundle_verifier: Any
    manifest_signer: Any

    def __post_init__(self) -> None:
        methods = {
            "finalized_blocks": ("finalized_head_height", "verified_block_at"),
            "prior_readiness": ("verified_reveal_and_spent",),
            "anchor_ports": ("__call__", "verify_anchor"),
            "no_weight_capture": ("capture",),
            "bundle_verifier": ("verify",),
            "incident_bundle_verifier": ("verify",),
        }
        for name, required in methods.items():
            value = getattr(self, name)
            if any(not callable(getattr(value, method, None)) for method in required):
                raise TypeError(f"live-validator {name} port is incomplete")
        for name in (
            "pool_source",
            "closing_snapshot",
            "selection_pulse",
            "delivery_issuance",
            "prepared_assignments",
            "transcript_plan",
            "observe",
            "transcript_audit_release",
            "transport",
            "prepare_retry",
            "reveal_pulse",
            "decrypt",
            "reveal_audit_release",
            "weight_schedule",
            "weight_snapshot",
            "weight_close_resolver",
            "manifest_signer",
        ):
            if not callable(getattr(self, name)):
                raise TypeError(f"live-validator {name} port must be callable")


@dataclass(frozen=True, slots=True)
class LiveValidatorBuildContext:
    """Local durable objects made available to one synchronous port factory."""

    policy: ScoringPolicy
    config: LiveValidatorConfig
    runtime_validation: LiveRuntimeValidation
    paths: LiveValidatorPaths
    control_plane: ValidatorControlPlane
    stage_journal: ValidatorStageJournal
    extrinsic_journal: ValidatorExtrinsicJournal
    assignments: ValidatorAssignmentStore
    window_material: ValidatorWindowMaterialStore
    protocol_state: ValidatorProtocolStateStore
    monitoring_state: ValidatorMonitoringStateStore
    reveal_coordinator: RevealTransitionCoordinator


class LiveValidatorPortFactory(Protocol):
    def __call__(self, context: LiveValidatorBuildContext) -> LiveValidatorPorts: ...


@dataclass(frozen=True, slots=True)
class ProductionAnchorContext:
    """Exact inputs for the already-implemented three-anchor factory."""

    policy: ScoringPolicy
    config: LiveValidatorConfig
    paths: LiveValidatorPaths
    extrinsic_journal: ValidatorExtrinsicJournal
    finality: DurableGrandpaFinalityPort
    storage_proof_verifier: SubprocessStorageProofVerifier
    finality_verifier_sha256: str


class ProductionAnchorFactory(Protocol):
    def __call__(self, context: ProductionAnchorContext) -> BittensorAnchorPorts: ...


@dataclass(frozen=True, slots=True)
class ProductionTranscriptContext:
    """Exact inputs for the concrete transcript-port composition."""

    policy: ScoringPolicy
    config: LiveValidatorConfig
    paths: LiveValidatorPaths
    material_store: ValidatorWindowMaterialStore
    stage_journal: ValidatorStageJournal
    anchor_ports: BittensorAnchorPorts
    finality: DurableGrandpaFinalityPort
    rounds: GrandpaQuicknetRoundPort
    weight_schedule: Any
    validator_capacity_set: VerifiedValidatorCapacitySet


class ProductionTranscriptFactory(Protocol):
    def __call__(self, context: ProductionTranscriptContext) -> ProductionTranscriptPorts: ...


@dataclass(frozen=True, slots=True)
class ProductionPoolRevealContext:
    """Exact non-signing inputs for concrete pool/reveal read adapters."""

    policy: ScoringPolicy
    config: LiveValidatorConfig
    paths: LiveValidatorPaths
    finality: DurableGrandpaFinalityPort
    closing_snapshot: ProofBackedClosingSnapshotCollector
    prepared_assignments: Any
    mirror_discovery_rule_bytes: bytes
    mirror_request_headers: Mapping[str, Mapping[str, str]]
    mirror_readiness: VerifiedLiveMirrorReadiness
    reveal_audit_release_boundary: RevealAuditReleaseBoundaryPort


@dataclass(frozen=True, slots=True)
class ProductionPoolRevealPorts:
    """Concrete, internally bound pool/reveal adapters used by production."""

    pool: PoolEffectPorts
    reveal: RevealEffectPorts
    mirror: DurablePoolMirrorSource
    delivery_issuance: AuthenticatedMirrorDeliveryIssuer
    quicknet: QuicknetClient
    audit_release: FinalizedRevealAuditReleaseAdapter


class PrivateBtauthTranscriptFactory:
    """Keep the request-auth wallet behind the exact transcript adapter factory.

    The wallet never appears on ``LiveValidatorProductionDependencies`` or the
    returned runtime.  The concrete transcript module resolves only its hotkey
    signer and exposes prepared-attempt and bounded HTTP callables.
    """

    __slots__ = ("__wallet",)

    def __init__(self, wallet: Any) -> None:
        self.__wallet = wallet

    def __call__(self, context: ProductionTranscriptContext) -> ProductionTranscriptPorts:
        if not isinstance(context, ProductionTranscriptContext):
            raise TypeError("context must be ProductionTranscriptContext")
        return build_production_transcript_ports(
            policy=context.policy,
            validator_hotkey=context.config.validator_hotkey,
            wallet=self.__wallet,
            material_store=context.material_store,
            journal=context.stage_journal,
            anchor_ports=context.anchor_ports,
            finality=context.finality,
            rounds=context.rounds,
            schedule=context.weight_schedule,
            validator_capacity_set=context.validator_capacity_set,
            resource_root=context.paths.transcript_resources,
            nonce_root=context.paths.btauth_nonces,
            request_timeout_seconds=context.config.transport_timeout_seconds,
        )


class PrivateValidatorManifestSigner:
    """Expose one self-verifying hotkey digest signer and nothing broader."""

    __slots__ = ("__signer", "account_id32", "scheme")

    def __init__(
        self,
        wallet: Any,
        *,
        validator_hotkey: str,
        signature_scheme: Literal["sr25519", "ed25519"],
    ) -> None:
        import bittensor as bt

        signer = bt.resolve_signer(wallet, role="hotkey")
        scheme = bt.wallets.format_crypto_type(signer.crypto_type)
        if scheme != signature_scheme:
            raise ValueError("manifest signer scheme disagrees with live configuration")
        if account_id32(signer.ss58_address) != account_id32(validator_hotkey):
            raise ValueError("manifest signer hotkey disagrees with live configuration")
        self.__signer = signer
        self.account_id32 = account_id32(validator_hotkey)
        self.scheme = signature_scheme

    def __call__(self, digest: bytes) -> bytes:
        if not isinstance(digest, bytes) or len(digest) != 32:
            raise ValueError("manifest signer requires one raw 32-byte digest")
        signature = self.__signer.sign(digest)
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
            raise ValueError("manifest hotkey signer returned an invalid signature")
        result = bytes(signature)
        import bittensor as bt

        hotkey = bt.sp_core.ss58_encode(self.account_id32)
        if not verify_response_signature(
            digest,
            hotkey_ss58=hotkey,
            scheme=self.scheme,
            signature="0x" + result.hex(),
        ):
            raise ValueError("manifest hotkey signature did not self-verify")
        return result


def build_production_pool_reveal_ports(
    context: ProductionPoolRevealContext,
) -> ProductionPoolRevealPorts:
    """Build the policy-bound pool, Quicknet, decrypt, and release adapters.

    Construction is local-only: no mirror, drand, or chain request is made.  The
    only injected callables left in this boundary are deterministic assignment
    preparation and the proof-backed release-boundary resolver.
    """

    if not isinstance(context, ProductionPoolRevealContext):
        raise TypeError("context must be ProductionPoolRevealContext")
    if not callable(context.prepared_assignments):
        raise TypeError("prepared assignments port must be callable")
    if not callable(context.reveal_audit_release_boundary):
        raise TypeError("reveal audit-release boundary port must be callable")
    request_timeout = min(
        context.config.transport_timeout_seconds,
        context.config.stage_port_timeout_seconds,
    )
    mirror = DurablePoolMirrorSource(
        policy=context.policy,
        discovery_rule_bytes=context.mirror_discovery_rule_bytes,
        state_path=context.paths.pool_mirror,
        request_headers=context.mirror_request_headers,
        mirror_readiness=context.mirror_readiness,
        require_mirror_readiness=True,
        timeout_seconds=request_timeout,
    )
    delivery_issuance = AuthenticatedMirrorDeliveryIssuer(
        policy=context.policy,
        source=mirror,
    )
    quicknet = QuicknetClient(timeout_seconds=request_timeout)
    audit_release = FinalizedRevealAuditReleaseAdapter(
        policy=context.policy,
        finality=context.finality,
        boundary=context.reveal_audit_release_boundary,
    )
    pool = build_live_pool_effect_ports(
        policy=context.policy,
        source=mirror,
        closing_snapshot=context.closing_snapshot,
        delivery_issuance=delivery_issuance,
        prepared_assignments=context.prepared_assignments,
        quicknet_client=quicknet,
    )
    reveal = build_live_reveal_effect_ports(
        policy=context.policy,
        quicknet_client=quicknet,
        audit_release=audit_release,
    )
    result = ProductionPoolRevealPorts(
        pool=pool,
        reveal=reveal,
        mirror=mirror,
        delivery_issuance=delivery_issuance,
        quicknet=quicknet,
        audit_release=audit_release,
    )
    _validate_pool_reveal_ports(result, context)
    return result


@dataclass(frozen=True, slots=True)
class LiveValidatorProductionDependencies:
    """External capabilities assembled by the installed operator command.

    Every field defaults to ``None`` so construction can report the complete
    missing-capability set before starting service work. The operator
    composition supplies these values explicitly; there is no dynamic
    ``module:callable`` loader in the command.
    """

    raw_json_rpc: Any | None = None
    anchor_ports_factory: ProductionAnchorFactory | None = None
    transcript_ports_factory: ProductionTranscriptFactory | None = None
    validator_capacity_set: VerifiedValidatorCapacitySet | None = None
    mirror_discovery_rule_bytes: bytes | None = None
    mirror_request_headers: Mapping[str, Mapping[str, str]] | None = None
    mirror_readiness: VerifiedLiveMirrorReadiness | None = None
    manifest_signer: PrivateValidatorManifestSigner | None = None

    def missing_capability_codes(self) -> tuple[str, ...]:
        names = (
            ("raw_json_rpc", "missing_raw_json_rpc"),
            ("anchor_ports_factory", "missing_anchor_ports_factory"),
            ("transcript_ports_factory", "missing_transcript_ports_factory"),
            ("validator_capacity_set", "missing_validator_capacity_set"),
            (
                "mirror_discovery_rule_bytes",
                "missing_mirror_discovery_rule_bytes",
            ),
            ("mirror_request_headers", "missing_mirror_request_headers"),
            ("mirror_readiness", "missing_mirror_readiness"),
            ("manifest_signer", "missing_calibration_manifest_signer"),
        )
        return tuple(code for name, code in names if getattr(self, name) is None)

    def invalid_capability_codes(self) -> tuple[str, ...]:
        checks = (
            (
                "invalid_raw_json_rpc",
                self.raw_json_rpc is not None
                and not isinstance(self.raw_json_rpc, BittensorRawJsonRpc),
            ),
            (
                "invalid_anchor_ports_factory",
                self.anchor_ports_factory is not None and not callable(self.anchor_ports_factory),
            ),
            (
                "invalid_transcript_ports_factory",
                self.transcript_ports_factory is not None
                and not callable(self.transcript_ports_factory),
            ),
            (
                "invalid_validator_capacity_set",
                self.validator_capacity_set is not None
                and not isinstance(
                    self.validator_capacity_set,
                    VerifiedValidatorCapacitySet,
                ),
            ),
            (
                "invalid_mirror_discovery_rule_bytes",
                self.mirror_discovery_rule_bytes is not None
                and (
                    not isinstance(self.mirror_discovery_rule_bytes, bytes)
                    or not self.mirror_discovery_rule_bytes
                ),
            ),
            (
                "invalid_mirror_request_headers",
                self.mirror_request_headers is not None
                and not _is_origin_header_mapping(self.mirror_request_headers),
            ),
            (
                "invalid_mirror_readiness",
                self.mirror_readiness is not None
                and not isinstance(self.mirror_readiness, VerifiedLiveMirrorReadiness),
            ),
        )
        invalid = [code for code, failed in checks if failed]
        for name, code in (("manifest_signer", "invalid_calibration_manifest_signer"),):
            value = getattr(self, name)
            if value is not None and not isinstance(
                value,
                PrivateValidatorManifestSigner,
            ):
                invalid.append(code)
        return tuple(invalid)


class LiveValidatorRuntime:
    """Owned service/finality lifetime with no public mutation capability."""

    __slots__ = (
        "_closed",
        "_closers",
        "_control_plane",
        "_engine",
        "_finality_runner",
        "_paths",
        "_policy_hash",
        "_service",
    )

    def __init__(
        self,
        *,
        service: ValidatorService,
        engine: ValidatorEngine,
        control_plane: ValidatorControlPlane,
        finality_runner: Any | None,
        paths: LiveValidatorPaths,
        policy_hash: str,
        closers: Sequence[Callable[[], None]],
    ) -> None:
        self._service = service
        self._engine = engine
        self._control_plane = control_plane
        self._finality_runner = finality_runner
        self._paths = paths
        self._policy_hash = policy_hash
        self._closers = tuple(closers)
        self._closed = False

    @property
    def service(self) -> ValidatorService:
        """Return the scheduler, which still exposes no wallet or call builder."""

        return self._service

    @property
    def configured_stages(self) -> tuple[WindowStage, ...]:
        return self._engine.configured_stages

    @property
    def paths(self) -> LiveValidatorPaths:
        return self._paths

    @property
    def scoring_policy_hash(self) -> str:
        return self._policy_hash

    def recovery_state(self):
        """Return the durable control-plane recovery view without exposing mutation."""

        return self._control_plane.recovery_state()

    async def run(self, stop_event: asyncio.Event, *, poll_seconds: float) -> None:
        """Supervise the owned finality observer and responsive scheduler together."""

        if not isinstance(stop_event, asyncio.Event):
            raise TypeError("stop_event must be an asyncio.Event")
        if self._closed:
            raise LiveValidatorRuntimeError("runtime_closed")
        jobs = [
            asyncio.create_task(
                self._service.run(stop_event, poll_seconds=poll_seconds),
                name="umi-validator-service",
            )
        ]
        if self._finality_runner is not None:
            run = getattr(self._finality_runner, "run", None)
            if not callable(run):
                raise LiveValidatorRuntimeError("finality_runner_invalid")
            jobs.append(asyncio.create_task(run(stop_event), name="umi-grandpa-finality"))
        try:
            done, pending = await asyncio.wait(jobs, return_when=asyncio.FIRST_COMPLETED)
            failure: BaseException | None = None
            for task in done:
                try:
                    exception = task.exception()
                except asyncio.CancelledError as error:
                    exception = error
                if exception is not None:
                    failure = exception
                    break
            if failure is None and not stop_event.is_set():
                failure = LiveValidatorRuntimeError("supervised_component_stopped")
            stop_event.set()
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            if failure is not None:
                raise failure
        finally:
            stop_event.set()
            for task in jobs:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*jobs, return_exceptions=True)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for close in reversed(self._closers):
            with suppress(Exception):
                close()

    def __enter__(self) -> LiveValidatorRuntime:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def load_live_validator_config(path: str | Path) -> LiveValidatorConfig:
    """Load one exact RFC 8785 startup document from a regular file."""

    encoded = _read_startup_file(path, label="config")
    try:
        config = LiveValidatorConfig.model_validate_json(encoded)
    except (ValidationError, ValueError) as error:
        raise LiveValidatorConfigError("config_invalid") from error
    if canonical_json_bytes(config) != encoded:
        raise LiveValidatorConfigError("config_noncanonical")
    return config


def load_live_policy(config: LiveValidatorConfig) -> ScoringPolicy:
    """Load and bind the exact canonical policy selected by ``config``."""

    if not isinstance(config, LiveValidatorConfig):
        raise TypeError("config must be a LiveValidatorConfig")
    encoded = _read_startup_file(config.policy_path, label="policy")
    try:
        policy = ScoringPolicy.model_validate_json(encoded)
    except (ValidationError, ValueError) as error:
        raise LiveValidatorConfigError("policy_invalid") from error
    if canonical_json_bytes(policy) != encoded:
        raise LiveValidatorConfigError("policy_noncanonical")
    if hashlib.sha256(encoded).hexdigest() != config.scoring_policy_sha256:
        raise LiveValidatorConfigError("policy_digest_mismatch")
    _require_live_policy(policy, config)
    return policy


def validate_live_startup(
    config: LiveValidatorConfig,
    policy: ScoringPolicy,
) -> LiveRuntimeValidation:
    """Verify the target-specific binaries and return their exact audit binding."""

    _require_live_policy(policy, config)
    try:
        selected = validate_live_shadow_runtime(
            policy,
            target_triple=config.target_triple,
            storage_proof_verifier_binary=config.storage_proof_verifier_binary,
            finality_verifier_binary=config.finality_verifier_binary,
            finality_chain_spec_path=config.finality_chain_spec_path,
        )
    except Exception as error:
        raise LiveValidatorConfigError("runtime_pin_validation_failed") from error
    validation = LiveRuntimeValidation.from_mapping(selected)
    _require_runtime_validation(policy, config, validation)
    _execute_packaged_conformance(policy, config)
    return validation


def _execute_packaged_conformance(
    policy: ScoringPolicy,
    config: LiveValidatorConfig,
) -> None:
    """Rerun the signed release's exact fixtures and executables at startup."""

    pins = policy.implementation_pins
    live = pins.live_chain
    proof = pins.storage_proof_verifier
    finality = pins.finality_verifier
    report_sha256 = pins.conformance_execution_report_sha256
    if live is None or proof is None or finality is None or report_sha256 is None:
        raise LiveValidatorConfigError("policy_not_fully_pinned")

    root = Path(config.conformance_release_root)

    def artifact(digest: str, filename: str) -> Path:
        return root / "artifacts" / "sha256" / digest / filename

    expected_policy_path = root / "scoring-policy.json"
    proof_path = artifact(
        proof.release_sha256_by_target[config.target_triple],
        "umi-substrate-proof-verifier",
    )
    finality_path = artifact(
        finality.release_sha256_by_target[config.target_triple],
        "umi-grandpa-finality-observer",
    )
    chain_spec_path = artifact(finality.chain_spec_sha256, "finney-chain-spec.json")
    if (
        Path(config.policy_path) != expected_policy_path
        or Path(config.storage_proof_verifier_binary) != proof_path
        or Path(config.finality_verifier_binary) != finality_path
        or Path(config.finality_chain_spec_path) != chain_spec_path
    ):
        raise LiveValidatorConfigError("conformance_release_path_binding_mismatch")

    report_path = root / "conformance-execution-report.json"
    report_bytes = _read_startup_file(report_path, label="conformance_report")
    if hashlib.sha256(report_bytes).hexdigest() != report_sha256:
        raise LiveValidatorConfigError("conformance_report_digest_mismatch")
    try:
        report = ConformanceExecutionReport.model_validate_json(report_bytes)
    except Exception as error:
        raise LiveValidatorConfigError("conformance_report_invalid") from error
    if canonical_json_bytes(report) != report_bytes:
        raise LiveValidatorConfigError("conformance_report_noncanonical")

    fixture_paths = ConformanceFixturePaths(
        normalization=artifact(
            pins.scoring.normalization_fixture_set_sha256,
            "normalization-fixtures.json",
        ),
        media=artifact(
            pins.media.frame_digest_fixture_set_sha256,
            "frame-digest-fixtures.json",
        ),
        timelock=artifact(
            pins.timelock.portable_envelope_fixture_set_sha256,
            "portable-envelope-fixtures.json",
        ),
        chain=artifact(pins.chain.chain_fixture_set_sha256, "chain-fixtures.json"),
        live_chain=artifact(live.live_chain_fixture_set_sha256, "live-chain-fixtures.json"),
        storage_proof=artifact(
            proof.proof_fixture_set_sha256,
            "storage-proof-fixtures.json",
        ),
        finality=artifact(finality.finality_fixture_set_sha256, "finality-fixtures.json"),
    )
    binaries = ConformanceBinaryPins(
        ffmpeg_path=artifact(pins.media.ffmpeg_binary_sha256, "ffmpeg"),
        ffmpeg_sha256=pins.media.ffmpeg_binary_sha256,
        ffprobe_path=artifact(pins.media.ffprobe_binary_sha256, "ffprobe"),
        ffprobe_sha256=pins.media.ffprobe_binary_sha256,
        storage_proof_verifier_path=proof_path,
        storage_proof_verifier_sha256=proof.release_sha256_by_target[config.target_triple],
        finality_verifier_path=finality_path,
        finality_verifier_sha256=finality.release_sha256_by_target[config.target_triple],
    )
    try:
        execution = _run_conformance_suite(fixture_paths, binaries)
    except ConformanceError as error:
        raise LiveValidatorConfigError(
            f"conformance_execution_failed:{error.reason_code}"
        ) from error
    except Exception as error:
        raise LiveValidatorConfigError("conformance_execution_failed") from error
    if (
        execution.verified is not True
        or execution.canonical_report_bytes != report_bytes
        or execution.report_sha256 != report_sha256
        or execution.report != report
    ):
        raise LiveValidatorConfigError("conformance_report_reproduction_mismatch")


def _run_conformance_suite(
    fixture_paths: ConformanceFixturePaths,
    binaries: ConformanceBinaryPins,
) -> ConformanceExecution:
    """Run the synchronous suite outside an already-running event loop."""

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return execute_conformance_suite(fixture_paths, binaries=binaries)
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="umi-conformance") as executor:
        return executor.submit(
            execute_conformance_suite,
            fixture_paths,
            binaries=binaries,
        ).result()


def build_live_validator_primer(
    *,
    config: LiveValidatorConfig,
) -> LiveValidatorPrimer:
    """Build the read-only planner needed before a window readiness set exists.

    The primer owns only the finalized-header observer, deterministic plan source,
    prior-bundle replay boundary, and stores required to record the next window.
    It has no wallet, mirror client, anchor adapter, transcript transport, or stage
    engine. Full validator construction remains a separate readiness-gated path.
    """

    if not isinstance(config, LiveValidatorConfig):
        raise TypeError("config must be a LiveValidatorConfig")
    policy = load_live_policy(config)
    runtime_validation = validate_live_startup(config, policy)
    paths = LiveValidatorPaths.below(config.state_root)
    _prepare_state_root(paths.root)
    protocol_state: ValidatorProtocolStateStore | None = None
    finality: DurableGrandpaFinalityPort | None = None
    try:
        control = ValidatorControlPlane(paths.control_plane)
        control.pause(
            PauseScope.WEIGHT_SUBMISSION,
            reason_code="live_shadow_calibration",
            operation_id=WEIGHT_DISABLED_HOLD_ID,
        )
        journal = ValidatorStageJournal(paths.stage_journal)
        protocol_state = ValidatorProtocolStateStore(paths.protocol_state)
        finality = DurableGrandpaFinalityPort.from_policy(
            policy,
            target_triple=config.target_triple,
            binary_path=config.finality_verifier_binary,
            chain_spec_path=config.finality_chain_spec_path,
            state_path=paths.finality_state,
            initial_minimum_finalized_block=config.initial_minimum_finalized_block,
        )
        proof_verifier = SubprocessStorageProofVerifier(
            binary_path=config.storage_proof_verifier_binary,
            expected_sha256=runtime_validation.storage_proof_verifier_sha256,
        )
        bundle_verifier = build_production_calibration_bundle_verifier(
            policy=policy,
            target_triple=config.target_triple,
            finality_verifier_binary=config.finality_verifier_binary,
            finality_chain_spec=config.finality_chain_spec_path,
            storage_proof_verifier=proof_verifier,
        )
        _validate_bundle_verifier(
            bundle_verifier,
            policy,
            runtime_validation,
            proof_verifier,
        )
        prior_readiness = ProofBackedPriorWindowReadiness(
            policy=policy,
            protocol_state=protocol_state,
            journal=journal,
            bundle_root=paths.bundles,
            incident_bundle_root=paths.incident_bundles,
            bundle_verifier=ReplayPublishedBundleVerifier(bundle_verifier.ports),
            finality=finality,
        )
        plan_source = DeterministicWindowPlanSource(
            policy=policy,
            control_plane=control,
            finalized_blocks=finality,
            prior_readiness=prior_readiness,
            observation_cache_path=paths.plan_observations,
        )
        return LiveValidatorPrimer(
            control_plane=control,
            plan_source=plan_source,
            finality=finality,
            protocol_state=protocol_state,
            paths=paths,
            policy_hash=scoring_policy_hash(policy),
        )
    except LiveValidatorError:
        if protocol_state is not None:
            protocol_state.close()
        if finality is not None:
            finality.close()
        raise
    except Exception as error:
        if protocol_state is not None:
            protocol_state.close()
        if finality is not None:
            finality.close()
        raise LiveValidatorCompositionError("prime_composition_failed") from error


def build_live_validator(
    *,
    config: LiveValidatorConfig,
    policy: ScoringPolicy,
    runtime_validation: LiveRuntimeValidation,
    port_factory: LiveValidatorPortFactory,
) -> LiveValidatorRuntime:
    """Assemble all seven effects around one synchronous injectable port factory.

    This construction path is useful for deterministic tests and for the strict
    production wrapper below.  It performs local durable-store recovery only.
    The port factory must not perform I/O; an awaitable result is rejected.
    """

    if not isinstance(config, LiveValidatorConfig):
        raise TypeError("config must be a LiveValidatorConfig")
    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be a ScoringPolicy")
    if not isinstance(runtime_validation, LiveRuntimeValidation):
        raise TypeError("runtime_validation must be LiveRuntimeValidation")
    if not callable(port_factory):
        raise TypeError("port_factory must be callable")
    _require_live_policy(policy, config)
    _require_runtime_validation(policy, config, runtime_validation)
    paths = LiveValidatorPaths.below(config.state_root)
    _prepare_state_root(paths.root)

    closers: list[Callable[[], None]] = []
    try:
        control = ValidatorControlPlane(paths.control_plane)
        control.pause(
            PauseScope.WEIGHT_SUBMISSION,
            reason_code="live_shadow_calibration",
            operation_id=WEIGHT_DISABLED_HOLD_ID,
        )
        stage_journal = ValidatorStageJournal(paths.stage_journal)
        extrinsics = ValidatorExtrinsicJournal(paths.extrinsic_journal)
        assignments = ValidatorAssignmentStore(paths.assignments)
        abort_registry = DurableTranscriptAbortRegistry(assignments.root / "abort-registry")
        material = ValidatorWindowMaterialStore(paths.window_material)
        protocol_state = ValidatorProtocolStateStore(paths.protocol_state)
        closers.append(protocol_state.close)
        monitoring_state = ValidatorMonitoringStateStore(
            paths.monitoring_state,
            policy=_monitoring_policy(policy, config.validator_hotkey),
        )
        closers.append(monitoring_state.close)
        coordinator = RevealTransitionCoordinator(paths.reveal_coordinator)
        closers.append(coordinator.close)
        context = LiveValidatorBuildContext(
            policy=policy,
            config=config,
            runtime_validation=runtime_validation,
            paths=paths,
            control_plane=control,
            stage_journal=stage_journal,
            extrinsic_journal=extrinsics,
            assignments=assignments,
            window_material=material,
            protocol_state=protocol_state,
            monitoring_state=monitoring_state,
            reveal_coordinator=coordinator,
        )
        ports = port_factory(context)
        if inspect.isawaitable(ports):
            raise LiveValidatorCompositionError("async_port_factory_forbidden")
        if not isinstance(ports, LiveValidatorPorts):
            raise LiveValidatorCompositionError("port_factory_result_invalid")
        close_finality = getattr(ports.finalized_blocks, "close", None)
        if callable(close_finality):
            closers.append(close_finality)

        transcript_ports = TranscriptEffectPorts(
            plan=ports.transcript_plan,
            observe=ports.observe,
            anchor_ports=ports.anchor_ports,
            verify_anchor=ports.anchor_ports.verify_anchor,
            audit_release_block=ports.transcript_audit_release,
            transport=ports.transport,
            prepare_retry=ports.prepare_retry,
        )
        effects = {
            WindowStage.POOL_AND_SELECTION: PoolAndSelectionEffect(
                policy=policy,
                validator_hotkey=config.validator_hotkey,
                material_store=material,
                protocol_state=protocol_state,
                ports=PoolEffectPorts(
                    source=ports.pool_source,
                    closing_snapshot=ports.closing_snapshot,
                    selection_pulse=ports.selection_pulse,
                    delivery_issuance=ports.delivery_issuance,
                    prepared_assignments=ports.prepared_assignments,
                    incident_audit_release=ports.transcript_audit_release,
                ),
                abort_registry=abort_registry,
                port_timeout_seconds=config.stage_port_timeout_seconds,
            ),
            WindowStage.ASSIGNMENT: AssignmentTranscriptEffect(
                assignments=assignments,
                extrinsics=extrinsics,
                ports=transcript_ports,
                abort_registry=abort_registry,
                maximum_anchor_advances=config.maximum_anchor_advances,
            ),
            WindowStage.REQUEST_TRANSCRIPT: RequestTranscriptEffect(
                assignments=assignments,
                extrinsics=extrinsics,
                ports=transcript_ports,
                maximum_transport_concurrency=config.maximum_transport_concurrency,
                transport_timeout_seconds=config.transport_timeout_seconds,
                maximum_anchor_advances=config.maximum_anchor_advances,
                abort_registry=abort_registry,
            ),
            WindowStage.SEALED_RESPONSE: SealedResponseTranscriptEffect(
                assignments=assignments,
                extrinsics=extrinsics,
                ports=transcript_ports,
                maximum_anchor_advances=config.maximum_anchor_advances,
                abort_registry=abort_registry,
            ),
            WindowStage.REVEAL_AND_SCORE: ValidatorRevealEffect(
                policy=policy,
                validator_hotkey=config.validator_hotkey,
                journal=stage_journal,
                material_store=material,
                protocol_state=protocol_state,
                monitoring_state=monitoring_state,
                coordinator=coordinator,
                ports=RevealEffectPorts(
                    reveal_pulse=ports.reveal_pulse,
                    decrypt=ports.decrypt,
                    audit_release=ports.reveal_audit_release,
                ),
                port_timeout_seconds=config.stage_port_timeout_seconds,
            ),
            WindowStage.WEIGHT_BUILD: ShadowWeightBuildEffect(
                policy=policy,
                journal=stage_journal,
                protocol_state=protocol_state,
                ports=WeightBuildEffectPorts(
                    schedule=ports.weight_schedule,
                    snapshot=ports.weight_snapshot,
                ),
                validator_hotkey=config.validator_hotkey,
            ),
            WindowStage.COMMIT_AND_TERMINAL_STATE: CalibrationNoWeightTerminalEffect(
                policy=policy,
                journal=stage_journal,
                no_weight_capture=ports.no_weight_capture,
                weight_close_resolver=ports.weight_close_resolver,
                bundle_root=paths.bundles,
                bundle_verifier=ports.bundle_verifier,
                validator_account=config.validator_hotkey,
                signature_scheme=config.signature_scheme,
                manifest_signer=ports.manifest_signer,
                software_revisions=runtime_validation.software_revisions(config.umi_revision),
            ),
        }
        incident_observer = ShadowIncidentReceiptObserver(
            policy=policy,
            journal=stage_journal,
            no_weight_capture=ports.no_weight_capture,
            bundle_root=paths.incident_bundles,
            bundle_verifier=ports.incident_bundle_verifier,
            validator_account=config.validator_hotkey,
            signature_scheme=config.signature_scheme,
            manifest_signer=ports.manifest_signer,
            software_revisions=runtime_validation.software_revisions(config.umi_revision),
        )
        adapters = {
            stage: JournalStageAdapter(
                stage=stage,
                journal=stage_journal,
                effect=effects[stage],
                receipt_observer=incident_observer,
            )
            for stage in STAGE_ORDER
        }
        engine = ValidatorEngine(control, adapters)
        if engine.configured_stages != STAGE_ORDER:
            raise LiveValidatorCompositionError("seven_stage_adapter_set_incomplete")
        plan_source = DeterministicWindowPlanSource(
            policy=policy,
            control_plane=control,
            finalized_blocks=ports.finalized_blocks,
            prior_readiness=ports.prior_readiness,
            observation_cache_path=paths.plan_observations,
        )
        policy_hash = scoring_policy_hash(policy)
        service = ValidatorService(
            control_plane=control,
            engine=engine,
            plan_source=plan_source,
            scoring_policy_hash=policy_hash,
        )
        return LiveValidatorRuntime(
            service=service,
            engine=engine,
            control_plane=control,
            finality_runner=(
                ports.finalized_blocks
                if callable(getattr(ports.finalized_blocks, "run", None))
                else None
            ),
            paths=paths,
            policy_hash=policy_hash,
            closers=closers,
        )
    except BaseException:
        for close in reversed(closers):
            with suppress(Exception):
                close()
        raise


def build_production_live_validator(
    *,
    config: LiveValidatorConfig,
    dependencies: LiveValidatorProductionDependencies,
) -> LiveValidatorRuntime:
    """Validate pins and build every currently concrete production component."""

    if not isinstance(config, LiveValidatorConfig):
        raise TypeError("config must be a LiveValidatorConfig")
    if not isinstance(dependencies, LiveValidatorProductionDependencies):
        raise TypeError("dependencies must be LiveValidatorProductionDependencies")
    policy = load_live_policy(config)
    missing = dependencies.missing_capability_codes()
    if missing:
        raise LiveValidatorMissingCapabilities(missing)
    invalid = dependencies.invalid_capability_codes()
    if invalid:
        raise LiveValidatorInvalidCapabilities(invalid)
    runtime_validation = validate_live_startup(config, policy)

    def production_ports(context: LiveValidatorBuildContext) -> LiveValidatorPorts:
        pins = policy.implementation_pins
        live = pins.live_chain
        proof_pin = pins.storage_proof_verifier
        finality_pin = pins.finality_verifier
        if (
            live is None or proof_pin is None or finality_pin is None
        ):  # narrowed by _require_live_policy
            raise LiveValidatorCompositionError("live_runtime_pins_missing")
        try:
            finality = DurableGrandpaFinalityPort.from_policy(
                policy,
                target_triple=config.target_triple,
                binary_path=config.finality_verifier_binary,
                chain_spec_path=config.finality_chain_spec_path,
                state_path=context.paths.finality_state,
                initial_minimum_finalized_block=(config.initial_minimum_finalized_block),
            )
            proof_verifier = SubprocessStorageProofVerifier(
                binary_path=config.storage_proof_verifier_binary,
                expected_sha256=runtime_validation.storage_proof_verifier_sha256,
            )
            bundle_verifier = build_production_calibration_bundle_verifier(
                policy=policy,
                target_triple=config.target_triple,
                finality_verifier_binary=config.finality_verifier_binary,
                finality_chain_spec=config.finality_chain_spec_path,
                storage_proof_verifier=proof_verifier,
            )
            runtime_pin = FinalizedRuntimePin(
                metadata_sha256=live.metadata_sha256,
                spec_version=live.runtime_spec_version,
                transaction_version=live.transaction_version,
                state_version=live.state_version,
                ss58_prefix=42,
            )
            proofs = FinalizedProofCollector(
                dependencies.raw_json_rpc,
                finality=finality,
                verifier=proof_verifier,
            )
            scan_port = LiveFinalizedBlockScanPort(
                rpc=dependencies.raw_json_rpc,
                proofs=proofs,
                runtime_pin=runtime_pin,
            )
            scanner = FinalizedBlockScanner(
                scan_port,
                extrinsics_root_verifier=proof_verifier.verify_extrinsics_root,
                event_proof_verifier=proof_verifier,
                supported_runtime_pins=(runtime_pin,),
            )
            closing = ProofBackedClosingSnapshotCollector(
                policy=policy,
                finality=finality,
                proofs=proofs,
            )
            no_weight = LiveNoWeightCapturePort(
                finality=finality,
                scanner=scanner,
                validator_account=config.validator_hotkey,
            )
            weight_ports = build_live_weight_ports(
                policy=policy,
                finality=finality,
                proofs=proofs,
                validator_hotkey=config.validator_hotkey,
            )
            rounds = GrandpaQuicknetRoundPort(
                finality=finality,
                scoring_policy_sha256=scoring_policy_hash(policy),
                chain_observation=live,
                finality_pin=finality_pin,
                finality_verifier_sha256=runtime_validation.finality_verifier_sha256,
            )
            close_resolver = ProofBackedWeightBuildCloseResolver(proof_verifier)
            anchor = dependencies.anchor_ports_factory(
                ProductionAnchorContext(
                    policy=policy,
                    config=config,
                    paths=context.paths,
                    extrinsic_journal=context.extrinsic_journal,
                    finality=finality,
                    storage_proof_verifier=proof_verifier,
                    finality_verifier_sha256=runtime_validation.finality_verifier_sha256,
                )
            )
            transcript_context = ProductionTranscriptContext(
                policy=policy,
                config=config,
                paths=context.paths,
                material_store=context.window_material,
                stage_journal=context.stage_journal,
                anchor_ports=anchor,
                finality=finality,
                rounds=rounds,
                weight_schedule=weight_ports.schedule,
                validator_capacity_set=dependencies.validator_capacity_set,
            )
            transcript = dependencies.transcript_ports_factory(transcript_context)
            prepared_assignments = FinalizedPreparedAssignmentsAdapter(
                policy=policy,
                validator_hotkey=config.validator_hotkey,
                finality=finality,
                btauth=transcript.btauth,
            )
            reveal_audit_release_boundary = ProofBackedRevealAuditReleaseBoundaryPort(
                policy=policy,
                schedule=weight_ports.schedule,
            )
            pool_reveal_context = ProductionPoolRevealContext(
                policy=policy,
                config=config,
                paths=context.paths,
                finality=finality,
                closing_snapshot=closing,
                prepared_assignments=prepared_assignments,
                mirror_discovery_rule_bytes=dependencies.mirror_discovery_rule_bytes,
                mirror_request_headers=dependencies.mirror_request_headers,
                mirror_readiness=dependencies.mirror_readiness,
                reveal_audit_release_boundary=reveal_audit_release_boundary,
            )
            pool_reveal = build_production_pool_reveal_ports(pool_reveal_context)
        except LiveValidatorError:
            raise
        except Exception as error:
            raise LiveValidatorCompositionError(
                "production_read_only_port_composition_failed"
            ) from error
        _validate_anchor_adapter(anchor, policy, config, runtime_validation, runtime_pin)
        _validate_transcript_ports(
            transcript,
            transcript_context,
        )
        _validate_bundle_verifier(
            bundle_verifier,
            policy,
            runtime_validation,
            proof_verifier,
        )
        published_bundle_verifier = ReplayPublishedBundleVerifier(bundle_verifier.ports)
        prior_readiness = ProofBackedPriorWindowReadiness(
            policy=policy,
            protocol_state=context.protocol_state,
            journal=context.stage_journal,
            bundle_root=context.paths.bundles,
            incident_bundle_root=context.paths.incident_bundles,
            bundle_verifier=published_bundle_verifier,
            finality=finality,
        )
        return LiveValidatorPorts(
            finalized_blocks=finality,
            prior_readiness=prior_readiness,
            pool_source=pool_reveal.pool.source,
            closing_snapshot=pool_reveal.pool.closing_snapshot,
            selection_pulse=pool_reveal.pool.selection_pulse,
            delivery_issuance=pool_reveal.pool.delivery_issuance,
            prepared_assignments=pool_reveal.pool.prepared_assignments,
            transcript_plan=transcript.plan,
            observe=transcript.observe,
            anchor_ports=anchor,
            transcript_audit_release=transcript.audit_release,
            transport=transcript.transport,
            prepare_retry=transcript.btauth,
            reveal_pulse=pool_reveal.reveal.reveal_pulse,
            decrypt=pool_reveal.reveal.decrypt,
            reveal_audit_release=pool_reveal.reveal.audit_release,
            weight_schedule=weight_ports.schedule,
            weight_snapshot=weight_ports.snapshot,
            no_weight_capture=no_weight,
            weight_close_resolver=close_resolver,
            bundle_verifier=bundle_verifier,
            incident_bundle_verifier=ReplayIncidentBundleVerifier(bundle_verifier.ports),
            manifest_signer=dependencies.manifest_signer,
        )

    return build_live_validator(
        config=config,
        policy=policy,
        runtime_validation=runtime_validation,
        port_factory=production_ports,
    )


def _require_live_policy(policy: ScoringPolicy, config: LiveValidatorConfig) -> None:
    if config.target_triple not in SUPPORTED_LIVE_VALIDATOR_TARGETS:
        raise LiveValidatorConfigError("live_validator_target_unsupported")
    if sys.platform != "linux":
        raise LiveValidatorConfigError("live_validator_host_unsupported")
    machine = platform.machine().casefold()
    host_target = {
        "aarch64": "aarch64-unknown-linux-musl",
        "arm64": "aarch64-unknown-linux-musl",
        "amd64": "x86_64-unknown-linux-musl",
        "x86_64": "x86_64-unknown-linux-musl",
    }.get(machine)
    if host_target is None:
        raise LiveValidatorConfigError("live_validator_host_unsupported")
    if config.target_triple != host_target:
        raise LiveValidatorConfigError("live_validator_host_target_mismatch")
    if policy.translation_weights_active is not False:
        raise LiveValidatorConfigError("policy_weights_active")
    pins = policy.implementation_pins
    if (
        pins.pin_profile != LIVE_SHADOW_MODE
        or not pins.conformance_fixtures_verified
        or pins.conformance_execution_report_sha256 is None
        or pins.live_chain is None
        or pins.storage_proof_verifier is None
        or pins.finality_verifier is None
    ):
        raise LiveValidatorConfigError("policy_not_fully_pinned")
    digest = scoring_policy_hash(policy)
    if digest != config.scoring_policy_sha256:
        raise LiveValidatorConfigError("policy_digest_mismatch")
    account = account_id32(config.validator_hotkey)
    if account not in {account_id32(item.validator_hotkey) for item in policy.validator_registry}:
        raise LiveValidatorConfigError("validator_not_in_policy_registry")
    if config.target_triple not in pins.storage_proof_verifier.release_sha256_by_target:
        raise LiveValidatorConfigError("storage_proof_target_unpinned")
    if config.target_triple not in pins.finality_verifier.release_sha256_by_target:
        raise LiveValidatorConfigError("finality_target_unpinned")
    if policy.activation_block <= 0:
        raise LiveValidatorConfigError("activation_block_has_no_scannable_parent")
    if config.initial_minimum_finalized_block != policy.activation_block - 1:
        raise LiveValidatorConfigError("initial_finality_height_not_activation_parent")
    if config.initial_minimum_finalized_block < pins.finality_verifier.bootstrap_block_number:
        raise LiveValidatorConfigError("initial_finality_height_precedes_bootstrap")


def _require_runtime_validation(
    policy: ScoringPolicy,
    config: LiveValidatorConfig,
    validation: LiveRuntimeValidation,
) -> None:
    pins = policy.implementation_pins
    proof = pins.storage_proof_verifier
    finality = pins.finality_verifier
    if proof is None or finality is None:
        raise LiveValidatorConfigError("policy_not_fully_pinned")
    expected = (
        config.target_triple,
        proof.release_sha256_by_target.get(config.target_triple),
        finality.release_sha256_by_target.get(config.target_triple),
        finality.chain_spec_sha256,
    )
    actual = (
        validation.target_triple,
        validation.storage_proof_verifier_sha256,
        validation.finality_verifier_sha256,
        validation.finality_chain_spec_sha256,
    )
    if actual != expected:
        raise LiveValidatorConfigError("runtime_validation_policy_mismatch")


def _monitoring_policy(policy: ScoringPolicy, validator_hotkey: str) -> MonitoringStatePolicy:
    publishers = tuple(
        sorted(account_id32(item.publisher_hotkey) for item in policy.publisher_registry)
    )
    groups = tuple(
        sorted(bytes.fromhex(item.control_group_id) for item in policy.control_group_registry)
    )
    mappings = tuple(
        sorted(
            (
                account_id32(item.publisher_hotkey),
                bytes.fromhex(item.control_group_id),
            )
            for item in policy.publisher_registry
        )
    )
    return MonitoringStatePolicy(
        validator_account_id32=account_id32(validator_hotkey),
        scoring_policy_hash=bytes.fromhex(scoring_policy_hash(policy)),
        maximum_batches=policy.limits.publisher_monitoring_batches,
        minimum_clips_per_side_and_stratum=(
            policy.limits.divergence_minimum_clips_per_side_and_stratum
        ),
        alert_threshold=policy.thresholds.source_divergence_alert_threshold.fraction,
        publisher_sources=publishers,
        control_group_sources=groups,
        publisher_control_groups=mappings,
    )


def _validate_anchor_adapter(
    anchor: object,
    policy: ScoringPolicy,
    config: LiveValidatorConfig,
    validation: LiveRuntimeValidation,
    runtime_pin: FinalizedRuntimePin,
) -> None:
    if not isinstance(anchor, BittensorAnchorPorts):
        raise LiveValidatorCompositionError("anchor_ports_not_production_adapter")
    live = policy.implementation_pins.live_chain
    if live is None:
        raise LiveValidatorCompositionError("anchor_live_chain_pin_missing")
    if (
        anchor.signer_account_id32 != account_id32(config.validator_hotkey)
        or anchor.runtime_pin != runtime_pin
        or anchor.genesis_hash != live.genesis_block_hash
        or anchor.finality_verifier_sha256 != validation.finality_verifier_sha256
    ):
        raise LiveValidatorCompositionError("anchor_ports_binding_mismatch")


def _validate_transcript_ports(
    value: object,
    context: ProductionTranscriptContext,
) -> None:
    """Reject a concrete-looking transcript bundle with any substituted authority."""

    if not isinstance(value, ProductionTranscriptPorts):
        raise LiveValidatorCompositionError("transcript_ports_not_production_adapters")
    if not isinstance(value.ports, TranscriptEffectPorts):
        raise LiveValidatorCompositionError("transcript_effect_ports_not_exact")
    if not isinstance(value.plan, TranscriptPreflightPlanPort):
        raise LiveValidatorCompositionError("transcript_plan_not_production_adapter")
    if not isinstance(value.resources, DurableTranscriptResourceStore):
        raise LiveValidatorCompositionError("transcript_resources_not_durable_adapter")
    if not isinstance(value.btauth, LiveBtauthAttemptPort):
        raise LiveValidatorCompositionError("transcript_btauth_not_production_adapter")
    if not isinstance(value.transport, BoundedHttpTranscriptTransport):
        raise LiveValidatorCompositionError("transcript_transport_not_production_adapter")
    if not isinstance(value.observe, FinalizedTranscriptObservationPort):
        raise LiveValidatorCompositionError("transcript_observe_not_production_adapter")
    if not isinstance(value.audit_release, ObservedScheduleAuditReleasePort):
        raise LiveValidatorCompositionError("transcript_audit_not_production_adapter")
    if not isinstance(value.btauth.nonces, DurableBtauthNonceStore):
        raise LiveValidatorCompositionError("transcript_nonce_store_not_durable_adapter")

    ports = value.ports
    verify_anchor = ports.verify_anchor
    if (
        ports.plan is not value.plan
        or ports.observe is not value.observe
        or ports.anchor_ports is not context.anchor_ports
        or getattr(verify_anchor, "__self__", None) is not context.anchor_ports
        or getattr(verify_anchor, "__func__", None) is not BittensorAnchorPorts.verify_anchor
        or ports.audit_release_block is not value.audit_release
        or ports.transport is not value.transport
        or ports.prepare_retry is not value.btauth
    ):
        raise LiveValidatorCompositionError("transcript_effect_port_binding_mismatch")

    policy_hash = scoring_policy_hash(context.policy)
    if (
        value.plan.policy is not context.policy
        or value.plan.policy_hash != policy_hash
        or value.plan.material_store is not context.material_store
        or value.plan.journal is not context.stage_journal
        or not isinstance(
            value.plan.baseline,
            ReceiptReplayTranscriptResourceBaseline,
        )
        or value.plan.baseline.policy is not context.policy
        or value.plan.baseline.validator_account_id32
        != account_id32(context.config.validator_hotkey)
        or value.plan.baseline.material_store is not context.material_store
        or value.plan.baseline.journal is not context.stage_journal
        or value.plan.baseline.capacity_set is not context.validator_capacity_set
        or value.plan.resources is not value.resources
        or value.btauth.policy is not context.policy
        or value.btauth.policy_hash != policy_hash
        or value.btauth.validator_account_id32 != account_id32(context.config.validator_hotkey)
        or value.btauth.material_store is not context.material_store
        or hasattr(value.btauth, "wallet")
        or value.transport.policy is not context.policy
        or value.transport.policy_hash != policy_hash
        or value.transport.material_store is not context.material_store
        or value.transport.resources is not value.resources
        or value.transport.timeout_seconds != context.config.transport_timeout_seconds
        or value.transport.transport is not None
        or value.transport.resolver is not None
        or value.observe.policy_hash != policy_hash
        or value.observe.finality is not context.finality
        or value.observe.rounds is not context.rounds
        or value.audit_release.policy is not context.policy
        or value.audit_release.policy_hash != policy_hash
        or value.audit_release.schedule is not context.weight_schedule
    ):
        raise LiveValidatorCompositionError("transcript_ports_binding_mismatch")

    resource_root = value.resources.root.resolve(strict=False)
    nonce_root = value.btauth.nonces.root.resolve(strict=False)
    if (
        resource_root != context.paths.transcript_resources.resolve(strict=False)
        or nonce_root != context.paths.btauth_nonces.resolve(strict=False)
        or resource_root == nonce_root
    ):
        raise LiveValidatorCompositionError("transcript_durable_path_binding_mismatch")


def _validate_pool_reveal_ports(
    value: object,
    context: ProductionPoolRevealContext,
) -> None:
    """Reject any substituted or broadened pool/reveal production adapter."""

    if not isinstance(value, ProductionPoolRevealPorts):
        raise LiveValidatorCompositionError("pool_reveal_ports_not_production_adapters")
    if not isinstance(value.pool, PoolEffectPorts) or not isinstance(
        value.reveal, RevealEffectPorts
    ):
        raise LiveValidatorCompositionError("pool_reveal_effect_ports_not_exact")
    if not isinstance(value.mirror, DurablePoolMirrorSource):
        raise LiveValidatorCompositionError("pool_mirror_not_production_adapter")
    if not isinstance(value.delivery_issuance, AuthenticatedMirrorDeliveryIssuer):
        raise LiveValidatorCompositionError("delivery_issuance_not_production_adapter")
    if not isinstance(value.quicknet, QuicknetClient):
        raise LiveValidatorCompositionError("quicknet_not_verified_adapter")
    if not isinstance(value.audit_release, FinalizedRevealAuditReleaseAdapter):
        raise LiveValidatorCompositionError("reveal_audit_not_production_adapter")
    selection = value.pool.selection_pulse
    reveal_pulse = value.reveal.reveal_pulse
    decrypt = value.reveal.decrypt
    if (
        not isinstance(selection, QuicknetSelectionPulseAdapter)
        or not isinstance(reveal_pulse, QuicknetRevealPulseAdapter)
        or not isinstance(decrypt, TLERevealDecryptAdapter)
    ):
        raise LiveValidatorCompositionError("pool_reveal_adapter_type_mismatch")
    if (
        value.pool.source is not value.mirror
        or value.pool.delivery_issuance is not value.delivery_issuance
        or value.delivery_issuance.source is not value.mirror
        or value.delivery_issuance.policy is not context.policy
        or value.pool.closing_snapshot is not context.closing_snapshot
        or value.pool.prepared_assignments is not context.prepared_assignments
        or value.reveal.audit_release is not value.audit_release
        or selection.policy is not context.policy
        or selection.client is not value.quicknet
        or reveal_pulse.policy is not context.policy
        or reveal_pulse.client is not value.quicknet
        or decrypt.policy is not context.policy
        or value.audit_release.policy is not context.policy
        or value.audit_release.finality is not context.finality
        or value.audit_release.boundary is not context.reveal_audit_release_boundary
        or value.mirror.policy is not context.policy
        or value.mirror._mirror_readiness is not context.mirror_readiness
        or not value.mirror._require_mirror_readiness
    ):
        raise LiveValidatorCompositionError("pool_reveal_adapter_binding_mismatch")
    if (
        value.mirror._path.resolve(strict=False) != context.paths.pool_mirror.resolve(strict=False)
        or value.mirror._transport is not None
        or value.mirror._resolver is not None
        or value.mirror._allow_http_for_tests
        or value.quicknet.transport is not None
    ):
        raise LiveValidatorCompositionError("pool_reveal_network_binding_mismatch")


def _is_string_header_mapping(value: object) -> bool:
    if not isinstance(value, Mapping) or not value:
        return False
    return all(
        isinstance(name, str)
        and bool(name)
        and isinstance(header_value, str)
        and "\r" not in header_value
        and "\n" not in header_value
        for name, header_value in value.items()
    )


def _is_origin_header_mapping(value: object) -> bool:
    if not isinstance(value, Mapping) or not value:
        return False
    return all(
        isinstance(origin, str) and bool(origin) and _is_string_header_mapping(headers)
        for origin, headers in value.items()
    )


def _validate_bundle_verifier(
    verifier: object,
    policy: ScoringPolicy,
    validation: LiveRuntimeValidation,
    storage_verifier: SubprocessStorageProofVerifier,
) -> None:
    if not isinstance(verifier, ReplayCalibrationBundleVerifier):
        raise LiveValidatorCompositionError("bundle_verifier_not_replay_adapter")
    ports = verifier.ports
    if (
        ports.target_triple != validation.target_triple
        or ports.storage_proof_verifier_sha256 != validation.storage_proof_verifier_sha256
        or ports.finality_verifier_sha256 != validation.finality_verifier_sha256
    ):
        raise LiveValidatorCompositionError("bundle_verifier_pin_mismatch")
    if not isinstance(ports.finality_verifier, GrandpaFinalityReplayVerifier):
        raise LiveValidatorCompositionError("bundle_finality_replay_not_production")
    if ports.event_proof_verifier is not storage_verifier:
        raise LiveValidatorCompositionError("bundle_event_proof_verifier_mismatch")
    if getattr(ports.extrinsics_root_verifier, "__self__", None) is not storage_verifier:
        raise LiveValidatorCompositionError("bundle_extrinsics_verifier_mismatch")
    expected_hooks = {calibration_stage_replay_hook_id(policy, stage_id) for stage_id in STAGE_IDS}
    if set(ports.stage_replay_hooks) != expected_hooks:
        raise LiveValidatorCompositionError("bundle_stage_replay_hooks_incomplete")


def _read_startup_file(path: str | Path, *, label: str) -> bytes:
    value = Path(path)
    if not value.is_absolute():
        raise LiveValidatorConfigError(f"{label}_path_not_absolute")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(value, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise LiveValidatorConfigError(f"{label}_file_unsafe") from error
        raise LiveValidatorConfigError(f"{label}_file_unavailable") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_mode & 0o022
            or before.st_size <= 0
            or before.st_size > MAX_STARTUP_DOCUMENT_BYTES
        ):
            raise LiveValidatorConfigError(f"{label}_file_unsafe")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MAX_STARTUP_DOCUMENT_BYTES - total + 1),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_STARTUP_DOCUMENT_BYTES:
                raise LiveValidatorConfigError(f"{label}_file_unsafe")
        encoded = b"".join(chunks)
        after = os.fstat(descriptor)
    except LiveValidatorError:
        raise
    except OSError as error:
        raise LiveValidatorConfigError(f"{label}_file_unavailable") from error
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after or len(encoded) != before.st_size:
        raise LiveValidatorConfigError(f"{label}_file_changed")
    return encoded


def _prepare_state_root(root: Path) -> None:
    try:
        if os.path.lexists(root) and root.is_symlink():
            raise LiveValidatorConfigError("state_root_unsafe")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        details = root.stat()
    except LiveValidatorError:
        raise
    except OSError as error:
        raise LiveValidatorConfigError("state_root_unavailable") from error
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.getuid()
        or details.st_mode & 0o077
    ):
        raise LiveValidatorConfigError("state_root_unsafe")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the pinned, no-weight UMI live-shadow validator"
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--operator-config",
        type=Path,
        help=(
            "canonical wallet, capacity-set, and mirror configuration; enables the "
            "installed production composition without Python dependency injection"
        ),
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--check",
        action="store_true",
        help="validate and assemble without starting finality, network reads, or broadcasts",
    )
    action.add_argument(
        "--prime-next-window",
        action="store_true",
        help=(
            "observe finalized headers and durably record the deterministic next window "
            "without loading a wallet, mirror readiness, or any stage adapter"
        ),
    )
    return parser


def _prime_poll_seconds(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("poll_seconds must be numeric")
    result = float(value)
    if not MIN_POLL_SECONDS <= result <= MAX_POLL_SECONDS:
        raise ValueError(f"poll_seconds must be between {MIN_POLL_SECONDS} and {MAX_POLL_SECONDS}")
    return result


async def _wait_for_prime_progress(
    stop_event: asyncio.Event,
    finality_task: asyncio.Task[None],
    delay: float,
) -> None:
    stop_waiter = asyncio.create_task(stop_event.wait())
    try:
        await asyncio.wait(
            (stop_waiter, finality_task),
            timeout=delay,
            return_when=asyncio.FIRST_COMPLETED,
        )
    finally:
        if not stop_waiter.done():
            stop_waiter.cancel()
        await asyncio.gather(stop_waiter, return_exceptions=True)


async def _run_until_signal(runtime: LiveValidatorRuntime, *, poll_seconds: float) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    installed: list[signal.Signals] = []
    for item in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(item, stop.set)
            installed.append(item)
        except (NotImplementedError, RuntimeError):
            pass
    try:
        await runtime.run(stop, poll_seconds=poll_seconds)
    finally:
        stop.set()
        for item in installed:
            loop.remove_signal_handler(item)


async def _prime_until_signal(
    primer: LiveValidatorPrimer,
    *,
    poll_seconds: float,
) -> tuple[WindowRecord, bool]:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    installed: list[signal.Signals] = []
    for item in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(item, stop.set)
            installed.append(item)
        except (NotImplementedError, RuntimeError):
            pass
    try:
        try:
            record, created = await primer.prime(stop, poll_seconds=poll_seconds)
        except LiveValidatorError:
            raise
        except Exception as error:
            raise LiveValidatorRuntimeError("prime_window_failed") from error
        if record is None:
            raise LiveValidatorRuntimeError("prime_interrupted")
        return record, created
    finally:
        stop.set()
        for item in installed:
            loop.remove_signal_handler(item)


def run_cli(
    argv: Sequence[str] | None = None,
    *,
    dependencies: LiveValidatorProductionDependencies | None = None,
) -> int:
    """Run the installed command; dependency injection is explicit and in-process."""

    args = _parser().parse_args(argv)
    if args.operator_config is not None and dependencies is not None:
        raise ValueError("operator config and injected dependencies are mutually exclusive")
    if args.prime_next_window and (args.operator_config is not None or dependencies is not None):
        print(
            canonical_json_bytes(
                {
                    "reason_code": "prime_requires_live_config_only",
                    "status": "blocked",
                    "translation_weights_active": False,
                    "weight_submission_capability": False,
                }
            ).decode("utf-8"),
            file=sys.stderr,
        )
        return 2
    if args.operator_config is not None:
        from .validator_operator import run_installed_operator

        return asyncio.run(
            run_installed_operator(
                config_path=args.config,
                operator_config_path=args.operator_config,
                check=args.check,
            )
        )
    runtime: LiveValidatorRuntime | None = None
    primer: LiveValidatorPrimer | None = None
    try:
        config = load_live_validator_config(args.config)
        if args.prime_next_window:
            primer = build_live_validator_primer(config=config)
            window, created = asyncio.run(
                _prime_until_signal(primer, poll_seconds=config.poll_seconds)
            )
            print(
                canonical_json_bytes(
                    {
                        "mirror_readiness_required_for_serving": True,
                        "mode": LIVE_SHADOW_MODE,
                        "proposal_close_block": window.plan.proposal_close_block,
                        "scoring_policy_sha256": primer.policy_hash,
                        "stage": window.stage.value,
                        "status": "primed" if created else "already_primed",
                        "translation_weights_active": False,
                        "weight_submission_capability": False,
                        "window_id": window.plan.window_id,
                        "window_index": window.plan.window_index,
                    }
                ).decode("utf-8")
            )
            return 0
        selected = dependencies or LiveValidatorProductionDependencies()
        runtime = build_production_live_validator(
            config=config,
            dependencies=selected,
        )
        ready = {
            "configured_stages": [stage.value for stage in runtime.configured_stages],
            "mode": LIVE_SHADOW_MODE,
            "scoring_policy_sha256": runtime.scoring_policy_hash,
            "status": "ready",
            "translation_weights_active": False,
            "weight_submission_capability": False,
        }
        print(canonical_json_bytes(ready).decode("utf-8"))
        if args.check:
            return 0
        asyncio.run(_run_until_signal(runtime, poll_seconds=config.poll_seconds))
        return 0
    except LiveValidatorMissingCapabilities as error:
        print(
            canonical_json_bytes(
                {
                    "missing_capabilities": list(error.missing_codes),
                    "reason_code": error.reason_code,
                    "status": "blocked",
                    "translation_weights_active": False,
                    "weight_submission_capability": False,
                }
            ).decode("utf-8"),
            file=sys.stderr,
        )
        return 2
    except LiveValidatorInvalidCapabilities as error:
        print(
            canonical_json_bytes(
                {
                    "invalid_capabilities": list(error.invalid_codes),
                    "reason_code": error.reason_code,
                    "status": "blocked",
                    "translation_weights_active": False,
                    "weight_submission_capability": False,
                }
            ).decode("utf-8"),
            file=sys.stderr,
        )
        return 2
    except LiveValidatorError as error:
        print(
            canonical_json_bytes(
                {
                    "reason_code": error.reason_code,
                    "status": "blocked",
                    "translation_weights_active": False,
                    "weight_submission_capability": False,
                }
            ).decode("utf-8"),
            file=sys.stderr,
        )
        return 2
    finally:
        if runtime is not None:
            runtime.close()
        if primer is not None:
            primer.close()


def main() -> None:
    raise SystemExit(run_cli())


__all__ = [
    "FORBIDDEN_WEIGHT_CAPABILITY_NAMES",
    "LIVE_SHADOW_MODE",
    "LIVE_VALIDATOR_CONFIG_SCHEMA",
    "WEIGHT_DISABLED_HOLD_ID",
    "LiveRuntimeValidation",
    "LiveValidatorBuildContext",
    "LiveValidatorCompositionError",
    "LiveValidatorConfig",
    "LiveValidatorConfigError",
    "LiveValidatorError",
    "LiveValidatorInvalidCapabilities",
    "LiveValidatorMissingCapabilities",
    "LiveValidatorPaths",
    "LiveValidatorPortFactory",
    "LiveValidatorPorts",
    "LiveValidatorPrimer",
    "LiveValidatorProductionDependencies",
    "LiveValidatorRuntime",
    "LiveValidatorRuntimeError",
    "PrivateBtauthTranscriptFactory",
    "PrivateValidatorManifestSigner",
    "ProductionAnchorContext",
    "ProductionAnchorFactory",
    "ProductionPoolRevealContext",
    "ProductionPoolRevealPorts",
    "ProductionTranscriptContext",
    "ProductionTranscriptFactory",
    "build_live_validator",
    "build_live_validator_primer",
    "build_production_live_validator",
    "build_production_pool_reveal_ports",
    "load_live_policy",
    "load_live_validator_config",
    "main",
    "run_cli",
    "validate_live_startup",
]
