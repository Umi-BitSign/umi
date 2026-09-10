"""Deterministic runtime engine for the install-once validator supervisor.

The engine deliberately owns no HTTP, chain-RPC, OCI-runtime, wallet, or
subprocess implementation.  Those effects arrive through narrow async ports.
Network input can select only one of the fixed worker methods below; it can
never supply a command, argument vector, environment, unit name, or socket.

Every reconciliation is serialized.  A directive is authenticated and written
to the durable monotonic high-water record before it can activate a worker.  A
missing, malformed, expired, incompatible, unhealthy, or otherwise unusable
directive replaces the managed worker with the inert hold.  There is no path
that restores an older worker after a newer directive has been accepted or
after a chain-capable worker may have produced effects.
"""

from __future__ import annotations

import asyncio
import hmac
import math
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol, runtime_checkable

from .validator_supervisor import (
    SignedSupervisorDirective,
    SupervisorDirectiveState,
    SupervisorMode,
    SupervisorOperatorInputTarget,
    SupervisorReleaseTarget,
    ValidatorSupervisorConfig,
    ValidatorSupervisorError,
    advance_supervisor_directive_history_state,
    advance_supervisor_directive_state,
    load_supervisor_directive_state,
    parse_canonical_supervisor_directive_page,
    store_supervisor_directive_state,
)

DIRECTIVE_STATE_FILENAME = "directive-state.json"
MAX_FINALIZED_BLOCK = (1 << 53) - 1
MIN_RUNTIME_POLL_SECONDS = 0.01
MAX_RUNTIME_POLL_SECONDS = 3_600.0
MIN_WORKER_ACTIVATION_HEADROOM_BLOCKS = 2

CHAIN_CAPABLE_MODES = frozenset(
    {"inactive_shadow", "bootstrap_service_weights", "translation_weights"}
)
_WORKER_MODES = frozenset({"inactive_shadow", "bootstrap_service_weights", "translation_weights"})
_EXPECTED_ENTRYPOINT = {
    "inactive_shadow": "umi-live-shadow-validator/1",
    "bootstrap_service_weights": "umi-bootstrap-weight-validator/2",
    "translation_weights": "umi-translation-validator/1",
}


class ValidatorSupervisorRuntimeError(RuntimeError):
    """Stable, non-sensitive runtime failure that supervision may log."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class SupervisorReconcileStatus(str, Enum):
    """One deterministic result from a serialized reconciliation."""

    HOLDING = "holding"
    WAITING_FOR_ACTIVATION = "waiting_for_activation"
    WORKER_STARTED = "worker_started"
    WORKER_HEALTHY = "worker_healthy"


@dataclass(frozen=True, slots=True)
class SupervisorWorkerActivation:
    """Verified inputs passed to one fixed worker-adapter method.

    The structure intentionally has no command-like field.  A production
    adapter must derive its fixed entrypoint from ``mode`` and independently
    verify/pull the signed immutable OCI target during preflight.
    """

    mode: SupervisorMode
    sequence: int
    directive_sha256: str
    policy_sha256: str
    valid_from_block: int
    valid_through_block: int
    release: SupervisorReleaseTarget
    operator_inputs: SupervisorOperatorInputTarget | None

    def __post_init__(self) -> None:
        if self.mode not in _WORKER_MODES:
            raise ValueError("worker activation cannot use the hold or an unknown mode")
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise TypeError("worker activation sequence must be an integer")
        if self.sequence < 1 or self.sequence > MAX_FINALIZED_BLOCK:
            raise ValueError("worker activation sequence is outside the canonical range")
        if not isinstance(self.directive_sha256, str) or len(self.directive_sha256) != 64:
            raise ValueError("worker activation directive digest is invalid")
        if not isinstance(self.policy_sha256, str) or len(self.policy_sha256) != 64:
            raise ValueError("worker activation policy digest is invalid")
        _validated_finalized_block(self.valid_from_block)
        _validated_finalized_block(self.valid_through_block)
        if self.valid_through_block < self.valid_from_block:
            raise ValueError("worker activation block interval is inverted")
        if not isinstance(self.release, SupervisorReleaseTarget):
            raise TypeError("worker activation release must be a SupervisorReleaseTarget")
        if self.release.entrypoint_profile != _EXPECTED_ENTRYPOINT[self.mode]:
            raise ValueError("worker activation mode and entrypoint profile disagree")
        if self.mode == "bootstrap_service_weights":
            if not isinstance(self.operator_inputs, SupervisorOperatorInputTarget):
                raise TypeError("bootstrap worker activation requires immutable operator inputs")
        elif self.operator_inputs is not None:
            raise ValueError("only bootstrap worker activation may name operator inputs")

    @property
    def may_have_chain_effects(self) -> bool:
        return self.mode in CHAIN_CAPABLE_MODES


@dataclass(frozen=True, slots=True)
class SupervisorWorkerIdentity:
    """Identity of the one worker this engine has successfully started."""

    mode: SupervisorMode
    directive_sha256: str | None
    sequence: int | None

    @property
    def may_have_chain_effects(self) -> bool:
        return self.mode in CHAIN_CAPABLE_MODES


@dataclass(frozen=True, slots=True)
class SupervisorReconcileResult:
    """Non-sensitive evidence from one reconciliation attempt."""

    status: SupervisorReconcileStatus
    active_mode: SupervisorMode
    reason_code: str
    finalized_block: int | None
    accepted_sequence: int | None
    accepted_directive_sha256: str | None
    prior_worker_may_have_chain_effects: bool

    def __post_init__(self) -> None:
        if not isinstance(self.status, SupervisorReconcileStatus):
            raise TypeError("reconcile status must be a SupervisorReconcileStatus")
        if self.active_mode not in {
            "hold",
            "inactive_shadow",
            "bootstrap_service_weights",
            "translation_weights",
        }:
            raise ValueError("reconcile result contains an unknown active mode")
        if not isinstance(self.reason_code, str) or not self.reason_code:
            raise ValueError("reconcile result requires a reason code")
        if self.finalized_block is not None:
            _validated_finalized_block(self.finalized_block)
        if (self.accepted_sequence is None) != (self.accepted_directive_sha256 is None):
            raise ValueError("accepted directive evidence must be complete or absent")
        if self.accepted_sequence is not None and self.accepted_sequence < 1:
            raise ValueError("accepted sequence must be positive")
        if self.accepted_directive_sha256 is not None and len(self.accepted_directive_sha256) != 64:
            raise ValueError("accepted directive digest is invalid")
        if not isinstance(self.prior_worker_may_have_chain_effects, bool):
            raise TypeError("prior worker effect classification must be boolean")


@runtime_checkable
class SupervisorDirectiveFetcher(Protocol):
    """Fetch one bounded cursor-bound page of signed directives."""

    async def fetch_directive_page(
        self,
        *,
        after_sequence: int,
        after_directive_sha256: str | None,
    ) -> bytes | None:
        """Return one canonical page echoing the supplied high-water cursor."""


@runtime_checkable
class SupervisorFinalizedBlockReader(Protocol):
    """Read the newest independently verified finalized block height."""

    async def read_finalized_block(self) -> int:
        """Return one canonical finalized Finney block height."""


@runtime_checkable
class SupervisorWorkerAdapter(Protocol):
    """Own exactly one fixed-profile worker process or inert hold.

    ``stop_worker`` must return only after no worker managed by this adapter
    remains alive.  Every start method must fail without leaving a child, or
    permit a following ``stop_worker`` to remove that partial child.  Preflight
    may stage and verify artifacts and inspect chain state, but must not submit a
    transaction or launch the candidate worker.
    """

    async def stop_worker(self) -> None:
        """Stop the exact managed worker and confirm its absence."""

    async def worker_is_healthy(self) -> bool:
        """Return whether the one managed worker matches its expected profile."""

    async def preflight_activation(self, *, activation: SupervisorWorkerActivation) -> None:
        """Verify the immutable release and all non-mutating activation gates."""

    async def start_hold(self, *, reason_code: str) -> None:
        """Start the inert, wallet-free hold profile."""

    async def start_inactive_shadow(self, *, activation: SupervisorWorkerActivation) -> None:
        """Start the fixed inactive-shadow entrypoint."""

    async def start_bootstrap_service_weights(
        self, *, activation: SupervisorWorkerActivation
    ) -> None:
        """Start the fixed temporary bootstrap-weight entrypoint."""

    async def start_translation_weights(self, *, activation: SupervisorWorkerActivation) -> None:
        """Start the fixed translation-weight entrypoint."""


WaitFunction = Callable[[asyncio.Event, float], Awaitable[None]]


class ValidatorSupervisorRuntime:
    """Authenticate, persist, and reconcile one install-once validator worker."""

    def __init__(
        self,
        *,
        config: ValidatorSupervisorConfig,
        directive_fetcher: SupervisorDirectiveFetcher,
        finalized_block_reader: SupervisorFinalizedBlockReader,
        worker_adapter: SupervisorWorkerAdapter,
        wait: WaitFunction | None = None,
    ) -> None:
        if not isinstance(config, ValidatorSupervisorConfig):
            raise TypeError("config must be a ValidatorSupervisorConfig")
        if not callable(getattr(directive_fetcher, "fetch_directive_page", None)):
            raise TypeError("directive_fetcher must define fetch_directive_page()")
        if not callable(getattr(finalized_block_reader, "read_finalized_block", None)):
            raise TypeError("finalized_block_reader must define read_finalized_block()")
        for method in (
            "stop_worker",
            "worker_is_healthy",
            "preflight_activation",
            "start_hold",
            "start_inactive_shadow",
            "start_bootstrap_service_weights",
            "start_translation_weights",
        ):
            if not callable(getattr(worker_adapter, method, None)):
                raise TypeError(f"worker_adapter must define {method}()")
        if wait is not None and not callable(wait):
            raise TypeError("wait must be an async callable")
        if "hold" not in config.allowed_modes:
            raise ValueError("the locally allowed modes must include hold")

        self.config = config
        self._directive_fetcher = directive_fetcher
        self._finalized_block_reader = finalized_block_reader
        self._worker_adapter = worker_adapter
        self._wait: WaitFunction = wait or _wait_for_stop
        self._state_path = Path(config.state_root) / DIRECTIVE_STATE_FILENAME
        self._trust_policy = config.trust_policy()
        self._reconcile_lock = asyncio.Lock()
        self._active_worker: SupervisorWorkerIdentity | None = None
        self._preflighted_directive_sha256: str | None = None
        self._chain_effects_may_exist = False
        self._restart_fence_complete = False

    @property
    def active_worker(self) -> SupervisorWorkerIdentity | None:
        """Return the in-process worker identity, never a secret or process handle."""

        return self._active_worker

    async def reconcile(self) -> SupervisorReconcileResult:
        """Perform one serialized fetch, verification, persistence, and transition."""

        async with self._reconcile_lock:
            return await self._reconcile_locked()

    async def poll(self, stop_event: asyncio.Event) -> None:
        """Reconcile until stopped using the locally pinned polling interval."""

        if not isinstance(stop_event, asyncio.Event):
            raise TypeError("stop_event must be an asyncio.Event")
        delay = _validated_poll_seconds(float(self.config.poll_seconds))
        while not stop_event.is_set():
            await self.reconcile()
            if stop_event.is_set():
                break
            await self._wait(stop_event, delay)

    async def stop(self) -> None:
        """Stop the managed worker under the same replacement lock."""

        async with self._reconcile_lock:
            try:
                await self._worker_adapter.stop_worker()
            except Exception as error:
                raise ValidatorSupervisorRuntimeError("worker_stop_failed") from error
            self._active_worker = None
            self._preflighted_directive_sha256 = None

    async def _reconcile_locked(self) -> SupervisorReconcileResult:
        try:
            prior_state = load_supervisor_directive_state(
                self._state_path,
                trust_policy=self._trust_policy,
            )
        except Exception as error:
            return await self._fail_closed(
                _stable_supervisor_reason(error, "directive_state_read_failed"),
                finalized_block=None,
                state=None,
            )
        if prior_state is not None and (
            prior_state.accepted_mode in CHAIN_CAPABLE_MODES or prior_state.accepted_sequence > 1
        ):
            # The high-water record is the restart-safe conservative fence.  It
            # need not prove that a call happened; it is enough that this host
            # accepted a chain-capable assignment, or that an earlier directive
            # may have done so before a later hold was persisted.
            self._chain_effects_may_exist = True

        if prior_state is not None and not self._restart_fence_complete:
            prior_effects = self._prior_worker_may_have_chain_effects()
            await self._ensure_hold("restart_fence")
            self._restart_fence_complete = True
            return _result(
                status=SupervisorReconcileStatus.HOLDING,
                active_mode="hold",
                reason_code="restart_fence",
                finalized_block=None,
                state=prior_state,
                prior_worker_may_have_chain_effects=prior_effects,
            )
        self._restart_fence_complete = True

        cursor_sequence = 0 if prior_state is None else prior_state.accepted_sequence
        cursor_digest = None if prior_state is None else prior_state.accepted_directive_sha256
        try:
            payload = await self._directive_fetcher.fetch_directive_page(
                after_sequence=cursor_sequence,
                after_directive_sha256=cursor_digest,
            )
        except Exception:
            return await self._fail_closed(
                "directive_fetch_failed",
                finalized_block=None,
                state=prior_state,
            )
        if payload is None:
            return await self._fail_closed(
                "directive_missing",
                finalized_block=None,
                state=prior_state,
            )

        try:
            page = parse_canonical_supervisor_directive_page(payload)
        except Exception as error:
            return await self._fail_closed(
                _stable_supervisor_reason(error, "directive_page_invalid"),
                finalized_block=None,
                state=prior_state,
            )
        if page.after_sequence != cursor_sequence or not _optional_digest_equal(
            page.after_directive_sha256,
            cursor_digest,
        ):
            return await self._fail_closed(
                "directive_page_cursor_mismatch",
                finalized_block=None,
                state=prior_state,
            )

        try:
            finalized_block = _validated_finalized_block(
                await self._finalized_block_reader.read_finalized_block()
            )
        except Exception:
            return await self._fail_closed(
                "finalized_block_read_failed",
                finalized_block=None,
                state=prior_state,
            )

        next_state = prior_state
        historical = page.directives if page.more else page.directives[:-1]
        for historical_signed in historical:
            try:
                advanced = advance_supervisor_directive_history_state(
                    historical_signed,
                    config=self.config,
                    finalized_block=finalized_block,
                    prior_state=next_state,
                )
                store_supervisor_directive_state(
                    self._state_path,
                    advanced,
                    trust_policy=self._trust_policy,
                    expected_prior=next_state,
                )
            except Exception as error:
                return await self._fail_closed(
                    _stable_supervisor_reason(error, "directive_history_rejected"),
                    finalized_block=finalized_block,
                    state=next_state,
                )
            next_state = advanced
            # A newly accepted directive supersedes the currently selected
            # worker as soon as its monotonic high-water record is durable.
            # Stop that worker before any release download or other potentially
            # slow preflight operation, so an older chain writer cannot remain
            # live while its replacement is being prepared.
            self._preflighted_directive_sha256 = None
            await self._ensure_hold("directive_transition")

        if page.more:
            prior_effects = self._prior_worker_may_have_chain_effects()
            await self._ensure_hold("directive_catchup_more")
            return _result(
                status=SupervisorReconcileStatus.HOLDING,
                active_mode="hold",
                reason_code="directive_catchup_more",
                finalized_block=finalized_block,
                state=next_state,
                prior_worker_may_have_chain_effects=prior_effects,
            )

        signed = page.head
        try:
            advanced = advance_supervisor_directive_state(
                signed,
                config=self.config,
                finalized_block=finalized_block,
                prior_state=next_state,
            )
        except Exception as error:
            return await self._fail_closed(
                _stable_supervisor_reason(error, "directive_rejected"),
                finalized_block=finalized_block,
                state=next_state,
            )

        if advanced != next_state:
            try:
                store_supervisor_directive_state(
                    self._state_path,
                    advanced,
                    trust_policy=self._trust_policy,
                    expected_prior=next_state,
                )
            except Exception as error:
                return await self._fail_closed(
                    _stable_supervisor_reason(error, "directive_state_write_failed"),
                    finalized_block=finalized_block,
                    state=next_state,
                )
            next_state = advanced
            self._preflighted_directive_sha256 = None
            await self._ensure_hold("directive_transition")

        directive = signed.directive
        activation = None if directive.mode == "hold" else _worker_activation(signed)
        if (
            activation is not None
            and self._preflighted_directive_sha256 != activation.directive_sha256
        ):
            try:
                # Preflight is intentionally after the monotonic state write.  If a
                # newer candidate is unavailable or invalid, a later poll cannot
                # revive the older chain-capable directive as an implicit rollback.
                await self._worker_adapter.preflight_activation(activation=activation)
            except Exception:
                return await self._fail_closed(
                    "worker_preflight_failed",
                    finalized_block=finalized_block,
                    state=next_state,
                )
            self._preflighted_directive_sha256 = activation.directive_sha256

            # Preflight can include a bounded release download and OCI import.
            # Re-read finality afterwards instead of starting from the stale
            # height used to authenticate the directive before that work.
            try:
                refreshed_finalized_block = _validated_finalized_block(
                    await self._finalized_block_reader.read_finalized_block()
                )
            except Exception:
                return await self._fail_closed(
                    "finalized_block_refresh_failed",
                    finalized_block=finalized_block,
                    state=next_state,
                )
            if refreshed_finalized_block < finalized_block:
                self._preflighted_directive_sha256 = None
                return await self._fail_closed(
                    "finalized_block_refresh_rollback",
                    finalized_block=refreshed_finalized_block,
                    state=next_state,
                )
            if refreshed_finalized_block == finalized_block:
                self._preflighted_directive_sha256 = None
                return await self._fail_closed(
                    "finalized_block_refresh_not_advanced",
                    finalized_block=refreshed_finalized_block,
                    state=next_state,
                )
            finalized_block = refreshed_finalized_block
            if finalized_block > directive.valid_through_block:
                self._preflighted_directive_sha256 = None
                return await self._fail_closed(
                    "directive_expired_after_preflight",
                    finalized_block=finalized_block,
                    state=next_state,
                )
            if (
                directive.valid_through_block - finalized_block
                < MIN_WORKER_ACTIVATION_HEADROOM_BLOCKS
            ):
                self._preflighted_directive_sha256 = None
                return await self._fail_closed(
                    "directive_activation_headroom_insufficient",
                    finalized_block=finalized_block,
                    state=next_state,
                )

        if finalized_block < directive.valid_from_block:
            prior_effects = self._prior_worker_may_have_chain_effects()
            await self._ensure_hold("directive_not_yet_active")
            return _result(
                status=SupervisorReconcileStatus.WAITING_FOR_ACTIVATION,
                active_mode="hold",
                reason_code="directive_not_yet_active",
                finalized_block=finalized_block,
                state=next_state,
                prior_worker_may_have_chain_effects=prior_effects,
            )

        if directive.mode == "hold":
            prior_effects = self._prior_worker_may_have_chain_effects()
            await self._ensure_hold("directive_hold")
            return _result(
                status=SupervisorReconcileStatus.HOLDING,
                active_mode="hold",
                reason_code="directive_hold",
                finalized_block=finalized_block,
                state=next_state,
                prior_worker_may_have_chain_effects=prior_effects,
            )

        if activation is None:  # pragma: no cover - mode narrowing above is exhaustive.
            raise ValidatorSupervisorRuntimeError("worker_directive_incomplete")
        desired = SupervisorWorkerIdentity(
            mode=activation.mode,
            directive_sha256=activation.directive_sha256,
            sequence=activation.sequence,
        )
        if (
            self._active_worker != desired
            and directive.valid_through_block - finalized_block
            < MIN_WORKER_ACTIVATION_HEADROOM_BLOCKS
        ):
            self._preflighted_directive_sha256 = None
            return await self._fail_closed(
                "directive_activation_headroom_insufficient",
                finalized_block=finalized_block,
                state=next_state,
            )
        if self._active_worker == desired:
            try:
                healthy = await self._worker_adapter.worker_is_healthy()
            except Exception:
                healthy = False
            if healthy:
                return _result(
                    status=SupervisorReconcileStatus.WORKER_HEALTHY,
                    active_mode=activation.mode,
                    reason_code="worker_healthy",
                    finalized_block=finalized_block,
                    state=next_state,
                    prior_worker_may_have_chain_effects=desired.may_have_chain_effects,
                )
            self._preflighted_directive_sha256 = None
            return await self._fail_closed(
                "worker_unhealthy",
                finalized_block=finalized_block,
                state=next_state,
            )

        prior_effects = self._prior_worker_may_have_chain_effects()
        try:
            await self._activate_worker(activation, desired)
        except ValidatorSupervisorRuntimeError as error:
            self._preflighted_directive_sha256 = None
            return await self._fail_closed(
                error.reason_code,
                finalized_block=finalized_block,
                state=next_state,
            )
        return _result(
            status=SupervisorReconcileStatus.WORKER_STARTED,
            active_mode=activation.mode,
            reason_code="worker_started",
            finalized_block=finalized_block,
            state=next_state,
            prior_worker_may_have_chain_effects=prior_effects,
        )

    async def _activate_worker(
        self,
        activation: SupervisorWorkerActivation,
        desired: SupervisorWorkerIdentity,
    ) -> None:
        try:
            await self._worker_adapter.stop_worker()
        except Exception as error:
            raise ValidatorSupervisorRuntimeError("worker_stop_failed") from error
        self._active_worker = None

        if activation.may_have_chain_effects:
            # Set the fence before launch: an ambiguous or partial start may have
            # signed or submitted a call even when the adapter later raises.
            self._chain_effects_may_exist = True
        try:
            if activation.mode == "inactive_shadow":
                await self._worker_adapter.start_inactive_shadow(activation=activation)
            elif activation.mode == "bootstrap_service_weights":
                await self._worker_adapter.start_bootstrap_service_weights(activation=activation)
            elif activation.mode == "translation_weights":
                await self._worker_adapter.start_translation_weights(activation=activation)
            else:  # pragma: no cover - typed validation makes this unreachable.
                raise ValidatorSupervisorRuntimeError("worker_mode_unsupported")
        except ValidatorSupervisorRuntimeError:
            await self._cleanup_failed_start()
            raise
        except Exception as error:
            await self._cleanup_failed_start()
            raise ValidatorSupervisorRuntimeError("worker_start_failed") from error
        self._active_worker = desired

    async def _cleanup_failed_start(self) -> None:
        try:
            await self._worker_adapter.stop_worker()
        except Exception as error:
            self._active_worker = None
            raise ValidatorSupervisorRuntimeError("worker_cleanup_failed") from error
        self._active_worker = None

    async def _ensure_hold(self, reason_code: str) -> bool:
        if self._active_worker is not None and self._active_worker.mode == "hold":
            try:
                if await self._worker_adapter.worker_is_healthy():
                    return False
            except Exception:
                pass
        try:
            await self._worker_adapter.stop_worker()
        except Exception as error:
            self._active_worker = None
            raise ValidatorSupervisorRuntimeError("fail_closed_hold_stop_failed") from error
        self._active_worker = None
        try:
            await self._worker_adapter.start_hold(reason_code=reason_code)
        except Exception as error:
            try:
                await self._worker_adapter.stop_worker()
            except Exception as cleanup_error:
                raise ValidatorSupervisorRuntimeError(
                    "fail_closed_hold_cleanup_failed"
                ) from cleanup_error
            raise ValidatorSupervisorRuntimeError("fail_closed_hold_start_failed") from error
        self._active_worker = SupervisorWorkerIdentity(
            mode="hold",
            directive_sha256=None,
            sequence=None,
        )
        return True

    async def _fail_closed(
        self,
        reason_code: str,
        *,
        finalized_block: int | None,
        state: SupervisorDirectiveState | None,
    ) -> SupervisorReconcileResult:
        prior_effects = self._prior_worker_may_have_chain_effects()
        await self._ensure_hold(reason_code)
        return _result(
            status=SupervisorReconcileStatus.HOLDING,
            active_mode="hold",
            reason_code=reason_code,
            finalized_block=finalized_block,
            state=state,
            prior_worker_may_have_chain_effects=prior_effects,
        )

    def _prior_worker_may_have_chain_effects(self) -> bool:
        return self._chain_effects_may_exist or (
            self._active_worker is not None and self._active_worker.may_have_chain_effects
        )


def _worker_activation(signed: SignedSupervisorDirective) -> SupervisorWorkerActivation:
    directive = signed.directive
    if directive.mode == "hold" or directive.release is None or directive.policy_sha256 is None:
        raise ValidatorSupervisorRuntimeError("worker_directive_incomplete")
    return SupervisorWorkerActivation(
        mode=directive.mode,
        sequence=directive.sequence,
        directive_sha256=signed.directive_sha256,
        policy_sha256=directive.policy_sha256,
        valid_from_block=directive.valid_from_block,
        valid_through_block=directive.valid_through_block,
        release=directive.release,
        operator_inputs=directive.operator_inputs,
    )


def _result(
    *,
    status: SupervisorReconcileStatus,
    active_mode: SupervisorMode,
    reason_code: str,
    finalized_block: int | None,
    state: SupervisorDirectiveState | None,
    prior_worker_may_have_chain_effects: bool,
) -> SupervisorReconcileResult:
    return SupervisorReconcileResult(
        status=status,
        active_mode=active_mode,
        reason_code=reason_code,
        finalized_block=finalized_block,
        accepted_sequence=None if state is None else state.accepted_sequence,
        accepted_directive_sha256=(None if state is None else state.accepted_directive_sha256),
        prior_worker_may_have_chain_effects=prior_worker_may_have_chain_effects,
    )


def _stable_supervisor_reason(error: Exception, fallback: str) -> str:
    if isinstance(error, ValidatorSupervisorError):
        return error.reason_code
    return fallback


def _optional_digest_equal(left: str | None, right: str | None) -> bool:
    if left is None or right is None:
        return left is right
    return hmac.compare_digest(left, right)


def _validated_finalized_block(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("finalized block must be an integer")
    if value < 1 or value > MAX_FINALIZED_BLOCK:
        raise ValueError("finalized block is outside the canonical range")
    return value


def _validated_poll_seconds(value: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < MIN_RUNTIME_POLL_SECONDS
        or value > MAX_RUNTIME_POLL_SECONDS
    ):
        raise ValueError("poll seconds are outside the supported range")
    return float(value)


async def _wait_for_stop(stop_event: asyncio.Event, delay: float) -> None:
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=delay)
    except asyncio.TimeoutError:
        return


__all__ = [
    "CHAIN_CAPABLE_MODES",
    "DIRECTIVE_STATE_FILENAME",
    "SupervisorDirectiveFetcher",
    "SupervisorFinalizedBlockReader",
    "SupervisorReconcileResult",
    "SupervisorReconcileStatus",
    "SupervisorWorkerActivation",
    "SupervisorWorkerAdapter",
    "SupervisorWorkerIdentity",
    "ValidatorSupervisorRuntime",
    "ValidatorSupervisorRuntimeError",
]
