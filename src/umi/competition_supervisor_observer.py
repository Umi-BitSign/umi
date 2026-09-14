"""Host-owned, read-only proof capture for successor supervision.

The immutable installation binds an initial observer policy/configuration for
head, permit and rollback checks. It is not a reward authorization, and its
policy need not equal a later worker policy. Target weight observations use the
exact separately authorized target configuration without rewriting its digest.

The host must supply the genuine installed-input capability and expose its
verified helpers/spec at the fixed worker paths. The finality state root must
be a private host-owned mapping, separate from worker container state. No
wallet, injected provider name, RPC override or mutable authority JSON is an
input to this adapter. Runtime high-water tracking remains outside its caches.
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .competition_chain import CompetitionChainConfig
from .competition_chain_state import (
    FinalizedCompetitionWeightProvider,
    OwnedCompetitionChainObservation,
    validate_owned_weight_observation,
)
from .competition_host_activation import (
    AuthenticatedSuccessorWorkerInputs,
    _validate_worker_execution_bindings,
    validate_authenticated_successor_installation,
)
from .competition_supervisor import (
    load_bound_successor_replay_package,
    parse_canonical_successor_supervisor_directive_history,
    verify_bound_successor_chain_authorization,
    verify_signed_successor_supervisor_directive_history,
)
from .competition_supervisor_adapters import SuccessorArtifactFiles
from .competition_supervisor_runtime import SuccessorWorkerSelection
from .competition_worker_cli import (
    WORKER_CHAIN_SPEC,
    WORKER_FINALITY_BINARY,
    WORKER_FINALITY_STATE_ROOT,
    WORKER_PROOF_BINARY,
    SuccessorWorkerExecutionConfig,
)
from .encoding import account_id32
from .open_competition import CompetitionPolicy, Registration, digest
from .protocol import StrictProtocolModel, canonical_json_bytes

HOST_OBSERVER_FILENAME = "observer-config.json"
MAX_HOST_OBSERVER_CONFIG_BYTES = 512 * 1024


class SuccessorHostObserverConfig(StrictProtocolModel):
    schema_: Literal["umi-successor-host-observer-config/1"] = Field(alias="schema")
    policy: CompetitionPolicy
    chain: CompetitionChainConfig

    @model_validator(mode="after")
    def exact_policy_and_paths(self) -> Self:
        if self.chain.policy_sha256 != digest(self.policy):
            raise ValueError("host observer configuration binds a different initial policy")
        actual = (
            self.chain.finality_binary,
            self.chain.proof_binary,
            self.chain.chain_spec,
            self.chain.state_directory,
        )
        expected = tuple(
            str(path)
            for path in (
                WORKER_FINALITY_BINARY,
                WORKER_PROOF_BINARY,
                WORKER_CHAIN_SPEC,
                WORKER_FINALITY_STATE_ROOT,
            )
        )
        if actual != expected or self.chain.target_triple not in {
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
        }:
            raise ValueError("host observer paths and platform must use the fixed Linux profile")
        return self


def parse_successor_host_observer_config(payload: bytes) -> SuccessorHostObserverConfig:
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_HOST_OBSERVER_CONFIG_BYTES:
        raise ValueError("host observer configuration exceeds its byte bound")
    value = SuccessorHostObserverConfig.model_validate_json(payload)
    if canonical_json_bytes(value) != payload:
        raise ValueError("host observer configuration is not canonical")
    return value


def successor_host_observer_config_sha256(value: SuccessorHostObserverConfig) -> str:
    payload = canonical_json_bytes(value)
    parse_successor_host_observer_config(payload)
    return hashlib.sha256(payload).hexdigest()


class OwnedSuccessorHostObserver:
    """Concrete runtime and per-target proof ports; never submits to chain."""

    def __init__(self, *, installation: AuthenticatedSuccessorWorkerInputs):
        validate_authenticated_successor_installation(installation)
        self.installation = installation
        self._initial_bytes = canonical_json_bytes(installation.observer_config)
        initial = parse_successor_host_observer_config(self._initial_bytes)
        expected_target = {
            "linux/amd64": "x86_64-unknown-linux-gnu",
            "linux/arm64": "aarch64-unknown-linux-gnu",
        }.get(installation.config.target_platform)
        if initial.chain.target_triple != expected_target:
            raise ValueError("initial observer platform differs from installed host")
        self._lock = asyncio.Lock()
        self._closed = False

    def _initial(self):
        validate_authenticated_successor_installation(self.installation)
        if canonical_json_bytes(self.installation.observer_config) != self._initial_bytes:
            raise ValueError("initial host observer configuration changed")
        return parse_successor_host_observer_config(self._initial_bytes)

    async def _capture(self, config, policy, recipients):
        async with self._lock:
            if self._closed:
                raise ValueError("host observer is closed")
            self._initial()
            # One provider owns the fixed cache root at a time. Its existing
            # namespaced cache retains exact per-configuration proof history.
            provider = FinalizedCompetitionWeightProvider(config, policy)
            try:
                await provider.start()
                observation = await provider.wait_weights_ready(
                    self.installation.config.validator_hotkey, recipients
                )
                validate_owned_weight_observation(observation)
                if (
                    observation.chain_config_sha256 != digest(config)
                    or account_id32(observation.validator_hotkey)
                    != account_id32(self.installation.config.validator_hotkey)
                    or observation.block < self.installation.checkpoint_finalized_block
                ):
                    raise ValueError("owned host observation differs from its installed inputs")
                self._initial()
                return observation
            finally:
                await provider.aclose()

    async def observe(self) -> OwnedCompetitionChainObservation:
        initial = self._initial()
        # Expiration of the initial reward policy does not invalidate a
        # read-only head/permit proof. It cannot authorize any reward row.
        return await self._capture(initial.chain, initial.policy, ())

    async def observe_for(
        self, selection: SuccessorWorkerSelection, artifacts: SuccessorArtifactFiles
    ) -> OwnedCompetitionChainObservation:
        initial = self._initial()
        if type(artifacts) is not SuccessorArtifactFiles:
            raise TypeError("host observer requires bounded successor artifact files")
        if selection.continuation_bytes is not None and (
            selection.continuation_bytes != artifacts.current_directive_page_bytes
        ):
            raise ValueError("observer target differs from the runtime's retained history")
        directive = selection.signed.directive
        verify_signed_successor_supervisor_directive_history(
            selection.signed,
            config=self.installation.config,
            operator_consent=self.installation.operator_consent,
            finalized_block=max(
                directive.issued_at_block, self.installation.checkpoint_finalized_block
            ),
        )
        page = parse_canonical_successor_supervisor_directive_history(
            artifacts.current_directive_page_bytes
        )
        if page.more or page.head != selection.signed:
            raise ValueError("observer target is not the complete staged signed head")
        package = load_bound_successor_replay_package(
            artifacts.package_path,
            directive=directive,
            observed_release=directive.release.replay_release_identity,
        )
        execution = SuccessorWorkerExecutionConfig.model_validate_json(
            artifacts.worker_execution_bytes
        )
        if canonical_json_bytes(execution) != artifacts.worker_execution_bytes:
            raise ValueError("target observer execution bytes are not canonical")
        authorization = None
        if selection.mode == "competition_weights":
            authorization = verify_bound_successor_chain_authorization(
                artifacts.authorization_bytes,
                directive=directive,
                config=self.installation.config,
                package=package,
            )
        elif artifacts.authorization_bytes is not None:
            raise ValueError("replay target carries unexpected weight authority")
        _validate_worker_execution_bindings(
            execution,
            directive=directive,
            release_identity=directive.release.replay_release_identity,
            authorization_body=authorization,
            limits=self.installation.worker_execution_limits,
        )
        if execution.weights is None:
            if initial.chain.chain_pin != directive.chain.chain_pin:
                raise ValueError("replay target needs an independently approved observer pin")
            return await self._capture(initial.chain, initial.policy, ())
        recipients = tuple(
            Registration(uid=item.uid, hotkey=item.hotkey)
            for item in package.retained_settlement.projection.allocations
        )
        return await self._capture(execution.weights.chain, package.policy, recipients)

    async def aclose(self):
        async with self._lock:
            self._closed = True
