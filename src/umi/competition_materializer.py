"""Deliver, stage and select successor inputs through the installed trust boundary.

Fetching never changes current. The runtime calls activation only after it has
confirmed worker absence and reconciled retained transactions. This adapter
selects verified inputs, reloads the fixed read-only mount and returns the
genuine activation capability; it never starts a worker or submits a weight.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from .competition_chain_state import validate_owned_weight_observation
from .competition_delivery import HTTPSSuccessorArtifactDelivery
from .competition_host_activation import (
    AuthenticatedSuccessorWorkerInputs,
    activate_successor_worker,
    load_successor_worker_inputs,
    validate_authenticated_successor_installation,
)
from .competition_host_anchor import load_materialized_successor_anchor
from .competition_materialization import (
    SuccessorCurrentMaterializationLimits,
    select_staged_successor_current,
    stage_successor_current,
)
from .competition_supervisor import verify_signed_successor_supervisor_directive
from .competition_supervisor_adapters import SuccessorArtifactFiles, SuccessorArtifactObserver
from .competition_supervisor_runtime import SuccessorWorkerSelection
from .encoding import account_id32
from .protocol import canonical_json_bytes


class SuccessorMaterializerError(ValueError):
    pass


class AuthenticatedSuccessorArtifactMaterializer:
    def __init__(
        self,
        *,
        installation: AuthenticatedSuccessorWorkerInputs,
        delivery: HTTPSSuccessorArtifactDelivery,
        observer: SuccessorArtifactObserver,
        config_path: Path,
        limits: SuccessorCurrentMaterializationLimits,
    ):
        validate_authenticated_successor_installation(installation)
        self.installation = installation
        self.config = installation.config
        self.delivery = delivery
        self.observer = observer
        self.config_path = config_path
        self.limits = SuccessorCurrentMaterializationLimits.model_validate_json(
            canonical_json_bytes(limits)
        )
        self._mutex = asyncio.Lock()
        self._anchor = load_materialized_successor_anchor(config_path)
        self._recheck()

    def _recheck(self):
        validate_authenticated_successor_installation(self.installation)
        self._anchor.recheck()
        if (
            self._anchor.config != self.config
            or self._anchor.receipt_sha256 != self.installation.receipt_sha256
            or self._anchor.operator_consent != self.installation.operator_consent
            or self._anchor.worker_execution_limits != self.installation.worker_execution_limits
            or self._anchor.observer_config != self.installation.observer_config
            or self.delivery.config != self.config
            or self.delivery.consent != self.installation.operator_consent
            or self.delivery.worker_limits != self.installation.worker_execution_limits
        ):
            raise SuccessorMaterializerError(
                "materializer differs from the installed root controls"
            )

    def _stage(self, selection, files):
        self._recheck()
        return stage_successor_current(
            selection=selection,
            files=files,
            config=self.config,
            operator_consent=self.installation.operator_consent,
            worker_limits=self.installation.worker_execution_limits,
            limits=self.limits,
        )

    async def fetch(self, selection: SuccessorWorkerSelection) -> SuccessorArtifactFiles:
        async with self._mutex:
            self._recheck()
            files = await self.delivery.fetch(selection)
            self._stage(selection, files)
            self._recheck()
            return files

    def _floor(self, observation, selection):
        validate_owned_weight_observation(observation)
        if (
            account_id32(observation.validator_hotkey) != account_id32(self.config.validator_hotkey)
            or observation.genesis_hash.removeprefix("0x")
            != selection.signed.directive.chain.chain_pin.genesis_block_hash
        ):
            raise SuccessorMaterializerError(
                "materializer observation belongs to another chain or validator"
            )
        return observation.block, observation.block_hash

    async def _fresh(self, selection, files, floor, *, worker_inputs=None):
        # Root source/archive authentication may be expensive. Complete it
        # before capturing finality; afterward the verified RO inode snapshot
        # detects changes without re-reading/replaying the same evidence.
        self._recheck()
        observation = await self.observer.observe_for(selection, files)
        if worker_inputs is None:
            validate_authenticated_successor_installation(self.installation)
        else:
            worker_inputs.recheck()
        block, block_hash = self._floor(observation, selection)
        if block < floor[0] or (block == floor[0] and block_hash != floor[1]):
            raise SuccessorMaterializerError(
                "materializer finalized observation rolled back or forked"
            )
        directive = selection.signed.directive
        verify_signed_successor_supervisor_directive(
            selection.signed,
            config=self.config,
            operator_consent=self.installation.operator_consent,
            finalized_block=block,
        )
        if (
            not observation.validator_permit
            or block < directive.valid_from_block
            or directive.valid_through_block - block < directive.minimum_activation_headroom_blocks
        ):
            raise SuccessorMaterializerError(
                "materializer activation permit or interval is unavailable"
            )
        return observation

    async def activate(self, selection, artifacts, *, owned_observation):
        async with self._mutex:
            self._recheck()
            # This immutable floor is not current authority after slow work.
            floor = self._floor(owned_observation, selection)
            staged = self._stage(selection, artifacts)
            current = await self._fresh(selection, artifacts, floor)
            floor = (current.block, current.block_hash)
            select_staged_successor_current(staged, anchor=self._anchor)
            self._recheck()
            inputs = load_successor_worker_inputs()  # Only the fixed read-only mount.
            if (
                inputs.receipt_sha256 != self.installation.receipt_sha256
                or inputs.config != self.config
                or inputs.signed_directive != selection.signed
                or canonical_json_bytes(inputs.current_page)
                != artifacts.current_directive_page_bytes
                or canonical_json_bytes(inputs.worker_execution_config)
                != artifacts.worker_execution_bytes
                or (
                    canonical_json_bytes(inputs.authorization)
                    if inputs.authorization is not None
                    else None
                )
                != artifacts.authorization_bytes
            ):
                raise SuccessorMaterializerError(
                    "read-only mount did not select the exact staged controls"
                )
            # Loading replays the package and can be slow. Recapture rather than
            # extending the lifetime of the pre-copy or pre-load observation.
            current = await self._fresh(selection, artifacts, floor, worker_inputs=inputs)
            return activate_successor_worker(inputs, owned_observation=current)
