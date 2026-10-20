"""Owned native polling for automatic reference approvals and channel updates.

Sources are immutable signed decisions and compact effective allocations. This
service never opens the standing writer/coordinator journals, replays large
packages, reads miner models or submits chain transactions.
"""

from __future__ import annotations

import asyncio
import os
import time
from contextlib import AsyncExitStack, suppress
from pathlib import Path

from .competition_chain import OwnedFinalityStale, RegistrationProviderTimeout, _AwaitingFinality
from .competition_chain_state import FinalizedCompetitionWeightProvider
from .competition_reward_control import FinalizedRewardControlProvider
from .competition_reward_decisions import StandingRewardControlReader
from .concurrency import await_owned_task, run_owned_thread
from .open_competition import digest
from .private_files import ensure_private_directory, lock_private_file
from .protocol import canonical_json_bytes
from .translation_reference_channel import (
    ReferenceChannelConflict,
    TranslationReferenceChannelPublisher,
)
from .translation_reference_publication import (
    ReferenceRowPending,
    TranslationReferenceApprovalPublisher,
)
from .translation_reference_renewal import ReferenceDirectiveRenewal
from .validator_chain import ValidatorChainError


class TranslationReferencePublisherService:
    def __init__(
        self,
        *,
        root: Path,
        reader: StandingRewardControlReader,
        provider: FinalizedRewardControlProvider,
        approval: TranslationReferenceApprovalPublisher,
        channels: tuple[TranslationReferenceChannelPublisher, ...],
        decisions,
        allocations,
        horizons: dict[str, int],
        directive_renewal: ReferenceDirectiveRenewal | None = None,
        poll_seconds: int = 30,
        progress=None,
    ):
        if (
            type(reader) is not StandingRewardControlReader
            or not isinstance(provider, FinalizedRewardControlProvider)
            or not isinstance(provider, FinalizedCompetitionWeightProvider)
            or type(approval) is not TranslationReferenceApprovalPublisher
            or approval.reader is not reader
            or not channels
            or digest(provider.config) != reader.chain_config_sha256
            or digest(provider.policy) != digest(reader.policy)
            or any(type(c) is not TranslationReferenceChannelPublisher for c in channels)
            or len({c.config.channel_id for c in channels}) != len(channels)
            or type(poll_seconds) is not int
            or not 1 <= poll_seconds <= 3600
        ):
            raise ValueError("reference publication service owners differ")
        if directive_renewal is not None:
            directive_renewal = ReferenceDirectiveRenewal.model_validate_json(
                canonical_json_bytes(directive_renewal)
            )
        if (horizons or directive_renewal is None) and (
            set(horizons) != {digest(p) for p in reader.series.cohorts}
            or any(type(v) is not int or not 1 <= v <= 2**53 - 1 for v in horizons.values())
            or any(horizons[digest(p)] < p.not_before_block for p in reader.series.cohorts)
        ):
            raise ValueError("reference publication needs explicit valid cohort horizons")
        self.root, self.reader, self.provider, self.approval = root, reader, provider, approval
        self.channels, self.decisions, self.allocations = channels, decisions, allocations
        self.horizons, self.poll_seconds, self.progress = dict(horizons), poll_seconds, progress
        self.directive_renewal = directive_renewal

    def _window(self, block: int, cohort: str | None = None) -> tuple[int, int]:
        if self.directive_renewal is not None:
            return (
                self.directive_renewal.through_block(block),
                self.directive_renewal.renew_before_blocks,
            )
        return (max(self.horizons.values()) if cohort is None else self.horizons[cohort], 0)

    def _event(self, stage, started, *, completed=0, total=1, status="running", row_pending=None):
        if self.progress is not None:
            self.progress(
                dict(
                    stage=stage,
                    completed=completed,
                    total=total,
                    percent=100 * completed / total if total else 100,
                    elapsed_seconds=time.monotonic() - started,
                    eta_seconds=0 if completed == total and status == "complete" else None,
                    planning_seconds=[2, 120] if status == "running" else None,
                    eta_basis="planning for native control/registration and channel count; "
                    "missing inputs/retries have no measured finish; external rows separate",
                    status=status,
                    stalled=status in {"waiting_inputs", "retrying"},
                    retrying=status == "retrying",
                    **(
                        dict(
                            reason_code="reference_current_row_pending",
                            reference_last_update=row_pending.last_update,
                            minimum_reference_update=row_pending.minimum_update,
                        )
                        if row_pending is not None
                        else {}
                    ),
                )
            )

    async def tick(self):
        started = time.monotonic()
        self._event("reference_owner_current_control", started)
        await self.provider.start()
        self.provider.ensure_observer_running()
        control = await self.provider.collect_control(self.reader.series.control_hotkey)
        selected = await run_owned_thread(self.reader.select, control, self.decisions)
        self._event("reference_owner_current_control", started, completed=1, status="complete")
        if selected.state in {"admitted", "draining"}:
            self._event("reference_owner_wait_selection", started, status="waiting_inputs")
            return selected.state
        if selected.state in {"revoked", "suspended"}:
            horizon, margin = self._window(control.snapshot.block_number)
            for index, channel in enumerate(self.channels, 1):
                await run_owned_thread(
                    lambda channel=channel: channel.select_hold(
                        self.reader,
                        control=control,
                        source=self.decisions,
                        valid_through_block=horizon,
                        renew_before_blocks=margin,
                    )
                )
                self._event(
                    "reference_owner_hold_channels",
                    started,
                    completed=index,
                    total=len(self.channels),
                    status="complete" if index == len(self.channels) else "running",
                )
            return selected.state
        activation = selected.activation
        if activation is None or activation.cohort_sha256 not in {
            digest(p) for p in self.reader.series.cohorts
        }:
            raise ValueError("selected cohort has no configured publication horizon")
        horizon, margin = self._window(control.snapshot.block_number, activation.cohort_sha256)
        allocation_sha = activation.effective_allocation_sha256 or activation.allocation_sha256
        self._event("reference_owner_allocation", started)
        allocation = await run_owned_thread(self.allocations, allocation_sha)
        self._event("reference_owner_allocation", started, completed=1, status="complete")
        self._event("reference_owner_current_registration", started)
        chain = await self.provider.collect_registered_weights(
            self.approval.reference_hotkey, at=control.snapshot
        )
        self._event("reference_owner_current_registration", started, completed=1, status="complete")
        inputs = dict(
            control=control,
            source=self.decisions,
            allocation=allocation,
            chain=chain,
            chain_config=self.provider.config,
        )
        for index, channel in enumerate(self.channels, 1):
            await run_owned_thread(
                lambda channel=channel: channel.step(
                    self.approval,
                    valid_through_block=horizon,
                    renew_before_blocks=margin,
                    **inputs,
                )
            )
            self._event(
                "reference_owner_channels",
                started,
                completed=index,
                total=len(self.channels),
                status="complete" if index == len(self.channels) else "running",
            )
        return "selected"

    async def run(self, stop: asyncio.Event):
        ensure_private_directory(self.root)

        async def close_provider():
            await await_owned_task(asyncio.create_task(self.provider.aclose()))

        async with AsyncExitStack() as resources:
            try:
                descriptor = lock_private_file(self.root / "reference-owner.lock")
            except BaseException:
                await close_provider()
                raise
            resources.callback(os.close, descriptor)
            resources.push_async_callback(close_provider)
            while not stop.is_set():
                started = time.monotonic()
                try:
                    await self.tick()
                except FileNotFoundError:
                    self._event("reference_owner_wait_inputs", started, status="waiting_inputs")
                except ReferenceRowPending as error:
                    self._event(
                        "reference_owner_wait_reference_row",
                        started,
                        status="waiting_inputs",
                        row_pending=error,
                    )
                except (
                    OSError,
                    TimeoutError,
                    ReferenceChannelConflict,
                    OwnedFinalityStale,
                    RegistrationProviderTimeout,
                    _AwaitingFinality,
                    ValidatorChainError,
                ):
                    self._event("reference_owner_transport_retry", started, status="retrying")
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=self.poll_seconds)
