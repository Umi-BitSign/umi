"""Owned-finality and local-conflict gates for per-round authority signing.

The publisher owns its finalized provider and reads the retained intake and
publication journals. It has release-authority hotkeys, never validator or
coldkey wallets. HTTP requests cannot supply heads, source status or signers.
The coordinator stays wallet-free. Distribution is a separate operation.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path

from .competition_chain import CompetitionChainConfig
from .competition_execution import execution_boundary
from .competition_package import PreparedCompetitionPackage
from .concurrency import run_owned_thread
from .encoding import account_id32
from .open_competition import RegistrationSnapshot, digest
from .protocol import canonical_json_bytes


class CurrentSuccessorRoundPublisher:
    """A managed provider must be started before this local service is called."""

    def __init__(self, builder, store, replay_worker, provider):
        plan = builder.plan
        config = CompetitionChainConfig.model_validate_json(canonical_json_bytes(provider.config))
        target = config.target_triple
        if (
            digest(store.policy) != plan.policy_sha256
            or provider.policy != store.policy
            or config.policy_sha256 != plan.policy_sha256
            or config.chain_pin != plan.chain.chain_pin
            or config.finality_pin.release_sha256_by_target.get(target)
            != plan.weights.required_finality_verifier_sha256_by_target.get(target)
            or config.proof_binary_sha256
            != plan.weights.required_storage_proof_verifier_sha256_by_target.get(target)
            or target not in plan.weights.required_finality_verifier_sha256_by_target
            or target not in plan.weights.required_storage_proof_verifier_sha256_by_target
            or replay_worker.package_limits != plan.package_limits
        ):
            raise ValueError("publisher sources differ from approved policy or verifier pins")
        self.builder, self.store, self.replay, self.provider = (
            builder,
            store,
            replay_worker,
            provider,
        )
        self._config_sha256 = digest(config)
        self._collection_timeout = config.collection_timeout_seconds
        self._serial = asyncio.Lock()
        builder.journal.put(
            "source",
            "current",
            {
                "schema": "umi-successor-publisher-sources/1",
                "chain_config_sha256": self._config_sha256,
                "intake_journal": str(store.path),
                "replay_journal": str(replay_worker.path),
            },
        )

    async def _head(self, package=None):
        if digest(self.provider.config) != self._config_sha256:
            raise ValueError("publisher finalized provider configuration changed")
        capture = await asyncio.wait_for(self.provider.collect(), timeout=self._collection_timeout)
        head = execution_boundary(capture)
        plan = self.builder.plan
        if not plan.valid_from_block <= head.block <= plan.valid_through_block:
            raise ValueError("publisher plan is not current")
        if package is not None and plan.maximum_settlement_reuse_blocks is not None:
            snapshot = RegistrationSnapshot.model_validate_json(
                canonical_json_bytes(capture.snapshot)
            )
            if digest(snapshot) != head.snapshot_sha256:
                raise ValueError("publisher recipient capture changed")
            registrations = {
                entry.uid: account_id32(entry.hotkey) for entry in snapshot.registrations
            }
            for entry in package.retained_settlement.projection.allocations:
                if registrations.get(entry.uid) != account_id32(entry.hotkey):
                    raise ValueError("settlement recipient registration changed")
            burn = package.policy.unallocated_model_burn
            if burn is not None and snapshot.burn_destination != burn:
                raise ValueError("model burn destination changed before publication")
        return head

    def _source(self, package, result):
        if digest(self.store.policy) != self.builder.plan.policy_sha256:
            raise ValueError("publisher intake policy changed")
        if (
            result.receipt.package_sha256 != package.package_sha256
            or result.receipt.status != "replayed_no_weight"
            or result.current_status.held
            or not result.current_status.cutoff_certificate_retained
            or not result.current_status.settlement_certificate_retained
        ):
            raise ValueError("publisher replay is held or incomplete")
        self.replay.verify_publication_unchanged(result)
        material = self.store.settlement_material(
            package.settlement_certificate.publication.round, limits=package.replay_limits
        )
        if (
            material["retained_settlement"] != package.retained_settlement
            or material["submissions"] != package.roster.submissions
            or material["evidence"]
            != tuple((e.submission, e.evidence) for e in package.evidence.entries)
            or material["cutoff_schedule"] != package.cutoff_certificate.publication.cutoff_schedule
            or self.store.reviewed_promotion_head(
                package.manifest.round_sha256,
                maximum_bytes=min(
                    16 * 1024**2, self.builder.plan.package_limits.maximum_settlement_bytes
                ),
            )
            != package.retained_settlement.promotion_head
        ):
            raise ValueError("publisher package differs from current retained source")
        self.replay.verify_publication_unchanged(result)

    async def build(self, prepared, *, authorization_wallet, directive_wallets, renew=False):
        """Return a current signed round, with durable partial-signature recovery.

        Heavy replay runs off the event loop. Each signing boundary asks the
        process-owned provider for a fresh capture, then checks current source
        conflicts. Cancellation drains the signing thread before releasing the
        service lock; a canceled call cannot leave an unobserved signing task.
        """
        prepared = PreparedCompetitionPackage.model_validate_json(canonical_json_bytes(prepared))
        directive_wallets = tuple(directive_wallets)
        async with self._serial:
            initial = await self._head()
            loop = asyncio.get_running_loop()
            stopped = threading.Event()

            def check_stopped():
                if stopped.is_set():
                    raise RuntimeError("publisher operation canceled")

            def work():
                check_stopped()
                result = self.replay.run(
                    Path(prepared.package_path),
                    expected_package_sha256=prepared.package_sha256,
                    expected_policy_sha256=self.builder.plan.policy_sha256,
                    observed_release=self.builder.plan.release.replay_release_identity,
                )

                def gate(package):
                    check_stopped()
                    self._source(package, result)
                    pending = asyncio.run_coroutine_threadsafe(self._head(package), loop)
                    try:
                        head = pending.result(timeout=self._collection_timeout + 1)
                    finally:
                        if not pending.done():
                            pending.cancel()
                    check_stopped()
                    self._source(package, result)
                    return head.block

                check_stopped()
                return self.builder.build(
                    prepared,
                    finalized_block=initial.block,
                    authorization_wallet=authorization_wallet,
                    directive_wallets=directive_wallets,
                    current_gate=gate,
                    renew=renew,
                )

            return await run_owned_thread(work, on_cancel=stopped.set)
