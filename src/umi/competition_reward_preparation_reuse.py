"""Native preparation completion and its separately resumable dependencies.

Only StandingRewardPreparation writes native completion, after its actual replay
or an owner-restored coverage verdict. Records are local verification state, not
signing authority. Transaction selection and projection still use fresh proofs.
"""

from __future__ import annotations

from .competition_cohort_reward_allocation import CohortRewardAllocation
from .competition_reward_adoption import verify_reward_adoption
from .competition_reward_preparation_checkpoint import (
    PreparationCheckpointRepairRequired,
    PreparationCheckpoints,
)
from .competition_transport_verification import TransferProgress
from .competition_verification_rules import runtime_identity
from .competition_verification_snapshot import VerifiedPackageSnapshot, verified_package_digest
from .concurrency import run_owned_thread
from .open_competition import digest
from .protocol import canonical_json_bytes

SCHEMA = "umi-standing-preparation-native/1"


class PreparationReuse:
    def __init__(self, preparation):
        self.preparation = preparation
        self.models_checked = {}
        self.consumer_dependency_keys = {}
        progress = TransferProgress(
            "reward_preparation_checkpoint_open",
            1,
            unit="stores",
            planning_unit_seconds=(0.001, 1),
        )
        try:
            with progress:
                self.store = PreparationCheckpoints(
                    preparation.verification_reuse.directory / "prepared-rewards",
                    binding={
                        "series": preparation.series_sha256,
                        "policy": preparation.policy_sha256,
                        "chain": preparation.reader.chain_config_sha256,
                        "semantics": runtime_identity(),
                    },
                )
                progress.advance(1)
        except PreparationCheckpointRepairRequired:
            progress.emit("repair_required", reason="preparation_checkpoint_owner_changed")
            raise

    def _context(self, package, activation):
        from .competition_reward_coverage_models import _context as model_context

        p = self.preparation
        p._authority()
        requirement = p.manifest.requirement(activation.cohort_sha256)
        if type(package) is VerifiedPackageSnapshot:
            path, stamp = package.original_identity(maximum_bytes=p.maximum_package_bytes)
            package_identity = {"kind": "snapshot", "path": str(path), "stamp": list(stamp)}
        else:
            # The compatibility API accepts an in-memory package, not a trusted
            # immutable file capability. Its caller-owned bytes must first be
            # detached and validated by _validated_reward_snapshot. The ordinary
            # installed path uses snapshots and never reads package payload here.
            package_identity = {"kind": "inline", "sha256": verified_package_digest(package)}
        if (
            verified_package_digest(package) != activation.package_sha256
            or digest(package.allocation) != activation.allocation_sha256
            or digest(package.inputs.history.plan) != activation.cohort_sha256
            or digest(package.inputs.history.authority.authority)
            != digest(p.reader.series.recovery.authority)
        ):
            raise ValueError("retained preparation changes the selected package")
        transport = p.transport_qualifications.load(
            activation.package_sha256, activation.cohort_sha256
        )
        if transport is None:
            raise PreparationCheckpointRepairRequired(
                "completed preparation lost its transport qualification"
            )
        return {
            "schema": SCHEMA,
            "activation_sha256": digest(activation),
            "package_sha256": activation.package_sha256,
            "package_identity": package_identity,
            "policy_sha256": p.policy_sha256,
            "series_sha256": p.series_sha256,
            "chain_config_sha256": p.reader.chain_config_sha256,
            "authority_sha256": digest(p.reader.series.recovery.authority),
            "requirement_sha256": digest(requirement),
            "transport_sha256": digest(transport),
            "model_verifier_sha256": (
                None if p.model_artifacts is None else digest(model_context(p.model_artifacts))
            ),
            "semantics_sha256": runtime_identity(),
        }

    def retain(self, package, prepared):
        """Commit in the native replay thread before exposing its completion."""
        context = self._context(package, prepared.activation)
        value = context | {
            "reviewed_at_block": prepared.reviewed_at_block,
            "allocation": prepared.allocation.model_dump(mode="json", by_alias=True),
        }
        activation = digest(prepared.activation)
        self.store.begin(activation, prepared.activation.package_sha256)
        with TransferProgress(
            "reward_preparation_native_completion",
            1,
            unit="preparations",
            planning_unit_seconds=(0.001, 1),
        ) as progress:
            self.store.retain_native(activation, prepared.reviewed_at_block, value)
            progress.advance(1)

    def _restore(self, package, activation, block):
        p = self.preparation
        value = self.store.status(digest(activation), block)
        if value is None:
            self.store.begin(digest(activation), activation.package_sha256)
            return None
        context = self._context(package, activation)
        binding = value
        dependency_key = None
        if any(value.get(key) != expected for key, expected in context.items()):
            # Shared verification stores can contain an earlier completed fact
            # for another consumer's package path or model verifier. Reuse this
            # consumer's original fact without rewriting either completion.
            binding = self.store.consumer_fact(digest(activation), context=context)
            if binding is None:
                raise PreparationCheckpointRepairRequired("completed preparation disappeared")
            if binding["reviewed_at_block"] <= block:
                value = binding
            else:
                from .competition_reward_preparation_consumer import completed_consumer_dependencies

                with TransferProgress(
                    "reward_preparation_consumer_restore",
                    2,
                    unit="completed_preparations",
                    planning_unit_seconds=(0.001, 1),
                ) as progress:
                    dependency_key = completed_consumer_dependencies(self.store, value, binding)
                    progress.advance(2, restored=True)
        if set(binding) != set(context) | {"reviewed_at_block", "allocation"} or any(
            binding[key] != expected for key, expected in context.items()
        ):
            raise PreparationCheckpointRepairRequired(
                "completed preparation dependencies changed; scoped repair is required"
            )
        allocation = CohortRewardAllocation.model_validate_json(
            canonical_json_bytes(value["allocation"])
        )
        if (
            digest(allocation)
            != (activation.effective_allocation_sha256 or activation.allocation_sha256)
            or allocation.policy_sha256 != p.policy_sha256
            or allocation.round_sha256 != package.allocation.round_sha256
        ):
            raise PreparationCheckpointRepairRequired("completed preparation allocation changed")
        if activation.reward_adoption_sha256 is not None:
            verify_reward_adoption(
                getattr(p.reader, "reward_adoptions", None),
                activation.reward_adoption_sha256,
                series=p.reader.series,
                policy=p.reader.policy,
                activation=activation,
                current_block=block,
            )
        # Legacy allocations depend on the selected promotion and live conflict
        # state. Recheck that bounded native receipt, not the complete package.
        if allocation.model_award is None:
            promotion = p.promotion_store.reviewed_promotion_at(
                allocation.round_sha256,
                allocation.promotion_head.promotion_sha256,
                maximum_bytes=p.maximum_promotion_bytes,
            )
            if promotion != allocation.promotion_head:
                raise PreparationCheckpointRepairRequired("completed promotion binding changed")
        prepared = p._issue_prepared(
            package,
            activation,
            allocation,
            value["reviewed_at_block"],
            context["requirement_sha256"],
        )
        key = self.store.key(digest(activation), prepared.reviewed_at_block)
        if dependency_key is None:
            self.consumer_dependency_keys.pop(key, None)
        else:
            self.consumer_dependency_keys[key] = dependency_key
        return prepared

    async def restore(self, package, activation, block):
        progress = TransferProgress(
            "reward_preparation_native_restore",
            1,
            unit="preparations",
            planning_unit_seconds=(0.001, 10),
        )
        try:
            with progress:
                prepared = await run_owned_thread(self._restore, package, activation, block)
                progress.advance(1, restored=prepared is not None)
                return prepared
        except PreparationCheckpointRepairRequired:
            progress.emit("repair_required", reason="completed_preparation_changed")
            raise

    async def finish(self, package, prepared, *, native_completed_here=False):
        from .competition_reward_coverage_models import CoverageModelDependencyRepairRequired

        progress = TransferProgress(
            "reward_preparation_dependencies",
            1,
            unit="preparations",
            planning_unit_seconds=(0.001, 30),
        )
        try:
            with progress:
                return await self._finish(
                    package, prepared, progress, native_completed_here=native_completed_here
                )
        except (PreparationCheckpointRepairRequired, CoverageModelDependencyRepairRequired):
            progress.emit("repair_required", reason="completed_preparation_dependencies_changed")
            raise

    async def _finish(self, package, prepared, progress, *, native_completed_here):
        # Imported lazily because coverage's native capability depends on the
        # preparation owner. These helpers authenticate model receipts, not rows.
        from .competition_reward_coverage_models import (
            capture_coverage_model_dependencies,
            restore_completed_model_dependencies,
        )

        p = self.preparation
        key = self.store.key(digest(prepared.activation), prepared.reviewed_at_block)
        key = self.consumer_dependency_keys.get(key, key)
        completion = await run_owned_thread(self.store.load_completion, key)
        if completion is None:
            models = await capture_coverage_model_dependencies(p, package, prepared)
            if models["mode"] == "not_selected":
                await restore_completed_model_dependencies(
                    p,
                    models,
                    self.models_checked,
                    cohort_sha256=prepared.activation.cohort_sha256,
                )
            if models["mode"] == "native_required" and not native_completed_here:
                await self._refresh_legacy_models(package, prepared)
            completion = {"schema": "umi-standing-preparation-dependencies/1", "models": models}
            await run_owned_thread(self.store.retain_completion, key, completion)
        else:
            if (
                set(completion) != {"schema", "models"}
                or completion["schema"] != "umi-standing-preparation-dependencies/1"
            ):
                raise PreparationCheckpointRepairRequired(
                    "completed preparation dependency schema changed"
                )
            restored = await restore_completed_model_dependencies(
                p,
                completion["models"],
                self.models_checked,
                cohort_sha256=prepared.activation.cohort_sha256,
            )
            if not restored:
                # Directory-backed legacy models have no immutable remote
                # dependency receipt. Keep their existing native asset check
                # without repeating unaffected allocation or history replay.
                await self._refresh_legacy_models(package, prepared)
        p._check_prepared(prepared)
        p._prepared[digest(prepared.activation)] = prepared
        await run_owned_thread(p._export_allocations, package.allocation, prepared.allocation)
        progress.advance(1, restored=True)
        return prepared

    async def _refresh_legacy_models(self, package, prepared):
        async with self.preparation._reference_scope(package):
            await self.preparation._ensure_model_artifacts(package)
            await run_owned_thread(self._legacy_models, package, prepared)

    def _legacy_models(self, package, prepared):
        p = self.preparation
        award = prepared.allocation.model_award
        if p.model_artifacts is None or award is None:
            raise PreparationCheckpointRepairRequired("legacy model verifier is not selected")
        participants = {
            digest(item.record.request.signed_submission.submission): item
            for item in package.inputs.roster.participants
        }
        with TransferProgress(
            "reward_preparation_legacy_model_refresh", len(award.acceptances), unit="models"
        ) as progress:
            for certificate in award.acceptances:
                p.model_artifacts.verify_candidate(
                    certificate,
                    participants[certificate.acceptance.submission_sha256],
                    certification_history=package.inputs.history,
                )
                progress.advance(1)
