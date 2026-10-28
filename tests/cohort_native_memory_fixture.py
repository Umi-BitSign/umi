"""Real private leases around native test consumers; no host capacity claim.

Virtual HTTP roles get fresh Contexts, as separate installed processes would.
The small reservation sizes and mocked MemAvailable are fixture policy only.
All native protocol checks, original evidence and real file locks remain active.
"""

import asyncio
from collections import Counter
from contextlib import AsyncExitStack
from contextvars import Context
from functools import wraps
from pathlib import Path

import httpx
import pytest

from umi import competition_cohort_request_export as export_module
from umi import competition_cohort_request_remote_review as request_module
from umi import competition_cohort_settlement_service as settlement_module
from umi import competition_reward_coordinator as reward_module
from umi import host_memory_admission as admission
from umi import host_memory_runtime as memory
from umi.competition_cohort_review_config import PhaseReviewServiceConfig
from umi.competition_cohort_review_selection import SelectedPhaseReviewer
from umi.competition_reward_control_publisher import StandingControlPublisher
from umi.competition_reward_offers import StandingRewardOffers
from umi.competition_reward_preparation import StandingRewardPreparation
from umi.competition_store import CompetitionStore
from umi.competition_verification_snapshot import VerificationSnapshotRepairRequired
from umi.concurrency import await_owned_task
from umi.open_competition import digest
from umi.policy import scoring_policy_hash
from umi.private_files import publish_private_model


def isolated_asgi_transport(base, selection, maximum):
    class IsolatedASGITransport(base):
        async def handle_async_request(self, request):
            async def dispatch():
                with memory.memory_runtime(selection, maximum_aggregate_bytes=maximum):
                    return await super(IsolatedASGITransport, self).handle_async_request(request)

            # Keep HTTP roles from inheriting the caller's active operation,
            # without clearing or bypassing the actual runtime's nested guard.
            task = Context().run(asyncio.create_task, dispatch())
            return await await_owned_task(task, on_cancel=task.cancel)

    return IsolatedASGITransport


class NativeAdmissionProbe:
    def __init__(self, provisioned, monkeypatch, owner):
        _, path, policy, write, _ = provisioned
        cohorts = tuple(sorted(digest(p) for p in owner.config.series.cohorts))
        assert len(cohorts) <= len(policy["settlement_signals"])
        policy["settlement_signals"] = [
            dict(signal, cohort_sha256=cohort)
            for signal, cohort in zip(
                policy["settlement_signals"][: len(cohorts)], cohorts, strict=True
            )
        ]
        policy["maximum_aggregate_bytes"] = 1024**3
        self.selection = memory.HostMemoryAdmissionSelection(
            policy_path=str(path), policy_sha256=write(policy)
        )
        selected = owner.config.admission_owner.model_copy(
            update={
                "host_memory_admission": self.selection,
                "maximum_aggregate_evidence_bytes": policy["maximum_aggregate_bytes"],
            }
        )
        owner.config = owner.config.model_copy(update={"admission_owner": selected})
        owner.service.config = owner.config
        self.maximum = policy["maximum_aggregate_bytes"]
        self.report_path = path.parent / "selected-admission-proof.json"
        self.patch, self.stack = monkeypatch, AsyncExitStack()
        self.calls, self.granted, self.released = Counter(), Counter(), Counter()
        self.live = {}
        self.nodes = []
        self.try_acquire = admission.HostMemoryAdmission.try_acquire
        self.try_settlement = admission.HostMemoryAdmission.try_settlement

    async def __aenter__(self):
        await self.stack.__aenter__()
        self.controller = self.stack.enter_context(
            memory.memory_runtime(self.selection, maximum_aggregate_bytes=self.maximum)
        )
        self.patch.setattr(
            httpx,
            "ASGITransport",
            isolated_asgi_transport(httpx.ASGITransport, self.selection, self.maximum),
        )
        self._instrument()
        return self

    async def __aexit__(self, *error):
        return await self.stack.__aexit__(*error)

    def _held(self, lane):
        selected = memory.selected_memory()
        assert selected is not None and selected.policy_sha256 == self.selection.policy_sha256
        if lane == "transient":
            active = memory._active.get()
            assert active is not None and not active.closed and active.slot.lane == lane
        lease = self.try_acquire(self.controller, lane)
        if lease is not None:
            lease.close()
            pytest.fail(f"native {lane} work entered without its selected lease")

    def _free(self, *, role=None, cohort=None):
        lease = (
            self.try_settlement(self.controller, cohort, role)
            if role
            else self.try_acquire(self.controller, "transient")
        )
        assert lease is not None
        lease.close()

    def _watch_sync(self, target, attribute, label, lane="transient"):
        original = getattr(target, attribute)

        @wraps(original)
        def observed(*args, **kwargs):
            self._held(lane)
            if label == "request_export":
                # This worker serves a separately isolated HTTP role while
                # the reviewer keeps its own native replay reservation.
                assert memory._active.get() is None
                transient = self.try_acquire(self.controller, "transient")
                if transient is not None:
                    transient.close()
                    pytest.fail("request owner export did not overlap admitted remote review")
                self.calls["request_owner_reviewer_overlap"] += 1
            self.calls[label] += 1
            try:
                return original(*args, **kwargs)
            except Exception:
                self.calls[label + ":failure"] += 1
                raise

        self.patch.setattr(target, attribute, observed)

    def _instrument(self):
        close = admission.HostMemoryLease.close

        def remember(lease):
            if lease is not None:
                key = lease.slot.settlement_role or lease.slot.lane
                self.live[id(lease)] = key
                self.granted[key] += 1
            return lease

        def acquire(controller, lane):
            return remember(self.try_acquire(controller, lane))

        def retained(controller, cohort, role):
            return remember(self.try_settlement(controller, cohort, role))

        def release(lease):
            key = self.live.pop(id(lease), None)
            if key is not None:
                self.released[key] += 1
            close(lease)

        self.patch.setattr(admission.HostMemoryAdmission, "try_acquire", acquire)
        self.patch.setattr(admission.HostMemoryAdmission, "try_settlement", retained)
        self.patch.setattr(admission.HostMemoryLease, "close", release)
        self._watch_sync(
            export_module.RequestReviewExporter, "export", "request_export", "owner_export"
        )
        self._watch_sync(request_module, "replay_request_export", "request_replay")
        self._watch_sync(reward_module, "review_reward_decision", "reward_review")
        self._watch_sync(StandingRewardOffers, "__call__", "reward_offer")
        self._watch_sync(reward_module.StandingRewardCoordinator, "_readback", "reward_readback")
        self._watch_sync(StandingControlPublisher, "_delivered", "reward_delivered")
        self._watch_sync(StandingRewardPreparation, "_prepare_initial", "validator_prepare")
        service = settlement_module.CohortSettlementService
        original_init, original_load = service.__init__, service._load_active_inputs

        @wraps(original_init)
        def initialize(node, *args, **kwargs):
            original_init(node, *args, **kwargs)
            assert node.config.host_memory_admission == self.selection
            assert node._memory_admission.policy_sha256 == self.selection.policy_sha256
            self.nodes.append(node)

        @wraps(original_load)
        async def load(node, history):
            lease = node._memory_lease
            assert lease is not None and not lease.closed
            assert lease.slot.settlement_role == node.config.role
            contender = self.try_settlement(self.controller, node.cohort, node.config.role)
            if contender is not None:
                contender.close()
                pytest.fail("native settlement role is not exclusively reserved")
            self.calls["settlement_load:" + node.config.role] += 1
            try:
                return await original_load(node, history)
            finally:
                # The caller owns release after this worker has drained.
                assert not lease.closed

        self.patch.setattr(service, "__init__", initialize)
        self.patch.setattr(service, "_load_active_inputs", load)

    async def request_reviewer(self, owner, name, signing, source, root):
        h = owner.h
        root = root.with_name(root.name + "-host")
        config = PhaseReviewServiceConfig(
            schema="umi-cohort-phase-review-service/1",
            series=owner.config.series,
            policy=h.intake.policy,
            manifest=owner.config.manifest,
            chain=owner.config.dispatch.origins.model_copy(
                update={"state_directory": str(root / "chain")}
            ),
            signing=signing,
            signer_key_file=str(root / "key"),
            owner_hotkey=owner.config.admission_owner.owner_hotkey,
            owner_origin="https://owner.example",
            owner_token_file=str(root / "owner-token"),
            vote_token_file=str(root / "vote-token"),
            inputs_directory=str(root / "selections"),
            promotion_directory=str(root / "promotion"),
            proof_import_directory=str(root / "proofs"),
            eligible_tracks=("endpoint", "model"),
            listen_port=18100 if name == "Charlie" else 18101,
            maximum_export_bytes=64 * 1024**2,
            maximum_aggregate_evidence_bytes=self.maximum,
            review_timeout_seconds=2400,
            host_memory_admission=self.selection,
        )
        inputs = Path(config.inputs_directory)
        for folder, key, value in (
            ("rosters", h.cohort, source.roster),
            ("terms", digest(h.terms), h.terms),
            ("transport", scoring_policy_hash(source.transport), source.transport),
            *(("catalogs", digest(value.catalog), value) for value in source.catalogs),
        ):
            publish_private_model(inputs / folder / (key + ".json"), value)
        client = await self.stack.enter_async_context(httpx.AsyncClient())
        return SelectedPhaseReviewer(
            config,
            h.provider,
            client,
            "e" * 32,
            h.provider.retained_archive,
            CompetitionStore(Path(config.promotion_directory), h.intake.policy),
        )

    async def recover_settlement(self, nodes, start, deliver, output, signatures):
        deliver()
        coordinator = nodes["Charlie"]
        cohort = coordinator.cohort
        expected, signed = output.read_bytes(), dict(signatures)
        original, _ = coordinator.package_reference
        replica = Path(coordinator.config.exchange_outbox) / "inputs" / (cohort + ".json")
        original_bytes = original.read_bytes()
        before = self.calls["settlement_load:coordinator"]
        replica.unlink()
        assert await coordinator.maintain() == "package_published"
        assert replica.read_bytes() == original_bytes
        assert self.calls["settlement_load:coordinator"] == before
        self.calls["replica_repaired_without_replay"] += 1

        # No coordinator native graph is held while a cold reviewer restores
        # its original terminal state. Missing/corrupt originals refuse natively.
        reviewer = start("Dave")
        self._free(role="coordinator", cohort=cohort)
        path = Path(reviewer.config.inputs_directory) / (cohort + ".json")
        raw = path.read_bytes()
        path.unlink()
        try:
            with pytest.raises(VerificationSnapshotRepairRequired):
                await reviewer.tick()
            assert reviewer.data is None and reviewer._memory_lease is None
            self._free(role="reviewer", cohort=cohort)
            path.write_bytes(b'{"corrupt_native_original":true}')
            path.chmod(0o600)
            with pytest.raises(ValueError):
                await reviewer.tick()
            assert reviewer.data is None and reviewer._memory_lease is None
            self._free(role="reviewer", cohort=cohort)
        finally:
            path.write_bytes(raw)
            path.chmod(0o600)
        deliver()
        assert await reviewer.tick() == "reviewing"
        assert reviewer.data is None and reviewer._memory_lease is None
        assert reviewer.reviewed_terminal_tip is not None
        self.calls["reviewer_only_native_recovery"] += 1

        output.unlink()
        assert await coordinator.tick() == "package_published"
        assert output.read_bytes() == expected and original.read_bytes() == original_bytes
        assert self.calls["settlement_load:coordinator"] == before + 1
        assert dict(signatures) == signed
        self.calls["generated_output_native_recovery"] += 1
        self._free(role="coordinator", cohort=cohort)
        self._free(role="reviewer", cohort=cohort)

    def assert_completed(self):
        for name in (
            "request_export",
            "request_owner_reviewer_overlap",
            "request_replay",
            "settlement_load:coordinator",
            "settlement_load:reviewer",
            "replica_repaired_without_replay",
            "reviewer_only_native_recovery",
            "generated_output_native_recovery",
            "reward_offer",
            "reward_review",
            "reward_readback:failure",
            "reward_delivered",
            "validator_prepare",
        ):
            assert self.calls[name] > 0, (name, dict(self.calls))
        assert set(self.granted) == {"owner_export", "transient", "coordinator", "reviewer"}
        assert self.granted == self.released and not self.live
        assert all(node.data is None and node._memory_lease is None for node in self.nodes)
        publish_private_model(
            self.report_path,
            {
                "schema": "umi-native-selected-admission-test/1",
                "native_calls": dict(self.calls),
                "leases_granted": dict(self.granted),
                "leases_released": dict(self.released),
                "live_leases": len(self.live),
                "selected_capacity_bytes": self.maximum,
                "http_process_contexts": "isolated_with_same_pinned_policy",
                "memory_sample_and_reservation_sizes": "synthetic_fixture",
                "whole_host_resources_qualified": False,
                "installed_hosts_qualified": False,
                "transaction_submitted": False,
            },
        )
