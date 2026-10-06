"""Compose endpoint dispatch, response recovery and independent reviewer votes."""

from pathlib import Path
from typing import Annotated, Literal

import bittensor as bt
from pydantic import Field, model_serializer

from .competition_artifacts import preserved_bundle_available
from .competition_chain import CompetitionChainConfig
from .competition_cohort_attempt_worker import CohortEndpointAttemptWorker
from .competition_cohort_clip_delivery import ClipDeliveryConfig
from .competition_cohort_endpoint_decision_signer import (
    CohortEndpointDecisionConfig,
    CohortEndpointDecisionJournal,
    CohortEndpointDecisionSigner,
)
from .competition_cohort_endpoint_decision_worker import CohortEndpointCaseCoordinator
from .competition_cohort_endpoint_recovery import CohortEndpointResponseRecovery
from .competition_cohort_endpoint_retirement import CohortEndpointRetirement
from .competition_cohort_endpoint_vote_http import EndpointVotePeer
from .competition_cohort_endpoint_worker import CohortEndpointWorker
from .competition_cohort_executor import CohortExecutionAuthority
from .competition_cohort_history import verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_origin import CohortEndpointOrigin
from .competition_cohort_request_probe import (
    EvaluatorRequestReadiness,
    journal_stamp,
    tasks_running,
)
from .competition_cohort_request_signer import (
    EndpointRequestJournal,
    EndpointRequestSigner,
    EndpointRequestSignerConfig,
)
from .competition_cohort_request_worker import CohortEndpointRequestWorker
from .competition_cohort_review_http import CohortReviewPeerConfig
from .competition_cohort_service_quality import ServiceTerms
from .competition_cohort_settlement_delivery import SettlementEvidenceFiles
from .competition_execution import execution_boundary, read_case_video
from .competition_reward_boot import _disjoint
from .competition_runner import verify_runtime
from .competition_transport_finality import CompetitionTransportFinality
from .concurrency import run_owned_thread
from .open_competition import Hotkey, digest, identity
from .policy import ScoringPolicy, scoring_policy_hash
from .private_files import Directory, read_private_model
from .protocol import StrictProtocolModel, canonical_json_bytes


class EndpointHostConfig(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-host/1"] = Field(alias="schema")
    request_window_version: Literal[1, 2] = 1
    request_window_miner_hotkeys: Annotated[tuple[Hotkey, ...], Field(max_length=4096)] | None = (
        None
    )
    concurrency: Annotated[int, Field(strict=True, ge=1, le=32)] | None = None
    requests: EndpointRequestSignerConfig
    decisions: CohortEndpointDecisionConfig
    origins: CompetitionChainConfig
    clips: ClipDeliveryConfig
    objects_directory: Directory
    transport_directory: Directory
    reviewers: Annotated[tuple[CohortReviewPeerConfig, ...], Field(min_length=1, max_length=64)]

    @model_serializer(mode="wrap")
    def preserve_legacy_window_config(self, handler):
        value = handler(self)
        if self.request_window_version == 1:
            value.pop("request_window_version", None)
        if self.request_window_miner_hotkeys is None:
            value.pop("request_window_miner_hotkeys", None)
        if self.concurrency is None:
            value.pop("concurrency", None)
        return value

    def stores(self):
        return tuple(
            Path(p)
            for p in (
                self.requests.directory,
                self.decisions.directory,
                self.origins.state_directory,
                self.clips.directory,
                self.clips.videos_directory,
                self.clips.upload_token_file,
                self.objects_directory,
                self.transport_directory,
                *(r.token_file for r in self.reviewers),
            )
        )

    def check_scope(self, host):
        _disjoint(self.stores())
        for c in (self.requests, self.decisions):
            if (
                c.policy_sha256 != digest(host.policy)
                or c.cohorts != host.signing.cohorts
                or identity(c.signer) != identity(host.signing.signer)
            ):
                raise ValueError("endpoint worker changes evaluator or cohort selection")
        if (
            self.origins.policy_sha256 != digest(host.policy)
            or len(self.origins.proof_rpc_fallback_urls) != 2
        ):
            raise ValueError("endpoint origins require selected policy and two backup RPCs")
        expected = tuple(
            sorted(
                identity(e.hotkey)
                for e in host.policy.evaluators
                if identity(e.hotkey) != identity(host.signing.signer)
            )
        )
        if tuple(identity(p.signer) for p in self.reviewers) != expected:
            raise ValueError("endpoint host must configure each other authorized reviewer")


class EndpointHost:
    def __init__(self, config, benchmark, origins, client, credentials, key, sign, clips):
        self.config = c = EndpointHostConfig.model_validate_json(
            canonical_json_bytes(config.endpoint)
        )
        self.manifest, self.policy, self.benchmark = config.manifest, config.policy, benchmark
        self.clips, self.readiness_assignments = clips, {}
        self.readiness_stamp = None
        self.objects = SettlementEvidenceFiles(Path(c.objects_directory))
        self.transports = {}
        self.signer = EndpointRequestSigner(
            EndpointRequestJournal(c.requests, config.policy),
            benchmark.provider,
            None,
            benchmark.history,
            sign,
            transport_blocks=lambda policy: CompetitionTransportFinality(
                benchmark.provider, policy
            ),
        )
        self.decisions = CohortEndpointDecisionSigner(
            CohortEndpointDecisionJournal(c.decisions, config.policy),
            benchmark.provider,
            benchmark.history,
            bt.timelock.current_round,
            sign,
        )
        self.peers = {
            identity(peer.signer): EndpointVotePeer(
                client,
                peer.origin,
                policy=config.policy,
                cohorts=c.requests.cohorts,
                signer=peer.signer,
                token=token,
                timeout_seconds=peer.timeout_seconds,
            )
            for peer, token in zip(c.reviewers, credentials, strict=True)
        }
        authority = CohortExecutionAuthority(
            benchmark.execution, benchmark.provider, benchmark.history
        )
        self.recovery = CohortEndpointResponseRecovery(
            CohortEndpointOrigin(authority, origins), key
        )

        async def video(job, case):
            return await clips(case.video_sha256)

        async def request_vote(who, plan):
            return await self.peer(who).request_vote(plan)

        async def decision_vote(who, review):
            return await self.peer(who).decision_vote(review)

        requests = CohortEndpointRequestWorker(
            self.signer,
            self.recovery,
            request_vote,
            video_source=video,
            fresh_windows=c.request_window_version == 2,
            fresh_window_miner_hotkeys=c.request_window_miner_hotkeys,
        )
        decisions = CohortEndpointCaseCoordinator(
            CohortEndpointRetirement(self.recovery),
            self.decisions,
            decision_vote,
        )
        self.worker = CohortEndpointWorker(
            benchmark.inbox,
            CohortEndpointAttemptWorker(requests, decisions),
            self.transport,
            batch_size=benchmark.config.batch_size,
            concurrency=(
                c.concurrency if c.concurrency is not None else benchmark.config.concurrency
            ),
        )

    def peer(self, who):
        try:
            return self.peers[identity(who)]
        except KeyError as error:
            raise OSError("endpoint reviewer is not a remote configured peer") from error

    def _transport(self, assignment):
        cohort = assignment.certificate.order.round.cohort_sha256
        return self._cohort_transport(cohort)

    def _cohort_transport(self, cohort):
        if cohort not in self.transports:
            requirement = self.manifest.requirement(cohort)
            terms = ServiceTerms.model_validate_json(self.objects(requirement.terms_sha256))
            transport = read_private_model(
                Path(self.config.transport_directory) / (terms.transport_policy_sha256 + ".json"),
                ScoringPolicy,
                maximum_bytes=8 * 1024**2,
            )
            if scoring_policy_hash(transport) != terms.transport_policy_sha256:
                raise ValueError("endpoint transport differs from the selected cohort terms")
            self.transports[cohort] = transport
        return self.transports[cohort]

    async def transport(self, assignment):
        return await run_owned_thread(self._transport, assignment)

    async def request_vote(self, plan):
        if await self.transport(plan.assignment) != plan.transport:
            raise ValueError("endpoint request offered another transport policy")
        return await self.signer.attest(plan)

    async def decision_vote(self, review):
        if await self.transport(review.assignment) != review.selection.transport_policy:
            raise ValueError("endpoint decision offered another transport policy")
        return await self.decisions.attest(review)

    def _ready_assignments(self, probe):
        expected = probe.order_sha256s
        if expected != tuple(sorted(set(expected))):
            raise ValueError("readiness orders must be unique and sorted")
        self._cohort_transport(probe.cohort_sha256)
        stamp = journal_stamp(self.benchmark.inbox.journal)
        if stamp != self.readiness_stamp:
            self.readiness_assignments.clear()
        wanted = set(expected)
        self.readiness_assignments = {
            key: value for key, value in self.readiness_assignments.items() if key in wanted
        }
        # Acknowledged assignments are immutable, so retain their validated
        # objects in memory. Newly delivered orders are discovered on retry.
        if not wanted.issubset(self.readiness_assignments):
            after = ""
            while page := self.benchmark.inbox.assignments(after=after, limit=256):
                for slot in page:
                    value = self.benchmark.inbox.assignment(slot)
                    key = digest(value.certificate.order)
                    if key in wanted:
                        self.readiness_assignments[key] = value
                after = page[-1]
        result = []
        for key in expected:
            value = self.readiness_assignments.get(key)
            if value is None:
                raise FileNotFoundError("readiness assignment has not been delivered")
            order = value.certificate.order
            if (
                order.round.cohort_sha256 != probe.cohort_sha256
                or digest(order.round) != probe.round_sha256
            ):
                raise ValueError("readiness assignment differs from selected round")
            self._transport(value)
            result.append(value)
        if journal_stamp(self.benchmark.inbox.journal) != stamp:
            self.readiness_assignments.clear()
            raise OSError("assignment delivery changed during readiness; retry")
        self.readiness_stamp = stamp
        return tuple(result)

    def _ready_inputs(self, assignments):
        models, videos, runtimes = {}, {}, {}
        for value in assignments:
            order = value.certificate.order
            runtimes[digest(order.runtime)] = order.runtime
            models[digest(order.incumbent)] = order.incumbent
            if order.submission.submission.model_bundle is not None:
                bundle = order.submission.submission.model_bundle
                models[digest(bundle)] = bundle
            for case in order.cases:
                videos[case.video_sha256] = min(
                    videos.get(case.video_sha256, order.runtime.maximum_video_bytes),
                    order.runtime.maximum_video_bytes,
                )
        sandbox = self.benchmark.sandbox
        for model in models.values():
            preserved_bundle_available(model, sandbox.archive, self.policy)
        for key, maximum in videos.items():
            read_case_video(sandbox.videos, key, maximum)
        return tuple(runtimes.values()), tuple(sorted(videos))

    def _running(self):
        b = self.benchmark
        return (
            b.stop is not None
            and not b.stop.is_set()
            and set(b.tasks) == set(b.workers)
            and "endpoints" in b.tasks
            and tasks_running(b.tasks.values())
        )

    async def request_readiness(self, probe):
        b = self.benchmark
        requirement = self.manifest.requirement(probe.cohort_sha256)
        if (
            probe.policy_sha256 != digest(self.policy)
            or probe.cohort_sha256 not in b.inbox.cohorts
            or probe.catalog_sha256s != requirement.catalog_sha256s
        ):
            raise ValueError("request readiness differs from configured evaluator scope")
        b.provider.ensure_observer_running()
        self.recovery.origin.provider.ensure_observer_running()
        capture = await b.provider.collect()
        observation = execution_boundary(capture)
        ready = self._running()
        if ready:
            source = await b.history(probe.cohort_sha256)
            view = verify_cohort_history(
                source.history,
                self.policy,
                expected_tip_sha256=probe.recovery_tip_sha256,
                current_block=observation.block,
            )
            if view.state.phase != "requests":
                raise ValueError("request readiness requires an active request phase")
            assignments = await run_owned_thread(self._ready_assignments, probe)
            runtimes, videos = await run_owned_thread(self._ready_inputs, assignments)
            for runtime in runtimes:
                await verify_runtime(runtime, self.policy)
            for video in videos:
                await self.clips(video)
            latest = await b.history(probe.cohort_sha256)
            ready = self._running() and history_tip(latest.history) == probe.recovery_tip_sha256
        return EvaluatorRequestReadiness(
            schema="umi-evaluator-request-readiness/1",
            probe_sha256=digest(probe),
            observation=observation,
            ready=ready,
        )
