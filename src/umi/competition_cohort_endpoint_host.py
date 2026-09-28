"""Compose endpoint dispatch, response recovery and independent reviewer votes."""

from pathlib import Path
from typing import Annotated, Literal

import bittensor as bt
from pydantic import Field

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
from .competition_cohort_origin import CohortEndpointOrigin
from .competition_cohort_request_signer import (
    EndpointRequestJournal,
    EndpointRequestSigner,
    EndpointRequestSignerConfig,
)
from .competition_cohort_request_worker import CohortEndpointRequestWorker
from .competition_cohort_review_http import CohortReviewPeerConfig
from .competition_cohort_service_quality import ServiceTerms
from .competition_cohort_settlement_delivery import SettlementEvidenceFiles
from .competition_reward_boot import _disjoint
from .competition_transport_finality import CompetitionTransportFinality
from .concurrency import run_owned_thread
from .open_competition import digest, identity
from .policy import ScoringPolicy, scoring_policy_hash
from .private_files import Directory, read_private_model
from .protocol import StrictProtocolModel, canonical_json_bytes


class EndpointHostConfig(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-host/1"] = Field(alias="schema")
    requests: EndpointRequestSignerConfig
    decisions: CohortEndpointDecisionConfig
    origins: CompetitionChainConfig
    clips: ClipDeliveryConfig
    objects_directory: Directory
    transport_directory: Directory
    reviewers: Annotated[tuple[CohortReviewPeerConfig, ...], Field(min_length=1, max_length=64)]

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
            self.signer, self.recovery, request_vote, video_source=video
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
            concurrency=benchmark.config.concurrency,
        )

    def peer(self, who):
        try:
            return self.peers[identity(who)]
        except KeyError as error:
            raise OSError("endpoint reviewer is not a remote configured peer") from error

    def _transport(self, assignment):
        cohort = assignment.certificate.order.round.cohort_sha256
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
