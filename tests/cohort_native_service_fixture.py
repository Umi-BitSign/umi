"""Native service and endpoint hosts with explicit finality/media/inference ports.

The CLI builds the miner; public admission, grants, encrypted replies, independent
review and durable work receipts use their normal implementations.
"""

import hashlib
import time
from collections import Counter
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import bittensor as bt
import httpx
from fastapi import FastAPI

from umi import competition_cohort_dispatch_host as dispatch_module
from umi import competition_cohort_endpoint_host as endpoint_module
from umi import miner
from umi.competition_cohort_api import cohort_routes
from umi.competition_cohort_endpoint_decision_signer import CohortEndpointDecisionConfig
from umi.competition_cohort_endpoint_host import EndpointHost, EndpointHostConfig
from umi.competition_cohort_endpoint_vote_http import endpoint_vote_routes
from umi.competition_cohort_miner import CohortServiceMinerConfig
from umi.competition_cohort_miner_startup import CohortMinerStartupConfig
from umi.competition_cohort_participation import (
    CohortParticipationRequest,
    SignedCohortParticipationConsent,
)
from umi.competition_cohort_public_history import public_history_routes
from umi.competition_cohort_request_signer import EndpointRequestSignerConfig
from umi.competition_cohort_service_api import service_admission_routes
from umi.competition_cohort_service_export import ServiceWorkHTTPClient, ServiceWorkReader
from umi.competition_cohort_service_review import ServiceReviewConfig, ServiceWorkReviewer
from umi.competition_cohort_service_vote_http import service_vote_routes
from umi.competition_cohort_service_work import ServiceWorkClaim, SignedServiceWorkClaim
from umi.competition_cohort_settlement_delivery import SettlementEvidenceFiles
from umi.competition_endpoint_execution import RetainedRevealPulse
from umi.competition_execution import execution_boundary
from umi.competition_origin import EndpointOriginCapture
from umi.open_competition import digest, identity, sign_object
from umi.policy import ScoringPolicy, ValidatorRegistryEntry, scoring_policy_hash
from umi.private_files import publish_private_model
from umi.protocol import Video, canonical_json_bytes
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .test_competition_dispatch import dispatch_legacy_policy
from .test_drand import ROUND, pulse_record
from .test_open_competition import submission, wallet
from .test_validator_plans import FinalizedPort, _block, _clock

SERVICE_BYTES = b"inert native pipeline service video"
SERVICE_SHA = hashlib.sha256(SERVICE_BYTES).hexdigest()


def media(case):
    return ("inert native pipeline video " + case.case_id).encode()


def transport_policy():
    registry = tuple(
        sorted(
            (
                ValidatorRegistryEntry(
                    validator_hotkey=wallet(name).hotkey.ss58_address,
                    administrator_id=f"{i + 100:064x}",
                )
                for i, name in enumerate(("Charlie", "Dave", "Eve", "Ferdie"))
            ),
            key=lambda r: identity(r.validator_hotkey),
        )
    )
    return ScoringPolicy.model_validate_json(
        canonical_json_bytes(
            dispatch_legacy_policy().model_copy(update={"validator_registry": list(registry)})
        )
    )


async def admit_endpoint(o, scenario):
    h = o.h
    h.block += 1
    signed = submission(h.intake.policy, name="Bob")
    body = scenario["consent"].consent.model_copy(
        update={
            "hotkey": signed.submission.hotkey,
            "submission_sha256": digest(signed.submission),
            "signed_at_block": h.block,
        }
    )
    request = CohortParticipationRequest(
        signed_submission=signed,
        consent=SignedCohortParticipationConsent(
            consent=body, signature=sign_object(body, wallet("Bob"))
        ),
    )
    public = FastAPI()
    public.include_router(
        cohort_routes(h.intake, o.service.capture, maximum_body_bytes=4 * 1024**2)
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(public)) as client:
        response = await client.post(
            f"https://intake.example/v1/competition/cohorts/{h.cohort}/participation",
            content=canonical_json_bytes(request),
            headers={"content-type": "application/json"},
        )
    assert response.status_code == 200, response.text
    h.queue.attach_evidence(
        h.cohort,
        digest(request.consent.consent),
        *await h.provider.retained_archive(execution_boundary(h.capture(h.block))),
    )
    for worker in h.admissions:
        await worker.poll_once()
    return request


class NativeService:
    def __init__(self, o, scenario, root, monkeypatch, signatures, *, lose_reply=False):
        self.o, self.h, self.root = o, o.h, root
        self.monkeypatch, self.signatures = monkeypatch, signatures
        self.calls, self.endpoints = Counter(), {}
        self.lose_reply, self.lost_replies = lose_reply, 0
        self.bytes = {c.video_sha256: media(c) for c in scenario["suite"].cases}
        self.bytes[SERVICE_SHA] = SERVICE_BYTES
        self.blocks = None
        owner = self

        class Origins:
            def __init__(self, config, policy):
                self.config, self.policy = config, policy

            async def start(self):
                pass

            async def aclose(self):
                pass

            def _fresh(self, timestamp):
                assert timestamp == owner.h.timestamp

            async def _collect_origin_locked(self, signed, origin, *, recovery):
                assert recovery is not None
                capture = await owner.h.provider.collect()
                b = execution_boundary(capture)
                registration = next(
                    r
                    for r in capture.snapshot.registrations
                    if identity(r.hotkey) == identity(signed.submission.hotkey)
                )
                return EndpointOriginCapture(
                    submission_sha256=digest(signed.submission),
                    uid=registration.uid,
                    hotkey=registration.hotkey,
                    origin=origin,
                    block=b.block,
                    block_hash=b.block_hash,
                    state_root=b.state_root,
                    timestamp_ms=owner.h.timestamp,
                    evidence=b"fixture origin proof",
                    connection_origin="https://93.184.216.34:443",
                )

        self.origins = Origins(o.config.dispatch.origins, o.h.intake.policy)
        monkeypatch.setattr(dispatch_module, "CohortEndpointFinalityProvider", Origins)
        monkeypatch.setattr(dispatch_module, "CohortClipDelivery", lambda *a: self.clip)
        for module in (dispatch_module, endpoint_module):
            monkeypatch.setattr(module, "CompetitionTransportFinality", lambda *a: self.blocks)

    async def clip(self, sha):
        return Video(
            url=f"https://clips.example/{sha}.mp4",
            sha256=sha,
            size_bytes=len(self.bytes[sha]),
            media_type="video/mp4",
        )

    def window(self):
        """Place fixture finality inside a window with a verifiable reveal pulse."""
        h, transport = self.h, self.h.transport
        cohort_index = tuple(digest(plan) for plan in self.o.config.series.cohorts).index(h.cohort)
        index = (h.block - transport.activation_block) // transport.clock.window_stride_blocks + 2
        # Every production cohort reaches a different timelock window. Retain
        # that property while reusing the one signed fixture pulse; otherwise
        # the miner correctly treats later-cohort requests as duplicate
        # transmissions of the first cohort's assignments.
        announcement = _block(transport, index, block_byte=f"{0x31 + cohort_index:02x}")
        clock = _clock(transport)

        def derive(block):
            return clock.derive(
                index,
                netuid=transport.netuid,
                announcement_block_hash=block.block_hash,
                announcement_timestamp_ms=block.timestamp_ms,
                scoring_policy_hash=scoring_policy_hash(transport),
            )

        shift = (derive(announcement).reveal_round - ROUND) * QUICKNET_PERIOD_MS
        announcement = replace(announcement, timestamp_ms=announcement.timestamp_ms - shift)
        schedule = derive(announcement)
        assert schedule.reveal_round == ROUND
        issuance = _block(
            transport,
            0,
            height=schedule.closing_block + 1,
            block_byte=f"{0x41 + cohort_index:02x}",
            timestamp_ms=QUICKNET_GENESIS_MS + (schedule.selection_round - 1) * QUICKNET_PERIOD_MS,
        )
        self.blocks = FinalizedPort(
            head=issuance.height,
            blocks={announcement.height: announcement, issuance.height: issuance},
        )
        self.window_end = issuance.height + schedule.response_deadline_blocks + 1
        h.block, h.timestamp = issuance.height, issuance.timestamp_ms
        self.monkeypatch.setattr(time, "time", lambda: issuance.timestamp_ms / 1000)
        self.monkeypatch.setattr(bt.timelock, "current_round", lambda: schedule.selection_round)

    async def miner(self, stack):
        h, o, root, owner = self.h, self.o, self.root / "miner", self
        startup = CohortMinerStartupConfig(
            schema="umi-cohort-miner-startup/1",
            authority=CohortServiceMinerConfig(
                schema="umi-cohort-service-miner-config/1",
                directory=str(root / "grants"),
                cohorts=h.intake.config.cohorts,
                policy_sha256=digest(h.intake.policy),
                transport_policy_sha256=scoring_policy_hash(h.transport),
                miner_hotkey=wallet("Bob").hotkey.ss58_address,
                model_revision="b1" * 32,
                serving_origin="https://example.com",
                service_terms_sha256=digest(h.terms),
            ),
            history_origin="https://intake.example",
            history_owner_hotkey=wallet("Charlie").hotkey.ss58_address,
        )
        files = {
            "policy": h.transport,
            "competition-policy": h.intake.policy,
            "competition-cohort-config": startup,
        }
        for name, value in files.items():
            publish_private_model(root / (name + ".json"), value)
        args = miner._parser().parse_args(
            [
                "--wallet-name",
                "miner",
                "--hotkey",
                "hk",
                "--target-triple",
                "aarch64-apple-darwin",
                "--finality-verifier-binary",
                "fixture",
                "--finality-chain-spec",
                "fixture",
                "--finality-state",
                str(root / "finality"),
                "--translator",
                "fixture:translator",
                "--video-origin",
                "https://clips.example",
                "--model-revision",
                "b1" * 32,
                "--serving-origin",
                "https://example.com",
                "--nonce-db",
                str(root / "nonces.sqlite3"),
                "--assignment-db",
                str(root / "assignments.sqlite3"),
                "--max-recovery-assignments",
                "4096",
                *[arg for name in files for arg in ("--" + name, str(root / (name + ".json")))],
            ]
        )

        class Finality(miner.DurableGrandpaFinalityPort):
            def __init__(self):
                pass

            async def finalized_head_height(self):
                return await owner.blocks.finalized_head_height()

            async def verified_block_at(self, height):
                return await owner.blocks.verified_block_at(height)

            async def run(self, stop):
                await stop.wait()

        class Translator:
            async def translate(self, video, request):
                assert hashlib.sha256(video).hexdigest() == request.video.sha256
                owner.calls[(request.batch_id, request.challenge_id)] += 1
                return "hello"

        class Fetcher:
            async def fetch(self, descriptor):
                return owner.bytes[descriptor.sha256]

        self.monkeypatch.setattr(bt, "Wallet", lambda **_: wallet("Bob"))
        self.monkeypatch.setattr(
            miner.DurableGrandpaFinalityPort, "from_policy", lambda *a, **kw: Finality()
        )
        self.monkeypatch.setattr(miner, "_build_translator", lambda *a, **kw: Translator())
        self.monkeypatch.setattr(miner, "HttpVideoFetcher", lambda **kw: Fetcher())
        runtime = miner.build_runtime(args)
        # The fixture reuses one signed Drand pulse for every cohort, so
        # window() moves its synthetic round back to the new selection round.
        # Production time never moves backwards: record_request() prunes the
        # preceding closed window before admitting the next one. Reproduce that
        # transition explicitly before the shared fixture database handles the
        # next cohort, while preserving reserved response-recovery records.
        runtime.resource_ledger.prune_closed_windows(ROUND)
        stack.callback(runtime.resource_ledger.close)
        app = miner.create_app(runtime)
        await stack.enter_async_context(app.router.lifespan_context(app))

        async def delivery(scope, receive, send):
            if self.lose_reply and scope.get("path") == "/v1/translate":
                replies = []

                async def retain(message):
                    replies.append(message)

                await app(scope, receive, retain)
                if self.lose_reply and replies[0].get("status") == 200:
                    self.lose_reply = False
                    self.lost_replies += 1
                    raise httpx.ReadTimeout("fixture loses one already sealed miner response")
                for message in replies:
                    await send(message)
            else:
                await app(scope, receive, send)

        o.apps["example.com"] = o.apps["93.184.216.34"] = delivery
        public = FastAPI()
        public.include_router(
            public_history_routes(lambda: o.apps["owner.example"].state.history_exporter)
        )
        public.include_router(service_admission_routes(o.service.api))
        o.apps["intake.example"] = public

    def reviewers(self, nodes, client):
        o, h = self.o, self.h
        for name, node in nodes.items():
            root = self.root / name
            common = dict(
                policy_sha256=digest(h.intake.policy),
                signer=wallet(name).hotkey.ss58_address,
                cohorts=h.intake.config.cohorts,
            )

            async def sign(body, name=name):
                self.signatures[(name, digest(body))] += 1
                return sign_object(body, wallet(name))

            peers = tuple(
                p
                for p in o.config.admission_owner.reviewers
                if identity(p.signer) != identity(common["signer"])
            )
            config = EndpointHostConfig(
                schema="umi-cohort-endpoint-host/1",
                requests=EndpointRequestSignerConfig(
                    schema="umi-cohort-endpoint-request-signer/1",
                    directory=str(root / "requests"),
                    **common,
                ),
                decisions=CohortEndpointDecisionConfig(
                    schema="umi-cohort-endpoint-decision-config/1",
                    directory=str(root / "decisions"),
                    **common,
                ),
                origins=o.config.dispatch.origins,
                clips=o.config.dispatch.clips,
                objects_directory=str(root / "objects"),
                transport_directory=str(root / "transports"),
                reviewers=peers,
            )
            SettlementEvidenceFiles(Path(config.objects_directory)).publish(
                digest(h.terms), lambda _: canonical_json_bytes(h.terms)
            )
            publish_private_model(
                Path(config.transport_directory) / (scoring_policy_hash(h.transport) + ".json"),
                h.transport,
            )
            endpoint = EndpointHost(
                SimpleNamespace(
                    endpoint=config, manifest=o.config.manifest, policy=h.intake.policy
                ),
                node,
                self.origins,
                client,
                tuple("v" * 32 for _ in peers),
                wallet(name),
                sign,
                self.clip,
            )
            self.endpoints[name] = endpoint
            node.workers["endpoints"] = endpoint.worker
            o.apps[name.lower() + ".example"].include_router(
                endpoint_vote_routes(endpoint, token="v" * 32)
            )

            async def current_round():
                return bt.timelock.current_round()

            reviewer = ServiceWorkReviewer(
                ServiceReviewConfig(
                    schema="umi-service-review-config/1",
                    directory=str(root / "service-review"),
                    owner=o.config.admission_owner.owner_hotkey,
                    **common,
                ),
                h.intake.policy,
                h.transport,
                h.provider,
                self.blocks,
                o.service.history,
                ServiceWorkReader(
                    h.intake.policy,
                    o.config.admission_owner.owner_hotkey,
                    ServiceWorkHTTPClient(client, "https://owner.example", token="e" * 32),
                ),
                h.provider.retained_archive,
                current_round,
                sign,
            )
            o.apps[name.lower() + ".example"].include_router(
                service_vote_routes(reviewer, token="v" * 32)
            )

    async def claim(self, request, client):
        cohort_index = tuple(digest(plan) for plan in self.o.config.series.cohorts).index(
            self.h.cohort
        )
        assert (await self.o.service.poll_once())["catalogs_installed"] == cohort_index + 1
        key = digest(self.h.precommitted[0].catalog)
        body = ServiceWorkClaim(
            schema="umi-cohort-service-work-claim/1",
            catalog_sha256=key,
            hotkey=request.signed_submission.submission.hotkey,
            submission_sha256=digest(request.signed_submission.submission),
            nonce="61" * 32,
        )
        self.claimed = SignedServiceWorkClaim(
            claim=body, signature=sign_object(body, wallet("Bob"))
        )
        response = await client.post(
            f"https://intake.example/v1/competition/service-work/{key}/claims",
            content=canonical_json_bytes(self.claimed),
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 200, response.text
        return key

    def reveal(self):
        self.monkeypatch.setattr(bt.timelock, "current_round", lambda: ROUND)
        publish_private_model(
            Path(self.o.config.lifecycle.sources.pulses_directory) / (str(ROUND) + ".json"),
            RetainedRevealPulse(**pulse_record()),
        )
