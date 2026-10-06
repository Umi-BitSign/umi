"""Connect the recurring service worker to independently retained HTTP votes."""

import asyncio
from functools import partial

from .competition_cohort_endpoint_decision_contracts import SignedCohortEndpointCaseDecision
from .competition_cohort_service_grant import (
    ServiceMinerGrant,
    service_grant_slot,
    verify_service_grant,
    verify_service_parent_body,
)
from .competition_cohort_service_requests import ServiceWorkRequests
from .competition_cohort_service_review import (
    ServiceRequestReview,
    ServiceRetryReview,
    certify_service_retry,
    service_retry_decision,
)
from .competition_cohort_service_vote_http import ServiceVotePeer
from .competition_cohort_service_worker import _RETRY, ServiceWorkWorker
from .competition_round_journal import RecordReservation
from .concurrency import run_owned_thread
from .endpoint_retirement import verify_retirement_receipt
from .open_competition import Signature, digest, identity, verify_signature
from .protocol import canonical_json_bytes


class ServiceWorkPeerReviews:
    def __init__(self, requests: ServiceWorkRequests, peers: tuple[ServiceVotePeer, ...]):
        self.requests, self.journal = requests, requests.journal
        self.peers = {identity(p.signer): p for p in peers}
        if (
            not peers
            or len(self.peers) != len(peers)
            or any(p.policy != requests.policy for p in peers)
        ):
            raise ValueError("service peers must be distinct selected reviewers")
        self.serial, self.writes = asyncio.Lock(), asyncio.Lock()
        self.reviewers = {p.signer: partial(self.request, p) for p in peers}

    def _request(self, body):
        # Parallel reviewer reads must not compete for the owner's queue write
        # lock. The native worker retains selection before requesting votes;
        # each reviewer independently authenticates the accepted assignment.
        raw = self.journal.get("service_request", service_grant_slot(body))
        if raw is None or canonical_json_bytes(raw) != canonical_json_bytes(body):
            raise ValueError("service review differs from selected original request")
        parent = None
        if body.parent_grant_slot is not None:
            raw = self.journal.get("service_grant", body.parent_grant_slot)
            if raw is None:
                raise FileNotFoundError("service request parent certificate is missing")
            parent = verify_service_grant(
                ServiceMinerGrant.model_validate_json(canonical_json_bytes(raw)),
                self.requests.policy,
                self.requests.transport,
            )
            verify_service_parent_body(body, parent)
        return ServiceRequestReview(body=body, parent=parent)

    async def request(self, peer, body):
        return await peer.attest(await run_owned_thread(self._request, body))

    @staticmethod
    def _key(slot, who):
        return digest(["umi-service-retry-peer-vote/1", slot, who])

    def _prepare(self, review):
        slot = service_grant_slot(review.grant.body)
        if self.requests.certificate(slot) != review.grant:
            raise ValueError("service retry differs from selected original grant")
        body = review.grant.body
        verify_retirement_receipt(
            review.retirement,
            request=body.request,
            grant_sha256=digest(review.grant),
            miner_hotkey=body.assignment.admission.claim.claim.hotkey,
            evaluator_hotkey=body.evaluator_hotkey,
        )
        if review.retirement.receipt.result not in {
            "no_response_retained",
            "expired_response_opportunity",
        }:
            raise ValueError("service retry requires the original no-response fence")
        with self.journal.locked():
            self.journal.put("service_retry_peer_intent", slot, {"review": digest(review)})
            reservations = [RecordReservation("service_retry_certificate", slot, 32768)]
            reservations.extend(
                RecordReservation(
                    "service_retry_peer_vote", self._key(slot, identity(e.hotkey)), 2048
                )
                for e in self.requests.policy.evaluators
            )
            self.journal.reserve_records(
                digest(["umi-service-retry-peers/1", slot]), tuple(reservations)
            )
        return slot

    def _vote(self, review, who, raw):
        vote = Signature.model_validate_json(canonical_json_bytes(raw))
        if identity(vote.hotkey) != who or who == identity(
            review.grant.body.assignment.admission.claim.claim.hotkey
        ):
            raise ValueError("service retry vote changed its independent reviewer")
        verify_signature(service_retry_decision(review), vote)
        return vote

    def _retain(self, review, slot, who, vote):
        key = self._key(slot, who)
        self._vote(review, who, vote)
        with self.journal.locked():
            old = self.journal.get("service_retry_peer_vote", key)
            if old is not None:
                return self._vote(review, who, old)
            self.journal.put("service_retry_peer_vote", key, vote)
            return vote

    def _certificate(self, review, slot):
        with self.journal.locked():
            raw = self.journal.get("service_retry_certificate", slot)
            if raw is not None:
                cert = SignedCohortEndpointCaseDecision.model_validate_json(
                    canonical_json_bytes(raw)
                )
                if (
                    certify_service_retry(
                        review, self.requests.policy, self.requests.transport, cert.signatures
                    )
                    != cert
                ):
                    raise ValueError("service retry certificate changed original decision")
                return cert
            votes, groups = [], set()
            for evaluator in sorted(
                self.requests.policy.evaluators, key=lambda e: identity(e.hotkey)
            ):
                who = identity(evaluator.hotkey)
                raw = self.journal.get("service_retry_peer_vote", self._key(slot, who))
                if raw is None:
                    continue
                vote = self._vote(review, who, raw)
                if evaluator.control_group not in groups:
                    groups.add(evaluator.control_group)
                    votes.append(vote)
            cert = certify_service_retry(
                review, self.requests.policy, self.requests.transport, votes
            )
            self.journal.put("service_retry_certificate", slot, cert)
            return cert

    async def retry(self, grant, retirement):
        review = ServiceRetryReview(grant=grant, retirement=retirement)
        async with self.serial:
            slot = await run_owned_thread(self._prepare, review)
            # Completed certificates recover before contacting any reviewer.
            if (
                await run_owned_thread(self.journal.get, "service_retry_certificate", slot)
                is not None
            ):
                return await run_owned_thread(self._certificate, review, slot)

            async def collect(who, peer):
                if who == identity(grant.body.assignment.admission.claim.claim.hotkey):
                    return
                raw = await run_owned_thread(
                    self.journal.get, "service_retry_peer_vote", self._key(slot, who)
                )
                try:
                    vote = (
                        self._vote(review, who, raw)
                        if raw is not None
                        else await peer.attest(review)
                    )
                    async with self.writes:
                        await run_owned_thread(self._retain, review, slot, who, vote)
                except _RETRY:
                    return

            await ServiceWorkWorker._gather(collect(who, peer) for who, peer in self.peers.items())
            return await run_owned_thread(self._certificate, review, slot)
