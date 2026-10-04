"""Private delivery of original order votes and evaluator inbox receipts.

Lookups recover acknowledgements without creating new work. Native signers and
inboxes retain authority checks and immutable selections behind these routes.
"""

from __future__ import annotations

from fastapi import APIRouter

from .competition_cohort_order_inbox import CohortOrderInbox
from .competition_cohort_order_queue import SignedOrderDeliveryReceipt, check_delivery_receipt
from .competition_cohort_order_signer import (
    CohortOrderParticipant,
    CohortOrderSigner,
    CohortOrderVote,
    order_slot,
)
from .competition_cohort_orders import RecoverableEvaluationOrder, SignedRecoverableEvaluationOrder
from .competition_cohort_review_export import review_export_limits, review_selection
from .competition_cohort_review_http import PhaseReviewHTTPClient, phase_review_routes
from .open_competition import digest, identity, verify_signature
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_REQUEST_BYTES = 32 * 1024**2
MAX_REPLY_BYTES = 4096
PREFIX = "/internal/cohorts/orders"


class OrderLookup(StrictProtocolModel):
    slot: Hex32


class OrderAttestation(StrictProtocolModel):
    order: RecoverableEvaluationOrder
    participant: CohortOrderParticipant


class OrderDelivery(StrictProtocolModel):
    certificate: SignedRecoverableEvaluationOrder
    participant: CohortOrderParticipant


class OrderVoteReply(StrictProtocolModel):
    slot: Hex32
    vote: CohortOrderVote | None


class OrderReceiptReply(StrictProtocolModel):
    slot: Hex32
    receipt: SignedOrderDeliveryReceipt | None


class _Responder:
    maximum_bytes = MAX_REPLY_BYTES

    def __init__(self, action, timeout_seconds):
        review_export_limits(self.maximum_bytes, timeout_seconds)
        self.action, self.timeout_seconds = action, timeout_seconds

    async def respond(self, request):
        return canonical_json_bytes(await self.action(request))


def order_routes(
    signer: CohortOrderSigner, inbox: CohortOrderInbox, *, token: str, timeout_seconds=2400
):
    if (
        signer.journal.policy != inbox.policy
        or signer.journal.config.cohorts != inbox.config.cohorts
        or identity(signer.journal.config.signer) != identity(inbox.config.signer)
    ):
        raise ValueError("order review and inbox must belong to the same selected evaluator")

    async def vote_lookup(request):
        return OrderVoteReply(slot=request.slot, vote=await signer.lookup(request.slot))

    async def attest(request):
        return OrderVoteReply(
            slot=order_slot(request.order),
            vote=await signer.attest(request.order, request.participant),
        )

    async def receipt_lookup(request):
        return OrderReceiptReply(slot=request.slot, receipt=await inbox.lookup(request.slot))

    async def accept(request):
        return OrderReceiptReply(
            slot=order_slot(request.certificate.order),
            receipt=await inbox.accept(request.certificate, request.participant),
        )

    router = APIRouter()
    for path, model, action in (
        ("votes/lookup", OrderLookup, vote_lookup),
        ("votes/attest", OrderAttestation, attest),
        ("inbox/lookup", OrderLookup, receipt_lookup),
        ("inbox/accept", OrderDelivery, accept),
    ):
        router.include_router(
            phase_review_routes(
                _Responder(action, timeout_seconds),
                token=token,
                path=f"{PREFIX}/{path}",
                request_model=model,
                maximum_request_bytes=MAX_REQUEST_BYTES,
            )
        )
    return router


class _OrderPeer:
    def __init__(self, client, origin, *, policy, cohorts, signer, token, timeout_seconds=2400):
        self.policy, self.cohorts, _ = review_selection(policy, cohorts, signer)
        self.signer = identity(signer)
        self.clients = {
            action: PhaseReviewHTTPClient(
                client,
                origin,
                token=token,
                path=f"{PREFIX}/{action}",
                maximum_bytes=MAX_REPLY_BYTES,
                maximum_request_bytes=MAX_REQUEST_BYTES,
                timeout_seconds=timeout_seconds,
            )
            for action in ("votes/lookup", "votes/attest", "inbox/lookup", "inbox/accept")
        }

    def check_order(self, order):
        if order.round.policy_sha256 != digest(self.policy) or order.round.cohort_sha256 not in {
            c.cohort_sha256 for c in self.cohorts
        }:
            raise ValueError("order is outside configured reviewer cohorts")

    async def receive(self, action, request, model, slot):
        raw = await self.clients[action](request)
        reply = model.model_validate_json(raw)
        if canonical_json_bytes(reply) != raw or reply.slot != slot:
            raise ValueError("order response changed its original bytes or slot")
        return reply


class OrderReviewPeer(_OrderPeer):
    def check_vote(self, vote):
        if vote is not None and identity(vote.signature.hotkey) != self.signer:
            raise ValueError("order vote belongs to another reviewer")
        return vote

    async def lookup(self, slot):
        reply = await self.receive("votes/lookup", OrderLookup(slot=slot), OrderVoteReply, slot)
        # The native outbox verifies the returned vote against its original body.
        return self.check_vote(reply.vote)

    async def attest(self, order, participant):
        self.check_order(order)
        reply = await self.receive(
            "votes/attest",
            OrderAttestation(order=order, participant=participant),
            OrderVoteReply,
            order_slot(order),
        )
        vote = self.check_vote(reply.vote)
        if vote is None or vote.order_sha256 != digest(order):
            raise ValueError("order response has no vote for this original order")
        verify_signature(order, vote.signature)
        return vote


class OrderDeliveryPeer(_OrderPeer):
    def check_receipt(self, receipt, slot):
        if receipt is not None:
            if (
                receipt.receipt.slot != slot
                or identity(receipt.receipt.evaluator_hotkey) != self.signer
                or identity(receipt.signature.hotkey) != self.signer
            ):
                raise ValueError("order receipt belongs to another evaluator or slot")
            verify_signature(receipt.receipt, receipt.signature)
        return receipt

    async def lookup(self, slot):
        reply = await self.receive("inbox/lookup", OrderLookup(slot=slot), OrderReceiptReply, slot)
        return self.check_receipt(reply.receipt, slot)

    async def accept(self, certificate, participant):
        self.check_order(certificate.order)
        slot = order_slot(certificate.order)
        reply = await self.receive(
            "inbox/accept",
            OrderDelivery(certificate=certificate, participant=participant),
            OrderReceiptReply,
            slot,
        )
        receipt = self.check_receipt(reply.receipt, slot)
        if receipt is None:
            raise ValueError("order delivery has no retained acknowledgement")
        return check_delivery_receipt(certificate, receipt)
