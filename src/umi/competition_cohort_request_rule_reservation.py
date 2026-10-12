"""Fresh owner proof that adoption gates exist in both original journals."""

import secrets
from typing import Literal

from pydantic import Field

from .competition_cohort_recovery import CohortRecoveryTransition
from .competition_cohort_review_http import PhaseReviewHTTPClient, phase_review_routes
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import Signature, digest, identity, verify_signature
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

PATH = "/internal/cohorts/request-tail-adoption/reservation"


class RequestTailReservationRequest(StrictProtocolModel):
    schema_: Literal["umi-request-tail-reservation-request/1"] = Field(alias="schema")
    transition: CohortRecoveryTransition
    challenge: Hex32


class RequestTailReservationProof(StrictProtocolModel):
    schema_: Literal["umi-request-tail-reservation-proof/1"] = Field(alias="schema")
    request_sha256: Hex32
    history_sha256: Hex32


class SignedRequestTailReservationProof(StrictProtocolModel):
    proof: RequestTailReservationProof
    signature: Signature


class RequestTailReservationExporter:
    maximum_bytes = 4096

    def __init__(self, lifecycle):
        self.host = lifecycle
        self.timeout_seconds = lifecycle.timeout_seconds

    async def respond(self, request):
        transition = request.transition
        if transition.operation != "adopt_request_tail_rule":
            raise ValueError("request-rule reservation proof requires adoption")
        cohort = transition.cohort_sha256
        node = self.host.nodes.get(cohort)
        if node is None:
            raise OSError("request-rule reservation awaits its lifecycle owner")
        async with node.serial, node.controller.serial:
            history, state, _, _ = node.controller._history()
            _, pending = node.controller.store.status(cohort)
            intake_pending = await run_owned_thread(
                self.host.service.intake.pending_request_tail_adoption, cohort
            )
            if (
                pending != transition
                or intake_pending != transition
                or state.tip_sha256 != transition.predecessor_sha256
            ):
                raise ValueError("request-rule adoption is not reserved in both owner journals")
            proof = RequestTailReservationProof(
                schema="umi-request-tail-reservation-proof/1",
                request_sha256=digest(request),
                history_sha256=digest(history),
            )
            signature = await wait_for_owned(self.host.sign(proof), timeout=self.timeout_seconds)
            if identity(signature.hotkey) != identity(
                self.host.service.config.admission_owner.owner_hotkey
            ):
                raise ValueError("request-rule reservation proof has another owner")
            verify_signature(proof, signature)
            return canonical_json_bytes(
                SignedRequestTailReservationProof(proof=proof, signature=signature)
            )


def request_tail_reservation_routes(lifecycle, *, token):
    return phase_review_routes(
        RequestTailReservationExporter(lifecycle),
        token=token,
        path=PATH,
        request_model=RequestTailReservationRequest,
        maximum_request_bytes=32 * 1024,
    )


class RequestTailReservationReader:
    def __init__(
        self, client, origin, *, token, owner, timeout_seconds=2400, complete_exchange=False
    ):
        self.owner = identity(owner)
        self.complete_exchange = complete_exchange
        self.transport = PhaseReviewHTTPClient(
            client,
            origin,
            token=token,
            path=PATH,
            maximum_bytes=4096,
            maximum_request_bytes=32 * 1024,
            timeout_seconds=timeout_seconds,
        )

    async def __call__(self, transition, history):
        request = RequestTailReservationRequest(
            schema="umi-request-tail-reservation-request/1",
            transition=transition,
            challenge=secrets.token_hex(32),
        )
        # HTTPX's scalar bounds I/O inactivity. Selected complete-path profiles
        # also own the total exchange, matching the history reader's boundary.
        raw = (
            await wait_for_owned(self.transport(request), timeout=self.transport.timeout_seconds)
            if self.complete_exchange
            else await self.transport(request)
        )
        return await run_owned_thread(self._verify, raw, request, history)

    def _verify(self, raw, request, history):
        signed = SignedRequestTailReservationProof.model_validate_json(raw)
        if (
            canonical_json_bytes(signed) != raw
            or signed.proof.request_sha256 != digest(request)
            or signed.proof.history_sha256 != digest(history)
            or identity(signed.signature.hotkey) != self.owner
        ):
            raise ValueError("request-rule reservation changed challenge, history or owner")
        verify_signature(signed.proof, signed.signature)
        return signed
