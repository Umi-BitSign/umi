"""Fresh owner proof that adoption gates exist in both original journals."""

import secrets
from typing import Literal

from pydantic import Field

from .competition_cohort_model_delivery_api import adoption_owner_node, selected_owner_candidate
from .competition_cohort_model_delivery_census import census_model_delivery
from .competition_cohort_recovery import CohortRecoveryTransition
from .competition_cohort_review_http import PhaseReviewHTTPClient, phase_review_routes
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import Signature, digest, identity, verify_signature
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

PATH = "/internal/cohorts/model-delivery-adoption/reservation"


class ModelDeliveryReservationRequest(StrictProtocolModel):
    schema_: Literal["umi-model-delivery-reservation-request/1"] = Field(alias="schema")
    transition: CohortRecoveryTransition
    challenge: Hex32


class ModelDeliveryReservationProof(StrictProtocolModel):
    schema_: Literal["umi-model-delivery-reservation-proof/1"] = Field(alias="schema")
    request_sha256: Hex32
    history_sha256: Hex32


class SignedModelDeliveryReservationProof(StrictProtocolModel):
    proof: ModelDeliveryReservationProof
    signature: Signature


class ModelDeliveryReservationExporter:
    maximum_bytes = 4096

    def __init__(self, lifecycle):
        self.host = lifecycle
        self.timeout_seconds = lifecycle.timeout_seconds

    async def respond(self, request):
        transition = request.transition
        if transition.operation != "adopt_model_delivery":
            raise ValueError("model-delivery reservation proof requires adoption")
        cohort = transition.cohort_sha256
        # Held cohorts are not automatically opened after owner restart. The
        # authenticated proof request uses the same serialized initialization
        # as prepare/reserve, restoring the exact durable pending reservation.
        node = await adoption_owner_node(self.host, cohort)
        async with node.serial, node.controller.serial:
            history, state, _, _ = node.controller._history()
            _, pending = node.controller.store.status(cohort)
            intake_pending = await run_owned_thread(
                self.host.service.intake.pending_policy_adoption, cohort
            )
            if (
                pending != transition
                or intake_pending != transition
                or state.tip_sha256 != transition.predecessor_sha256
            ):
                raise ValueError("model-delivery adoption is not reserved in both owner journals")
            await run_owned_thread(
                census_model_delivery,
                self.host.service.intake,
                self.host.service.uploads,
                transition,
                selected_owner_candidate(self.host, cohort),
            )
            proof = ModelDeliveryReservationProof(
                schema="umi-model-delivery-reservation-proof/1",
                request_sha256=digest(request),
                history_sha256=digest(history),
            )
            signature = await wait_for_owned(self.host.sign(proof), timeout=self.timeout_seconds)
            if identity(signature.hotkey) != identity(
                self.host.service.config.admission_owner.owner_hotkey
            ):
                raise ValueError("model-delivery reservation proof has another owner")
            verify_signature(proof, signature)
            return canonical_json_bytes(
                SignedModelDeliveryReservationProof(proof=proof, signature=signature)
            )


def model_delivery_reservation_routes(lifecycle, *, token):
    return phase_review_routes(
        ModelDeliveryReservationExporter(lifecycle),
        token=token,
        path=PATH,
        request_model=ModelDeliveryReservationRequest,
        maximum_request_bytes=32 * 1024,
    )


class ModelDeliveryReservationReader:
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
        request = ModelDeliveryReservationRequest(
            schema="umi-model-delivery-reservation-request/1",
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
        signed = SignedModelDeliveryReservationProof.model_validate_json(raw)
        if (
            canonical_json_bytes(signed) != raw
            or signed.proof.request_sha256 != digest(request)
            or signed.proof.history_sha256 != digest(history)
            or identity(signed.signature.hotkey) != self.owner
        ):
            raise ValueError("model-delivery reservation changed challenge, history or owner")
        verify_signature(signed.proof, signed.signature)
        return signed
