"""Signed protocol retirement; absence of a response is not proof of no inference."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, TypeAdapter, model_validator

from .open_competition import Hotkey, Signature, identity, verify_signature
from .protocol import (
    Hex32,
    StrictProtocolModel,
    TranslationRequest,
    canonical_json_bytes,
    request_digest,
)


class EndpointRetirementReceipt(StrictProtocolModel):
    schema_: Literal["umi-endpoint-retirement/1"] = Field(alias="schema")
    grant_sha256: Hex32
    request_digest: Hex32
    miner_hotkey: Hotkey
    evaluator_hotkey: Hotkey
    result: Literal["response_retained", "no_response_retained"]
    response_sha256: Hex32 | None
    protocol_execution_fenced: Literal[True] = True
    original_receipt_timing_proven: Literal[False] = False
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def response_binding(self):
        if (self.result == "response_retained") != (self.response_sha256 is not None):
            raise ValueError("retirement response binding differs from result")
        return self


class ExpiredOpportunityRetirementReceipt(EndpointRetirementReceipt):
    """The miner fenced an expired response opportunity, not an unexpired one.

    This explicit extension never changes a retained /1 absence receipt. The
    original block deadline may still be ahead, but no original protocol work
    can execute after this durable, signed miner fence.
    """

    schema_: Literal["umi-endpoint-retirement/2"] = Field(alias="schema")
    result: Literal["expired_response_opportunity"]
    response_sha256: None = None


RetirementReceipt = Annotated[
    EndpointRetirementReceipt | ExpiredOpportunityRetirementReceipt,
    Field(discriminator="schema_"),
]
_receipt_adapter = TypeAdapter(RetirementReceipt)


def parse_retirement_receipt(raw):
    return _receipt_adapter.validate_json(raw)


def retirement_absence_elapsed(receipt, request, *, observed_block, observed_round):
    """Verify the explicit semantics; never relax legacy /1 absence expiry."""
    if type(observed_block) is not int or type(observed_round) is not int:
        return False
    if receipt.result == "no_response_retained":
        return (
            observed_block > request.deadline_block
            and observed_round >= request.response_close_round
        )
    if receipt.result == "expired_response_opportunity":
        return (
            observed_block >= request.issued_block
            and observed_round >= request.response_close_round
        )
    return False


class SignedEndpointRetirementReceipt(StrictProtocolModel):
    receipt: RetirementReceipt
    signature: Signature


def verify_retirement_receipt(
    value,
    *,
    request: TranslationRequest,
    grant_sha256: str,
    miner_hotkey: str,
    evaluator_hotkey: str,
) -> SignedEndpointRetirementReceipt:
    value = SignedEndpointRetirementReceipt.model_validate_json(canonical_json_bytes(value))
    body = value.receipt
    if (
        body.grant_sha256 != grant_sha256
        or body.request_digest != request_digest(request)
        or identity(body.miner_hotkey) != identity(miner_hotkey)
        or identity(body.evaluator_hotkey) != identity(evaluator_hotkey)
        or identity(value.signature.hotkey) != identity(miner_hotkey)
    ):
        raise ValueError("retirement receipt differs from selected request")
    verify_signature(body, value.signature)
    return value
