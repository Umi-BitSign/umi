"""Signed protocol retirement; absence of a response is not proof of no inference."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

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


class SignedEndpointRetirementReceipt(StrictProtocolModel):
    receipt: EndpointRetirementReceipt
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
