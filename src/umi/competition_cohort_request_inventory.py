"""Evaluator-authenticated local inventory after a selected request cutoff."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from .competition_cohort_endpoint_archive import read_endpoint_object
from .competition_cohort_request_partial import PartialRequestManifest, review_partial_request
from .competition_execution import ExecutionBoundary
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import Signature, digest, identity, verify_signature
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class RequestInventory(StrictProtocolModel):
    schema_: Literal["umi-cohort-request-inventory/1"] = Field(alias="schema")
    assignment_sha256: Hex32
    policy_sha256: Hex32
    manifest_sha256: Hex32
    observation: ExecutionBoundary
    request_completion_authorized: Literal[False] = False
    chain_submission_authorized: Literal[False] = False


class SignedRequestInventory(StrictProtocolModel):
    inventory: RequestInventory
    signature: Signature


class RequestInventoryCutoff(StrictProtocolModel):
    """Private advisory request for an inventory; it grants no phase authority."""

    schema_: Literal["umi-private-request-inventory-cutoff/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    policy_sha256: Hex32
    observation: ExecutionBoundary


def read_request_inventory(key, objects):
    return SignedRequestInventory.model_validate_json(read_endpoint_object(objects, key))


def request_inventory_observations(closure, objects):
    """Original signed inventory boundaries for independent native proof replay."""
    return tuple(
        read_request_inventory(key, objects).inventory.observation
        for participant in closure.skipped
        for key in participant.inventory_sha256s
    )


def review_request_inventory(
    key,
    objects,
    policy,
    order,
    *,
    opened_at_block,
    selected_at_block,
    completed_by_block,
):
    """Require a later finalized observation, then replay every retained original.

    A later block prevents a snapshot made earlier in the selection block from
    being mistaken for a post-cutoff inventory. The independent phase reviewer
    also authenticates this exact observation with its native proof provider.
    """
    signed = read_request_inventory(key, objects)
    body = signed.inventory
    if body.policy_sha256 != digest(policy):
        raise ValueError("request inventory changed its selected policy")
    if not selected_at_block < body.observation.block <= completed_by_block:
        raise ValueError("request inventory is stale or ahead of its closure")
    assignment = review_partial_request(
        body.manifest_sha256,
        objects,
        policy,
        order,
        opened_at_block=opened_at_block,
        completed_by_block=body.observation.block,
    )
    if body.assignment_sha256 != digest(assignment) or identity(
        signed.signature.hotkey
    ) != identity(assignment.delivery.receipt.evaluator_hotkey):
        raise ValueError("request inventory changed its original evaluator or assignment")
    verify_signature(body, signed.signature)
    manifest = PartialRequestManifest.model_validate_json(
        read_endpoint_object(objects, body.manifest_sha256)
    )
    return assignment, manifest, signed


async def seal_request_inventory(body, journal, sign, *, signer, timeout_seconds):
    """Resume the exact retained signing intent after any lost acknowledgement."""
    body = RequestInventory.model_validate_json(canonical_json_bytes(body))
    key = digest(body)
    await run_owned_thread(journal.put, "request_inventory_intent", key, body)
    raw = await run_owned_thread(journal.get, "request_inventory", key)
    if raw is None:
        signed = SignedRequestInventory(
            inventory=body,
            signature=await wait_for_owned(sign(body), timeout=timeout_seconds),
        )
    else:
        signed = SignedRequestInventory.model_validate_json(canonical_json_bytes(raw))
    if signed.inventory != body or identity(signed.signature.hotkey) != identity(signer):
        raise ValueError("request inventory signer changed its original body or evaluator")
    verify_signature(body, signed.signature)
    await run_owned_thread(journal.put, "request_inventory", key, signed)
    return signed
