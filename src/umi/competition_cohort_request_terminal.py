"""Evaluator-owned terminal evidence, sealed before complete request closure.

Each object is separately bounded. Missing records remain pending; exporting
or signing them does not close a phase, reveal answers or authorize rewards.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_endpoint_archive import (
    EndpointObjectSource,
    EndpointReplayArchive,
    JournalEndpointObjects,
    endpoint_archive_cases,
    endpoint_archive_header,
    read_endpoint_object,
)
from .competition_cohort_execution import replay_execution_steps
from .competition_cohort_execution_journal import CohortExecutionAssignment, CohortExecutionJournal
from .competition_cohort_order_queue import check_delivery_receipt
from .competition_cohort_orders import recoverable_order_job
from .competition_execution import ExecutionStep
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import CompetitionPolicy, Signature, digest, identity, verify_signature
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class RequestExecutionArchive(StrictProtocolModel):
    schema_: Literal["umi-request-execution-archive/1"] = Field(alias="schema")
    assignment_sha256: Hex32
    steps: Annotated[tuple[Hex32, ...], Field(min_length=3, max_length=4096)]


class RequestTerminal(StrictProtocolModel):
    schema_: Literal["umi-cohort-request-terminal/1"] = Field(alias="schema")
    assignment_sha256: Hex32
    execution_archive_sha256: Hex32
    endpoint_archive_sha256: Hex32 | None
    chain_submission_authorized: Literal[False] = False


class SignedRequestTerminal(StrictProtocolModel):
    terminal: RequestTerminal
    signature: Signature


def read_request_terminal(
    signed: SignedRequestTerminal,
    objects: EndpointObjectSource,
    policy: CompetitionPolicy,
    *,
    opened_at_block: int,
    completed_by_block: int,
) -> CohortExecutionAssignment:
    """Replay every assigned local step and endpoint case before accepting a seal.

    Order quorum, participant admission, complete roster and current authority
    are checked by the closure consumer. Proof hashes refer to host-owned
    evidence which its independent reviewers must authenticate separately.
    """
    signed = SignedRequestTerminal.model_validate_json(canonical_json_bytes(signed))
    body = signed.terminal
    assignment = CohortExecutionAssignment.model_validate_json(
        read_endpoint_object(objects, body.assignment_sha256)
    )
    check_delivery_receipt(assignment.certificate, assignment.delivery)
    evaluator = assignment.delivery.receipt.evaluator_hotkey
    if identity(signed.signature.hotkey) != identity(evaluator):
        raise ValueError("request terminal was not signed by its assigned evaluator")
    verify_signature(body, signed.signature)
    job = recoverable_order_job(assignment.certificate.order, evaluator)
    execution = RequestExecutionArchive.model_validate_json(
        read_endpoint_object(objects, body.execution_archive_sha256)
    )
    if execution.assignment_sha256 != body.assignment_sha256:
        raise ValueError("request execution archive changed its assignment")
    replay_execution_steps(
        job,
        (
            ExecutionStep.model_validate_json(read_endpoint_object(objects, key))
            for key in execution.steps
        ),
        policy,
        started_after=opened_at_block,
        finished_by=completed_by_block,
    )
    if job.mode == "endpoint_incumbent":
        if body.endpoint_archive_sha256 is None:
            raise ValueError("endpoint terminal omits the miner's responses")
        archive = EndpointReplayArchive.model_validate_json(
            read_endpoint_object(objects, body.endpoint_archive_sha256)
        )
        archived, _, _ = endpoint_archive_header(archive, objects, policy)
        if archived != assignment:
            raise ValueError("endpoint terminal belongs to another assignment")
        for _ in endpoint_archive_cases(
            archive, objects, policy, request_interval=(opened_at_block, completed_by_block)
        ):
            pass
    elif body.endpoint_archive_sha256 is not None:
        raise ValueError("model terminal contains unassigned endpoint work")
    return assignment


async def seal_request_terminal(
    owner: CohortExecutionJournal,
    slot: str,
    sign: Callable[[RequestTerminal], Awaitable[Signature]],
    *,
    endpoint_archive: EndpointReplayArchive | None = None,
    endpoint_objects: EndpointObjectSource | None = None,
) -> SignedRequestTerminal:
    """Owning-service port: retain complete output before one immutable signature.

    The owner serializes calls and holds its normal lifecycle lock. An endpoint
    source serves immutable exported objects, never another live SQLite journal.
    Signing retries reuse original evidence; there is no total elapsed timeout.
    """
    assignment = await run_owned_thread(owner.assignment, slot)
    evidence = await run_owned_thread(owner.evidence, slot)
    if evidence is None:
        raise FileNotFoundError("assigned local execution is still pending")
    objects = JournalEndpointObjects(owner.journal)
    retained = await run_owned_thread(owner.journal.get, "request_terminal_intent", slot)
    if retained is not None:
        intent = RequestTerminal.model_validate_json(canonical_json_bytes(retained))
        if intent.assignment_sha256 != digest(assignment):
            raise ValueError("retained terminal intent changed its assignment")
        if (
            endpoint_archive is not None
            and digest(endpoint_archive) != intent.endpoint_archive_sha256
        ):
            raise ValueError("retained terminal intent selected another endpoint archive")
        # A complete local export is independent of the old endpoint service.
        # Resume partial signing or a lost publication reply from owned bytes.
        endpoint_archive = (
            EndpointReplayArchive.model_validate_json(
                await run_owned_thread(
                    read_endpoint_object, objects, intent.endpoint_archive_sha256
                )
            )
            if intent.endpoint_archive_sha256 is not None
            else None
        )
        endpoint_objects = objects
    if (evidence.job.mode == "endpoint_incumbent") != (endpoint_archive is not None):
        raise ValueError("terminal export requires exactly its assigned endpoint evidence")
    endpoint_sha = None
    if endpoint_archive is not None:
        if endpoint_objects is None:
            raise FileNotFoundError("endpoint archive source is unavailable")

        def retain_object(key):
            raw = read_endpoint_object(endpoint_objects, key)
            # put accepts native strict models. This canonical object has already
            # passed its content digest and will be parsed by archive replay.
            owner.journal.put("endpoint_replay_object", key, json.loads(raw))
            return raw

        archived, _, _ = await run_owned_thread(
            endpoint_archive_header, endpoint_archive, retain_object, owner.policy
        )
        if archived != assignment:
            raise ValueError("terminal export changed the endpoint assignment")

        def copy_cases():
            for _ in endpoint_archive_cases(endpoint_archive, retain_object, owner.policy):
                pass

        await run_owned_thread(copy_cases)
        endpoint_sha = await run_owned_thread(objects.put, endpoint_archive)
    assignment_sha = await run_owned_thread(objects.put, assignment)
    steps = tuple([await run_owned_thread(objects.put, step) for step in evidence.steps])
    execution = RequestExecutionArchive(
        schema="umi-request-execution-archive/1", assignment_sha256=assignment_sha, steps=steps
    )
    execution_sha = await run_owned_thread(objects.put, execution)
    body = RequestTerminal(
        schema="umi-cohort-request-terminal/1",
        assignment_sha256=assignment_sha,
        execution_archive_sha256=execution_sha,
        endpoint_archive_sha256=endpoint_sha,
    )
    # Commit original bytes before signing; changed outputs cannot reuse a slot.
    await run_owned_thread(owner.journal.put, "request_terminal_intent", slot, body)
    raw = await run_owned_thread(owner.journal.get, "request_terminal", slot)
    if raw is None:
        signature = await wait_for_owned(sign(body), timeout=owner.config.signing_timeout_seconds)
        signed = SignedRequestTerminal(terminal=body, signature=signature)
    else:
        signed = SignedRequestTerminal.model_validate_json(canonical_json_bytes(raw))
    if signed.terminal != body or identity(signed.signature.hotkey) != identity(
        owner.config.signer
    ):
        raise ValueError("terminal signer returned another body or evaluator")
    verify_signature(body, signed.signature)
    await run_owned_thread(owner.journal.put, "request_terminal", slot, signed)
    await run_owned_thread(objects.put, signed)
    return signed
