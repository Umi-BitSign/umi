"""Evaluator-owned terminal evidence, sealed before complete request closure.

Each object is separately bounded. Missing records remain pending; exporting
or signing them does not close a phase, reveal answers or authorize rewards.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Annotated, Literal

from pydantic import Field, TypeAdapter

from .competition_cohort_endpoint_archive import (
    EndpointObjectSource,
    EndpointReplayArchive,
    JournalEndpointObjects,
    endpoint_archive_cases,
    endpoint_archive_header,
    read_endpoint_object,
)
from .competition_cohort_execution import (
    RecoverableExecutionEvidence,
    replay_execution_steps,
    replay_shared_incumbent_steps,
)
from .competition_cohort_execution_journal import CohortExecutionAssignment, CohortExecutionJournal
from .competition_cohort_order_queue import check_delivery_receipt
from .competition_cohort_orders import recoverable_order_job, verify_recoverable_order
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_execution import ExecutionBoundary, ExecutionStep
from .competition_verification_reuse import verified_replay
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import (
    CaseOutput,
    CompetitionPolicy,
    Signature,
    digest,
    identity,
    verify_signature,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class RequestExecutionArchive(StrictProtocolModel):
    schema_: Literal["umi-request-execution-archive/1"] = Field(alias="schema")
    assignment_sha256: Hex32
    steps: Annotated[tuple[Hex32, ...], Field(min_length=3, max_length=4096)]


class SharedIncumbentArchiveSource(StrictProtocolModel):
    terminal_sha256: Hex32
    source_reserved_at: ExecutionBoundary
    reuse_observed_at: ExecutionBoundary


class SharedRequestExecutionArchive(RequestExecutionArchive):
    schema_: Literal["umi-request-execution-archive/2"] = Field(alias="schema")
    incumbent_source: SharedIncumbentArchiveSource


_EXECUTION_ARCHIVE = TypeAdapter(
    Annotated[
        RequestExecutionArchive | SharedRequestExecutionArchive, Field(discriminator="schema_")
    ]
)


def parse_request_execution_archive(raw):
    return _EXECUTION_ARCHIVE.validate_json(raw)


class RequestTerminal(StrictProtocolModel):
    schema_: Literal["umi-cohort-request-terminal/1"] = Field(alias="schema")
    assignment_sha256: Hex32
    execution_archive_sha256: Hex32
    endpoint_archive_sha256: Hex32 | None
    chain_submission_authorized: Literal[False] = False


class SignedRequestTerminal(StrictProtocolModel):
    terminal: RequestTerminal
    signature: Signature


def replay_archived_execution(job, archive, objects, policy, *, started_after, finished_by):
    replay = (
        _replay_shared_archived_execution
        if isinstance(archive, SharedRequestExecutionArchive)
        else _replay_original_archived_execution
    )
    return replay(
        job, archive, objects, policy, started_after=started_after, finished_by=finished_by
    )


@verified_replay("archived_execution", TypeAdapter(dict[str, list[CaseOutput]]))
def _replay_original_archived_execution(
    job, archive, objects, policy, *, started_after, finished_by
):
    return replay_execution_steps(
        job,
        (
            ExecutionStep.model_validate_json(read_endpoint_object(objects, key))
            for key in archive.steps
        ),
        policy,
        started_after=started_after,
        finished_by=finished_by,
    )


def _read_shared_incumbent_assignment(assignment_sha256, objects, policy):
    """Quorum authorization is carried by the exact prospective assignment."""
    assignment = CohortExecutionAssignment.model_validate_json(
        read_endpoint_object(objects, assignment_sha256)
    )
    order = assignment.certificate.order
    verify_recovery_quorum(order, assignment.certificate.signatures, policy)
    if any(
        identity(s.hotkey) == identity(order.submission.submission.hotkey)
        for s in assignment.certificate.signatures
    ):
        raise ValueError("miner cannot authorize its own shared incumbent assignment")
    check_delivery_receipt(assignment.certificate, assignment.delivery)
    job = recoverable_order_job(order, assignment.delivery.receipt.evaluator_hotkey)
    if job.incumbent_observation_mode is None:
        raise ValueError("shared incumbent assignment lacks a prospective signed order capability")
    return assignment, job


@verified_replay(
    "shared_incumbent_source_terminal_v2",
    TypeAdapter(
        tuple[RecoverableExecutionEvidence, CohortExecutionAssignment, dict[str, list[CaseOutput]]]
    ),
)
def read_shared_incumbent_source(terminal_sha256, objects, policy, *, started_after, finished_by):
    """Authenticate one ordinary source; retain its original collector dependencies."""
    signed = SignedRequestTerminal.model_validate_json(
        read_endpoint_object(objects, terminal_sha256)
    )
    body = signed.terminal
    assignment, job = _read_shared_incumbent_assignment(body.assignment_sha256, objects, policy)
    evaluator = assignment.delivery.receipt.evaluator_hotkey
    if identity(signed.signature.hotkey) != identity(evaluator):
        raise ValueError("shared incumbent source has another terminal signer")
    verify_signature(body, signed.signature)
    archive = parse_request_execution_archive(
        read_endpoint_object(objects, body.execution_archive_sha256)
    )
    if (
        type(archive) is not RequestExecutionArchive
        or body.endpoint_archive_sha256 is not None
        or archive.assignment_sha256 != body.assignment_sha256
    ):
        raise ValueError("shared incumbent requires an original model source archive")
    if job.mode != "paired_model" or not any(
        member.submission_sha256 == digest(job.submission.submission)
        and member.admission_sha256 == digest(assignment.participant.admission.admission)
        for member in job.round.participants
    ):
        raise ValueError("shared incumbent source is outside its prepared model roster")
    outputs = replay_archived_execution(
        job, archive, objects, policy, started_after=started_after, finished_by=finished_by
    )
    evidence = RecoverableExecutionEvidence(
        schema="umi-recoverable-execution-evidence/1",
        job=job,
        steps=tuple(
            ExecutionStep.model_validate_json(read_endpoint_object(objects, key))
            for key in archive.steps
        ),
    )
    return evidence, assignment, outputs


@verified_replay("archived_execution_shared_incumbent_v2", TypeAdapter(dict[str, list[CaseOutput]]))
def _replay_shared_archived_execution(job, archive, objects, policy, *, started_after, finished_by):
    _assignment, assigned_job = _read_shared_incumbent_assignment(
        archive.assignment_sha256, objects, policy
    )
    if assigned_job != job:
        raise ValueError("shared incumbent consumer changed its signed assignment")
    binding = archive.incumbent_source
    source, _assignment, outputs = read_shared_incumbent_source(
        binding.terminal_sha256,
        objects,
        policy,
        started_after=started_after,
        finished_by=finished_by,
    )
    return replay_shared_incumbent_steps(
        job,
        tuple(
            ExecutionStep.model_validate_json(read_endpoint_object(objects, key))
            for key in archive.steps
        ),
        source,
        binding.source_reserved_at,
        binding.reuse_observed_at,
        policy,
        started_after=started_after,
        finished_by=finished_by,
        verified_source_outputs=outputs,
    )


@verified_replay("shared_incumbent_source_participant_v2", CohortExecutionAssignment)
def review_shared_incumbent_participant(
    terminal_sha256,
    objects,
    policy,
    history,
    *,
    expected_tip_sha256,
    current_block,
    opened_at_block,
    closed_at_block,
):
    """Closure authenticates the source's full original participation and history."""
    _source, assignment, _outputs = read_shared_incumbent_source(
        terminal_sha256,
        objects,
        policy,
        started_after=opened_at_block,
        finished_by=closed_at_block,
    )
    participant = assignment.participant
    verify_recoverable_order(
        assignment.certificate,
        policy,
        participant.consent,
        participant.admission,
        participant.admission_snapshot,
        history,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    return assignment


def retained_shared_incumbent_source(owner, job, *, shared=None):
    """The selected original must be sealed before its consumer can be exported."""
    reused = owner.paired_incumbent_reuse(job) if shared is None else shared
    if not reused:
        return None
    receipt, reservation, source_evidence = reused
    raw = owner.journal.get("request_terminal", reservation.source_slot)
    if raw is None:
        raise FileNotFoundError("shared incumbent original terminal is still pending")
    signed = SignedRequestTerminal.model_validate_json(canonical_json_bytes(raw))
    assignment = owner.assignment(reservation.source_slot)
    archive = parse_request_execution_archive(
        read_endpoint_object(
            JournalEndpointObjects(owner.journal), signed.terminal.execution_archive_sha256
        )
    )
    if (
        type(archive) is not RequestExecutionArchive
        or signed.terminal.endpoint_archive_sha256 is not None
        or signed.terminal.assignment_sha256 != digest(assignment)
        or archive.assignment_sha256 != digest(assignment)
        or archive.steps != tuple(digest(step) for step in source_evidence.steps)
    ):
        raise ValueError("retained shared incumbent terminal changed its selected original")
    return SharedIncumbentArchiveSource(
        terminal_sha256=digest(signed),
        source_reserved_at=reservation.reserved_at,
        reuse_observed_at=receipt.observed_at,
    )


@verified_replay("request_terminal", CohortExecutionAssignment)
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
    execution = parse_request_execution_archive(
        read_endpoint_object(objects, body.execution_archive_sha256)
    )
    if execution.assignment_sha256 != body.assignment_sha256:
        raise ValueError("request execution archive changed its assignment")
    replay_archived_execution(
        job,
        execution,
        objects,
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
    shared = await run_owned_thread(retained_shared_incumbent_source, owner, evidence.job)
    execution = (
        RequestExecutionArchive(
            schema="umi-request-execution-archive/1", assignment_sha256=assignment_sha, steps=steps
        )
        if shared is None
        else SharedRequestExecutionArchive(
            schema="umi-request-execution-archive/2",
            assignment_sha256=assignment_sha,
            steps=steps,
            incumbent_source=shared,
        )
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
