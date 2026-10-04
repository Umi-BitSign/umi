"""Export privacy-bounded mediator requests from validated execution evidence."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, field_validator

from .competition_execution import ModelExecutionEvidence, validate_execution
from .competition_mediator import MediatorRequest
from .open_competition import CompetitionPolicy, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


def _context_text(value: str) -> str:
    if len(value.encode("utf-8")) > 8192:
        raise ValueError("mediator context exceeds its UTF-8 byte bound")
    if any(ord(character) < 32 and character not in "\t\n\r" for character in value):
        raise ValueError("mediator context contains a disallowed control character")
    return value


class ApprovedMediatorContext(StrictProtocolModel):
    """Locally approved public or synthetic context for exactly one case."""

    schema_: Literal["umi-approved-mediator-context/1"] = Field(alias="schema")
    case_id: Hex32
    source: Literal["public", "synthetic"]
    provenance_sha256: Hex32
    text: Annotated[str, Field(max_length=8192)] = ""

    _bounded_text = field_validator("text")(_context_text)


def requests_from_execution(
    evidence: ModelExecutionEvidence,
    policy: CompetitionPolicy,
    contexts: tuple[ApprovedMediatorContext, ...],
) -> tuple[MediatorRequest, ...]:
    """Select successful candidate hypotheses without exporting protected metadata.

    Every successful non-empty candidate output needs one explicit approved
    context record. Case identifiers are used only for this local join and are
    absent from :class:`MediatorProviderRequest`.
    """

    evidence = ModelExecutionEvidence.model_validate_json(canonical_json_bytes(evidence))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    validate_execution(evidence, policy)

    canonical_contexts = tuple(
        ApprovedMediatorContext.model_validate_json(canonical_json_bytes(context))
        for context in contexts
    )
    by_case: dict[str, ApprovedMediatorContext] = {}
    for context in canonical_contexts:
        if context.case_id in by_case:
            raise ValueError("mediator context has a duplicate case identifier")
        by_case[context.case_id] = context

    case_ids = {case.case_id for case in evidence.job.cases}
    if not set(by_case).issubset(case_ids):
        raise ValueError("mediator context is not assigned to this execution")

    evidence_sha256 = digest(evidence)
    requests = []
    for step in evidence.steps:
        output = step.execution.output
        if step.role != "candidate" or step.execution.reason != "ok" or output.status != "ok":
            continue
        if not output.hypothesis:
            continue
        try:
            context = by_case[output.case_id]
        except KeyError as error:
            raise ValueError("successful mediator source lacks approved context") from error
        requests.append(
            MediatorRequest(
                schema="umi-mediator-request/1",
                source_evidence_sha256=evidence_sha256,
                source_output_sha256=digest(output),
                approved_context_sha256=digest(context),
                source_hypothesis=output.hypothesis,
                public_context=context.text,
            )
        )
    return tuple(requests)
