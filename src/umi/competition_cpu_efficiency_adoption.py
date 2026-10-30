"""Private, retained reviewer decisions for the authority-scoped CPU contract."""

from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator

from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cpu_efficiency_policy import (
    CohortCpuEfficiencyAdoption,
    default_cpu_efficiency_proposal,
)
from .competition_evaluation_runtime import (
    SignedCohortEvaluationRuntimeAdoption,
    authorize_evaluation_runtime,
)
from .competition_execution import execution_boundary
from .competition_work_progress import WorkProgress, work_heartbeats
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import Signature, digest, identity, verify_signature
from .private_files import read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_CPU_ADOPTION_BYTES = 256 * 1024


class CpuEfficiencyReviewRequest(StrictProtocolModel):
    schema_: Literal["umi-cpu-efficiency-review-request/1"] = Field(
        alias="schema", default="umi-cpu-efficiency-review-request/1"
    )
    adoption: CohortCpuEfficiencyAdoption
    anchor_cohort_sha256: Hex32
    runtime_adoption: SignedCohortEvaluationRuntimeAdoption | None = None
    operator_request_reference: Annotated[str, Field(min_length=1, max_length=2048)]

    @field_validator("operator_request_reference")
    @classmethod
    def explicit_reference(cls, value):
        if not value.strip() or any(ord(char) < 32 for char in value):
            raise ValueError("CPU adoption requires an explicit retained operator decision")
        return value


class CpuEfficiencyVote(StrictProtocolModel):
    adoption: CohortCpuEfficiencyAdoption
    signature: Signature


def check_cpu_efficiency_vote(vote, request, policy, *, signer=None):
    account = identity(vote.signature.hotkey)
    if (
        vote.adoption != request.adoption
        or account not in {identity(e.hotkey) for e in policy.evaluators}
        or (signer is not None and account != identity(signer))
    ):
        raise ValueError("CPU adoption vote changes its body or configured reviewer")
    verify_signature(vote.adoption, vote.signature)


def verify_cpu_efficiency_request(request, history, policy, *, current_block):
    """Independently verify the original intake authority and actual CPU runtime."""
    body = request.adoption
    authority = history.authority.authority
    view = verify_cohort_history(
        history, policy, expected_tip_sha256=history_tip(history), current_block=current_block
    )
    if (
        digest(history.plan) != request.anchor_cohort_sha256
        or history.plan.sequence < 8
        or view.state.phase != "intake"
        or body.issued_at_block > current_block
    ):
        raise ValueError("CPU adoption requires a prospective C8+ intake anchor")
    runtime = authorize_evaluation_runtime(
        request.runtime_adoption,
        policy=policy,
        authority=authority,
        plan=history.plan,
        current_block=body.issued_at_block,
    )
    expected = default_cpu_efficiency_proposal(
        policy=policy,
        authority=authority,
        runtime_sha256=(
            policy.evaluation_runtime_sha256 if runtime is None else digest(runtime.runtime)
        ),
        reason=body.reason,
        issued_at_block=body.issued_at_block,
    )
    if body != expected:
        raise ValueError("CPU adoption changes the fixed rule, authority scope or CPU runtime")


async def attest_cpu_efficiency(reviewer, request):
    """One immutable decision per authority; completed votes never reread history."""
    request = CpuEfficiencyReviewRequest.model_validate_json(canonical_json_bytes(request))
    body, cohort = request.adoption, request.anchor_cohort_sha256
    slot = body.authority_sha256
    if reviewer.cohorts.get(cohort) != slot:
        raise ValueError("CPU adoption is outside configured cohort authority")
    directory = reviewer.config.cpu_efficiency_adoptions_directory
    if directory is None:
        raise ValueError("CPU adoption candidates are not configured")
    async with reviewer.serial:
        with reviewer.journal.locked():
            saved = await run_owned_thread(reviewer.journal.get, "cpu_adoption_request", slot)
            vote = await run_owned_thread(reviewer.journal.get, "cpu_adoption_vote", slot)
            if saved is not None and canonical_json_bytes(saved) != canonical_json_bytes(request):
                raise ValueError("CPU adoption changes its original operator request")
            if vote is not None:
                if saved is None:
                    raise ValueError("CPU adoption vote lost its intent; repair required")
                vote = CpuEfficiencyVote.model_validate_json(canonical_json_bytes(vote))
                check_cpu_efficiency_vote(
                    vote, request, reviewer.policy, signer=reviewer.config.signer
                )
                return vote
            with (
                work_heartbeats(),
                WorkProgress(
                    "cpu_efficiency_adoption_review",
                    1,
                    unit="authorities",
                    cohort=cohort,
                    estimate=False,
                    planning_range_seconds=(0, reviewer.config.signing_timeout_seconds),
                    planning_basis="planning_current_authority_and_configured_signing_budget",
                ) as progress,
            ):
                if saved is None:
                    approved = await run_owned_thread(
                        partial(
                            read_private_model,
                            Path(directory) / (slot + ".candidate.json"),
                            CpuEfficiencyReviewRequest,
                            maximum_bytes=MAX_CPU_ADOPTION_BYTES,
                        )
                    )
                    if approved != request:
                        raise ValueError("CPU adoption differs from private operator selection")
                source = await reviewer.history(cohort)
                current = source.history
                block = execution_boundary(await reviewer.capture()).block
                verify_cpu_efficiency_request(
                    request, current, reviewer.policy, current_block=block
                )
                original = current
                if saved is not None:
                    raw = await run_owned_thread(reviewer.journal.get, "cpu_adoption_history", slot)
                    if raw is None:
                        raise ValueError("CPU adoption lost original history; repair required")
                    original = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(raw))
                    prefix = current.model_copy(
                        update={"transitions": current.transitions[: len(original.transitions)]}
                    )
                    if digest(prefix) != digest(original):
                        raise ValueError("CPU adoption history rolled back or changed")
                await run_owned_thread(
                    reviewer.journal.put_many,
                    (
                        ("cpu_adoption_request", slot, request),
                        ("cpu_adoption_history", slot, original),
                    ),
                )
                signature = await wait_for_owned(
                    reviewer.sign(body), timeout=reviewer.config.signing_timeout_seconds
                )
                vote = CpuEfficiencyVote(adoption=body, signature=signature)
                check_cpu_efficiency_vote(
                    vote, request, reviewer.policy, signer=reviewer.config.signer
                )
                await run_owned_thread(reviewer.journal.put, "cpu_adoption_vote", slot, vote)
                progress.advance()
                return vote
