"""Typed CPU contract on the existing resumable adoption operator path."""

from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_intake import history_tip
from .competition_cohort_model_batch_adoption_operator import (
    ModelBatchAdoptionOperatorConfig,
    ModelBatchAdoptionRefused,
    ModelBatchAdoptionTarget,
    _checked_target_routes,
    _run_retained_adoption,
    actor_publication,
    load_adoption_target,
    publish_for_actor,
)
from .competition_cohort_model_review_http import ModelReviewPeer
from .competition_cpu_efficiency_adoption import (
    CpuEfficiencyReviewRequest,
    CpuEfficiencyVote,
    check_cpu_efficiency_vote,
    verify_cpu_efficiency_request,
)
from .competition_cpu_efficiency_policy import (
    SignedCohortCpuEfficiencyAdoption,
    default_cpu_efficiency_proposal,
    verify_cpu_efficiency_adoption_selection,
)
from .competition_work_progress import WorkProgress, work_heartbeats
from .concurrency import run_owned_thread
from .open_competition import digest, identity
from .private_files import publish_private_model, read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

CPU_DEFAULT_REASON = "C8 and later: quality-qualified CPU efficiency reward adjustment"


class CpuEfficiencyActorPublication(StrictProtocolModel):
    target: ModelBatchAdoptionTarget
    request: CpuEfficiencyReviewRequest
    signed: SignedCohortCpuEfficiencyAdoption | None = None
    check_only: bool = False


class CpuEfficiencyOperatorConfig(ModelBatchAdoptionOperatorConfig):
    schema_: Literal["umi-cpu-efficiency-adoption-operator/1"] = Field(alias="schema")
    request: CpuEfficiencyReviewRequest


class CpuEfficiencyOperatorPlan(StrictProtocolModel):
    config: CpuEfficiencyOperatorConfig
    policy_sha256: Hex32
    history_sha256: Hex32
    request: CpuEfficiencyReviewRequest


class CpuEfficiencyOperatorCompletion(StrictProtocolModel):
    status: Literal["signed_selection_published"] = "signed_selection_published"
    authority_sha256: Hex32
    adoption_sha256: Hex32
    signed_sha256: Hex32
    reviewer_votes: Annotated[int, Field(ge=1, le=64)]
    selected_consumers: Annotated[int, Field(ge=2, le=65)]
    runtime_activation_verified: Literal[False] = False


cpu_actor_publication = partial(actor_publication, _action="publish-cpu")
publish_cpu_for_actor = partial(publish_for_actor, _cpu_efficiency=True)


def selected_cpu_targets(config, policy, request):
    targets = tuple(
        load_adoption_target(t, cpu_efficiency=True) for t in (config.owner, *config.reviewers)
    )
    body = request.adoption
    for selected in targets:
        if (
            selected.authority is None
            or digest(selected.authority) != body.authority_sha256
            or selected.authority.cohort_sha256s != body.cohort_sha256s
            or not any(
                c.cohort_sha256 == request.anchor_cohort_sha256
                and c.authority_sha256 == body.authority_sha256
                for c in selected.cohorts
            )
        ):
            raise ModelBatchAdoptionRefused("CPU adoption targets differ on selected authority")
    anchor = next((p for p in targets[0].plans if digest(p) == request.anchor_cohort_sha256), None)
    if anchor is None or anchor.sequence < 8:
        raise ModelBatchAdoptionRefused("CPU adoption has no selected prospective C8+ anchor")
    runtime = targets[0].runtime_adoption
    if runtime is not None and anchor.sequence < runtime.adoption.first_cohort_sequence:
        runtime = None
    if runtime != request.runtime_adoption:
        raise ModelBatchAdoptionRefused("CPU adoption changes the owner's selected CPU runtime")
    return _checked_target_routes(config, policy, targets)


async def run_cpu_efficiency_adoption(
    config,
    policy,
    history,
    *,
    client,
    publish=cpu_actor_publication,
    select=selected_cpu_targets,
    peer_factory=ModelReviewPeer,
):
    config = CpuEfficiencyOperatorConfig.model_validate_json(canonical_json_bytes(config))
    request = config.request
    if (
        config.expected_tip_sha256 != history_tip(history)
        or config.effective_at_block != request.adoption.issued_at_block
        or config.operator_request_reference != request.operator_request_reference
    ):
        raise ModelBatchAdoptionRefused("CPU adoption operator plan changes its exact decision")
    verify_cpu_efficiency_request(request, history, policy, current_block=config.effective_at_block)
    return await _run_retained_adoption(
        config,
        policy,
        history,
        request,
        client=client,
        publish=publish,
        select=select,
        peer_factory=peer_factory,
        cpu_efficiency=True,
    )


def _semantic_bindings(selected):
    return {
        (
            t.target.role,
            t.target.service_account,
            None if t.signer is None else identity(t.signer),
            str(t.directory),
        )
        for t in selected
    }


def _completed_cpu_job(state, config, policy, selected, publish):
    path = state / "completion.json"
    if not path.exists() and not path.is_symlink():
        return None
    try:
        completion = read_private_model(path, CpuEfficiencyOperatorCompletion)
        plan = read_private_model(state / "plan.json", CpuEfficiencyOperatorPlan)
        signed = read_private_model(state / "signed.json", SignedCohortCpuEfficiencyAdoption)
        history = read_private_model(state / "history.json", CohortRecoveryHistory)
    except (OSError, ValueError) as error:
        raise ModelBatchAdoptionRefused(
            "completed CPU adoption lost records; repair required"
        ) from error
    original = tuple(
        load_adoption_target(t, cpu_efficiency=True)
        for t in (plan.config.owner, *plan.config.reviewers)
    )
    if (
        completion.authority_sha256 != state.name
        or completion.adoption_sha256 != digest(plan.request.adoption)
        or completion.signed_sha256 != digest(signed)
        or signed.adoption != plan.request.adoption
        or digest(history) != plan.history_sha256
        or plan.policy_sha256 != digest(policy)
        or plan.request.operator_request_reference
        != config.cpu_efficiency_operator_request_reference
        or _semantic_bindings(original) != _semantic_bindings(selected)
        or any(
            t.policy_sha256 != digest(policy) or digest(t.authority) != state.name for t in selected
        )
    ):
        raise ModelBatchAdoptionRefused("completed CPU adoption changed selected dependencies")
    runtime = selected[0].runtime_adoption
    runtime_sha256 = (
        policy.evaluation_runtime_sha256 if runtime is None else digest(runtime.adoption.runtime)
    )
    verify_cpu_efficiency_adoption_selection(
        signed, policy=policy, authority=selected[0].authority, runtime_sha256=runtime_sha256
    )
    for target in selected[1:]:
        try:
            vote = read_private_model(
                state / ("vote-" + identity(target.signer) + ".json"), CpuEfficiencyVote
            )
            check_cpu_efficiency_vote(vote, plan.request, policy, signer=target.signer)
        except (OSError, ValueError) as error:
            raise ModelBatchAdoptionRefused(
                "completed CPU adoption lost votes; repair required"
            ) from error
    missing = []
    for target in (*selected[1:], selected[0]):
        receipt = publish(target.target, plan.request, signed, check_only=True)
        if receipt.get("selected_sha256") is None:
            missing.append(target)
        elif receipt.get("selected_sha256") != digest(signed):
            raise ModelBatchAdoptionRefused("CPU adoption selection changed; repair required")
    if missing:
        with WorkProgress(
            "cpu_efficiency_selection_repair",
            len(missing),
            unit="consumers",
            estimate=False,
            planning_range_seconds=(0, 30 * len(missing)),
            planning_basis="planning_exact_retained_actor_publication_budget",
        ) as progress:
            for target in missing:
                receipt = publish(target.target, plan.request, signed)
                if receipt.get("selected_sha256") != digest(signed):
                    raise ModelBatchAdoptionRefused("CPU adoption selection repair failed readback")
                progress.advance()
    return {**completion.model_dump(mode="json"), "restored_selected_consumers": len(missing)}


async def run_cpu_efficiency_series(
    config,
    policy,
    *,
    client,
    load_history,
    run_job=run_cpu_efficiency_adoption,
    select=None,
    publish=cpu_actor_publication,
):
    """One contract per selected authority, in the existing recurring series pass."""
    if config.cpu_efficiency_operator_request_reference is None:
        return {"status": "not_selected", "completed": 0, "total": 0}
    if select is None:
        select = partial(load_adoption_target, cpu_efficiency=True)
    with (
        work_heartbeats(),
        WorkProgress(
            "cpu_efficiency_authority_series",
            1,
            unit="authorities",
            estimate=False,
            planning_range_seconds=(
                0,
                60 * (1 + len(config.reviewers)) + 3600 * len(config.reviewers),
            ),
            planning_basis="planning_configured_review_and_publication_budget_for_one_authority",
        ) as progress,
    ):
        try:
            selected = tuple(
                [await run_owned_thread(select, t) for t in (config.owner, *config.reviewers)]
            )
            owner = selected[0]
            await run_owned_thread(_checked_target_routes, config, policy, selected)
            allowed = {c.cohort_sha256 for c in owner.cohorts}
            prospective = sorted(
                (
                    p
                    for p in owner.plans
                    if p.sequence >= 8
                    and digest(p) in allowed
                    and (p.eligible_tracks is None or "model" in p.eligible_tracks)
                ),
                key=lambda p: p.sequence,
            )
            if not prospective:
                progress.advance()
                return {"status": "outside_scope", "completed": 0, "total": 0}
            authority = digest(owner.authority)
            state = Path(config.state_directory) / "cpu-efficiency" / authority
            complete = await run_owned_thread(
                _completed_cpu_job, state, config, policy, selected, publish
            )
            if complete is not None:
                progress.advance()
                return {
                    **complete,
                    "status": "repaired" if complete["restored_selected_consumers"] else "reused",
                    "completed": 1,
                    "total": 1,
                }
            plan_path = state / "plan.json"
            if plan_path.exists() or plan_path.is_symlink():
                saved = await run_owned_thread(
                    read_private_model, plan_path, CpuEfficiencyOperatorPlan
                )
                job = saved.config
                if (
                    job.owner != config.owner
                    or job.reviewers != config.reviewers
                    or job.operator_request_reference
                    != config.cpu_efficiency_operator_request_reference
                ):
                    raise ModelBatchAdoptionRefused(
                        "unfinished CPU adoption changed routing; repair required"
                    )
                history = await run_owned_thread(
                    read_private_model, state / "history.json", CohortRecoveryHistory
                )
            else:
                retained = state / "history.json"
                if retained.exists() or retained.is_symlink():
                    history = await run_owned_thread(
                        read_private_model, retained, CohortRecoveryHistory
                    )
                elif config.cpu_efficiency_anchor_history_file is not None:
                    history = await run_owned_thread(
                        load_history, Path(config.cpu_efficiency_anchor_history_file)
                    )
                else:
                    raise ModelBatchAdoptionRefused(
                        "CPU adoption needs a current prospective intake history snapshot"
                    )
                if (
                    history.plan not in prospective
                    or digest(history.authority.authority) != authority
                ):
                    raise ModelBatchAdoptionRefused(
                        "CPU adoption history differs from selected authority"
                    )
                runtime = owner.runtime_adoption
                if (
                    runtime is not None
                    and history.plan.sequence < runtime.adoption.first_cohort_sequence
                ):
                    runtime = None
                issued = max(
                    history.transitions[-1].transition.observed_at_block
                    if history.transitions
                    else history.genesis.admitted_at_block,
                    owner.authority.issued_at_block,
                    0 if runtime is None else runtime.adoption.issued_at_block,
                )
                body = default_cpu_efficiency_proposal(
                    policy=policy,
                    authority=owner.authority,
                    runtime_sha256=policy.evaluation_runtime_sha256
                    if runtime is None
                    else digest(runtime.adoption.runtime),
                    issued_at_block=issued,
                    reason=CPU_DEFAULT_REASON,
                )
                request = CpuEfficiencyReviewRequest(
                    adoption=body,
                    anchor_cohort_sha256=digest(history.plan),
                    runtime_adoption=runtime,
                    operator_request_reference=config.cpu_efficiency_operator_request_reference,
                )
                job = CpuEfficiencyOperatorConfig(
                    schema="umi-cpu-efficiency-adoption-operator/1",
                    state_directory=str(state),
                    policy_file=config.policy_file,
                    history_file=str(state / "history.json"),
                    expected_tip_sha256=history_tip(history),
                    effective_at_block=issued,
                    operator_request_reference=request.operator_request_reference,
                    request=request,
                    owner=config.owner,
                    reviewers=config.reviewers,
                )
                await run_owned_thread(publish_private_model, state / "history.json", history)
            result = await run_job(job, policy, history, client=client)
            progress.advance()
            return {**result, "completed": 1, "total": 1}
        except (OSError, ValueError) as error:
            progress.interrupt()
            return {
                "status": "pending",
                "completed": 0,
                "total": 1,
                "error_type": type(error).__name__,
                "reason_code": getattr(error, "reason_code", None),
            }
