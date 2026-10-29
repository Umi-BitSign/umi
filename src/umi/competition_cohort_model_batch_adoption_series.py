"""Standing automatic adoption jobs for configured C7-and-later intake histories.

The host-update producer supplies current target configs and canonical history
snapshots. A service-managed recurring invocation calls this same per-cohort
adopter; it never needs a new operator decision for each successor. This module
does not close intake or alter any signed cohort clock.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_model_batch import SignedModelBatchCertificationAdoption
from .competition_cohort_model_batch_adoption import (
    ModelBatchAdoptionVote,
    check_model_batch_adoption_vote,
)
from .competition_cohort_model_batch_adoption_operator import (
    ModelBatchAdoptionOperatorCompletion,
    ModelBatchAdoptionOperatorConfig,
    ModelBatchAdoptionOperatorPlan,
    ModelBatchAdoptionRefused,
    ModelBatchAdoptionTarget,
    actor_publication,
    load_adoption_target,
    run_model_batch_adoption,
)
from .competition_host_activation import _read_root_control_path
from .competition_work_progress import WorkProgress, work_heartbeats
from .concurrency import run_owned_thread
from .open_competition import digest, identity
from .private_files import Directory, publish_private_model, read_private_model
from .protocol import StrictProtocolModel, canonical_json_bytes


class ModelBatchAdoptionSeriesConfig(StrictProtocolModel):
    schema_: Literal["umi-model-batch-adoption-series/1"] = Field(alias="schema")
    state_directory: Directory
    policy_file: Directory
    histories_directory: Directory
    standing_operator_request_reference: Annotated[str, Field(min_length=1, max_length=2048)]
    minimum_cohort_sequence: Annotated[int, Field(ge=7)] = 7
    owner: ModelBatchAdoptionTarget
    reviewers: Annotated[tuple[ModelBatchAdoptionTarget, ...], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def scope(self):
        if self.owner.role != "owner" or any(t.role != "reviewer" for t in self.reviewers):
            raise ValueError("batch adoption series requires one owner and explicit reviewers")
        targets = (self.owner, *self.reviewers)
        if len({t.service_unit for t in targets}) != len(targets):
            raise ValueError("batch adoption series repeats a service target")
        return self


def materialize_model_batch_adoption_job(config, history, policy):
    """Default new supported host configurations to the same prospective format.

    A trusted retained history supplies the earliest effective block; each
    reviewer independently checks current finalized authority before signing.
    Missing future history is pending work, never permission to fabricate it.
    """
    config = ModelBatchAdoptionSeriesConfig.model_validate_json(canonical_json_bytes(config))
    cohort = digest(history.plan)
    block = (
        history.transitions[-1].transition.observed_at_block
        if history.transitions
        else history.genesis.admitted_at_block
    )
    view = verify_cohort_history(
        history,
        policy,
        expected_tip_sha256=history_tip(history),
        current_block=block,
    )
    if history.plan.sequence < config.minimum_cohort_sequence or view.state.phase != "intake":
        return None
    state = Path(config.state_directory) / cohort
    return ModelBatchAdoptionOperatorConfig(
        schema="umi-model-batch-adoption-operator/1",
        state_directory=str(state),
        policy_file=config.policy_file,
        history_file=str(state / "history.json"),
        expected_tip_sha256=history_tip(history),
        effective_at_block=block,
        operator_request_reference=config.standing_operator_request_reference,
        owner=config.owner,
        reviewers=config.reviewers,
    )


def _load_history(path):
    raw = _read_root_control_path(path, 32 * 1024**2, modes={0o400, 0o444})
    history = CohortRecoveryHistory.model_validate_json(raw)
    if canonical_json_bytes(history) != raw:
        raise ModelBatchAdoptionRefused("batch adoption series history is not canonical")
    return history


def _completed_job(state, config, selected, policy, publish):
    """Reuse bounded durable completion; diagnose lost records instead of signing again."""
    completion_path = state / "completion.json"
    if not completion_path.exists() and not completion_path.is_symlink():
        return None
    try:
        completion = read_private_model(completion_path, ModelBatchAdoptionOperatorCompletion)
        plan = read_private_model(state / "plan.json", ModelBatchAdoptionOperatorPlan)
        signed = read_private_model(state / "signed.json", SignedModelBatchCertificationAdoption)
        history = read_private_model(state / "history.json", CohortRecoveryHistory)
    except (OSError, ValueError) as error:
        raise ModelBatchAdoptionRefused(
            "completed batch adoption lost retained records; repair required"
        ) from error
    original = (plan.config.owner, *plan.config.reviewers)
    # Host upgrades can change source/config hashes. Reuse remains valid when
    # the same authority, service accounts and durable selection directories
    # are carried forward by the supported host-config producer.
    old = tuple(load_adoption_target(t) for t in original)
    old_bindings = {
        (
            t.target.role,
            t.target.service_account,
            None if t.signer is None else identity(t.signer),
            str(t.directory),
        )
        for t in old
    }
    new_bindings = {
        (
            t.target.role,
            t.target.service_account,
            None if t.signer is None else identity(t.signer),
            str(t.directory),
        )
        for t in selected
    }
    if (
        completion.cohort_sha256 != state.name
        or digest(history) != plan.history_sha256
        or completion.adoption_sha256 != digest(plan.request.adoption)
        or completion.signed_sha256 != digest(signed)
        or signed.adoption != plan.request.adoption
        or plan.request.operator_request_reference != config.standing_operator_request_reference
        or old_bindings != new_bindings
        or any(t.policy_sha256 != signed.adoption.policy_sha256 for t in selected)
    ):
        raise ModelBatchAdoptionRefused("completed batch adoption changed selected dependencies")
    for target in selected:
        if not any(
            c.cohort_sha256 == state.name and c.authority_sha256 == signed.adoption.authority_sha256
            for c in target.cohorts
        ):
            raise ModelBatchAdoptionRefused("completed batch adoption changed cohort authority")
    for target in selected[1:]:
        try:
            vote = read_private_model(
                state / ("vote-" + identity(target.signer) + ".json"),
                ModelBatchAdoptionVote,
            )
            check_model_batch_adoption_vote(vote, plan.request, policy, signer=target.signer)
        except (OSError, ValueError) as error:
            raise ModelBatchAdoptionRefused(
                "completed batch adoption lost retained votes; repair required"
            ) from error
    missing = []
    for target in (*selected[1:], selected[0]):
        receipt = publish(target.target, plan.request, signed, check_only=True)
        if receipt.get("selected_sha256") is None:
            missing.append(target)
        elif receipt.get("selected_sha256") != digest(signed):
            raise ModelBatchAdoptionRefused(
                "completed batch adoption changed service selection; repair required"
            )
    if missing:
        with WorkProgress(
            "model_batch_adoption_selection_repair",
            len(missing),
            unit="consumers",
            cohort=state.name,
            estimate=False,
            planning_range_seconds=(0, 30 * len(missing)),
            planning_basis="planning_exact_retained_selection_actor_publication_budget",
        ) as progress:
            for target in missing:
                receipt = publish(target.target, plan.request, signed)
                if receipt.get("selected_sha256") != digest(signed):
                    raise ModelBatchAdoptionRefused(
                        "batch adoption selection repair failed readback"
                    )
                progress.advance()
    return {**completion.model_dump(mode="json"), "restored_selected_consumers": len(missing)}


async def run_model_batch_adoption_series(
    config,
    policy,
    *,
    client,
    run_job=run_model_batch_adoption,
    load_history=_load_history,
    select=load_adoption_target,
    publish=actor_publication,
):
    """One bounded pass, suitable for the supported persistent preparation timer."""
    config = ModelBatchAdoptionSeriesConfig.model_validate_json(canonical_json_bytes(config))
    targets = []
    for target in (config.owner, *config.reviewers):
        targets.append(await run_owned_thread(select, target))
    targets = tuple(targets)
    owner = targets[0]
    if owner.policy_sha256 != digest(policy):
        raise ModelBatchAdoptionRefused("batch adoption series changed the selected policy")
    cohorts = tuple(c.cohort_sha256 for c in owner.cohorts)
    outcomes = []
    with (
        work_heartbeats(),
        WorkProgress(
            "model_batch_adoption_series",
            len(cohorts),
            unit="cohorts",
            estimate=False,
            planning_range_seconds=(
                0,
                len(cohorts) * (60 * len(targets) + 3600 * len(config.reviewers)),
            ),
            planning_basis="planning_maximum_configured_review_and_publication_budget_per_unfinished_cohort",
        ) as progress,
    ):
        for cohort in cohorts:
            state = Path(config.state_directory) / cohort
            try:
                completed = await run_owned_thread(
                    _completed_job, state, config, targets, policy, publish
                )
                if completed is not None:
                    outcomes.append(
                        {
                            **completed,
                            "status": (
                                "repaired" if completed["restored_selected_consumers"] else "reused"
                            ),
                        }
                    )
                    progress.advance()
                    continue
                plan_path = state / "plan.json"
                if plan_path.exists() or plan_path.is_symlink():
                    plan = await run_owned_thread(
                        read_private_model, plan_path, ModelBatchAdoptionOperatorPlan
                    )
                    job = plan.config
                    if (
                        job.owner != config.owner
                        or job.reviewers != config.reviewers
                        or job.operator_request_reference
                        != config.standing_operator_request_reference
                    ):
                        raise ModelBatchAdoptionRefused(
                            "unfinished batch adoption changed routing; explicit repair required"
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
                    else:
                        history = await run_owned_thread(
                            load_history, Path(config.histories_directory) / (cohort + ".json")
                        )
                    if digest(history.plan) != cohort:
                        raise ModelBatchAdoptionRefused(
                            "batch adoption series history names another cohort"
                        )
                    job = materialize_model_batch_adoption_job(config, history, policy)
                    if job is None:
                        outcomes.append(
                            {"cohort_sha256": cohort, "status": "outside_prospective_intake"}
                        )
                        progress.advance()
                        continue
                    await run_owned_thread(publish_private_model, state / "history.json", history)
                result = await run_job(job, policy, history, client=client)
                outcomes.append(result)
                progress.advance()
            except (OSError, ValueError) as error:
                outcomes.append(
                    {
                        "cohort_sha256": cohort,
                        "status": "pending",
                        "error_type": type(error).__name__,
                        "reason_code": getattr(error, "reason_code", None),
                    }
                )
        pending = sum(o["status"] == "pending" for o in outcomes)
        if pending:
            progress.interrupt()
        return {
            "status": "pending" if pending else "complete",
            "completed": len(cohorts) - pending,
            "total": len(cohorts),
            "pending": pending,
            "cohorts": outcomes,
            "intake_closure_authorized": False,
            "runtime_activation_verified": False,
        }
