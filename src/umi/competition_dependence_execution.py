"""Retained positive-control execution for the continuous-dependence gate."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .competition_execution import ExecutionBoundary, read_case_video
from .competition_runner import (
    OFFLINE_RUNTIME,
    OfflineCaseExecution,
    OfflineRuntime,
    execute_offline_case,
    validate_case_execution,
)
from .open_competition import (
    DEPENDENCE_POLICY_SCHEMA,
    CompetitionPolicy,
    DependenceCalibration,
    EvaluationSuite,
    Hotkey,
    ModelBundle,
    digest,
    identity,
    validate_dependence_calibration_body,
    validate_suite_profile,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class DependenceCalibrationExecution(StrictProtocolModel):
    """Reference-free positive-control run with retained sandbox observations."""

    schema_: Literal["umi-dependence-calibration-execution/1"] = Field(alias="schema")
    policy_sha256: Hex32
    suite_sha256: Hex32
    runtime_sha256: Hex32
    model_sha256: Hex32
    evaluator_hotkey: Hotkey
    started: ExecutionBoundary
    finished: ExecutionBoundary
    executions: Annotated[tuple[OfflineCaseExecution, ...], Field(min_length=3, max_length=2048)]
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def ordered_boundaries(self) -> Self:
        if self.finished.block < self.started.block or (
            self.finished.block == self.started.block
            and (
                self.finished.block_hash,
                self.finished.state_root,
                self.finished.snapshot_sha256,
            )
            != (
                self.started.block_hash,
                self.started.state_root,
                self.started.snapshot_sha256,
            )
        ):
            raise ValueError("calibration finality boundary rolled back or changed")
        return self


class DependenceCalibrationPreparation(StrictProtocolModel):
    """Private retained evidence and the exact body evaluators may sign."""

    schema_: Literal["umi-dependence-calibration-preparation/1"] = Field(alias="schema")
    execution: DependenceCalibrationExecution
    calibration: DependenceCalibration
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def exact_derivation(self) -> Self:
        run = self.execution
        body = self.calibration
        if (
            body.policy_sha256 != run.policy_sha256
            or body.suite_sha256 != run.suite_sha256
            or body.runtime_sha256 != run.runtime_sha256
            or body.model_sha256 != run.model_sha256
            or body.execution_evidence_sha256 != digest(run)
            or body.evaluated_block != run.finished.block
            or body.outputs != tuple(item.output for item in run.executions)
        ):
            raise ValueError("calibration body differs from retained execution evidence")
        return self


def prepare_dependence_calibration(
    execution: DependenceCalibrationExecution,
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
) -> DependenceCalibrationPreparation:
    """Replay retained case evidence and derive the only signable body."""

    execution = DependenceCalibrationExecution.model_validate_json(canonical_json_bytes(execution))
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    validate_suite_profile(suite, policy)
    if policy.schema_ != DEPENDENCE_POLICY_SCHEMA:
        raise ValueError("positive-control execution requires policy version 4")
    evaluator_keys = {identity(item.hotkey) for item in policy.evaluators}
    if (
        execution.policy_sha256 != digest(policy)
        or execution.suite_sha256 != digest(suite)
        or execution.runtime_sha256 != policy.evaluation_runtime_sha256
        or execution.model_sha256 != policy.positive_control_model_sha256
        or identity(execution.evaluator_hotkey) not in evaluator_keys
    ):
        raise ValueError("positive-control execution binding mismatch")
    if len(execution.executions) != len(suite.cases):
        raise ValueError("positive-control execution omits suite cases")
    for case, record in zip(suite.cases, execution.executions, strict=True):
        validate_case_execution(record, policy)
        if (
            record.output.case_id != case.case_id
            or record.video_sha256 != case.video_sha256
            or record.model_sha256 != execution.model_sha256
            or record.runtime_sha256 != execution.runtime_sha256
        ):
            raise ValueError("positive-control case evidence differs from the suite")
    calibration = DependenceCalibration(
        schema="umi-continuous-dependence-calibration/1",
        policy_sha256=execution.policy_sha256,
        suite_sha256=execution.suite_sha256,
        runtime_sha256=execution.runtime_sha256,
        model_sha256=execution.model_sha256,
        execution_evidence_sha256=digest(execution),
        evaluated_block=execution.finished.block,
        outputs=tuple(item.output for item in execution.executions),
    )
    validate_dependence_calibration_body(
        calibration,
        suite,
        policy,
        latest_block=execution.finished.block,
    )
    return DependenceCalibrationPreparation(
        schema="umi-dependence-calibration-preparation/1",
        execution=execution,
        calibration=calibration,
    )


async def run_dependence_calibration(
    *,
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
    bundle: ModelBundle,
    runtime: OfflineRuntime,
    evaluator_hotkey: str,
    archive: Path,
    videos: Path,
    boundary_provider: Callable[[], Awaitable[ExecutionBoundary]],
) -> DependenceCalibrationPreparation:
    """Execute the pinned positive control once over the exact private suite."""

    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    bundle = ModelBundle.model_validate_json(canonical_json_bytes(bundle))
    runtime = OFFLINE_RUNTIME.validate_json(canonical_json_bytes(runtime))
    validate_suite_profile(suite, policy)
    if (
        policy.schema_ != DEPENDENCE_POLICY_SCHEMA
        or digest(bundle) != policy.positive_control_model_sha256
        or digest(runtime) != policy.evaluation_runtime_sha256
        or identity(evaluator_hotkey) not in {identity(item.hotkey) for item in policy.evaluators}
    ):
        raise ValueError("positive-control run configuration differs from policy")
    started = ExecutionBoundary.model_validate_json(canonical_json_bytes(await boundary_provider()))
    executions = []
    for case in suite.cases:
        video = read_case_video(videos, case.video_sha256, runtime.maximum_video_bytes)
        executions.append(
            await execute_offline_case(
                bundle=bundle,
                archive=archive,
                runtime=runtime,
                policy=policy,
                case_id=case.case_id,
                video_sha256=case.video_sha256,
                video=video,
            )
        )
    finished = ExecutionBoundary.model_validate_json(
        canonical_json_bytes(await boundary_provider())
    )
    execution = DependenceCalibrationExecution(
        schema="umi-dependence-calibration-execution/1",
        policy_sha256=digest(policy),
        suite_sha256=digest(suite),
        runtime_sha256=digest(runtime),
        model_sha256=digest(bundle),
        evaluator_hotkey=evaluator_hotkey,
        started=started,
        finished=finished,
        executions=tuple(executions),
    )
    return prepare_dependence_calibration(execution, suite, policy)


def validate_dependence_preparation(
    preparation: DependenceCalibrationPreparation,
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
    *,
    latest_block: int,
) -> DependenceCalibrationPreparation:
    """Reproduce the body and reject a future-dated private preparation."""

    preparation = DependenceCalibrationPreparation.model_validate_json(
        canonical_json_bytes(preparation)
    )
    reproduced = prepare_dependence_calibration(preparation.execution, suite, policy)
    if reproduced != preparation:
        raise ValueError("calibration preparation does not reproduce")
    validate_dependence_calibration_body(
        preparation.calibration,
        suite,
        policy,
        latest_block=latest_block,
    )
    return preparation


__all__ = (
    "DependenceCalibrationExecution",
    "DependenceCalibrationPreparation",
    "prepare_dependence_calibration",
    "run_dependence_calibration",
    "validate_dependence_preparation",
)
