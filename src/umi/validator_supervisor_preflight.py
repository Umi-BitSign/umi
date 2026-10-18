"""Fixed release-profile checks for common-channel installation preflight."""

from __future__ import annotations

import json
import sys
import time

from .translation_reference_policy_io import fetch_approved_reference_policy
from .validator_supervisor import COMMON_SUPERVISOR_AUTHORITY_HOTKEY, SignedSupervisorDirective
from .validator_supervisor_adapters import (
    SUPERVISOR_REGISTRATION_BRIDGE_INPUT_PROFILE,
    SUPERVISOR_SIMPLE_BOOTSTRAP_INPUT_PROFILE,
    ValidatorSupervisorAdapterError,
)
from .validator_supervisor_runtime import SupervisorWorkerActivation


class CommonPreflightProgress:
    def __init__(self, *, started: float) -> None:
        self.started = started
        self.stage: str | None = None
        self.stage_started = started

    def __call__(
        self, stage: str, completed: int, total: int | None, *, status: str | None = None
    ) -> None:
        now = time.monotonic()
        if self.stage != stage:
            self.stage, self.stage_started = stage, now
        done = total is not None and completed == total
        print(
            json.dumps(
                dict(
                    stage=stage,
                    completed=completed,
                    total=total,
                    percent=completed / total * 100 if total else None,
                    elapsed_seconds=now - self.stage_started,
                    overall_elapsed_seconds=now - self.started,
                    eta_seconds=0 if done else None,
                    planning_seconds=None if done else [1, 180],
                    eta_basis=(
                        "common-channel installation preflight; first-pass planning, "
                        "not worker readiness or fleet ETA"
                    ),
                    status=status or ("complete" if done else "running"),
                    retrying=False,
                    stalled=status == "refused",
                )
            ),
            file=sys.stderr,
            flush=True,
        )


async def prepare_common_activation(
    signed: SignedSupervisorDirective, *, https
) -> SupervisorWorkerActivation:
    """Validate only supported profiles and the fixed worker's approval domain.

    The caller has already authenticated the complete directive prefix and
    owns native finality. This function never starts or stops a worker, loads a
    signing key, changes high-water state or approves legacy transaction effects.
    """
    directive = signed.directive
    release, inputs = directive.release, directive.operator_inputs
    if release is None or directive.policy_sha256 is None:
        raise ValidatorSupervisorAdapterError("common_switch_release_required")
    if directive.mode == "bootstrap_service_weights":
        profiles = {
            ("umi-simple-bootstrap-validator/1", SUPERVISOR_SIMPLE_BOOTSTRAP_INPUT_PROFILE),
            ("umi-registration-bridge-validator/1", SUPERVISOR_REGISTRATION_BRIDGE_INPUT_PROFILE),
        }
        if inputs is None or (release.entrypoint_profile, inputs.profile) not in profiles:
            raise ValidatorSupervisorAdapterError("common_switch_release_required")
    elif directive.mode == "translation_weights":
        if release.entrypoint_profile != "umi-translation-validator/1" or inputs is not None:
            raise ValidatorSupervisorAdapterError("common_switch_release_required")
        try:
            await fetch_approved_reference_policy(
                directive.policy_sha256,
                expected_authority_hotkey=COMMON_SUPERVISOR_AUTHORITY_HOTKEY,
                http=https,
            )
        except Exception as error:
            raise ValidatorSupervisorAdapterError(
                "common_switch_reference_approval_invalid"
            ) from error
    else:
        raise ValidatorSupervisorAdapterError("common_switch_release_required")
    return SupervisorWorkerActivation(
        mode=directive.mode,
        sequence=directive.sequence,
        directive_sha256=signed.directive_sha256,
        policy_sha256=directive.policy_sha256,
        valid_from_block=directive.valid_from_block,
        valid_through_block=directive.valid_through_block,
        release=release,
        operator_inputs=inputs,
    )
