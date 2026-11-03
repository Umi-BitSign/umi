"""Fresh service-owned completion diagnostics, never new protocol authority.

The selected launch and journald's trusted unit/invocation/PID/boot fields must
authenticate these events. Self-reported source identity alone is not evidence.
Only compact existing results are copied; no proof, payload or signature is
rechecked to produce a completion witness.
"""

from __future__ import annotations

import hashlib
import logging
import os
from contextlib import suppress
from functools import wraps
from pathlib import Path

from .host_memory_workload_profile import selected_workload
from .protocol import canonical_json_bytes

# Supported reviewer/settlement CLIs already install this exact logger with a
# message-only StreamHandler; the public owner CLI uses the same root format.
_LOG = logging.getLogger("umi.competition.progress")
_SOURCE = Path(__file__)
_MAX_EVENT_BYTES = 48 * 1024


def _source_revision():
    parts = _SOURCE.parts
    parent = "umi-validator-supervisor-hosts"
    if parent not in parts:
        return None
    index = parts.index(parent) + 1
    revision = parts[index] if index < len(parts) else ""
    return (
        revision if len(revision) == 40 and all(c in "0123456789abcdef" for c in revision) else None
    )


def productive_operation_completed(kind, *, inputs, result):
    """Emit only under an actual selected profile and installed source identity.

    Diagnostics cannot convert a committed native success into a retry. Missing
    telemetry therefore leaves external qualification pending, never fabricated.
    The count describes one completed operation, not full workload qualification.
    """
    with suppress(Exception):
        workload = selected_workload()
        revision = _source_revision()
        invocation = os.environ.get("INVOCATION_ID", "")
        if (
            workload is None
            or revision is None
            or len(invocation) != 32
            or any(c not in "0123456789abcdef" for c in invocation)
        ):
            return False
        input_raw, result_raw = canonical_json_bytes(inputs), canonical_json_bytes(result)
        if len(input_raw) + len(result_raw) > _MAX_EVENT_BYTES - 2048:
            return False
        # Decode compact bytes so model objects cannot outlive this operation
        # through a logging handler's retained arguments.
        import json

        body = dict(
            schema="umi-native-productive-operation/1",
            status="completed",
            kind=kind,
            source_revision=revision,
            profile_sha256=workload.sha256,
            inputs=json.loads(input_raw),
            result=json.loads(result_raw),
            inputs_sha256=hashlib.sha256(input_raw).hexdigest(),
            result_sha256=hashlib.sha256(result_raw).hexdigest(),
            completed=1,
            total=1,
            pid=os.getpid(),
            invocation_id=invocation,
        )
        encoded = canonical_json_bytes(body)
        if len(encoded) > _MAX_EVENT_BYTES:
            return False
        _LOG.info("%s", encoded.decode())
        return True
    return False


def productive_model_operation(kind):
    """Observe an owner return after its native transaction/export has finished."""

    def decorate(function):
        @wraps(function)
        def completed(self, cohort, submission, *args, **kwargs):
            result = function(self, cohort, submission, *args, **kwargs)
            with suppress(Exception):
                productive_operation_completed(
                    kind,
                    inputs=dict(cohort_sha256=cohort, submission_sha256=submission),
                    result=(result.certificate if kind == "model_export" else result),
                )
            return result

        return completed

    return decorate


def productive_settlement_operation(function):
    """Observe an actual successful terminal maintenance/tick, not an idle poll."""

    @wraps(function)
    async def completed(self, *args, **kwargs):
        result = await function(self, *args, **kwargs)
        with suppress(Exception):
            terminal = getattr(self, "terminal_certification_sha256", None)
            tip = getattr(
                self,
                "published_tip" if self.config.role == "coordinator" else "reviewed_terminal_tip",
                None,
            )
            package = getattr(self, "package_reference", None)
            if result not in {"package_published", "reviewing"} or not all(
                (terminal, tip, package)
            ):
                return result
            inputs = dict(
                cohort_sha256=self.cohort,
                input_package_sha256=package[1],
                certification_sha256=terminal,
                history_tip_sha256=tip,
            )
            reward = getattr(self, "reward_package_reference", None)
            outcome = dict(
                schema="umi-settlement-operation-result/1",
                status=result,
                role=self.config.role,
                **inputs,
                reward_package_sha256=None if reward is None else reward[1],
                reviewed_requests=[
                    dict(phase=phase, kind=kind, request_sha256=sha)
                    for (phase, kind), sha in sorted(self.completed_requests.items())
                ],
            )
            # One current-process event for an unchanged successful native result
            # is sufficient. Failed/missing telemetry remains retryable.
            identity = canonical_json_bytes(outcome)
            if getattr(
                self, "_productive_completion", None
            ) != identity and productive_operation_completed(
                "settlement_" + function.__name__, inputs=inputs, result=outcome
            ):
                self._productive_completion = identity
        return result

    return completed
