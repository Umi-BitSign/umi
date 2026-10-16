import asyncio
import json
import logging

import pytest

from umi import competition_progress as progress


@pytest.fixture
def progress_events(monkeypatch):
    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(json.loads(record.getMessage()))

    logger = logging.Logger("isolated-progress", level=logging.INFO)
    logger.addHandler(Capture())
    monkeypatch.setattr(progress, "_LOG", logger)
    return records


def test_nested_phases_preserve_result_and_do_not_log_arguments(progress_events):
    secret = "https://origin/v1/clips/bearer-capability/private.mp4"

    @progress.log_phase("package_verification")
    def inner(value):
        return value

    @progress.log_phase("artifact_staging")
    def outer(value):
        return inner(value)

    assert outer(secret) is secret
    assert [e["event"] for e in progress_events] == ["started", "started", "completed", "completed"]
    assert progress_events[1]["parent_phase_id"] == progress_events[0]["phase_id"]
    assert progress_events[2]["phase_id"] == progress_events[1]["phase_id"]
    assert progress_events[0]["parent_phase_id"] is None
    assert progress_events[3]["elapsed_ms"] >= 0
    assert secret not in json.dumps(progress_events)
    assert progress._PARENT.get() is None


def test_container_failure_classifies_without_untrusted_output(progress_events):
    progress.report_container_command_failure(
        "create",
        125,
        b"Error: statfs /run/umi-successor-activation: no such file or directory\n"
        b"GET https://origin/v1/clips/private-capability/video.mp4?token=secret\n"
        b"/v1/clips/another-capability/video.mp4",
    )
    event = progress_events[-1]
    assert event["event"] == "container_command_failed"
    assert event["command"] == "create" and event["returncode"] == 125
    assert event["reason_codes"] == ["path_missing"]
    assert "stderr" not in event
    assert "capability" not in json.dumps(event) and "secret" not in json.dumps(event)
    assert "https://origin" not in json.dumps(event)


def test_rate_limit_is_an_expected_wait_with_next_eligible_block(progress_events):
    from umi.competition_weight_timing import WeightRateLimitWait

    wait = WeightRateLimitWait(170, 179)
    with pytest.raises(WeightRateLimitWait) as raised, progress.progress_phase("worker_start"):
        raise wait
    assert raised.value is wait
    event = progress_events[-1]
    assert event["event"] == "waiting"
    assert event["reason_code"] == "weights_rate_limited"
    assert event["observed_block"] == 170 and event["next_eligible_block"] == 179
    assert "causes" not in event and progress._PARENT.get() is None


def test_container_failure_does_not_log_unknown_command_arguments(progress_events):
    progress.report_container_command_failure(
        "secret-value", 125, b"x" * 32768, observed_bytes=32768
    )
    assert progress_events[-1]["command"] == "unknown"
    assert progress_events[-1]["classified_bytes"] == 16384
    assert progress_events[-1]["truncated"] is True
    assert progress_events[-1]["reason_codes"] == ["unclassified_runtime_error"]


@pytest.mark.parametrize(
    "error,reason",
    [
        (
            ValueError("successor activation headroom is insufficient"),
            "activation_headroom_insufficient",
        ),
        (
            ValueError("weight observation was not issued by the owned proof adapter"),
            "owned_proof_rejected",
        ),
        (
            ValueError("materializer activation permit or interval is unavailable"),
            "activation_unavailable",
        ),
        (
            ValueError("materializer finalized observation rolled back or forked"),
            "finality_rollback_or_fork",
        ),
        (ValueError("private hypothesis and capability URL"), "validation_failed"),
        (TimeoutError("secret endpoint"), "timeout"),
        (PermissionError("private wallet path"), "permission_denied"),
        (RuntimeError("private response"), "internal_error"),
        (OSError("private filename"), "os_error"),
        (SystemExit("private process state"), "process_exit"),
    ],
)
def test_failures_keep_exact_exception_without_message_or_traceback(progress_events, error, reason):
    @progress.log_phase("preflight")
    def operation():
        raise error

    with pytest.raises(type(error)) as raised:
        operation()
    assert raised.value is error
    assert progress_events[-1]["reason_code"] == reason
    assert progress_events[-1]["event"] == "failed"
    assert str(error) not in json.dumps(progress_events)
    assert "traceback" not in json.dumps(progress_events)
    assert progress._PARENT.get() is None


@pytest.mark.asyncio
async def test_cancellation_is_logged_then_propagated(progress_events):
    entered = asyncio.Event()

    @progress.log_phase("chain_observation")
    async def operation():
        entered.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(operation())
    await entered.wait()
    assert len(progress_events) == 1 and progress_events[0]["event"] == "started"
    task.cancel("private cancellation reason")
    with pytest.raises(asyncio.CancelledError):
        await task
    assert progress_events[-1]["reason_code"] == "cancelled"
    assert "private cancellation" not in json.dumps(progress_events)
    assert progress._PARENT.get() is None


@pytest.mark.asyncio
async def test_concurrent_tasks_keep_independent_phase_parents(progress_events):
    ready = asyncio.Event()

    @progress.log_phase("reconcile")
    async def operation():
        ready.set()
        await asyncio.sleep(0)
        with progress.progress_phase("chain_observation"):
            return 42

    first = asyncio.create_task(operation())
    await ready.wait()
    second = asyncio.create_task(operation())
    assert await asyncio.gather(first, second) == [42, 42]
    roots = [e for e in progress_events if e["phase"] == "reconcile" and e["event"] == "started"]
    assert len(roots) == 2 and all(e["parent_phase_id"] is None for e in roots)
    children = [
        e for e in progress_events if e["phase"] == "chain_observation" and e["event"] == "started"
    ]
    assert {e["parent_phase_id"] for e in children} == {e["phase_id"] for e in roots}


def test_broken_logging_cannot_replace_success_or_original_failure(monkeypatch, progress_events):
    def broken(*args, **kwargs):
        raise OSError("diagnostic sink failed")

    monkeypatch.setattr(progress._LOG, "log", broken)
    with progress.progress_phase("preflight"):
        pass
    error = ValueError("original failure")
    with pytest.raises(ValueError) as raised, progress.progress_phase("preflight"):
        raise error
    assert raised.value is error
    assert progress._PARENT.get() is None


def test_logger_setup_is_idempotent_and_does_not_enable_http_logging(monkeypatch, capsys):
    logger = logging.Logger("isolated-progress")
    monkeypatch.setattr(progress, "_LOG", logger)
    http_level = logging.getLogger("httpx").level
    root_handlers = list(logging.getLogger().handlers)
    progress.configure_progress_logging()
    progress.configure_progress_logging()
    assert len(logger.handlers) == 1 and not logger.propagate
    assert logging.getLogger("httpx").level == http_level
    assert logging.getLogger().handlers == root_handlers
    with progress.progress_phase("preflight"):
        pass
    captured = capsys.readouterr()
    assert captured.out == ""
    assert len([json.loads(line) for line in captured.err.splitlines()]) == 2


def test_unrecognized_phase_cannot_be_used_to_log_arbitrary_text(progress_events):
    with pytest.raises(ValueError, match="unknown competition diagnostic phase"):
        progress.log_phase("secret capability")
    assert progress_events == []


def test_native_reason_and_chained_cause_survive_generic_phase_error(progress_events):
    from umi.grandpa_finality_supervisor import GrandpaFinalitySupervisorError
    from umi.validator_chain import ValidatorChainError

    with pytest.raises(ValidatorChainError), progress.progress_phase("chain_observation"):
        try:
            raise GrandpaFinalitySupervisorError("no_verified_finalized_head")
        except GrandpaFinalitySupervisorError as error:
            raise ValidatorChainError("owned_finality_unavailable") from error
    failure = progress_events[-1]
    assert failure["reason_code"] == "owned_finality_unavailable"
    assert [c["reason_code"] for c in failure["causes"]] == [
        "owned_finality_unavailable",
        "no_verified_finalized_head",
    ]
    assert failure["causes"][0]["error_type"] == "umi.validator_chain.ValidatorChainError"


def test_admission_diagnostics_never_log_request_or_exception_text(progress_events):
    secret = "https://private.example/video?token=secret private reference"
    try:
        raise PermissionError(secret)
    except PermissionError as error:
        progress.report_admission_failure("model_delivery", "reserve", error)
    event = progress_events[-1]
    assert event["operation"] == "model_delivery" and event["stage"] == "reserve"
    assert event["causes"][0]["reason_code"] == "permission_denied"
    assert secret not in json.dumps(progress_events)
    progress.report_admission_failure(secret, secret, ValueError(secret))
    assert progress_events[-1]["operation"] == "unknown"
    assert progress_events[-1]["stage"] == "unknown"
    assert secret not in json.dumps(progress_events)


def test_settlement_retry_reports_bounded_causes_without_inputs(progress_events):
    secret = "https://private.example/capability/secret"
    try:
        try:
            raise PermissionError(secret)
        except PermissionError as cause:
            raise ValueError(secret) from cause
    except ValueError as error:
        progress.report_settlement_retry(
            cohort="a" * 64, role="coordinator", stage="maintenance", error=error
        )
    event = progress_events[-1]
    assert event["event"] == "settlement_retry"
    assert event["cohort_sha256"] == "a" * 64
    assert event["role"] == "coordinator" and event["stage"] == "maintenance"
    assert [cause["reason_code"] for cause in event["causes"]] == [
        "validation_failed",
        "permission_denied",
    ]
    assert event["state"] == "retrying" and event["eta_seconds"] is None
    assert secret not in json.dumps(event)
    progress.report_settlement_retry(
        cohort=secret, role=secret, stage=secret, error=OSError(secret)
    )
    assert progress_events[-1]["cohort_sha256"] is None
    assert progress_events[-1]["role"] == progress_events[-1]["stage"] == "unknown"
    assert secret not in json.dumps(progress_events)


async def test_settlement_retry_keeps_scheduler_status_and_releases_error_frames(
    progress_events, monkeypatch
):
    from types import SimpleNamespace

    from umi import competition_cohort_settlement_service as settlement

    failure = ValueError("private rejected payload")
    node = SimpleNamespace(cohort="b" * 64, config=SimpleNamespace(role="reviewer"))
    observations = []
    original = settlement.discard_error_frames

    def discard(error):
        observations.append((error is failure, len(progress_events)))
        original(error)

    monkeypatch.setattr(settlement, "discard_error_frames", discard)

    async def operation():
        raise failure

    assert await settlement.SettlementSeriesScheduler._attempt(node, operation, stage="tick") == (
        False,
        "retry:ValueError",
    )
    assert observations == [(True, 1)]
    assert failure.__traceback__ is None
    assert progress_events[-1]["cohort_sha256"] == node.cohort
    assert progress_events[-1]["stage"] == "tick"


async def test_settlement_failed_diagnostics_preserve_retry_and_cancellation(monkeypatch):
    from types import SimpleNamespace

    from umi.competition_cohort_settlement_service import SettlementSeriesScheduler

    class FailedSink:
        def log(self, *args, **kwargs):
            raise RuntimeError("sink unavailable")

    monkeypatch.setattr(progress, "_LOG", FailedSink())
    node = SimpleNamespace(cohort="c" * 64, config=SimpleNamespace(role="coordinator"))

    async def failed():
        raise OSError("private input")

    assert await SettlementSeriesScheduler._attempt(node, failed, stage="maintenance") == (
        False,
        "retry:OSError",
    )
    cancelled = asyncio.CancelledError()

    async def cancel():
        raise cancelled

    with pytest.raises(asyncio.CancelledError) as caught:
        await SettlementSeriesScheduler._attempt(node, cancel, stage="tick")
    assert caught.value is cancelled


async def test_standalone_settlement_emits_retry_before_clean_drain(progress_events):
    from types import SimpleNamespace

    from umi.competition_cohort_settlement_service import CohortSettlementService

    stopped = asyncio.Event()
    released = []
    node = object.__new__(CohortSettlementService)
    node.cohort = "d" * 64
    node.config = SimpleNamespace(role="coordinator", poll_seconds=0.001)
    node.last_report = None
    node.provider = SimpleNamespace(ensure_observer_running=lambda: None)
    node._release_active_inputs = lambda: released.append("inputs")
    node._release_memory = lambda: released.append("memory")

    async def tick():
        stopped.set()
        raise PermissionError("private journal path")

    node.tick = tick
    await node.run(stopped)
    assert node.last_report == "retry:PermissionError"
    assert released == ["inputs", "memory"]
    assert progress_events[-1]["event"] == "settlement_retry"
    assert progress_events[-1]["cohort_sha256"] == node.cohort
    assert progress_events[-1]["reason_code"] == "permission_denied"
    assert "private journal path" not in json.dumps(progress_events)
