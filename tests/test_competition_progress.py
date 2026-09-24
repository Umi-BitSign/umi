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
