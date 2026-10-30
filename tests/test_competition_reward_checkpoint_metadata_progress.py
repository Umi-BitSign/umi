"""Metadata stage estimates neither claim native work nor hide unfinished checks."""

import logging
from types import SimpleNamespace

import pytest

from umi import competition_reward_admission_runner as admission_runner
from umi import competition_reward_checkpoint_progress as module
from umi import competition_reward_coordinator_cli as coordinator_cli
from umi import competition_reward_cutover_cli as cutover_cli
from umi import competition_supervisor_cli as supervisor_cli
from umi.competition_reward_checkpoint_progress import CheckpointMetadataProgress

from .logging_helpers import progress_payloads


def observations(caplog):
    return progress_payloads(
        caplog.records, logger=module.__name__, event="reward_history_checkpoint_metadata_progress"
    )


@pytest.mark.parametrize(
    "log_context",
    [
        coordinator_cli._logs,
        supervisor_cli._standing_logs,
        admission_runner._logs,
        cutover_cli._logs,
    ],
)
def test_owner_entrypoints_emit_metadata_progress(log_context, capsys):
    with (
        log_context(),
        CheckpointMetadataProgress("checkpoint_metadata_loading", 1000, 1099) as progress,
    ):
        progress.checked()
    output = capsys.readouterr().err
    assert output.count("reward_history_checkpoint_metadata_progress") == 2
    assert "'completed_block_checks': 1" in output
    assert "'eta_scope': 'current_bounded_metadata_batch_only'" in output
    assert "'native_verification_or_application_credit': False" in output


def test_counted_metadata_eta_has_explicit_batch_scope_and_no_native_credit(
    caplog, monkeypatch, http_log_redaction
):
    clock = [100.0]
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    caplog.set_level(logging.INFO, logger=module.__name__)
    with CheckpointMetadataProgress("checkpoint_metadata_loading", 1000, 1099) as progress:
        clock[0] += 5
        for _ in range(49):
            progress.checked()
        clock[0] += 5
        progress.checked()
        middle = observations(caplog)[-1]
        assert middle["completed_block_checks"] == 50
        assert middle["total_block_checks"] == 100
        assert middle["elapsed_seconds"] == middle["eta_seconds"] == 10
        assert middle["eta_scope"] == "current_bounded_metadata_batch_only"
        assert middle["native_verification_or_application_credit"] is False
        for _ in range(50):
            progress.checked()
    assert observations(caplog)[-1]["eta_seconds"] == 0
    assert observations(caplog)[-1]["completed_block_checks"] == 100


def test_missing_new_checkpoint_finishes_lookup_without_claiming_the_requested_range(
    caplog, http_log_redaction
):
    caplog.set_level(logging.INFO, logger=module.__name__)
    with CheckpointMetadataProgress("checkpoint_metadata_loading", 1000, 1099) as progress:
        progress.checked()
        progress.checked(retained=False)
    last = observations(caplog)[-1]
    assert last["requested_block_checks"] == 100
    assert last["total_block_checks"] == last["completed_block_checks"] == 2
    assert last["retained_results"] == 1
    assert last["native_verification_or_application_credit"] is False


def test_failed_check_withdraws_eta_and_preserves_its_unfinished_work(caplog, http_log_redaction):
    caplog.set_level(logging.INFO, logger=module.__name__)
    with (
        pytest.raises(ValueError, match="repair required"),
        CheckpointMetadataProgress("checkpoint_metadata_recheck", 1000, 1099) as progress,
    ):
        progress.checked()
        raise ValueError("repair required")
    last = observations(caplog)[-1]
    assert last["state"] == "repair_required"
    assert last["completed_block_checks"] == 1 and last["total_block_checks"] == 100
    assert last["eta_seconds"] is None and last["planning_eta_seconds"] is None
    assert last["eta_basis"] == "withdrawn_failed_metadata_check"
    assert last["retrying"] is False
