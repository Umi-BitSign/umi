"""Transfer CLI refuses invalid work and reports status without private errors."""

import json
from types import SimpleNamespace

import pytest


def test_root_prepares_source_before_account_drop(monkeypatch, capsys):
    from umi import competition_reward_history_transfer_cli as cli

    events, source, anchor = [], object(), object()
    progress_reports = []
    progress_type = cli.TransferProgress
    progress_instances = []

    def synchronous_progress(*args, **kwargs):
        progress = progress_type(*args, report=progress_reports.append, **kwargs)
        progress_instances.append(progress)
        return progress

    monkeypatch.setattr(cli, "TransferProgress", synchronous_progress)
    monkeypatch.setattr(
        cli, "os", SimpleNamespace(getuid=lambda: 0, geteuid=lambda: 0, umask=lambda value: None)
    )

    def prepare(path):
        assert str(path) == "/source"
        events.append("prepared")
        return source

    def account(args):
        # Actual namespace setup refuses the heartbeat thread created by
        # TransferProgress.__enter__; this must still be synchronous here.
        assert len(progress_instances) == 1
        assert progress_instances[0].thread is None
        assert args.coordinator_config is source
        events.append("dropped")
        return anchor

    async def run(args, selected):
        assert args.coordinator_config is source and selected is anchor
        events.append("run")
        return {"status": "complete", "chain_submission_authorized": False}

    monkeypatch.setattr(cli, "prepare_history_transfer_source", prepare)
    monkeypatch.setattr(cli, "_installed_account", account)
    monkeypatch.setattr(cli, "_run", run)
    cli.main(
        [
            "--unit",
            "fixture.service",
            "--config",
            "/config",
            "--standing-boot",
            "/boot",
            "--coordinator-config",
            "/source",
            "--first-block",
            "10",
            "--through-block",
            "11",
        ]
    )
    assert events == ["prepared", "dropped", "run"]
    assert progress_reports[0]["status"] == "started"
    assert progress_reports[-1]["status"] == "completed"
    assert progress_reports[-1]["completed_units"] == progress_reports[-1]["total_units"] == 2
    assert progress_reports[-1]["eta_seconds"] == 0
    assert json.loads(capsys.readouterr().out)["status"] == "complete"


def test_cli_import_and_invalid_interval_refuse_before_account_selection(monkeypatch, capsys):
    from umi import competition_reward_history_transfer_cli as cli

    monkeypatch.setattr(cli, "_installed_account", lambda args: pytest.fail("account selected"))
    with pytest.raises(SystemExit) as stopped:
        cli.main(
            [
                "--unit",
                "fixture.service",
                "--config",
                "/config",
                "--standing-boot",
                "/boot",
                "--coordinator-config",
                "/source",
                "--first-block",
                "10",
                "--through-block",
                "9",
            ]
        )
    assert stopped.value.code == 2
    assert "positive interval" in capsys.readouterr().err


@pytest.mark.parametrize("status,exit_code", [("complete", None), ("interrupted", 130)])
def test_cli_reports_completion_or_interruption_without_submission(
    monkeypatch, capsys, status, exit_code
):
    from umi import competition_reward_history_transfer_cli as cli

    anchor = object()
    monkeypatch.setattr(cli, "_installed_account", lambda args: anchor)

    async def run(args, selected):
        assert selected is anchor
        return {"status": status, "chain_submission_authorized": False}

    monkeypatch.setattr(cli, "_run", run)
    args = [
        "--unit",
        "fixture.service",
        "--config",
        "/config",
        "--standing-boot",
        "/boot",
        "--coordinator-config",
        "/source",
        "--first-block",
        "10",
        "--through-block",
        "11",
    ]
    if exit_code is None:
        cli.main(args)
    else:
        with pytest.raises(SystemExit) as stopped:
            cli.main(args)
        assert stopped.value.code == exit_code
    report = json.loads(capsys.readouterr().out)
    assert report == {"status": status, "chain_submission_authorized": False}


def test_cli_redacts_exception_payload(monkeypatch, capsys):
    from umi import competition_reward_history_transfer_cli as cli

    def failure(args):
        raise ValueError("private fixture payload")

    monkeypatch.setattr(cli, "_installed_account", failure)
    with pytest.raises(SystemExit) as stopped:
        cli.main(
            [
                "--unit",
                "fixture.service",
                "--config",
                "/config",
                "--standing-boot",
                "/boot",
                "--coordinator-config",
                "/source",
                "--first-block",
                "10",
                "--through-block",
                "11",
            ]
        )
    assert stopped.value.code == 1
    output = capsys.readouterr()
    assert "private fixture payload" not in output.out + output.err
    assert json.loads(output.out) == {
        "status": "repair_required",
        "error_type": "ValueError",
        "chain_submission_authorized": False,
    }
