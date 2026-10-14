"""Operator entry point uses the original private paths and explicit repair."""

import json

import pytest

from umi import competition_verification_snapshot_cli as cli
from umi.competition_cohort_aggregate_files import publish_aggregate_model
from umi.competition_cohort_reward_package import RewardPackageObject
from umi.open_competition import digest

from .test_competition_verification_snapshot import Package


def test_prepare_check_and_explicit_repair_resume_without_source_changes(
    tmp_path, monkeypatch, capsys
):
    from umi import competition_verification_snapshot as snapshot_module

    monkeypatch.setattr(cli, "CohortRewardPackage", Package)
    value = {"payload": "retained"}
    package = Package(
        name="operator-input", objects=(RewardPackageObject(sha256=digest(value), value=value),)
    )
    source, store = tmp_path / "source.json", tmp_path / "verification"
    publish_aggregate_model(source, package, maximum_bytes=1024**2)
    args = [
        "--store",
        str(store),
        "--source",
        str(source),
        "--kind",
        "reward",
        "--maximum-bytes",
        str(1024**2),
        "--package-sha256",
        digest(package),
    ]
    with pytest.raises(SystemExit):
        cli.main(["check", *args])
    assert json.loads(capsys.readouterr().out)["status"] == "preparation_required"
    cli.main(["prepare", *args])
    assert json.loads(capsys.readouterr().out)["status"] == "ready"
    original = source.stat()

    def no_import(*args, **kwargs):
        pytest.fail("warm or damaged completion silently reimported source")

    with monkeypatch.context() as warm:
        warm.setattr(snapshot_module, "read_aggregate_model", no_import)
        for action in ("check", "prepare"):
            cli.main([action, *args])
            assert json.loads(capsys.readouterr().out)["status"] == "ready"
        record = next(
            path
            for path in store.glob("*.json")
            if json.loads(path.read_bytes()).get("schema") == "umi-private-verification-snapshot/1"
        )
        record.unlink()
        for action in ("check", "prepare"):
            with pytest.raises(SystemExit):
                cli.main([action, *args])
            assert json.loads(capsys.readouterr().out)["status"] == "repair_required"
    cli.main(["repair", *args, "--reason", "restore deleted snapshot metadata"])
    assert json.loads(capsys.readouterr().out)["status"] == "ready"
    assert source.stat() == original
    cli.main(["check", *args])
    assert json.loads(capsys.readouterr().out)["status"] == "ready"


@pytest.mark.parametrize("action,reason", [("repair", None), ("repair", " "), ("check", "repair")])
def test_repair_requires_explicit_reason_only_for_repair(tmp_path, action, reason):
    args = [
        action,
        "--store",
        str(tmp_path / "store"),
        "--source",
        str(tmp_path / "source"),
        "--kind",
        "reward",
        "--maximum-bytes",
        "1024",
        "--package-sha256",
        "ab" * 32,
    ]
    if reason is not None:
        args += ["--reason", reason]
    with pytest.raises(SystemExit) as failure:
        cli.main(args)
    assert failure.value.code == 2
    assert not (tmp_path / "store").exists()
