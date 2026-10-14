"""Native root-selected launch controls and exact original preparation binding."""

import hashlib
import os
from types import SimpleNamespace

import pytest

from umi import competition_reward_history_preparation as preparation
from umi import competition_reward_history_preparation_runtime as runtime
from umi.competition_chain_resources import CompetitionChainResources
from umi.competition_reward_host import StandingRewardHostApproval
from umi.competition_reward_writer_broker import writer_broker_command
from umi.competition_reward_writer_broker_worker import arguments
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_reward_writer_adoption import (  # noqa: F401
    activation_case,
    adopted,
    anchor_case,
    boot_inputs,
    chain,
    chain_config,
    control,
    explicit,
    installed_case,
    limits,
    package_case,
    package_limits,
    policy,
    prepared,
    release_identity,
    replay_limits,
    series_case,
    staging_case,
    successor_release,
    trusted_ports,
    worker_capacity,
)


@pytest.fixture
def launch_case(adopted, monkeypatch, tmp_path):  # noqa: F811
    c = adopted
    # Use the existing isolated filesystem ownership port, while retaining real
    # native anchors, quorum signatures, original approvals and source hashing.
    monkeypatch.setattr(runtime, "_root_owner_uid", os.getuid)
    approval = StandingRewardHostApproval(
        schema="umi-standing-reward-host-approval/1",
        source_config_sha256=digest(c.anchor.config),
        installation_receipt_sha256=c.anchor.receipt_sha256,
        host_manifest_sha256=c.anchor.receipt.host_manifest_sha256,
        validator_hotkey=c.anchor.config.validator_hotkey,
        series_sha256=digest(c.config.series),
        policy_sha256=digest(c.config.policy),
        manifest_sha256=digest(c.config.manifest),
        chain_config_sha256=digest(c.config.chain),
        legacy_handoff_plan_sha256=digest(c.config.handoff),
    )
    c.save(c.held, canonical_json_bytes(approval))
    source, python_root = tmp_path / "source", tmp_path / "runtime"
    (source / "src/umi").mkdir(parents=True, mode=0o700)
    (source / "src/umi/fixture.py").write_text("# sealed synthetic worker source\n")
    for entry in (source, source / "src", source / "src/umi"):
        entry.chmod(0o700)
    (source / "src/umi/fixture.py").chmod(0o644)
    python_root.mkdir(mode=0o700)
    launch = runtime.HistoryPreparationLaunch(
        schema="umi-history-preparation-launch/1",
        preparation_approval_sha256=digest(c.approval),
        source_root=str(source),
        source_tree_sha256=runtime.preparation_source_identity(source),
        python_root=str(python_root),
        resources=CompetitionChainResources.from_config(c.config.chain),
        input_archive=str(tmp_path / "input"),
        through_block=199,
    )
    path = tmp_path / "launch.json"
    c.save(path, canonical_json_bytes(launch))
    c.args = SimpleNamespace(
        standing_boot=c.boot,
        held_approval=c.held,
        preparation_approval=c.path,
        launch=path,
        history="current",
        unit="umi-fixture.service",
        config=c.anchor.source_root / "source-config.json",
        readiness_only=False,
        reward_adoptions=c.adoption_path,
    )
    return c


def test_broker_pins_supplemental_input_for_child_without_rebinding_preparation(launch_case):
    c = launch_case
    before = c.boot.read_bytes(), c.path.read_bytes(), c.held.read_bytes()
    command, approval, controls = writer_broker_command(c.anchor, c.args, 17)
    sha = hashlib.sha256(c.adoption_path.read_bytes()).hexdigest()
    assert command[-4:] == [
        "--reward-adoptions",
        str(c.adoption_path),
        "--reward-adoptions-sha256",
        sha,
    ]
    assert controls[-1] == preparation._control(c.adoption_path, 256 * 1024)[1]
    worker = arguments(command[command.index("--unit") :])
    assert worker.reward_adoptions == c.adoption_path
    assert worker.reward_adoptions_sha256 == sha
    assert worker.through_block == 199
    assert approval == c.approval
    assert before == (c.boot.read_bytes(), c.path.read_bytes(), c.held.read_bytes())
    c.args.reward_adoptions = None
    old_command, old_approval, old_controls = writer_broker_command(c.anchor, c.args, 18)
    assert "--reward-adoptions" not in old_command
    assert len(old_controls) == 2 and old_approval == approval


def test_replacing_prepared_boot_with_adopted_boot_still_refuses(launch_case):
    c = launch_case
    c.save(
        c.boot, canonical_json_bytes(c.config.model_copy(update={"reward_adoptions": c.adoptions}))
    )
    with pytest.raises(ValueError, match="original authenticated preparation"):
        writer_broker_command(c.anchor, c.args, 17)


def test_child_requires_root_digest_and_path_together():
    base = [
        "--unit",
        "fixture.service",
        "--config",
        "/config",
        "--standing-boot",
        "/boot",
        "--held-approval",
        "/held",
        "--history",
        "current",
        "--through-block",
        "1",
        "--socket-fd",
        "2",
        "--parent-pid",
        "3",
    ]
    for extra in (["--reward-adoptions", "/adoption"], ["--reward-adoptions-sha256", "aa" * 32]):
        with pytest.raises(SystemExit):
            arguments(base + extra)
