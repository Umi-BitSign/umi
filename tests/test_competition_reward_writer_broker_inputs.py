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
from umi.competition_reward_writer_resources import select_writer_resources
from umi.competition_reward_writer_review import select_stopped_writer_boot
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
    assert worker.launch == c.args.launch
    assert worker.launch_sha256 == hashlib.sha256(c.args.launch.read_bytes()).hexdigest()
    assert worker.preparation_approval == c.path
    assert worker.preparation_approval_sha256 == hashlib.sha256(c.path.read_bytes()).hexdigest()
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
        "--launch",
        "/launch",
        "--launch-sha256",
        "aa" * 32,
        "--preparation-approval",
        "/preparation-approval",
        "--preparation-approval-sha256",
        "bb" * 32,
    ]
    for extra in (["--reward-adoptions", "/adoption"], ["--reward-adoptions-sha256", "aa" * 32]):
        with pytest.raises(SystemExit):
            arguments(base + extra)


def test_explicit_source_preservation_reaches_native_child(launch_case):
    c = launch_case
    command, _, _ = writer_broker_command(c.anchor, c.args, 17)
    assert not arguments(command[command.index("--unit") :]).preserve_unverified_original
    c.args.preserve_unverified_original = True
    command, _, _ = writer_broker_command(c.anchor, c.args, 17)
    assert arguments(command[command.index("--unit") :]).preserve_unverified_original


def test_artifact_locations_propagate_but_original_finality_state_never_moves(launch_case):
    c = launch_case
    launch = runtime.HistoryPreparationLaunch.model_validate_json(c.args.launch.read_bytes())
    resources = launch.resources.model_copy(
        update={
            "finality_binary": "/physical/finality",
            "proof_binary": "/physical/proof",
            "chain_spec": "/physical/spec.json",
            "state_directory": str(runtime.WORK / "finality"),
        }
    )
    c.save(c.args.launch, canonical_json_bytes(launch.model_copy(update={"resources": resources})))
    command, _, controls = writer_broker_command(c.anchor, c.args, 17)
    worker = arguments(command[command.index("--unit") :])
    before = c.boot.read_bytes(), c.path.read_bytes(), c.held.read_bytes()
    selected = select_stopped_writer_boot(c.anchor, c.boot, held_approval=c.held)
    native = select_writer_resources(
        c.anchor,
        selected,
        worker.history,
        launch_path=worker.launch,
        preparation_approval=worker.preparation_approval,
        expected_launch_sha256=worker.launch_sha256,
        expected_approval_sha256=worker.preparation_approval_sha256,
        through_block=worker.through_block,
    )
    assert native.resources.state_directory == c.config.chain.state_directory
    assert native.resources.state_directory != resources.state_directory
    assert native.resources.proof_binary == "/physical/proof"
    assert native.resources.finality_binary == "/physical/finality"
    assert native.resources.chain_spec == "/physical/spec.json"
    assert native.controls == controls[:2]
    native.recheck()
    assert before == (c.boot.read_bytes(), c.path.read_bytes(), c.held.read_bytes())


@pytest.mark.parametrize("changed", ["launch", "approval", "wrong_hash", "scope", "mode"])
def test_child_reauthenticates_resource_controls_and_rechecks_later(launch_case, changed):
    c = launch_case
    command, _, _ = writer_broker_command(c.anchor, c.args, 17)
    worker = arguments(command[command.index("--unit") :])
    selected = select_stopped_writer_boot(c.anchor, c.boot, held_approval=c.held)
    kwargs = dict(
        launch_path=worker.launch,
        preparation_approval=worker.preparation_approval,
        expected_launch_sha256=worker.launch_sha256,
        expected_approval_sha256=worker.preparation_approval_sha256,
        through_block=worker.through_block,
    )
    native = select_writer_resources(c.anchor, selected, worker.history, **kwargs)
    if changed == "launch":
        c.save(worker.launch, worker.launch.read_bytes() + b"\n")
    elif changed == "approval":
        c.save(worker.preparation_approval, worker.preparation_approval.read_bytes() + b"\n")
    elif changed == "wrong_hash":
        kwargs["expected_launch_sha256"] = "00" * 32
    elif changed == "scope":
        kwargs["through_block"] = 200
    else:
        launch = runtime.HistoryPreparationLaunch.model_validate_json(worker.launch.read_bytes())
        resources = launch.resources.model_copy(update={"runtime_metadata_binary": "/extra"})
        c.save(
            worker.launch, canonical_json_bytes(launch.model_copy(update={"resources": resources}))
        )
        kwargs["expected_launch_sha256"] = hashlib.sha256(worker.launch.read_bytes()).hexdigest()
    with pytest.raises(ValueError):
        select_writer_resources(c.anchor, selected, worker.history, **kwargs)
    if changed in {"launch", "approval", "mode"}:
        with pytest.raises(ValueError, match="resource controls changed"):
            native.recheck()


def test_legacy_writer_resource_selection_keeps_original_paths(launch_case):
    c = launch_case
    selected = select_stopped_writer_boot(c.anchor, c.boot, held_approval=c.held)
    native = select_writer_resources(c.anchor, selected, "current")
    assert native.resources == CompetitionChainResources.from_config(c.config.chain)
    assert not native.controls
    with pytest.raises(ValueError, match="both launch"):
        select_writer_resources(c.anchor, selected, "current", launch_path=c.args.launch)


@pytest.mark.parametrize("mode", ["exchange", "readiness", "standalone"])
async def test_failed_artifact_preflight_precedes_owners_journals_and_exchange(
    launch_case, monkeypatch, mode
):
    from umi import competition_reward_writer_exchange as exchange
    from umi import competition_reward_writer_review as review
    from umi.runtime_metadata import RuntimeMetadataError

    c = launch_case
    command, _, _ = writer_broker_command(c.anchor, c.args, 17)
    worker = arguments(command[command.index("--unit") :])
    worker.readiness_only = mode == "readiness"
    before = c.boot.read_bytes(), c.path.read_bytes(), c.held.read_bytes()
    checked = []

    async def bad_artifact(config, resources):
        checked.append(resources)
        assert resources.state_directory == c.config.chain.state_directory
        raise RuntimeMetadataError("binary_not_executable")

    def forbidden(*args, **kwargs):
        pytest.fail("resource failure reached original ownership or history mutation")

    for module in (exchange, review):
        monkeypatch.setattr(module, "preflight_chain_resources", bad_artifact)
        monkeypatch.setattr(module, "hold_successor_startup_lease", forbidden)
        monkeypatch.setattr(module, "HistoricalRewardControlProvider", forbidden)
        monkeypatch.setattr(module, "RewardControlHistoryReader", forbidden)
    with pytest.raises(RuntimeMetadataError, match="binary_not_executable"):
        if mode == "standalone":
            await review.review_installed_standing_writer(
                c.anchor,
                c.boot,
                unit=worker.unit,
                config_path=worker.config,
                through_block=worker.through_block,
                held_approval=c.held,
                resource_launch=worker.launch,
                preparation_approval=worker.preparation_approval,
            )
        else:
            await exchange.exchange_installed_standing_writer(
                c.anchor, worker, SimpleNamespace(send=forbidden, receive=forbidden)
            )
    assert len(checked) == 1
    assert before == (c.boot.read_bytes(), c.path.read_bytes(), c.held.read_bytes())
