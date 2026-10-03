"""Fixed boot configuration/lifecycle with substituted provider and service ports.

Canonical files, authority schemas, journals and named-key signing are native.
These assembly tests do not qualify an installed Linux service or chain effect.
"""

import asyncio
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_reward_coordinator_boot as boot
from umi import competition_reward_coordinator_cli as cli
from umi.competition_reward_decisions import StandingRewardSeries
from umi.competition_reward_handoff_models import StandingRewardHandoffPlan
from umi.open_competition import digest, verify_signature
from umi.private_files import PrivateStateBusyError, lock_private_file
from umi.protocol import canonical_json_bytes

from .test_competition_reward_boot import chain as chain
from .test_competition_reward_boot import chain_config as chain_config
from .test_competition_reward_boot import control as control
from .test_competition_reward_boot import direct_reward_config
from .test_competition_reward_boot import inputs as inputs
from .test_competition_reward_boot import policy as policy
from .test_competition_reward_boot import series_case as series_case
from .test_competition_reward_decisions import successor_series
from .test_open_competition import wallet


@pytest.fixture
def config_case(inputs, tmp_path):
    common = {k: getattr(inputs.value, k) for k in type(inputs.value).model_fields}
    keep = {k: common[k] for k in boot.RewardCoordinatorConfig.model_fields if k in common}
    keep.update(
        schema="umi-reward-coordinator-config/1",
        role="coordinator",
        signer_hotkey=wallet("Charlie").hotkey.ss58_address,
        proposer_hotkey=wallet("Charlie").hotkey.ss58_address,
        signer_key_file=str(tmp_path / "keys" / "Charlie"),
        control_key_file=str(tmp_path / "keys" / "Ferdie"),
        state_directory=str(tmp_path / "coordinator-state"),
        files_directory=str(tmp_path / "files"),
        readback_directory=str(tmp_path / "readback"),
        settlement_directory=str(tmp_path / "settlements"),
        exchange_inbox=str(tmp_path / "inbox"),
        exchange_outbox=str(tmp_path / "outbox"),
    )
    keep.pop("schema_", None)
    config = boot.RewardCoordinatorConfig(**keep)
    inputs.save(inputs.path, canonical_json_bytes(config))
    return SimpleNamespace(config=config, path=inputs.path, save=inputs.save, c=inputs.c)


def test_root_selection_and_cli_check_report_no_credentials(config_case, capsys):
    h = config_case
    assert boot.load_reward_coordinator_config(h.path) == h.config
    cli.main(["check", "--config", str(h.path)])
    report = json.loads(capsys.readouterr().out)
    assert report == dict(
        status="configuration_valid",
        role="coordinator",
        series_sha256=digest(h.config.series),
        config_sha256=digest(h.config),
        runtime_qualified=False,
    )
    h.save(h.path, b" " + canonical_json_bytes(h.config))
    with pytest.raises(ValueError, match="canonical"):
        boot.load_reward_coordinator_config(h.path)


def test_direct_series_requires_read_only_coordinator_source(config_case, tmp_path):
    direct = direct_reward_config(config_case.config, tmp_path, "umi-reward-coordinator-config/2")
    assert boot.RewardCoordinatorConfig.model_validate_json(canonical_json_bytes(direct)) == direct
    with pytest.raises(ValueError, match="approved role or authority"):
        boot.RewardCoordinatorConfig.model_validate_json(
            canonical_json_bytes(direct.model_copy(update={"direct_model_review": None}))
        )


def test_successor_configuration_binds_complete_predecessor_context(config_case):
    old = config_case.config
    successor = successor_series(old.series)
    manifest = old.manifest.model_copy(
        update={
            "cohorts": tuple(
                requirement.model_copy(update={"cohort_sha256": digest(plan)})
                for requirement, plan in zip(
                    old.manifest.cohorts, successor.cohorts, strict=False
                )
            )
        }
    )
    successor = StandingRewardSeries.model_validate_json(
        canonical_json_bytes(
            successor.model_copy(update={"manifest_sha256": digest(manifest)})
        )
    )
    handoff = StandingRewardHandoffPlan(
        schema="umi-standing-reward-handoff-plan/1",
        series_sha256=digest(successor),
        cohort_sha256=digest(successor.cohorts[0]),
        predecessor=successor.predecessor,
    )
    candidate = old.model_copy(
        update={
            "schema_": "umi-reward-coordinator-config/3",
            "series": successor,
            "manifest": manifest,
            "handoff": handoff,
            "predecessor_series": old.series,
            "predecessor_manifest": old.manifest,
            "predecessor_eligibility": old.eligibility,
        }
    )
    checked = boot.RewardCoordinatorConfig.model_validate_json(
        canonical_json_bytes(candidate)
    )
    assert checked == candidate
    assert b'"predecessor_series"' not in canonical_json_bytes(old)
    for change in (
        {"predecessor_series": None},
        {
            "predecessor_manifest": old.manifest.model_copy(
                update={"policy_sha256": "ff" * 32}
            )
        },
        {"schema_": "umi-reward-coordinator-config/1"},
    ):
        with pytest.raises(ValueError):
            boot.RewardCoordinatorConfig.model_validate_json(
                canonical_json_bytes(candidate.model_copy(update=change))
            )


@pytest.mark.parametrize(
    "change",
    [
        {"role": "reviewer"},
        {"control_key_file": None},
        {"signer_hotkey": wallet("Alice").hotkey.ss58_address},
        {"proposer_hotkey": wallet("Dave").hotkey.ss58_address},
        {"manifest": None},
    ],
)
def test_role_and_authority_changes_are_rejected_before_loading_keys(config_case, change):
    with pytest.raises(ValueError):
        boot.RewardCoordinatorConfig.model_validate(
            config_case.config.model_dump(by_alias=True) | change
        )


def test_wallet_and_replication_stores_cannot_overlap(config_case):
    config = config_case.config
    for change in (
        {"readback_directory": config.files_directory},
        {"exchange_outbox": config.exchange_inbox + "/nested"},
        {"signer_key_file": config.files_directory + "/private-key"},
    ):
        with pytest.raises(ValueError):
            boot.RewardCoordinatorConfig.model_validate(config.model_dump(by_alias=True) | change)


@pytest.mark.parametrize(
    "role,failure",
    [
        (role, failure)
        for role in ("coordinator", "reviewer")
        for failure in (None, "key", "start", "run")
    ]
    + [("coordinator", "coverage"), ("coordinator", "coverage_exit")],
)
async def test_boot_loads_only_role_keys_and_closes_provider_on_every_exit(
    config_case, monkeypatch, role, failure
):
    h = config_case
    config = h.config
    if role == "reviewer":
        config = boot.RewardCoordinatorConfig.model_validate(
            config.model_dump(by_alias=True)
            | dict(
                role=role,
                signer_hotkey=wallet("Dave").hotkey.ss58_address,
                signer_key_file=str(Path(config.signer_key_file).with_name("Dave")),
                control_key_file=None,
                readback_directory=None,
                settlement_directory=None,
            )
        )
    providers, loaded, collector_lifecycle = [], [], []

    class Provider:
        def __init__(self, chain, policy, **kwargs):
            self.config, self.policy = chain, policy
            self.started, self.closed = False, False
            providers.append(self)

        async def start(self):
            if failure == "start":
                raise OSError("start failure")
            self.started = True

        async def aclose(self):
            if collector_lifecycle:
                assert collector_lifecycle[-1] == "stopped"
            self.closed = True

    def key(path, expected):
        loaded.append(path.name)
        if failure == "key":
            raise OSError("key failure")
        value = wallet(path.name).hotkey
        assert value.ss58_address == expected
        return value

    monkeypatch.setattr(boot, "HistoricalRewardControlProvider", Provider)
    monkeypatch.setattr(boot, "StandingRewardDecisionReviewer", lambda **kw: SimpleNamespace(**kw))
    monkeypatch.setattr(boot, "load_named_hotkey", key)
    monkeypatch.setattr(boot, "StandingControlPublisher", lambda **kw: SimpleNamespace(**kw))

    async def running(signer, provider):
        assert provider.started
        # Exercise the actual named-key signing callback, independent of the
        # substituted outer service. It cannot open another wallet or coldkey.
        body = h.c.genesis.decision.model_copy(update={"series_sha256": digest(config.series)})
        signature = await signer.sign(body)
        verify_signature(body, signature)
        assert signature.hotkey == config.signer_hotkey
        if failure == "run":
            raise OSError("run failure")

    class Coordinator:
        def __init__(self, **kw):
            self.kw = kw

        async def run(self, stop, *, poll_seconds):
            assert self.kw["publisher"].provider is self.kw["reviewer"].provider
            with pytest.raises(PrivateStateBusyError):
                lock_private_file(Path(config.state_directory) / "control-writer.lock")
            await running(self.kw["signer"], self.kw["reviewer"].provider)
            if failure in {"coverage", "coverage_exit"}:
                await asyncio.Event().wait()
            stop.set()

    async def collect(self, stop, *, poll_seconds):
        collector_lifecycle.append("started")
        try:
            if failure == "coverage":
                raise OSError("coverage failure")
            if failure == "coverage_exit":
                return
            await stop.wait()
        finally:
            collector_lifecycle.append("stopped")

    async def reviewer(self, owner, stop, *, poll_seconds):
        await running(self.signer, owner.provider)

    monkeypatch.setattr(boot, "StandingRewardCoordinator", Coordinator)
    monkeypatch.setattr(boot.StandingRewardCoverageService, "run", collect)
    monkeypatch.setattr(boot.RewardReviewExchange, "run_reviewer", reviewer)
    if failure:
        with pytest.raises(RuntimeError if failure == "coverage_exit" else OSError):
            await boot.run_reward_coordinator(config, asyncio.Event())
    else:
        await boot.run_reward_coordinator(config, asyncio.Event())
    assert providers and all(p.closed for p in providers)
    assert (
        loaded == (["Charlie"] if failure == "key" else ["Charlie", "Ferdie"])
        if role == "coordinator"
        else loaded == ["Dave"]
    )
    import os

    descriptor = lock_private_file(
        Path(config.state_directory) / digest(config.series) / "service.lock"
    )
    os.close(descriptor)
    if role == "coordinator":
        descriptor = lock_private_file(Path(config.state_directory) / "control-writer.lock")
        os.close(descriptor)


def test_cli_failure_omits_exception_values(monkeypatch, capsys):
    def fail(_):
        raise ValueError("https://private.invalid/?token=not-for-output")

    monkeypatch.setattr(cli, "load_reward_coordinator_config", fail)
    with pytest.raises(SystemExit) as error:
        cli.main(["check", "--config", "/not-a-config"])
    assert error.value.code == 1
    assert json.loads(capsys.readouterr().out) == dict(status="failed", error_type="ValueError")


def test_real_module_entrypoint_keeps_configuration_check_separate_from_run():
    result = subprocess.run(
        [sys.executable, "-B", "-m", "umi.competition_reward_coordinator_cli", "--help"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0 and "{check,run}" in result.stdout and "--config" in result.stdout
