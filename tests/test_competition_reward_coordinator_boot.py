"""Fixed boot configuration/lifecycle with substituted provider and service ports.

Canonical files, authority schemas, journals and named-key signing are native.
These assembly tests do not qualify an installed Linux service or chain effect.
"""

import asyncio
import json
import logging
import signal
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_reward_coordinator_boot as boot
from umi import competition_reward_coordinator_cli as cli
from umi.competition_reward_decisions import StandingRewardSeries
from umi.competition_reward_handoff_models import StandingRewardHandoffPlan
from umi.competition_reward_history_workers import HistoryVerificationProfile
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


@pytest.mark.parametrize(
    "name",
    [
        "umi.competition.progress",
        "umi.competition_reward_history_progress",
        "umi.competition_reward_history_checkpoint",
        "umi.competition_reward_history_repair",
        "umi.competition_reward_coverage_collector",
        "umi.historical_header_progress",
    ],
)
def test_reward_cli_emits_work_progress_once_and_restores_logging(capsys, name):
    logger = logging.getLogger(name)
    before = (logger.level, logger.propagate, tuple(logger.handlers))
    with cli._logs():
        logger.info("work_progress completed=1 total=2")
    assert capsys.readouterr().err.count("work_progress completed=1 total=2") == 1
    assert (logger.level, logger.propagate, tuple(logger.handlers)) == before


def test_proof_read_selection_preserves_existing_configuration_bytes(config_case):
    h = config_case
    original = canonical_json_bytes(h.config)
    assert b'"runtime_proof_reads"' not in original
    assert not boot.load_reward_coordinator_config(h.path).runtime_proof_reads
    selected = h.config.model_copy(update={"runtime_proof_reads": True})
    h.save(h.path, canonical_json_bytes(selected))
    assert boot.load_reward_coordinator_config(h.path).runtime_proof_reads
    assert (
        canonical_json_bytes(selected.model_copy(update={"runtime_proof_reads": False})) == original
    )
    with pytest.raises(ValueError):
        boot.RewardCoordinatorConfig.model_validate(
            h.config.model_dump(by_alias=True) | {"runtime_proof_reads": "true"}
        )


def test_forecast_budget_preserves_existing_configuration_bytes(config_case):
    h = config_case
    original = canonical_json_bytes(h.config)
    assert b'"forecast_accounting_bytes"' not in original
    selected = h.config.model_copy(update={"forecast_accounting_bytes": 64 * 1024**2})
    h.save(h.path, canonical_json_bytes(selected))
    assert boot.load_reward_coordinator_config(h.path).forecast_accounting_bytes == 64 * 1024**2
    assert (
        canonical_json_bytes(
            selected.model_copy(update={"forecast_accounting_bytes": 512 * 1024**2})
        )
        == original
    )


def test_coordinator_history_capacity_matches_native_history_envelope(config_case):
    original = config_case.config.model_dump(by_alias=True)
    for maximum in [1024, 16 * 1024**3 + 1, 64 * 1024**3, 512 * 1024**3]:
        selected = boot.RewardCoordinatorConfig.model_validate(
            original | {"maximum_history_bytes": maximum}
        )
        assert selected.maximum_history_bytes == maximum
    for maximum in [True, 1023, 512 * 1024**3 + 1]:
        with pytest.raises(ValueError):
            boot.RewardCoordinatorConfig.model_validate(
                original | {"maximum_history_bytes": maximum}
            )


def test_direct_series_requires_read_only_coordinator_source(config_case, tmp_path):
    direct = direct_reward_config(config_case.config, tmp_path, "umi-reward-coordinator-config/2")
    assert boot.RewardCoordinatorConfig.model_validate_json(canonical_json_bytes(direct)) == direct
    with pytest.raises(ValueError, match="approved role or authority"):
        boot.RewardCoordinatorConfig.model_validate_json(
            canonical_json_bytes(direct.model_copy(update={"direct_model_review": None}))
        )


def successor_configuration(old):
    successor = successor_series(old.series)
    manifest = old.manifest.model_copy(
        update={
            "cohorts": tuple(
                requirement.model_copy(update={"cohort_sha256": digest(plan)})
                for requirement, plan in zip(old.manifest.cohorts, successor.cohorts, strict=False)
            )
        }
    )
    successor = StandingRewardSeries.model_validate_json(
        canonical_json_bytes(successor.model_copy(update={"manifest_sha256": digest(manifest)}))
    )
    handoff = StandingRewardHandoffPlan(
        schema="umi-standing-reward-handoff-plan/1",
        series_sha256=digest(successor),
        cohort_sha256=digest(successor.cohorts[0]),
        predecessor=successor.predecessor,
    )
    return old.model_copy(
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


def test_successor_configuration_binds_complete_predecessor_context(config_case):
    old = config_case.config
    candidate = successor_configuration(old)
    checked = boot.RewardCoordinatorConfig.model_validate_json(canonical_json_bytes(candidate))
    assert checked == candidate
    assert b'"predecessor_series"' not in canonical_json_bytes(old)
    assert b'"forecast_accounting_bytes"' not in canonical_json_bytes(candidate)
    for change in (
        {"predecessor_series": None},
        {"predecessor_manifest": old.manifest.model_copy(update={"policy_sha256": "ff" * 32})},
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


@pytest.mark.parametrize("proof_reads", [False, True])
@pytest.mark.parametrize("successor", [False, True])
@pytest.mark.parametrize(
    "role,failure",
    [
        (role, failure)
        for role in ("coordinator", "reviewer")
        for failure in (None, "key", "start", "run", "coverage", "coverage_exit")
    ],
)
async def test_boot_loads_only_role_keys_and_closes_provider_on_every_exit(
    config_case, monkeypatch, role, failure, proof_reads, successor
):
    h = config_case
    config = (successor_configuration(h.config) if successor else h.config).model_copy(
        update={
            "runtime_proof_reads": proof_reads,
            "maximum_history_bytes": 512 * 1024**3
            if proof_reads
            else h.config.maximum_history_bytes,
        }
    )
    history_profile = (
        HistoryVerificationProfile(schema="umi-history-verification-profile/1")
        if proof_reads
        else None
    )
    config = config.model_copy(
        update={
            "service": config.service.model_copy(update={"history_verification": history_profile})
        }
    )
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
            assert kwargs["runtime_proof_reads"] is proof_reads
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
            selected_series = self.preparation.reader.series
            assert self.preparation.allocation_sink.__self__.root == Path(config.files_directory)
            predecessor = selected_series != config.series
            assert not predecessor or selected_series == config.predecessor_series
            assert self.journal.runtime_selection == boot.select_boot_runtime(
                config, predecessor=predecessor
            )
            assert self.history.journal.maximum_bytes == config.maximum_history_bytes
            assert self.history.verification_profile == history_profile
            assert self.history.shutdown_event is stop
            assert self.history.progress.forecast is not None
            assert self.history.progress.forecast.identity["series_sha256"] == digest(
                selected_series
            )
            assert self.history.progress.forecast.identity["role"] == role
            if config.proof_stores is not None:
                assert self.history.archive.remote.config == config.proof_stores.imported
                assert self.history.export_archive.remote.config == config.proof_stores.exported
                assert self.journal.remote_store is self.history.remote_store
            if failure == "coverage":
                raise OSError("coverage failure")
            if failure == "coverage_exit":
                return
            await stop.wait()
        finally:
            collector_lifecycle.append("stopped")

    async def reviewer(self, owner, stop, *, poll_seconds):
        await running(self.signer, owner.provider)
        if failure in {"coverage", "coverage_exit"}:
            await asyncio.Event().wait()
        stop.set()

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


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT])
async def test_cli_signal_drains_reader_before_removing_handlers(monkeypatch, signum):
    loop = asyncio.get_running_loop()
    handlers, events = {}, []
    config = object()

    def remove(value):
        assert events == ["reader-started", "reader-drained"]
        del handlers[value]

    async def run(selected, stop):
        assert selected is config
        events.append("reader-started")
        handlers[signum]()
        assert stop.is_set()
        try:
            await asyncio.Event().wait()
        finally:
            events.append("reader-drained")

    monkeypatch.setattr(
        loop, "add_signal_handler", lambda value, callback: handlers.update({value: callback})
    )
    monkeypatch.setattr(loop, "remove_signal_handler", remove)
    monkeypatch.setattr(cli, "run_reward_coordinator", run)
    await asyncio.wait_for(cli._run(config), 30)
    assert not handlers and events == ["reader-started", "reader-drained"]


def test_real_module_entrypoint_keeps_configuration_check_separate_from_run():
    result = subprocess.run(
        [sys.executable, "-B", "-m", "umi.competition_reward_coordinator_cli", "--help"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert (
        result.returncode == 0
        and "{check,run,repair-history,repair-credit}" in result.stdout
        and "--config" in result.stdout
        and "--through-block" in result.stdout
    )


@pytest.mark.parametrize("role", ["coordinator", "reviewer"])
@pytest.mark.parametrize(
    "legacy_read_through,source_release_batch_records", [(False, 0), (True, 0), (True, 1)]
)
async def test_r2_reward_owner_boot_retains_selection_on_restart(
    config_case, tmp_path, monkeypatch, role, legacy_read_through, source_release_batch_records
):
    from .test_competition_remote_proof_store import select_remote_proofs

    config_case.config, opened, _ = select_remote_proofs(
        config_case.config,
        tmp_path,
        monkeypatch,
        legacy_read_through=legacy_read_through,
        source_release_batch_records=source_release_batch_records,
    )
    for _ in range(2):
        await test_boot_loads_only_role_keys_and_closes_provider_on_every_exit(
            config_case, monkeypatch, role, None, True, successor=False
        )
    assert len(opened) == 4
    assert [s.config.source_release_batch_records for s in opened] == [
        0,
        source_release_batch_records,
        0,
        source_release_batch_records,
    ]


@pytest.mark.parametrize("extra", [[], ["--through-block", "0"]])
def test_credit_repair_validates_scope_before_loading_mutable_owner(monkeypatch, extra):
    def forbidden(_):
        pytest.fail("invalid repair must not load or open an owner")

    monkeypatch.setattr(cli, "load_reward_coordinator_config", forbidden)
    interval = "not-a-digest" if not extra else "a" * 64
    with pytest.raises(SystemExit) as error:
        cli.main(
            [
                "repair-credit",
                "--config",
                "/unused",
                "--interval",
                interval,
                "--reason",
                "restore original metadata",
                *extra,
            ]
        )
    assert error.value.code == 2


@pytest.mark.parametrize("kind", ["owner_busy", "repair_required"])
def test_credit_repair_cli_reports_owned_failure_without_secrets(monkeypatch, capsys, kind):
    from umi.competition_reward_coverage_credits import CoverageCreditRepairRequired

    monkeypatch.setattr(cli, "load_reward_coordinator_config", lambda _: object())

    async def repair(*args, **kwargs):
        if kind == "owner_busy":
            raise PrivateStateBusyError("repair-credit", "b" * 64, 11)
        raise CoverageCreditRepairRequired("private endpoint and credentials must not leak")

    monkeypatch.setattr(cli, "_run", repair)
    with pytest.raises(SystemExit) as error:
        cli.main(
            [
                "repair-credit",
                "--config",
                "/unused",
                "--interval",
                "a" * 64,
                "--reason",
                "original endpoint requalified",
            ]
        )
    assert error.value.code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == kind
    assert "private endpoint" not in str(report)


@pytest.mark.parametrize("history", ["current", "predecessor"])
async def test_credit_repair_boot_owns_original_state_without_signing_or_collecting(
    config_case, monkeypatch, history
):
    config = (
        config_case.config if history == "current" else successor_configuration(config_case.config)
    )
    events = []

    class Provider:
        def __init__(self, chain, policy, **kwargs):
            self.config, self.policy = chain, policy

        async def start(self):
            events.append("provider_started")

        async def aclose(self):
            events.append("provider_closed")

    async def repair(self, *, key, reason, stop):
        assert events == ["provider_started"]
        assert key == "a" * 64 and reason == "original endpoint restored"
        assert self.preparation.reader.series == (
            config.series if history == "current" else config.predecessor_series
        )
        with pytest.raises(PrivateStateBusyError), boot.owned_reward_state(config):
            pass
        events.append("repair")
        return {"status": "coverage_credit_repaired"}

    def forbidden(*args, **kwargs):
        pytest.fail("credit metadata repair must not load a key or start normal work")

    monkeypatch.setattr(boot, "HistoricalRewardControlProvider", Provider)
    monkeypatch.setattr(boot.StandingRewardCoverageService, "repair_credit", repair)
    for name in ("load_named_hotkey", "StandingControlPublisher", "StandingRewardCoordinator"):
        monkeypatch.setattr(boot, name, forbidden)
    result = await boot.run_reward_coordinator(
        config,
        asyncio.Event(),
        credit_repair=dict(key="a" * 64, reason="original endpoint restored", history=history),
    )
    assert result == {"status": "coverage_credit_repaired"}
    assert events == ["provider_started", "repair", "provider_closed"]
