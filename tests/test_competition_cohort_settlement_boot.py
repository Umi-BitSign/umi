"""Root configuration and lifecycle checks; provider/node ports are substituted."""

import asyncio
import json
from pathlib import Path

import pytest

from umi import competition_cohort_settlement_boot as boot
from umi import competition_cohort_settlement_cli as cli
from umi.competition_cohort_direct_model_review import DirectModelReviewSourceConfig
from umi.competition_cohort_execution_journal import CohortExecutionConfig
from umi.competition_cohort_intake import CohortIntakeBinding
from umi.competition_cohort_model_static_review import StandingModelReviewPolicy
from umi.competition_cohort_recovery import (
    ModelDeliveryProfile,
    SignedCohortRecoveryAuthority,
)
from umi.competition_cohort_settlement_config import (
    SettlementServiceConfig,
    load_settlement_service_config,
)
from umi.open_competition import digest, identity, sign_object, verify_signature
from umi.private_files import lock_private_file
from umi.protocol import canonical_json_bytes

from .test_competition_reward_boot import chain as chain
from .test_competition_reward_boot import chain_config as chain_config
from .test_competition_reward_boot import control as control
from .test_competition_reward_boot import inputs as inputs
from .test_competition_reward_boot import policy as policy
from .test_competition_reward_boot import series_case as series_case
from .test_open_competition import wallet


@pytest.fixture
def selected(inputs, tmp_path):
    v = inputs.value
    who = wallet("Charlie").hotkey.ss58_address
    config = SettlementServiceConfig(
        schema="umi-cohort-settlement-config/1",
        role="coordinator",
        series=v.series,
        policy=v.policy,
        manifest=v.manifest,
        chain=v.chain,
        signer_hotkey=who,
        proposer_hotkey=who,
        signer_key_file=str(tmp_path / "keys" / "Charlie"),
        executions=(
            CohortExecutionConfig(
                schema="umi-cohort-execution-config/1",
                directory=str(tmp_path / "executions"),
                policy_sha256=digest(v.policy),
                signer=who,
                cohorts=tuple(
                    {
                        "cohort_sha256": key,
                        "authority_sha256": digest(v.series.recovery.authority),
                    }
                    for key in sorted(digest(p) for p in v.series.cohorts)
                ),
            ),
        ),
        **{
            key: str(tmp_path / key)
            for key in (
                "state_directory",
                "inputs_directory",
                "history_directory",
                "promotion_directory",
                "settlement_directory",
                "proof_import_directory",
                "proof_export_directory",
                "exchange_inbox",
                "exchange_outbox",
            )
        },
        maximum_package_bytes=8 * 1024**2,
        maximum_promotion_bytes=8 * 1024**2,
        maximum_state_bytes=16 * 1024**2,
    )
    inputs.config = config
    inputs.save(inputs.path, canonical_json_bytes(config))
    return inputs


def test_settlement_config_and_cli_use_exact_root_selection(selected, capsys):
    assert load_settlement_service_config(selected.path) == selected.config
    cli.main(["check", "--config", str(selected.path)])
    assert json.loads(capsys.readouterr().out)["runtime_qualified"] is False
    selected.save(selected.path, b" " + canonical_json_bytes(selected.config))
    with pytest.raises(ValueError, match="canonical"):
        load_settlement_service_config(selected.path)


@pytest.mark.parametrize(
    "fault", [None, "version", "role", "tracks", "cohort", "authority", "key", "overlap"]
)
def test_original_sources_are_explicit_coordinator_selection(selected, tmp_path, fault):
    from .cohort_settlement_original_fixture import select_original_sources

    c = selected.config
    assert "original_sources" not in c.model_dump(mode="json", by_alias=True)
    data = c.model_dump(mode="json", by_alias=True)
    plan = c.series.cohorts[0]
    from types import SimpleNamespace

    sources = select_original_sources(
        tmp_path / "originals",
        SimpleNamespace(
            plan=plan,
            authority=c.series.recovery,
        ),
    ).model_dump(mode="json")
    sources["intake"]["cohorts"] = [
        {"cohort_sha256": digest(p), "authority_sha256": digest(c.series.recovery.authority)}
        for p in sorted(c.series.cohorts, key=digest)
    ]
    data.update(schema="umi-cohort-settlement-config/2", original_sources=sources)
    if fault == "version":
        data["schema"] = "umi-cohort-settlement-config/1"
    elif fault == "role":
        data.update(role="reviewer", proposer_hotkey=wallet("Dave").hotkey.ss58_address)
    elif fault == "tracks":
        sources["eligible_tracks"] = ["endpoint", "endpoint"]
    elif fault == "cohort":
        sources["intake"]["cohorts"][0]["cohort_sha256"] = "12" * 32
    elif fault == "authority":
        sources["intake"]["cohorts"][0]["authority_sha256"] = "12" * 32
    elif fault == "key":
        data["signer_key_file"] = sources["objects_directory"] + "/key"
    elif fault == "overlap":
        sources["round_directory"] = c.inputs_directory
    if fault:
        with pytest.raises(ValueError):
            SettlementServiceConfig.model_validate_json(canonical_json_bytes(data))
    else:
        value = SettlementServiceConfig.model_validate_json(canonical_json_bytes(data))
        selected.save(selected.path, canonical_json_bytes(value))
        assert load_settlement_service_config(selected.path) == value


@pytest.mark.parametrize("fault", ["role", "key", "stores", "execution", "rpc", "authority"])
def test_settlement_config_rejects_changed_authority_and_shared_stores(selected, fault):
    c = selected.config
    changes = {
        "role": {"role": "reviewer"},
        "key": {"signer_key_file": c.exchange_outbox + "/key"},
        "stores": {"history_directory": c.inputs_directory},
        "execution": {
            "executions": (
                c.executions[0].model_copy(
                    update={
                        "signer": wallet("Dave").hotkey.ss58_address,
                    }
                ),
            )
        },
        "rpc": {"chain": c.chain.model_copy(update={"proof_rpc_fallback_urls": ()})},
        "authority": {
            "series": c.series.model_copy(
                update={
                    "recovery": c.series.recovery.model_copy(
                        update={
                            "signatures": (c.series.recovery.signatures[0],),
                        }
                    ),
                }
            )
        },
    }[fault]
    with pytest.raises(ValueError):
        SettlementServiceConfig.model_validate_json(
            canonical_json_bytes(c.model_copy(update=changes))
        )


@pytest.mark.parametrize("failure", ["stop", "node", "key"])
async def test_settlement_boot_owns_keys_locks_and_drains_children(selected, monkeypatch, failure):
    events, stop = [], asyncio.Event()
    config = selected.config

    class Provider:
        def __init__(self, chain, policy):
            events.append("provider")
            self.policy = policy

        async def start(self):
            events.append("started")

        async def aclose(self):
            events.append("closed")

    def key(path, hotkey):
        assert path == Path(config.signer_key_file) and hotkey == config.signer_hotkey
        events.append("key")
        if failure == "key":
            raise ValueError("key unavailable")
        return wallet("Charlie")

    class Node:
        def __init__(self, conf, plan, *, sign, **ports):
            self.plan, self.sign = plan, sign
            assert conf == config and ports["provider"].policy == conf.policy

        async def run(self, halted):
            events.append("node")
            try:
                vote = await self.sign(self.plan)
                verify_signature(self.plan, vote)
                if failure == "node":
                    raise RuntimeError("node exited")
                await asyncio.sleep(0)
                halted.set()
                await halted.wait()
            finally:
                events.append("drained")

    monkeypatch.setattr(boot, "HistoricalRegistrationProvider", Provider)
    monkeypatch.setattr(boot, "load_named_hotkey", key)
    monkeypatch.setattr(boot, "CohortSettlementService", Node)
    if failure == "stop":
        await boot.run_settlement_service(config, stop)
    else:
        with pytest.raises((ValueError, RuntimeError)):
            await boot.run_settlement_service(config, stop)
    assert events[-1] == "closed"
    assert ("drained" in events) == (failure != "key")
    import os

    root = Path(config.state_directory) / digest(config.series)
    os.close(lock_private_file(root / "service.lock"))
    for plan in config.series.cohorts:
        if failure != "key":
            with boot.settlement_store(root / digest(plan), config.maximum_state_bytes):
                pass


def test_settlement_sqlite_rejects_duplicate_owner_and_unsafe_files(tmp_path):
    root = tmp_path / "state"
    with (
        boot.settlement_store(root, 1024**2),
        pytest.raises(BlockingIOError),
        boot.settlement_store(root, 1024**2),
    ):
        pass
    path = root / "history.sqlite3"
    path.chmod(0o644)
    with pytest.raises(ValueError, match="private"), boot.settlement_store(root, 1024**2):
        pass
    path.chmod(0o600)
    with boot.settlement_store(root, 1024**2):
        pass
    outside = tmp_path / "unrelated"
    outside.write_bytes(b"preserve")
    auxiliary = root / "history.sqlite3-wal"
    auxiliary.symlink_to(outside)
    with pytest.raises(ValueError, match="auxiliary"), boot.settlement_store(root, 1024**2):
        pass
    assert outside.read_bytes() == b"preserve"


@pytest.mark.parametrize("fault", [None, "version", "missing", "key", "execution"])
def test_request_export_is_explicit_private_configuration(selected, tmp_path, fault):
    c = selected.config
    assert "request_export_directory" not in c.model_dump(mode="json", by_alias=True)
    data = c.model_dump(mode="json", by_alias=True)
    data.update(
        schema="umi-cohort-settlement-config/3",
        request_export_directory=str(tmp_path / "request-exports"),
    )
    if fault == "version":
        data["schema"] = "umi-cohort-settlement-config/1"
    elif fault == "missing":
        data.pop("request_export_directory")
    elif fault == "key":
        data["request_export_directory"] = str(Path(c.signer_key_file).parent)
    elif fault == "execution":
        data["request_export_directory"] = c.executions[0].directory
    if fault:
        with pytest.raises(ValueError):
            SettlementServiceConfig.model_validate_json(canonical_json_bytes(data))
    else:
        value = SettlementServiceConfig.model_validate_json(canonical_json_bytes(data))
        selected.save(selected.path, canonical_json_bytes(value))
        assert load_settlement_service_config(selected.path) == value


def test_direct_series_requires_read_only_settlement_source(selected, tmp_path):
    c = selected.config
    plans = list(c.series.cohorts)
    plans[-1] = plans[-1].model_copy(
        update={
            "schema_": "umi-recoverable-cohort-plan/3",
            "eligible_tracks": ("model",),
            "service_pool_bps": 0,
            "model_delivery": ModelDeliveryProfile(
                schema="umi-model-delivery-profile/1",
                mechanism="direct_r2_multipart_v1",
                part_size_bytes=64 * 1024**2,
                maximum_concurrent_parts=4,
                capability_ttl_seconds=3600,
            ),
        }
    )
    plans = tuple(plans)
    authority = c.series.recovery.authority.model_copy(
        update={"cohort_sha256s": tuple(sorted(digest(plan) for plan in plans))}
    )
    recovery = SignedCohortRecoveryAuthority(
        authority=authority,
        signatures=tuple(
            sorted(
                (sign_object(authority, wallet(name)) for name in ("Charlie", "Dave")),
                key=lambda signature: identity(signature.hotkey),
            )
        ),
    )
    manifest = c.manifest.model_copy(
        update={
            "cohorts": tuple(
                requirement.model_copy(update={"cohort_sha256": digest(plan)})
                for requirement, plan in zip(c.manifest.cohorts, plans, strict=True)
            )
        }
    )
    series = c.series.model_copy(
        update={
            "cohorts": plans,
            "recovery": recovery,
            "manifest_sha256": digest(manifest),
        }
    )
    cohorts = tuple(
        CohortIntakeBinding(cohort_sha256=digest(plan), authority_sha256=digest(authority))
        for plan in sorted(plans, key=digest)
    )
    execution = c.executions[0].model_copy(update={"cohorts": cohorts})
    standing = StandingModelReviewPolicy(
        schema="umi-standing-model-artifact-review-policy/1",
        competition_policy_sha256=digest(c.policy),
        contribution_terms_sha256=c.policy.contribution_terms_sha256,
        standing_approval_record_sha256="ab" * 32,
        approved_by="operator@example.test",
        approved_at_utc="2026-10-02T12:00:00Z",
        complete_declared_bundle_rights_approved=True,
        licenses_and_notices_reviewed=True,
        public_redistribution_and_evaluation_approved=True,
    )
    source = DirectModelReviewSourceConfig(
        schema="umi-direct-model-review-source/1",
        r2_credentials_file=str(tmp_path / "r2-reader.env"),
        r2_bucket="umi-model-artifacts",
        standing_review_policy=standing,
    )
    direct = c.model_copy(
        update={
            "schema_": "umi-cohort-settlement-config/4",
            "series": series,
            "manifest": manifest,
            "executions": (execution,),
            "request_export_directory": str(tmp_path / "request-exports"),
            "direct_model_review": source,
        }
    )
    assert SettlementServiceConfig.model_validate_json(canonical_json_bytes(direct)) == direct
    with pytest.raises(ValueError, match="version four"):
        SettlementServiceConfig.model_validate_json(
            canonical_json_bytes(direct.model_copy(update={"direct_model_review": None}))
        )
    with pytest.raises(ValueError, match="version four"):
        SettlementServiceConfig.model_validate_json(
            canonical_json_bytes(
                c.model_copy(
                    update={
                        "schema_": "umi-cohort-settlement-config/4",
                        "request_export_directory": str(tmp_path / "legacy-exports"),
                        "direct_model_review": source,
                    }
                )
            )
        )


@pytest.mark.parametrize("failure", [None, "construction", "runtime"])
async def test_export_worker_runs_before_settlement_and_drains_with_it(
    selected, tmp_path, monkeypatch, failure
):
    config = SettlementServiceConfig.model_validate_json(
        canonical_json_bytes(
            selected.config.model_copy(
                update={
                    "schema_": "umi-cohort-settlement-config/3",
                    "request_export_directory": str(tmp_path / "exports"),
                }
            )
        )
    )
    events, stop, entered = [], asyncio.Event(), asyncio.Event()

    class Provider:
        def __init__(self, chain, policy):
            self.policy = policy

        async def start(self):
            events.append("provider_started")

        async def aclose(self):
            events.append("provider_closed")

    class Node:
        def __init__(self, *args, **kwargs):
            pass

        async def run(self, halted):
            events.append("node_started")
            try:
                entered.set()
                await halted.wait()
            finally:
                events.append("node_drained")

    class Exports:
        def __init__(self, executions, provider, sign, files, journal):
            assert executions[0].config == config.executions[0]
            assert files.root == Path(config.request_export_directory)
            if failure == "construction":
                raise ValueError("export constructor failed")
            self.sign = sign

        async def run(self, halted, *, poll_seconds):
            try:
                await entered.wait()
                events.append("export_started")
                signature = await self.sign(config.series)
                verify_signature(config.series, signature)
                if failure == "runtime":
                    raise RuntimeError("export worker failed")
                halted.set()
            finally:
                events.append("export_drained")

    monkeypatch.setattr(boot, "HistoricalRegistrationProvider", Provider)
    monkeypatch.setattr(boot, "load_named_hotkey", lambda *args: wallet("Charlie"))
    monkeypatch.setattr(boot, "CohortSettlementService", Node)
    monkeypatch.setattr(boot, "RequestExportWorker", Exports)
    if failure:
        with pytest.raises((ValueError, RuntimeError), match="export"):
            await boot.run_settlement_service(config, stop)
    else:
        await boot.run_settlement_service(config, stop)
    assert events[-1] == "provider_closed"
    assert ("node_started" in events) == (failure != "construction")
    assert ("node_drained" in events) == (failure != "construction")
    assert ("export_drained" in events) == (failure != "construction")
