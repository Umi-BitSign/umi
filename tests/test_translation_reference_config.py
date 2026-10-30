"""Installed owner wiring with real parsers/journals and no wallet/network access."""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import translation_reference_config as wiring
from umi.competition_chain_resources import CompetitionChainResources
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.translation_reference_cli import main
from umi.translation_reference_gateway import (
    REFERENCE_GATEWAY_ORIGIN,
    REFERENCE_GATEWAY_R2_ENDPOINT,
    R2ReferenceGatewayClient,
)

from .test_competition_cpu_efficiency_capacity import large_cpu_allocation as large_cpu_allocation
from .test_translation_reference_channel import (
    base_policy as base_policy,
)
from .test_translation_reference_channel import (
    chain as chain,
)
from .test_translation_reference_channel import (
    chain_config as chain_config,
)
from .test_translation_reference_channel import channel_case as channel_case
from .test_translation_reference_channel import (
    control as control,
)
from .test_translation_reference_channel import (
    policy as policy,
)
from .test_translation_reference_channel import (
    publication_case as publication_case,
)
from .test_translation_reference_channel import (
    series_case as series_case,
)


@pytest.fixture
def installed(channel_case, tmp_path, monkeypatch):
    c = channel_case
    monkeypatch.setattr(
        wiring, "COMMON_SUPERVISOR_AUTHORITY_HOTKEY", c.config.trusted_authorities[0].hotkey
    )
    root = tmp_path / "new-owner"
    credentials = tmp_path / "private" / "publisher.json"
    credentials.parent.mkdir(mode=0o700)
    # Preserve the existing operator export; credentials need not be canonical.
    credentials.write_text(
        json.dumps(
            {
                "access_key_id": "a" * 32,
                "secret_access_key": "b" * 64,
            },
            indent=2,
        )
        + "\n"
    )
    credentials.chmod(0o600)
    allocation = tmp_path / "allocation.json"
    allocation.write_bytes(canonical_json_bytes(c.native.reward))
    allocation.chmod(0o600)
    config = wiring.ReferencePublisherConfig(
        schema="umi-reference-publisher-config/1",
        coordinator_config=str(tmp_path / "coordinator.json"),
        state_directory=str(root),
        resources=CompetitionChainResources.from_config(c.native.item.config).model_copy(
            update={"state_directory": str(root / "proofs")}
        ),
        maximum_cache_bytes=256 * 1024**2,
        maximum_journal_bytes=16 * 1024**2,
        credentials_file=str(credentials),
        endpoint="https://" + "a" * 32 + ".r2.cloudflarestorage.com",
        bucket="umi-public-evidence",
        wallet_path=str(tmp_path / "wallets"),
        wallet_name="authority",
        wallet_hotkey="coordinator",
        reference_hotkey=c.native.reopen().reference_hotkey,
        channels=[wiring.ReferenceChannelSelection(config=c.config, release=c.release)],
        allocations={digest(c.native.reward): str(allocation)},
        horizons={digest(p): c.horizon for p in c.native.c.series.cohorts},
    )
    selected = SimpleNamespace(
        series=c.native.c.series,
        policy=c.native.item.policy,
        chain=c.native.item.config,
        state_directory=str(tmp_path / "production-owner"),
        files_directory=str(tmp_path / "files"),
        reward_adoptions=None,
        reward_adoption_feed=None,
    )
    monkeypatch.setattr(wiring, "load_reward_coordinator_config", lambda path: selected)

    def forbidden(*args, **kwargs):
        pytest.fail("configuration/wiring must not load a wallet or access the network")

    monkeypatch.setattr(wiring.bt, "Wallet", forbidden)
    provider_type = wiring.FinalizedRewardControlProvider

    def provider(chain, policy, **kwargs):
        return provider_type(
            chain, policy, finality=c.native.item.finality, proofs=c.native.item.proofs, **kwargs
        )

    monkeypatch.setattr(wiring, "FinalizedRewardControlProvider", provider)
    return SimpleNamespace(
        c=c,
        config=config,
        selected=selected,
        allocation=allocation,
        root=root,
        credentials=credentials,
    )


async def test_executable_owner_wires_isolated_native_resources_and_lazy_signer(installed):
    item = installed
    service = wiring.build_reference_service(item.config)
    assert service.provider.config.state_directory == str(item.root / "proofs")
    assert service.provider.config.maximum_cache_bytes == 256 * 1024**2
    assert service.provider.config.finality_binary == item.selected.chain.finality_binary
    assert service.reader.chain_config_sha256 == digest(service.provider.config)
    assert service.horizons == item.config.horizons
    assert service.allocations(digest(item.c.native.reward)) == item.c.native.reward
    with pytest.raises(FileNotFoundError, match="not been replicated"):
        service.allocations("f" * 64)
    item.allocation.write_bytes(
        canonical_json_bytes(
            item.c.native.reward.model_copy(
                update={"burn_weight": item.c.native.reward.burn_weight + 1}
            )
        )
    )
    with pytest.raises(ValueError):
        service.allocations(digest(item.c.native.reward))
    await service.provider.aclose()


async def test_reference_reader_accepts_cpu_allocation_above_old_file_limit(
    installed, large_cpu_allocation
):
    item, allocation = installed, large_cpu_allocation
    raw = canonical_json_bytes(allocation)
    assert len(raw) > 1024**2
    item.allocation.write_bytes(raw)
    config = item.config.model_copy(
        update={
            "allocations": {digest(allocation): str(item.allocation)},
        }
    )
    service = wiring.build_reference_service(config)
    try:
        assert service.allocations(digest(allocation)) == allocation
    finally:
        await service.provider.aclose()


async def test_reference_publisher_carries_declared_cache_predecessor(installed):
    config = installed.config.model_copy(
        update={
            "maximum_cache_bytes": 512 * 1024**2,
            "previous_maximum_cache_bytes": 256 * 1024**2,
        }
    )
    service = wiring.build_reference_service(config)
    try:
        assert service.provider.config.maximum_cache_bytes == 512 * 1024**2
        assert service.provider.config.previous_maximum_cache_bytes == 256 * 1024**2
        predecessor = service.provider.config.model_copy(
            update={"maximum_cache_bytes": 256 * 1024**2, "previous_maximum_cache_bytes": None}
        )
        assert service.reader.admission_chain_config_sha256 == digest(predecessor)
    finally:
        await service.provider.aclose()


async def test_reference_owner_adopts_signed_feed_and_retains_frontier_on_restart(installed):
    from umi.competition_reward_adoption_feed import RewardAdoptionFeed, RewardAdoptionFeedConfig

    from .test_competition_reward_adoption_boot import selected_adoption

    item = installed
    item.selected.reward_adoption_feed = RewardAdoptionFeedConfig(
        path=str(item.root.parent / "signed-adoptions.json")
    )
    producer = RewardAdoptionFeed(
        item.root.parent / "producer-feed",
        source=item.selected.reward_adoption_feed,
        series=item.selected.series,
        policy=item.selected.policy,
        initial=None,
    )
    service = wiring.build_reference_service(item.config)
    try:
        assert service.reader.reward_adoptions is None
        assert service.reader._reward_adoption_feed.journal is None
        signed = selected_adoption(item.selected).adoptions[0]
        accepted = producer.publish(signed)
        assert service.reader.refresh_reward_adoptions() == accepted
    finally:
        await service.provider.aclose()
    reopened = wiring.build_reference_service(item.config)
    try:
        # Construction occurs before the service's existing owner lease. The
        # protected first tick, rather than construction, restores the frontier.
        assert reopened.reader._reward_adoption_feed.journal is None
        assert reopened.reader.refresh_reward_adoptions() == accepted
        assert reopened.reader._reward_adoption_feed.journal.root != producer.journal.root
    finally:
        await reopened.provider.aclose()


def test_reference_feed_cannot_overlap_private_owner(installed):
    from umi.competition_reward_adoption_feed import RewardAdoptionFeedConfig

    installed.selected.reward_adoption_feed = RewardAdoptionFeedConfig(
        path=str(installed.root / "feed.json")
    )
    with pytest.raises(ValueError, match="overlaps"):
        wiring.selected_inputs(installed.config)
    assert not installed.root.exists()


@pytest.mark.parametrize("protected", ["state_directory", "files_directory"])
def test_installed_state_overlap_refuses_before_owner_creation(installed, protected):
    item = installed
    setattr(item.selected, protected, str(item.root / "production"))
    with pytest.raises(ValueError, match="overlaps"):
        wiring.selected_inputs(item.config)
    assert not item.root.exists()


def test_all_cohort_horizons_required_before_opening_credentials_or_journals(installed):
    item = installed
    bad = item.config.model_copy(update={"horizons": {}})
    item.credentials.unlink()
    with pytest.raises(ValueError, match="every signed cohort"):
        wiring.build_reference_service(bad)
    assert not item.root.exists()


@pytest.mark.parametrize("gateway", [False, True])
async def test_rolling_config_uses_current_block_without_rewriting_legacy_config(
    installed, gateway
):
    item = installed
    original = canonical_json_bytes(item.config)
    values = item.config.model_dump(mode="json", by_alias=True)
    values.update(
        schema="umi-reference-publisher-config/3",
        directive_renewal={
            "schema": "umi-reference-directive-renewal/1",
            "lifetime_blocks": 7200,
            "renew_before_blocks": 1200,
        },
    )
    values.pop("horizons")
    if gateway:
        values.update(
            gateway_origin=REFERENCE_GATEWAY_ORIGIN, endpoint=REFERENCE_GATEWAY_R2_ENDPOINT
        )
        item.credentials.write_text(json.dumps({"token": "a" * 64}))
    config = wiring.ReferencePublisherConfig.model_validate(values)
    service = wiring.build_reference_service(config)
    assert service.horizons == {}
    block = item.c.native.item.finality.ref.block_number
    assert service._window(block, digest(item.c.native.c.series.cohorts[0])) == (block + 7200, 1200)
    assert canonical_json_bytes(item.config) == original
    await service.provider.aclose()


def test_rolling_mode_cannot_be_smuggled_into_legacy_configuration(installed):
    from umi.translation_reference_renewal import ReferenceDirectiveRenewal

    item = installed
    renewal = ReferenceDirectiveRenewal(
        schema="umi-reference-directive-renewal/1",
        lifetime_blocks=7200,
        renew_before_blocks=1200,
    )
    item.credentials.unlink()
    bad = item.config.model_copy(update={"directive_renewal": renewal})
    with pytest.raises(ValueError, match="explicit config version3"):
        wiring.build_reference_service(bad)
    assert not item.root.exists()


def test_check_entrypoint_does_not_open_credentials_or_wallet(installed, tmp_path, capsys):
    config_path = tmp_path / "private" / "config.json"
    config_path.write_bytes(canonical_json_bytes(installed.config))
    config_path.chmod(0o600)
    installed.credentials.unlink()
    main(["check", "--config", str(config_path)])
    output = capsys.readouterr().out
    assert '"status": "configuration_valid"' in output
    assert '"credentials_opened": false' in output
    assert not installed.root.exists()


def test_entrypoint_error_never_prints_parser_input_secrets(tmp_path, capsys):
    tmp_path.chmod(0o700)
    config = tmp_path / "config.json"
    config.write_text('{"secret":"sensitive-never-report"}')
    config.chmod(0o600)
    with pytest.raises(SystemExit):
        main(["check", "--config", str(config)])
    output = capsys.readouterr().out
    assert "repair_required" in output and "sensitive-never-report" not in output


def test_expired_horizon_cli_reports_only_safe_numeric_diagnostics(
    installed, tmp_path, monkeypatch, capsys
):
    from umi import translation_reference_cli as cli
    from umi.translation_reference_channel import ReferenceHorizonExpired

    async def expired(_config):
        raise ReferenceHorizonExpired(selected_horizon=9317800, current_block=9327218)

    p = tmp_path / "private" / "config.json"
    p.write_bytes(canonical_json_bytes(installed.config))
    p.chmod(0o600)
    monkeypatch.setattr(cli, "run", expired)
    with pytest.raises(SystemExit):
        cli.main(["run", "--config", str(p)])
    record = json.loads(capsys.readouterr().out)
    assert record["reason_code"] == "reference_directive_horizon_expired"
    assert record["selected_horizon"] == 9317800 and record["current_block"] == 9327218


def test_reference_observer_failure_reports_redacted_cause(
    installed, tmp_path, monkeypatch, capsys
):
    from umi import translation_reference_cli as cli

    async def observer_stopped(_config):
        cause = RuntimeError("private provider URL and token must stay hidden")
        cause.reason_code = "proof_rpc_rate_limited"
        raise RuntimeError("owned_finality_observer_stopped") from cause

    p = tmp_path / "private" / "config.json"
    p.write_bytes(canonical_json_bytes(installed.config))
    p.chmod(0o600)
    monkeypatch.setattr(cli, "run", observer_stopped)
    with pytest.raises(SystemExit):
        cli.main(["run", "--config", str(p)])
    output = capsys.readouterr().out
    record = json.loads(output)
    assert record["error_chain"] == [
        {"error_type": "RuntimeError", "reason_code": "owned_finality_observer_stopped"},
        {"error_type": "RuntimeError", "reason_code": "proof_rpc_rate_limited"},
    ]
    assert "private provider URL" not in output and "token" not in output


def test_reference_observer_reports_stable_finality_reason_without_error_text(
    installed, tmp_path, monkeypatch, capsys
):
    from umi import translation_reference_cli as cli
    from umi.grandpa_finality import GrandpaFinalityObserverError

    async def observer_stopped(_config):
        cause = GrandpaFinalityObserverError("record_count_mismatch")
        raise RuntimeError("owned_finality_observer_stopped") from cause

    p = tmp_path / "private" / "config.json"
    p.write_bytes(canonical_json_bytes(installed.config))
    p.chmod(0o600)
    monkeypatch.setattr(cli, "run", observer_stopped)
    with pytest.raises(SystemExit):
        cli.main(["run", "--config", str(p)])
    record = json.loads(capsys.readouterr().out)
    assert record["error_chain"][-1] == {
        "error_type": "GrandpaFinalityObserverError",
        "reason_code": "record_count_mismatch",
    }


def test_original_input_reader_rejects_links_and_untrusted_writers(tmp_path):
    source = tmp_path / "signed.json"
    source.write_bytes(b"signed original")
    source.chmod(0o600)
    assert wiring.read_input(source, 128) == b"signed original"
    source.chmod(0o666)
    with pytest.raises(ValueError):
        wiring.read_input(source, 128)
    source.chmod(0o600)
    link = tmp_path / "link.json"
    link.symlink_to(source)
    with pytest.raises((OSError, ValueError)):
        wiring.read_input(link, 128)


async def test_gateway_configuration_adopts_transport_without_rebinding_signed_inputs(installed):
    item = installed
    before = canonical_json_bytes(item.config)
    assert b"gateway_origin" not in before
    assert (
        canonical_json_bytes(wiring.ReferencePublisherConfig.model_validate_json(before)) == before
    )
    updated = item.config.model_dump(mode="json", by_alias=True)
    updated.update(
        schema="umi-reference-publisher-config/2",
        gateway_origin=REFERENCE_GATEWAY_ORIGIN,
        endpoint=REFERENCE_GATEWAY_R2_ENDPOINT,
    )
    config = wiring.ReferencePublisherConfig.model_validate(updated)
    item.credentials.write_text(json.dumps({"token": "a" * 64}, indent=2))
    service = wiring.build_reference_service(config)
    assert isinstance(service.channels[0].store.client, R2ReferenceGatewayClient)
    assert service.reader.series == item.selected.series
    assert service.horizons == item.config.horizons
    assert service.provider.resources == item.config.resources
    await service.provider.aclose()
    wrong = dict(updated, endpoint="https://" + "b" * 32 + ".r2.cloudflarestorage.com")
    with pytest.raises(ValueError, match="different R2 binding"):
        wiring.ReferencePublisherConfig.model_validate(wrong)
    updated["schema"] = "umi-reference-publisher-config/1"
    with pytest.raises(ValueError, match="explicit configuration version"):
        wiring.ReferencePublisherConfig.model_validate(updated)


async def test_coordinator_account_inputs_use_the_configured_protected_producer(
    installed, monkeypatch
):
    item = installed
    source = Path(item.selected.files_directory)
    (source / "decisions").mkdir(parents=True, mode=0o700)
    source.chmod(0o700)
    key = "a" * 64
    path = source / "decisions" / (key + ".json")
    path.write_bytes(b"original signed producer bytes")
    path.chmod(0o600)
    service = wiring.build_reference_service(item.config)
    uid = os.geteuid()
    with monkeypatch.context() as context:
        context.setattr(wiring.os, "geteuid", lambda: uid + 123)
        with pytest.raises(ValueError):
            wiring.read_input(path, 1024)
        assert service.decisions(key) == b"original signed producer bytes"
        with pytest.raises(ValueError):
            wiring.read_input(path, 1024, producer_uid=uid + 456)
    source.chmod(0o777)
    with pytest.raises(ValueError, match="protected"):
        service.decisions(key)
    await service.provider.aclose()


async def test_allocation_discovery_uses_the_protected_producer_across_restart(
    installed, monkeypatch
):
    from umi.competition_reward_files import StandingRewardFiles

    item = installed
    config = item.config.model_copy(update={"allocations": {}})
    before = canonical_json_bytes(config)
    files = StandingRewardFiles(
        Path(item.selected.files_directory),
        maximum_package_bytes=1024**2,
        maximum_witness_bytes=1024**2,
    )
    allocation = item.c.native.reward
    sha = digest(allocation)
    service = wiring.build_reference_service(config)
    with pytest.raises(FileNotFoundError, match="not been replicated"):
        service.allocations(sha)
    files.retain_allocation(allocation)
    path = files.root / "allocations" / (sha + ".json")
    identity = path.stat()
    uid = os.geteuid()
    with monkeypatch.context() as separate_account:
        separate_account.setattr(wiring.os, "geteuid", lambda: uid + 123)
        assert service.allocations(sha) == allocation
    await service.provider.aclose()
    reopened = wiring.build_reference_service(config)
    assert reopened.allocations(sha) == files.allocation(sha) == allocation
    files.retain_allocation(allocation)
    assert path.stat() == identity
    assert (
        canonical_json_bytes(wiring.ReferencePublisherConfig.model_validate_json(before)) == before
    )
    await reopened.provider.aclose()


@pytest.mark.parametrize("damage", ["wrong_identity", "symlink", "writable_directory"])
async def test_discovered_allocation_damage_refuses_without_replacing_originals(installed, damage):
    from umi.competition_reward_files import StandingRewardFiles

    item = installed
    files = StandingRewardFiles(
        Path(item.selected.files_directory),
        maximum_package_bytes=1024**2,
        maximum_witness_bytes=1024**2,
    )
    files.retain_allocation(item.c.native.reward)
    sha = digest(item.c.native.reward)
    path = files.root / "allocations" / (sha + ".json")
    expected = path.read_bytes()
    service = wiring.build_reference_service(item.config.model_copy(update={"allocations": {}}))
    requested = sha
    if damage == "wrong_identity":
        requested = "f" * 64
        (path.parent / (requested + ".json")).write_bytes(expected)
    elif damage == "symlink":
        path.rename(path.with_suffix(".original"))
        path.symlink_to(path.with_suffix(".original"))
    else:
        files.root.chmod(0o777)
    with pytest.raises((ValueError, OSError)):
        service.allocations(requested)
    assert path.read_bytes() == expected
    await service.provider.aclose()
