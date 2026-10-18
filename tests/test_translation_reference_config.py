"""Installed owner wiring with real parsers/journals and no wallet/network access."""

import json
from types import SimpleNamespace

import pytest

from umi import translation_reference_config as wiring
from umi.competition_chain_resources import CompetitionChainResources
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.translation_reference_cli import main

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
    with pytest.raises(OSError):
        wiring.read_input(link, 128)
