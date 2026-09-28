"""Host-local locations preserve original signed chain and proof identities."""

from pathlib import Path

import pytest

from umi.competition_chain_resources import CompetitionChainResources
from umi.competition_reward_control import validate_owned_reward_control
from umi.competition_reward_control_archive import HistoricalRewardControlProvider
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_reward_control import chain as chain
from .test_competition_reward_control import chain_config as chain_config
from .test_competition_reward_control import control as control
from .test_competition_reward_control import policy as policy


async def test_relocation_keeps_original_identity_with_independent_cache_locks(control, tmp_path):
    item = control
    original = canonical_json_bytes(item.config)
    locations = CompetitionChainResources.from_config(item.config).model_copy(
        update={
            "state_directory": str(tmp_path / "host-cache"),
        }
    )

    def reopen():
        return HistoricalRewardControlProvider(
            item.config,
            item.policy,
            resources=locations,
            historical_header_directory=tmp_path / "host-headers",
            finality=item.finality,
            proofs=item.proofs,
            now_ms=lambda: item.clock.now,
        )

    # The existing writer still owns its original cache. Relocation must not
    # rewrite the configuration or use that writer's database/lock namespace.
    relocated = reopen()
    try:
        captured = await relocated.collect_control(item.hotkey)
        validate_owned_reward_control(
            captured,
            expected_control_hotkey=item.hotkey,
            expected_chain_config_sha256=digest(item.config),
        )
        assert canonical_json_bytes(relocated.config) == original
        assert captured.chain_config_sha256 == digest(item.config)
        assert relocated._path.is_relative_to(Path(locations.state_directory))
        assert not relocated._path.is_relative_to(Path(item.config.state_directory))
        with pytest.raises(BlockingIOError):
            reopen()
        # The original cache remains usable and receives identical authority.
        old = await item.provider.collect_control(item.hotkey)
        assert old.control_sha256 == captured.control_sha256
    finally:
        await relocated.aclose()
    relocated = reopen()
    try:
        later = await relocated.collect_control(item.hotkey)
        assert later.control_sha256 == captured.control_sha256
    finally:
        await relocated.aclose()


@pytest.mark.parametrize("corrupt", [False, True])
async def test_relocated_metadata_keeps_original_pin(control, tmp_path, corrupt):
    item = control
    config = item.config.model_copy(
        update={"storage_codec_metadata_path": str(tmp_path / "absent-codec")}
    )
    codec = tmp_path / "host-codec"
    codec.write_bytes(b"different" if corrupt else b"metadata")
    resources = CompetitionChainResources.from_config(config).model_copy(
        update={
            "state_directory": str(tmp_path / "codec-cache"),
            "storage_codec_metadata_path": str(codec),
        }
    )

    def create():
        return HistoricalRewardControlProvider(
            config,
            item.policy,
            resources=resources,
            historical_header_directory=tmp_path / "codec-headers",
            finality=item.finality,
            proofs=item.proofs,
            now_ms=lambda: item.clock.now,
        )

    if corrupt:
        with pytest.raises(ValueError, match="approved chain pin"):
            create()
    else:
        provider = create()
        try:
            value = await provider.collect_control(item.hotkey)
            validate_owned_reward_control(
                value,
                expected_control_hotkey=item.hotkey,
                expected_chain_config_sha256=digest(config),
            )
            assert not Path(config.storage_codec_metadata_path).exists()
        finally:
            await provider.aclose()


@pytest.mark.parametrize("field", ["storage_codec_metadata_path", "runtime_metadata_binary"])
def test_relocation_cannot_select_a_different_verification_mode(chain_config, tmp_path, field):
    resources = CompetitionChainResources.from_config(chain_config).model_copy(
        update={field: str(tmp_path / "other")}
    )
    with pytest.raises(ValueError, match="verification mode"):
        resources.check(chain_config)
