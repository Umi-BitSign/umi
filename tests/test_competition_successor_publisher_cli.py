"""Publisher command wiring; chain and wallet ports are explicit test doubles."""

import json
from pathlib import Path

import pytest

from umi import competition_successor_publisher_cli as cli
from umi.competition_launch import PublicLaunchIdentity
from umi.protocol import canonical_json_bytes

from .competition_checkpoint import bind_submission_checkpoint
from .test_competition_successor_publisher import (
    chain_config as chain_config,
)
from .test_competition_successor_publisher import (
    guarded as guarded,
)
from .test_competition_successor_publisher import (
    package_case as package_case,
)
from .test_competition_successor_publisher import (
    package_limits as package_limits,
)
from .test_competition_successor_publisher import (
    policy as policy,
)
from .test_competition_successor_publisher import (
    publication_case as publication_case,
)
from .test_competition_successor_publisher import (
    release_identity as release_identity,
)
from .test_competition_successor_publisher import (
    replay_limits as replay_limits,
)
from .test_competition_successor_publisher import (
    successor_case as successor_case,
)
from .test_competition_successor_publisher import (
    successor_chain as successor_chain,
)
from .test_competition_successor_publisher import (
    successor_release as successor_release,
)
from .test_competition_successor_publisher import (
    v3_predecessor as v3_predecessor,
)
from .test_competition_successor_publisher import (
    worker_capacity as worker_capacity,
)


@pytest.fixture
def config(guarded, tmp_path):
    wallet = cli.AuthorityWallet(
        wallet_name="authority", hotkey_name="release", wallet_path=str(tmp_path / "wallets")
    )
    public_launch = PublicLaunchIdentity(
        schema="umi-competition-public-launch/1",
        round_schedule=guarded.package.scenario.round.public_schedule,
        eligible_tracks=guarded.package.scenario.round.eligible_tracks,
    )
    checkpoint = tmp_path / "intake-checkpoint"
    guarded.store = bind_submission_checkpoint(guarded.store, public_launch, checkpoint)
    return cli.SuccessorPublisherConfig(
        schema="umi-successor-publisher-config/2",
        plan=guarded.builder.plan,
        public_launch=public_launch,
        chain=guarded.provider.config,
        intake_directory=str(guarded.store.directory),
        submission_head_checkpoint_directory=str(checkpoint),
        publication_directory=str(guarded.builder.journal.root),
        replay_directory=str(guarded.replay.state_root),
        replay_capacity=guarded.replay.capacity,
        authorization_wallet=wallet,
        directive_wallets=(wallet,),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("fail", [False, True])
async def test_managed_provider_is_closed_on_success_and_signing_failure(
    config, policy, guarded, monkeypatch, fail
):
    events = []

    class Provider:
        def __init__(self, chain, supplied_policy):
            assert chain == config.chain and supplied_policy == policy
            events.append("provider")

        async def start(self):
            events.append("start")

        async def wait_ready(self):
            events.append("ready")

        async def aclose(self):
            events.append("close")

    class Publisher:
        def __init__(self, builder, store, replay, provider):
            assert builder.plan == config.plan
            assert store.path == guarded.store.path
            assert replay.path == guarded.replay.path
            assert isinstance(provider, Provider)

        async def build(self, prepared, **signers):
            assert prepared == guarded.package.prepared
            assert signers == {
                "authorization_wallet": "hotkey-only",
                "directive_wallets": ("hotkey-only",),
            }
            events.append("sign")
            if fail:
                raise ValueError("injected signing failure")
            return {"signed": True}

    def load(self):
        assert events[-1] in {"ready", "wallet"}
        events.append("wallet")
        return "hotkey-only"

    monkeypatch.setattr(cli, "FinalizedRegistrationProvider", Provider)
    monkeypatch.setattr(cli, "CurrentSuccessorRoundPublisher", Publisher)
    monkeypatch.setattr(cli.AuthorityWallet, "load", load)
    if fail:
        with pytest.raises(ValueError, match="injected signing failure"):
            await cli.sign_round(config, policy, guarded.package.prepared)
    else:
        assert await cli.sign_round(config, policy, guarded.package.prepared) == {"signed": True}
    assert events == ["provider", "start", "ready", "wallet", "wallet", "sign", "close"]


@pytest.mark.asyncio
async def test_missing_intake_does_not_create_source_or_load_wallet(
    config, policy, guarded, tmp_path
):
    config = config.model_copy(update={"intake_directory": str(tmp_path / "absent-intake")})
    with pytest.raises(ValueError, match="retained intake"):
        await cli.sign_round(config, policy, guarded.package.prepared)
    assert not Path(config.intake_directory).exists()


def test_state_paths_cannot_overlap(config):
    data = json.loads(canonical_json_bytes(config))
    data["replay_directory"] = data["intake_directory"] + "/nested"
    with pytest.raises(ValueError, match="must be separate"):
        cli.SuccessorPublisherConfig.model_validate_json(canonical_json_bytes(data))


def test_cli_rejects_nonprivate_input_without_printing_payload(config, tmp_path, capsys):
    directory = tmp_path / "inputs"
    directory.mkdir(mode=0o700)
    path = directory / "config.json"
    path.write_bytes(canonical_json_bytes(config))
    path.chmod(0o644)
    with pytest.raises(SystemExit) as error:
        cli.main(["--config", str(path), "--policy", str(path), "--prepared-package", str(path)])
    assert error.value.code == 2
    out = capsys.readouterr()
    assert out.out == "" and "publication rejected" in out.err
    assert config.authorization_wallet.wallet_path not in out.err
    assert config.plan.policy_sha256 not in out.err
