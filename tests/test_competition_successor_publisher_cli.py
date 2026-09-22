"""Publisher command wiring; chain and wallet ports are explicit test doubles."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_successor_publisher_cli as cli
from umi.competition_launch import PublicLaunchIdentity
from umi.competition_package import load_competition_package, prepare_competition_package
from umi.competition_policy_lineage import clear_lineage_registry, registered_lineage
from umi.competition_successor_feed import SuccessorPublicationFeed
from umi.competition_successor_publication import (
    SignedSuccessorRoundPublication,
    verify_successor_round_publication,
)
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .competition_checkpoint import bind_submission_checkpoint
from .test_competition_publication import _scenario
from .test_competition_successor_feed import feed_case as feed_case
from .test_competition_successor_publication import authority_wallets
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


@pytest.fixture
def retained_successor(
    config, guarded, policy, replay_limits, package_limits, release_identity, tmp_path, monkeypatch
):
    """Old signed submissions, two operational successors, real certificates/package."""
    middle = policy.model_copy(
        update={
            "sequence": policy.sequence + 1,
            "predecessor_sha256": digest(policy),
            "maximum_inference_ms": policy.maximum_inference_ms * 2,
        }
    )
    current = middle.model_copy(
        update={"sequence": middle.sequence + 1, "predecessor_sha256": digest(middle)}
    )
    predecessors = (middle, policy)
    root = tmp_path / "carried"
    scenario = _scenario(
        policy,
        root / "scenario",
        replay_limits,
        successor_policy=current,
        predecessor_policies=predecessors,
    )
    prepared = prepare_competition_package(
        policy=current,
        cutoff_certificate=scenario.cutoff_certificate,
        settlement_certificate=scenario.settlement_certificate,
        retained_settlement=scenario.settlement,
        roster=scenario.submissions,
        evidence=scenario.evidence,
        replay_limits=replay_limits,
        release_identity=release_identity,
        destination_root=root / "packages",
        limits=package_limits,
    )
    checkpoint = root / "checkpoint"
    store = bind_submission_checkpoint(scenario.store, config.public_launch, checkpoint)
    with store._connection() as db:
        retained_bytes = db.execute(
            "SELECT digest,body FROM submissions ORDER BY digest"
        ).fetchall()
    assert {s.submission.policy_sha256 for s in scenario.submissions} == {digest(policy)}
    wallets = tuple(
        config.authorization_wallet.model_copy(update={"hotkey_name": f"release{i}"})
        for i in range(2)
    )
    config = config.model_copy(
        update={
            "plan": config.plan.model_copy(update={"policy_sha256": digest(current)}),
            "chain": config.chain.model_copy(update={"policy_sha256": digest(current)}),
            "intake_directory": str(store.directory),
            "submission_head_checkpoint_directory": str(checkpoint),
            "publication_directory": str(root / "publication"),
            "replay_directory": str(root / "replay"),
            "authorization_wallet": wallets[0],
            "directive_wallets": wallets,
        }
    )
    events = []

    class Provider(type(guarded.provider)):
        def __init__(self, chain, supplied_policy):
            self.config, self.policy = chain, supplied_policy
            events.append("provider")

        async def start(self):
            events.append("start")

        async def wait_ready(self):
            events.append("ready")

        async def aclose(self):
            events.append("close")

    def load(self):
        events.append("wallet")
        return authority_wallets()[int(self.hotkey_name.removeprefix("release"))]

    # Only chain I/O and wallet resolution are doubled. Store/checkpoint source
    # validation, certificate/package replay and publication signatures are native.
    monkeypatch.setattr(cli, "FinalizedRegistrationProvider", Provider)
    monkeypatch.setattr(cli.AuthorityWallet, "load", load)
    inputs = root / "inputs"
    inputs.mkdir(mode=0o700)

    def write(name, value):
        path = inputs / name
        path.write_bytes(canonical_json_bytes(value))
        path.chmod(0o600)
        return str(path)

    argv = [
        "--config",
        write("config.json", config),
        "--policy",
        write("policy.json", current),
        "--prepared-package",
        write("prepared.json", prepared),
    ]
    predecessor_paths = [write(f"predecessor-{i}.json", p) for i, p in enumerate(predecessors)]
    try:
        yield SimpleNamespace(
            argv=argv,
            predecessor_paths=predecessor_paths,
            current=current,
            config=config,
            prepared=prepared,
            store=store,
            retained_bytes=retained_bytes,
            events=events,
            release_identity=release_identity,
            package_limits=package_limits,
            root=root,
            write=write,
        )
    finally:
        Path(prepared.package_path).chmod(0o700)


@pytest.mark.parametrize("mode", ["prepared", "follow"])
def test_cli_publishes_retained_predecessor_submissions_with_explicit_lineage(
    retained_successor, feed_case, mode, capsys
):
    case = retained_successor
    clear_lineage_registry()
    argv = case.argv + [
        argument for path in case.predecessor_paths for argument in ("--predecessor-policy", path)
    ]
    if mode == "follow":
        certificates = case.root / "completed"
        certificates.mkdir(mode=0o700)
        manifest = json.loads((Path(case.prepared.package_path) / "manifest.json").read_bytes())
        descriptor = certificates / (manifest["settlement_publication_sha256"] + ".package.json")
        descriptor.write_bytes(canonical_json_bytes(case.prepared))
        descriptor.chmod(0o600)
        follow = cli.SuccessorFollowConfig(
            schema="umi-successor-follow-config/1",
            certificate_directory=str(certificates),
            package_directory=str(Path(case.prepared.package_path).parent),
        )
        execution = feed_case.config.execution
        chain = execution.weights.chain.model_copy(update={"policy_sha256": digest(case.current)})
        feed = feed_case.config.model_copy(
            update={
                "directory": str(case.root / "feed"),
                "plan": case.config.plan,
                "execution": execution.model_copy(
                    update={"weights": execution.weights.model_copy(update={"chain": chain})}
                ),
            }
        )
        # Replace the supplied-package option, retaining both explicit predecessors.
        argv = (
            argv[:4]
            + argv[6:]
            + [
                "--follow-config",
                case.write("follow.json", follow),
                "--feed-config",
                case.write("feed.json", feed),
                "--once",
            ]
        )
    cli.main(argv)
    output = capsys.readouterr().out
    if mode == "follow":
        assert json.loads(output)["status"] == "published"
        history = SuccessorPublicationFeed(feed).history()
        assert len(history) == 1
        signed = history[0]
    else:
        signed = SignedSuccessorRoundPublication.model_validate_json(output)
    package = load_competition_package(
        Path(case.prepared.package_path),
        expected_package_sha256=case.prepared.package_sha256,
        expected_policy_sha256=digest(case.current),
        observed_release=case.release_identity,
        limits=case.package_limits,
    )
    verify_successor_round_publication(case.config.plan, signed, package)
    assert signed.intent.package.package_sha256 == case.prepared.package_sha256
    assert signed.intent.authorization.policy_sha256 == digest(case.current)
    assert case.events == ["provider", "start", "ready", "wallet", "wallet", "wallet", "close"]
    with case.store._connection() as db:
        assert db.execute("SELECT digest,body FROM submissions ORDER BY digest").fetchall() == (
            case.retained_bytes
        )
    assert registered_lineage(case.current).admitted_policy_sha256s == (digest(case.current),)


@pytest.mark.parametrize("selection", [(), (0,), (1, 0)])
def test_cli_rejects_missing_or_reordered_predecessors_before_authority_access(
    retained_successor, selection, capsys
):
    case = retained_successor
    # Leave the fixture's correct process registry in place: it must not mask
    # missing operator inputs on this invocation.
    before = registered_lineage(case.current).admitted_policy_sha256s
    assert len(before) == 3
    argv = case.argv + [
        argument
        for index in selection
        for argument in ("--predecessor-policy", case.predecessor_paths[index])
    ]
    with pytest.raises(SystemExit) as error:
        cli.main(argv)
    assert error.value.code == 2
    output = capsys.readouterr()
    assert output.out == "" and "publication rejected" in output.err
    assert digest(case.current) not in output.err
    assert not case.events
    assert not Path(case.config.publication_directory).exists()
    assert registered_lineage(case.current).admitted_policy_sha256s == before
