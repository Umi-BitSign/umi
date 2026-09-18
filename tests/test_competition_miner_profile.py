from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from umi.competition_cli import main
from umi.competition_launch import PublicRoundSchedule
from umi.competition_miner_profile import (
    MinerFeedProfile,
    SignedMinerFeedProfile,
    verify_miner_feed_profile,
)
from umi.open_competition import Evaluator, digest, sign_object
from umi.policy import scoring_policy_hash
from umi.protocol import canonical_json_bytes

from .test_competition_authorization import build_authorization_fixture
from .test_competition_dispatch import dispatch_legacy_policy
from .test_competition_rounds import deployment_for
from .test_open_competition import policy as policy
from .test_open_competition import wallet


@pytest.fixture
def setup(policy):
    policy = policy.model_copy(update={"valid_through_block": 5000})
    transport = dispatch_legacy_policy()
    schedule = PublicRoundSchedule(
        schema="umi-public-round-schedule/1",
        intake_opened_block=1000,
        roster_close_earliest_block=1100,
        roster_close_latest_block=1110,
        work_signing_close_block=1120,
        evaluation_close_block=1200,
        protected_reference_reveal_block=1220,
        evidence_cutoff_block=1240,
        round_valid_through_block=1300,
    )
    deployment = deployment_for(schedule, ("endpoint",))
    profile = MinerFeedProfile(
        schema="umi-miner-feed-profile/1",
        policy_sha256=digest(policy),
        transport_policy_sha256=scoring_policy_hash(transport),
        public_launch=deployment.launch_identity(),
        assignment_feed_origin="https://assignments.example",
        allowed_video_origins=("https://clips.example",),
    )
    signed = sign(profile)
    return SimpleNamespace(policy=policy, transport=transport, deployment=deployment, signed=signed)


def sign(profile, names=("Charlie", "Dave")):
    return SignedMinerFeedProfile(
        profile=profile, signatures=tuple(sign_object(profile, wallet(name)) for name in names)
    )


def verify(setup, signed=None, **overrides):
    signed = signed or setup.signed
    values = {
        "expected_profile_sha256": digest(signed),
        "policy": setup.policy,
        "transport": setup.transport,
        "public_launch": setup.deployment.launch_identity(),
        "current_block": 1050,
        **overrides,
    }
    return verify_miner_feed_profile(signed, **values)


def test_valid_profile_is_connection_information_only(setup):
    assert verify(setup) == setup.signed.profile
    assert verify(setup).chain_submission_authorized is False
    for block in (1000, 1200):
        assert verify(setup, current_block=block) == setup.signed.profile


def test_single_evaluator_profile_and_transport_require_the_same_signer(setup):
    item = build_authorization_fixture(setup.policy, single_evaluator=True)
    profile = setup.signed.profile.model_copy(
        update={
            "policy_sha256": digest(item.policy),
            "transport_policy_sha256": scoring_policy_hash(item.legacy_policy),
        }
    )
    signed = sign(profile, ("Validator0",))
    assert verify(setup, signed, policy=item.policy, transport=item.legacy_policy) == profile
    policy = item.policy.model_copy(
        update={
            "evaluators": (
                Evaluator(hotkey=wallet("Charlie").hotkey.ss58_address, control_group="different"),
            )
        }
    )
    signed = sign(profile.model_copy(update={"policy_sha256": digest(policy)}), ("Charlie",))
    with pytest.raises(ValueError, match="cohort"):
        verify(setup, signed, policy=policy, transport=item.legacy_policy)


@pytest.mark.parametrize("block", [999, 1201, True, 1050.0, "1050"])
def test_profile_rejects_invalid_or_out_of_round_block(setup, block):
    with pytest.raises(ValueError, match="interval"):
        verify(setup, current_block=block)


@pytest.mark.parametrize("field", ["policy_sha256", "transport_policy_sha256"])
def test_even_authorized_signers_cannot_change_reviewed_policy(setup, field):
    signed = sign(setup.signed.profile.model_copy(update={field: "00" * 32}))
    with pytest.raises(ValueError, match="binding"):
        verify(setup, signed)


def test_signed_schedule_cannot_replace_public_deadline(setup):
    launch = setup.deployment.launch_identity()
    changed = launch.model_copy(
        update={
            "round_schedule": launch.round_schedule.model_copy(
                update={"evaluation_close_block": 1199}
            )
        }
    )
    signed = sign(setup.signed.profile.model_copy(update={"public_launch": changed}))
    with pytest.raises(ValueError, match="binding"):
        verify(setup, signed)


def test_profile_cannot_outlive_policy(setup):
    policy = setup.policy.model_copy(update={"valid_through_block": 1250})
    signed = sign(setup.signed.profile.model_copy(update={"policy_sha256": digest(policy)}))
    with pytest.raises(ValueError, match="interval"):
        verify(setup, signed, policy=policy)


@pytest.mark.parametrize("names", [("Charlie",), ("Charlie", "Charlie"), ("Charlie", "Alice")])
def test_profile_rejects_missing_duplicate_or_untrusted_signers(setup, names):
    with pytest.raises(ValueError):
        verify(setup, sign(setup.signed.profile, names))


def test_two_keys_in_one_control_group_are_not_quorum(setup):
    policy = setup.policy.model_copy(
        update={
            "evaluators": (
                Evaluator(hotkey=wallet("Charlie").hotkey.ss58_address, control_group="shared"),
                Evaluator(hotkey=wallet("Dave").hotkey.ss58_address, control_group="shared"),
                Evaluator(hotkey=wallet("Ferdie").hotkey.ss58_address, control_group="independent"),
            )
        }
    )
    signed = sign(setup.signed.profile.model_copy(update={"policy_sha256": digest(policy)}))
    with pytest.raises(ValueError, match="duplicate"):
        verify(setup, signed, policy=policy)


def test_profile_requires_exact_announced_signed_digest(setup):
    with pytest.raises(ValueError, match="published digest"):
        verify(setup, expected_profile_sha256="00" * 32)


def test_changed_origin_with_old_signatures_is_rejected(setup):
    signed = setup.signed.model_copy(
        update={
            "profile": setup.signed.profile.model_copy(
                update={"assignment_feed_origin": "https://attacker.example"}
            )
        }
    )
    with pytest.raises(ValueError, match="signature"):
        verify(setup, signed)


@pytest.mark.parametrize(
    "origin",
    [
        "http://clips.example",
        "https://user:password@clips.example",
        "https://clips.example/path",
        "https://clips.example?token=private",
        "https://clips.example#fragment",
        "https://clips.example/",
        "https://clips.example\n",
    ],
)
@pytest.mark.parametrize("field", ["assignment_feed_origin", "allowed_video_origins"])
def test_profile_rejects_unsafe_origins(setup, origin, field):
    raw = setup.signed.profile.model_dump(mode="json", by_alias=True)
    raw[field] = [origin] if field == "allowed_video_origins" else origin
    with pytest.raises(ValueError):
        MinerFeedProfile.model_validate_json(canonical_json_bytes(raw))


def test_profile_origins_are_canonical_and_reward_claim_is_forbidden(setup):
    raw = setup.signed.profile.model_dump(mode="json", by_alias=True)
    for update in (
        {"allowed_video_origins": ["https://clips.example", "https://clips.example"]},
        {"allowed_video_origins": ["https://z.example", "https://a.example"]},
        {"allowed_video_origins": []},
        {"chain_submission_authorized": True},
    ):
        with pytest.raises(ValueError):
            MinerFeedProfile.model_validate_json(canonical_json_bytes({**raw, **update}))


def test_cli_verification_loads_no_wallet_and_preserves_inputs(
    setup, tmp_path, monkeypatch, capsys
):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("profile verification must not load a wallet")

    monkeypatch.setattr("bittensor.Wallet", forbidden)
    paths = {}
    for name, value in {
        "policy": setup.policy,
        "legacy-policy": setup.transport,
        "deployment": setup.deployment,
        "profile": setup.signed,
    }.items():
        path = tmp_path / (name + ".json")
        path.write_bytes(canonical_json_bytes(value))
        paths[name] = path
    before = {p: p.read_bytes() for p in tmp_path.iterdir()}
    args = ["--policy", str(paths.pop("policy")), "verify-miner-feed-profile"]
    for name, path in paths.items():
        args.extend(["--" + name, str(path)])
    main([*args, "--expected-profile-sha256", digest(setup.signed), "--current-block", "1050"])
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "miner_feed_profile_verified"
    for key in (
        "finality_verified",
        "assignment_authorized",
        "availability_verified",
        "chain_submission_authorized",
    ):
        assert result[key] is False
    assert {p: p.read_bytes() for p in tmp_path.iterdir()} == before
