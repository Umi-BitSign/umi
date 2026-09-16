from fractions import Fraction
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.competition_chain import FinalizedRegistrationProvider
from umi.competition_package import load_competition_package, prepare_competition_package
from umi.competition_publication import settlement_signer_eligible
from umi.competition_weights import (
    CompetitionWeightAuthorizationBody,
    sign_competition_weight_authorization,
    verify_competition_weight_authorization,
)
from umi.open_competition import (
    BurnDestination,
    CompetitionPolicy,
    Evaluator,
    Registration,
    RegistrationSnapshot,
    digest,
    project_weights,
)
from umi.protocol import canonical_json_bytes
from umi.validator_chain import ValidatorChainError

from .test_competition_chain import _Runtime
from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_package import package_limits as package_limits
from .test_competition_package import release_identity as release_identity
from .test_competition_publication import _scenario
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_two_task_profile import launch_suite
from .test_open_competition import policy as policy
from .test_open_competition import result_for, round_for, snapshot, submission, wallet


def burn_policy(policy, *, owner="Ferdie", uid=0):
    return CompetitionPolicy.model_validate_json(
        canonical_json_bytes(
            {
                **policy.model_dump(mode="json", by_alias=True),
                "schema": "umi-open-competition-policy/3",
                "unallocated_model_burn": BurnDestination(
                    uid=uid, hotkey=wallet(owner).hotkey.ss58_address
                ).model_dump(mode="json"),
            }
        )
    )


def burn_snapshot(policy):
    base = snapshot(150)
    target = policy.unallocated_model_burn
    return RegistrationSnapshot(
        **base.model_dump(exclude={"registrations"}),
        registrations=(Registration(uid=target.uid, hotkey=target.hotkey), *base.registrations),
        burn_destination=target,
    )


def projection(policy, snap, *, contributor=None, baseline="hello"):
    endpoint = submission(policy, name="Bob")
    suite = launch_suite(policy)
    round_ = round_for(policy, suite, (endpoint,))
    return project_weights(
        policy=policy,
        round_=round_,
        suite=suite,
        evaluations=((endpoint, result_for(endpoint, round_, suite, baseline=baseline)),),
        snapshot=snap,
        current_block=150,
        promoted_model_sha256=round_.incumbent_model_sha256,
        promoted_hotkey=contributor,
    )


def test_burn_is_versioned_and_preserves_old_policy_and_snapshot_bytes(policy):
    for old in (policy, policy.model_copy(update={"schema_": "umi-open-competition-policy/2"})):
        body = old.model_dump(mode="json", by_alias=True)
        assert "unallocated_model_burn" not in body
        assert CompetitionPolicy.model_validate_json(canonical_json_bytes(body)) == old
        with pytest.raises(ValueError, match="version 3"):
            CompetitionPolicy.model_validate_json(
                canonical_json_bytes(
                    {
                        **body,
                        "unallocated_model_burn": burn_policy(
                            policy
                        ).unallocated_model_burn.model_dump(mode="json"),
                    }
                )
            )
    assert "burn_destination" not in snapshot().model_dump()
    body = policy.model_dump(mode="json", by_alias=True)
    body["schema"] = "umi-open-competition-policy/3"
    with pytest.raises(ValueError, match="version 3"):
        CompetitionPolicy.model_validate_json(canonical_json_bytes(body))
    assert digest(burn_policy(policy)) != digest(policy)


def test_unawarded_pool_is_burned_without_renormalizing_endpoint_share(policy):
    policy = burn_policy(policy)
    row = projection(policy, burn_snapshot(policy))
    amounts = {a.uid: Fraction(int(a.numerator), int(a.denominator)) for a in row.allocations}
    assert amounts == {0: Fraction(3, 10), 247: Fraction(7, 10)}
    assert sum(row.weights) == 65535
    assert row.weights[0] == 19661
    assert row.weights[247] == 45874
    assert row.chain_submission_authorized is False


def test_awarded_model_replaces_burn_without_changing_endpoint_share(policy):
    policy = burn_policy(policy)
    row = projection(policy, burn_snapshot(policy), contributor=wallet("Alice").hotkey.ss58_address)
    amounts = {a.uid: Fraction(int(a.numerator), int(a.denominator)) for a in row.allocations}
    assert amounts == {6: Fraction(3, 10), 247: Fraction(7, 10)}
    assert row.weights[0] == 0


@pytest.mark.parametrize("burn_owner", ["Ferdie", "Charlie"])
def test_unawarded_share_survives_signed_settlement_and_package_replay(
    policy,
    tmp_path,
    replay_limits,
    package_limits,
    release_identity,
    chain_config,
    burn_owner,
):
    policy = burn_policy(policy, owner=burn_owner)

    def current_snapshot(block=110):
        return burn_snapshot(policy).model_copy(
            update={
                "block": block,
                "block_hash": "0x" + f"{block:064x}",
            }
        )

    scenario = _scenario(
        policy,
        tmp_path / "scenario",
        replay_limits,
        promote_model=False,
        snapshot_factory=current_snapshot,
        suite_factory=launch_suite,
    )
    assert scenario.settlement.promotion_head.contributor_hotkey is None
    prepared = prepare_competition_package(
        policy=policy,
        cutoff_certificate=scenario.cutoff_certificate,
        settlement_certificate=scenario.settlement_certificate,
        retained_settlement=scenario.settlement,
        roster=scenario.submissions,
        evidence=scenario.evidence,
        replay_limits=replay_limits,
        release_identity=release_identity,
        destination_root=tmp_path / "packages",
        limits=package_limits,
    )
    path = Path(prepared.package_path)
    try:
        loaded = load_competition_package(
            path,
            expected_package_sha256=prepared.package_sha256,
            expected_policy_sha256=digest(policy),
            observed_release=release_identity,
            limits=package_limits,
        )
        assert loaded.retained_settlement.projection.weights[0] == 19661
        assert loaded.retained_settlement.projection.weights[247] == 45874
        assert loaded.retained_settlement.projection.weights[6] == 0
        body = CompetitionWeightAuthorizationBody(
            schema="umi-competition-weight-authorization/1",
            authorization_id="12" * 32,
            validator_scope="any_permitted_sn78",
            policy_sha256=digest(policy),
            package_sha256=loaded.package_sha256,
            settlement_sha256=loaded.manifest.settlement_sha256,
            projection_sha256=loaded.manifest.projection_sha256,
            release_identity_sha256=loaded.manifest.release_identity_sha256,
            predecessor_directive_sha256="34" * 32,
            required_recovery_profile="stopped_bootstrap_recovery/1",
            chain_pin=chain_config.chain_pin,
            required_finality_verifier_sha256_by_target={"aarch64-apple-darwin": "a2" * 32},
            required_storage_proof_verifier_sha256_by_target={"aarch64-apple-darwin": "a3" * 32},
            network="finney",
            netuid=78,
            mechanism_id=0,
            signed_at_block=160,
            valid_from_block=160,
            valid_through_block=200,
            weights_version_key=2**32,
            required_min_allowed_weights=256,
            required_max_allowed_uids=256,
            required_max_weights_limit=65535,
            required_weights_rate_limit=10,
            required_mechanism_count=1,
            required_commit_reveal_enabled=False,
            mortality_period=16,
            late_conflict_action="hold_no_automatic_correction",
        )
        authority = wallet("Ferdie")
        signed = sign_competition_weight_authorization(body, authority)
        assert (
            verify_competition_weight_authorization(
                signed,
                trusted_authority_hotkeys=(authority.hotkey.ss58_address,),
                package=loaded,
            )
            == body
        )
        unproven = loaded.retained_settlement.registration_snapshot.model_copy(
            update={"burn_destination": None},
        )
        missing_proof = loaded.model_copy(
            update={
                "retained_settlement": loaded.retained_settlement.model_copy(
                    update={
                        "registration_snapshot": unproven,
                    }
                ),
            }
        )
        with pytest.raises(ValueError, match="verified model burn"):
            verify_competition_weight_authorization(
                signed,
                trusted_authority_hotkeys=(authority.hotkey.ss58_address,),
                package=missing_proof,
            )
    finally:
        path.chmod(0o700)


@pytest.mark.parametrize(
    "mutation",
    [
        "policy_absent",
        "proof_absent",
        "wrong_uid",
        "wrong_share",
        "contributor",
        "roster",
        "paid_group",
    ],
)
def test_burn_signer_exception_does_not_exempt_paid_or_unproven_recipients(
    policy, tmp_path, replay_limits, mutation
):
    policy = burn_policy(policy, owner="Charlie")

    def current_snapshot(block=110):
        return burn_snapshot(policy).model_copy(
            update={"block": block, "block_hash": "0x" + f"{block:064x}"}
        )

    scenario = _scenario(
        policy,
        tmp_path,
        replay_limits,
        promote_model=False,
        snapshot_factory=current_snapshot,
        suite_factory=launch_suite,
    )
    publication = scenario.settlement_publication
    signer = wallet("Charlie").hotkey.ss58_address
    roster = scenario.submissions
    assert settlement_signer_eligible(signer, publication, policy, roster)
    settlement = publication.settlement
    if mutation == "policy_absent":
        policy = policy.model_copy(update={"unallocated_model_burn": None})
    elif mutation == "proof_absent":
        settlement = settlement.model_copy(
            update={
                "registration_snapshot": settlement.registration_snapshot.model_copy(
                    update={"burn_destination": None}
                )
            }
        )
    elif mutation in {"wrong_uid", "wrong_share"}:
        allocations = tuple(
            a.model_copy(
                update={"uid": 99}
                if mutation == "wrong_uid"
                else {"numerator": "4", "denominator": "10"}
            )
            if a.hotkey == signer
            else a
            for a in settlement.projection.allocations
        )
        settlement = settlement.model_copy(
            update={
                "projection": settlement.projection.model_copy(update={"allocations": allocations})
            }
        )
    elif mutation == "contributor":
        settlement = settlement.model_copy(
            update={
                "promotion_head": settlement.promotion_head.model_copy(
                    update={"contributor_hotkey": signer}
                )
            }
        )
    elif mutation == "roster":
        roster = (*roster, submission(policy, name="Charlie"))
    elif mutation == "paid_group":
        policy = policy.model_copy(
            update={
                "evaluators": (
                    *policy.evaluators,
                    Evaluator(hotkey=wallet("Bob").hotkey.ss58_address, control_group="c"),
                )
            }
        )
    publication = publication.model_copy(update={"settlement": settlement})
    assert not settlement_signer_eligible(signer, publication, policy, roster)


@pytest.mark.parametrize("mutation", ["absent", "different", "reused", "stale"])
def test_burn_requires_current_exact_proven_destination(policy, mutation):
    policy = burn_policy(policy)
    snap = burn_snapshot(policy)
    if mutation == "absent":
        snap = snap.model_copy(update={"burn_destination": None})
    elif mutation == "different":
        snap = snap.model_copy(
            update={
                "burn_destination": BurnDestination(
                    uid=6,
                    hotkey=wallet("Alice").hotkey.ss58_address,
                )
            }
        )
    elif mutation == "reused":
        snap = snap.model_copy(
            update={
                "registrations": (
                    Registration(uid=0, hotkey=wallet("Eve").hotkey.ss58_address),
                    *snap.registrations[1:],
                )
            }
        )
    else:
        snap = snap.model_copy(update={"block": 100})
    with pytest.raises(ValueError, match=r"burn|stale"):
        projection(policy, snap)


def test_burn_cannot_hide_stale_awarded_contributor_or_receive_rewards(policy):
    policy = burn_policy(policy)
    for contributor, baseline, error in (
        (wallet("Alice").hotkey.ss58_address, "", "promoted contributor"),
        (wallet("Eve").hotkey.ss58_address, "hello", "promoted contributor"),
        (wallet("Ferdie").hotkey.ss58_address, "hello", "burn destination"),
    ):
        with pytest.raises(ValueError, match=error):
            projection(policy, burn_snapshot(policy), contributor=contributor, baseline=baseline)


@pytest.fixture
def burn_chain(chain, tmp_path):
    policy = burn_policy(chain.policy, owner="Alice")
    chain.finality.policy = policy
    chain.rpc.values[("SubtensorModule", "SubnetOwnerHotkey", (78,))] = wallet(
        "Alice"
    ).hotkey.ss58_address
    chain.rpc.values[("SubtensorModule", "RecycleOrBurn", (78,))] = "Burn"
    config = chain.config.model_copy(
        update={
            "policy_sha256": digest(policy),
            "state_directory": str(tmp_path / "burn-chain"),
        }
    )
    chain.provider = FinalizedRegistrationProvider(
        config,
        policy,
        finality=chain.finality,
        proofs=chain.proofs,
        now_ms=lambda: chain.clock.now,
    )
    chain.policy = policy
    return chain


async def test_owned_provider_proves_burn_owner_and_mode_in_same_capture(burn_chain):
    capture = await burn_chain.provider.collect()
    assert capture.snapshot.burn_destination == burn_chain.policy.unallocated_model_burn
    assert len(burn_chain.verifier.checked) == 3
    assert capture.provenance["snapshot_sha256"] == digest(capture.snapshot)
    # Both claims use the same storage-proof verifier as the registration map.
    keys = [key for batch in burn_chain.verifier.checked for key, _ in batch["items"]]
    assert any(b"SubnetOwnerHotkey" in k for k in keys)
    assert any(b"RecycleOrBurn" in k for k in keys)


@pytest.mark.parametrize("default", ["Burn", "Recycle", None])
@pytest.mark.parametrize("bad_proof", [False, True])
async def test_burn_storage_absence_requires_verified_metadata_default(
    burn_chain, monkeypatch, default, bad_proof
):
    original = _Runtime.storage_entry

    def storage_entry(self, pallet, item):
        if (pallet, item) == ("SubtensorModule", "RecycleOrBurn") and default is not None:
            return SimpleNamespace(
                modifier="Default", default_bytes=canonical_json_bytes(default), value_type="json"
            )
        return original(self, pallet, item)

    monkeypatch.setattr(_Runtime, "storage_entry", storage_entry)
    del burn_chain.rpc.values[("SubtensorModule", "RecycleOrBurn", (78,))]
    burn_chain.rpc.bad_proof = bad_proof
    if default != "Burn" or bad_proof:
        with pytest.raises((ValueError, ValidatorChainError)):
            await burn_chain.provider.collect()
    else:
        capture = await burn_chain.provider.collect()
        assert capture.snapshot.burn_destination == burn_chain.policy.unallocated_model_burn
        assert any(
            b"RecycleOrBurn" in key and value is None
            for batch in burn_chain.verifier.checked
            for key, value in batch["items"]
        )


async def test_default_burn_does_not_allow_missing_owner(burn_chain, monkeypatch):
    original = _Runtime.storage_entry

    def storage_entry(self, pallet, item):
        if (pallet, item) == ("SubtensorModule", "RecycleOrBurn"):
            return SimpleNamespace(modifier="Default", default_bytes=b'"Burn"', value_type="json")
        return original(self, pallet, item)

    monkeypatch.setattr(_Runtime, "storage_entry", storage_entry)
    del burn_chain.rpc.values[("SubtensorModule", "RecycleOrBurn", (78,))]
    del burn_chain.rpc.values[("SubtensorModule", "SubnetOwnerHotkey", (78,))]
    with pytest.raises(ValueError, match="membership is incomplete"):
        await burn_chain.provider.collect()


@pytest.mark.parametrize("mutation", ["recycle", "missing", "owner", "uid", "proof"])
async def test_owned_provider_rejects_unproven_or_changed_burn(burn_chain, mutation):
    if mutation == "recycle":
        burn_chain.rpc.values[("SubtensorModule", "RecycleOrBurn", (78,))] = "Recycle"
    elif mutation == "missing":
        del burn_chain.rpc.values[("SubtensorModule", "RecycleOrBurn", (78,))]
    elif mutation == "owner":
        burn_chain.rpc.values[("SubtensorModule", "SubnetOwnerHotkey", (78,))] = wallet(
            "Bob"
        ).hotkey.ss58_address
    elif mutation == "uid":
        burn_chain.provider.policy = burn_chain.policy.model_copy(
            update={
                "unallocated_model_burn": BurnDestination(
                    uid=1, hotkey=wallet("Alice").hotkey.ss58_address
                ),
            }
        )
    else:
        burn_chain.rpc.bad_proof = True
    with pytest.raises((ValueError, ValidatorChainError)):
        await burn_chain.provider.collect()
