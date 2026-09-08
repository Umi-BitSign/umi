from __future__ import annotations

import hashlib

import bittensor as bt
import pytest
from pydantic import ValidationError

from tests.factories import dev_wallet
from umi.bootstrap_weights import (
    BOOTSTRAP_ELIGIBILITY_MANIFEST_SCHEMA,
    BOOTSTRAP_MANIFEST_SIGNATURE_DOMAIN,
    BOOTSTRAP_OPT_IN_SCHEMA,
    BOOTSTRAP_OPT_IN_SIGNATURE_DOMAIN,
    BOOTSTRAP_POLICY_HASH_DOMAIN,
    BOOTSTRAP_WEIGHT_POLICY_SCHEMA,
    U16_MAX,
    BootstrapEligibilityEntry,
    BootstrapEligibilityManifest,
    BootstrapOptIn,
    BootstrapWeightPolicy,
    SignedBootstrapEligibilityManifest,
    bootstrap_manifest_digest,
    bootstrap_opt_in_digest,
    bootstrap_policy_hash,
    build_bootstrap_eligibility_manifest,
    sign_bootstrap_eligibility_manifest,
    sign_bootstrap_opt_in,
    verify_bootstrap_opt_in,
    verify_signed_bootstrap_eligibility_manifest,
)
from umi.encoding import account_id32
from umi.protocol import canonical_json_bytes


def _policy(coordinator=None, **changes) -> BootstrapWeightPolicy:
    if coordinator is None:
        coordinator = dev_wallet("//BootstrapCoordinator")
    values = {
        "schema": BOOTSTRAP_WEIGHT_POLICY_SCHEMA,
        "network": "finney",
        "netuid": 78,
        "mechanism_id": 0,
        "translation_weights_active": False,
        "service_weights_active": True,
        "campaign_id": "11" * 32,
        "public_evidence_origin": "https://api.umi.vision",
        "coordinator_hotkey": coordinator.hotkey.ss58_address,
        "umi_git_revision": "ab" * 20,
        "weights_version_key": 1,
        "published_at_block": 100,
        "activation_block": 120,
        "commit_stop_block": 49_080,
        "hard_sunset_block": 50_520,
        "health_ttl_blocks": 10,
        "manifest_ttl_blocks": 5,
    }
    values.update(changes)
    return BootstrapWeightPolicy.model_validate(values)


def _entry(
    policy: BootstrapWeightPolicy,
    wallet,
    *,
    pilot_byte: str,
    uid: int,
    pilot_block: int = 90,
    signed_at_block: int = 110,
    health_block: int = 125,
) -> BootstrapEligibilityEntry:
    pilot_id = pilot_byte * 64
    opt_in = sign_bootstrap_opt_in(
        policy,
        pilot_id=pilot_id,
        wallet=wallet,
        signed_at_block=signed_at_block,
    )
    return BootstrapEligibilityEntry(
        pilot_id=pilot_id,
        miner_hotkey=wallet.hotkey.ss58_address,
        uid=uid,
        origin="https://8.8.8.8:443",
        pilot_block=pilot_block,
        health_block=health_block,
        utility=1,
        opt_in=opt_in,
    )


def test_policy_is_strict_inactive_translation_active_service_and_bounded() -> None:
    policy = _policy()

    assert policy.translation_weights_active is False
    assert policy.service_weights_active is True
    assert policy.netuid == 78
    assert policy.mechanism_id == 0
    assert policy.model_config["strict"] is True
    assert policy.model_config["frozen"] is True

    document = policy.model_dump(mode="json", by_alias=True)
    document["translation_weights_active"] = True
    with pytest.raises(ValidationError):
        BootstrapWeightPolicy.model_validate(document)
    document = policy.model_dump(mode="json", by_alias=True)
    document["unexpected"] = True
    with pytest.raises(ValidationError):
        BootstrapWeightPolicy.model_validate(document)
    with pytest.raises(ValidationError, match="published_at_block"):
        _policy(activation_block=100)
    with pytest.raises(ValidationError, match="exactly 50,400 blocks"):
        _policy(hard_sunset_block=50_521)
    with pytest.raises(ValidationError, match="exactly 1,440 blocks"):
        _policy(commit_stop_block=49_079)


def test_policy_and_signature_digests_are_domain_separated_canonical_sha256() -> None:
    coordinator = dev_wallet("//DigestCoordinator")
    miner = dev_wallet("//DigestMiner")
    policy = _policy(coordinator)
    opt_in = sign_bootstrap_opt_in(
        policy,
        pilot_id="22" * 32,
        wallet=miner,
        signed_at_block=110,
    )
    entry = _entry(policy, miner, pilot_byte="2", uid=2)
    manifest = build_bootstrap_eligibility_manifest(
        policy,
        [entry],
        frozen_at_block=125,
        frozen_at_block_hash="0x" + "12" * 32,
    )

    assert (
        bootstrap_policy_hash(policy)
        == hashlib.sha256(BOOTSTRAP_POLICY_HASH_DOMAIN + canonical_json_bytes(policy)).hexdigest()
    )
    unsigned_opt_in = {
        "schema": BOOTSTRAP_OPT_IN_SCHEMA,
        "policy_sha256": opt_in.policy_sha256,
        "pilot_id": opt_in.pilot_id,
        "miner_hotkey": opt_in.miner_hotkey,
        "signed_at_block": opt_in.signed_at_block,
    }
    assert (
        bootstrap_opt_in_digest(opt_in)
        == hashlib.sha256(
            BOOTSTRAP_OPT_IN_SIGNATURE_DOMAIN + canonical_json_bytes(unsigned_opt_in)
        ).digest()
    )
    assert (
        bootstrap_manifest_digest(manifest)
        == hashlib.sha256(
            BOOTSTRAP_MANIFEST_SIGNATURE_DOMAIN + canonical_json_bytes(manifest)
        ).digest()
    )


@pytest.mark.parametrize(
    ("crypto_type", "expected_scheme"),
    [
        (bt.sp_core.CRYPTO_SR25519, "sr25519"),
        (bt.sp_core.CRYPTO_ED25519, "ed25519"),
    ],
)
def test_miner_opt_in_is_signed_after_publication_and_bound_to_policy_pilot_and_hotkey(
    crypto_type, expected_scheme
) -> None:
    policy = _policy()
    miner = dev_wallet("//OptInMiner", crypto_type=crypto_type)

    opt_in = sign_bootstrap_opt_in(
        policy,
        pilot_id="33" * 32,
        wallet=miner,
        signed_at_block=101,
    )

    assert opt_in.signature_scheme == expected_scheme
    assert verify_bootstrap_opt_in(opt_in, policy=policy) == opt_in
    with pytest.raises(ValueError, match="published policy interval"):
        sign_bootstrap_opt_in(
            policy,
            pilot_id="33" * 32,
            wallet=miner,
            signed_at_block=100,
        )
    with pytest.raises(ValueError, match="published policy interval"):
        sign_bootstrap_opt_in(
            policy,
            pilot_id="33" * 32,
            wallet=miner,
            signed_at_block=policy.commit_stop_block,
        )

    changed = opt_in.model_dump(mode="json", by_alias=True)
    changed["pilot_id"] = "44" * 32
    with pytest.raises(ValueError, match="signature is invalid"):
        verify_bootstrap_opt_in(BootstrapOptIn.model_validate(changed), policy=policy)
    changed = opt_in.model_dump(mode="json", by_alias=True)
    changed["policy_sha256"] = "55" * 32
    with pytest.raises(ValueError, match="another policy"):
        verify_bootstrap_opt_in(BootstrapOptIn.model_validate(changed), policy=policy)


def test_manifest_sorts_by_account_and_builds_exact_max_upscaled_equal_row() -> None:
    coordinator = dev_wallet("//SortCoordinator")
    policy = _policy(coordinator)
    miners = [dev_wallet(f"//SortMiner{index}") for index in range(3)]
    entries = [
        _entry(policy, miners[0], pilot_byte="1", uid=9),
        _entry(policy, miners[1], pilot_byte="2", uid=2),
        _entry(policy, miners[2], pilot_byte="3", uid=7),
    ]

    manifest = build_bootstrap_eligibility_manifest(
        policy,
        list(reversed(entries)),
        frozen_at_block=125,
        frozen_at_block_hash="0x" + "12" * 32,
    )

    accounts = [account_id32(entry.miner_hotkey) for entry in manifest.entries]
    assert accounts == sorted(accounts)
    # Bittensor max-upscales equal positive inputs. Each encoded destination is
    # 65535; the row is not a fixed-sum apportionment.
    assert [(item.uid, item.value) for item in manifest.quantized_row] == [
        (2, U16_MAX),
        (7, U16_MAX),
        (9, U16_MAX),
    ]
    assert sum(item.value for item in manifest.quantized_row) == 3 * U16_MAX


@pytest.mark.parametrize("duplicate", ["hotkey", "uid", "pilot"])
def test_manifest_rejects_duplicate_identity_dimensions(duplicate: str) -> None:
    policy = _policy()
    first_wallet = dev_wallet("//DuplicateFirst")
    second_wallet = first_wallet if duplicate == "hotkey" else dev_wallet("//DuplicateSecond")
    first = _entry(policy, first_wallet, pilot_byte="6", uid=6)
    second = _entry(
        policy,
        second_wallet,
        pilot_byte="6" if duplicate == "pilot" else "7",
        uid=6 if duplicate == "uid" else 7,
    )

    label = {"hotkey": "miner hotkey", "uid": "UID", "pilot": "pilot"}[duplicate]
    with pytest.raises(ValidationError, match=f"duplicate {label}"):
        build_bootstrap_eligibility_manifest(
            policy,
            [first, second],
            frozen_at_block=125,
            frozen_at_block_hash="0x" + "12" * 32,
        )


def test_manifest_rejects_stale_health_and_blocks_outside_activation_or_sunset() -> None:
    policy = _policy()
    miner = dev_wallet("//FreshnessMiner")
    stale = _entry(policy, miner, pilot_byte="8", uid=8, health_block=124)

    with pytest.raises(ValidationError, match="policy activation"):
        build_bootstrap_eligibility_manifest(
            policy,
            [stale],
            frozen_at_block=119,
            frozen_at_block_hash="0x" + "12" * 32,
        )
    with pytest.raises(ValidationError, match="policy activation"):
        build_bootstrap_eligibility_manifest(
            policy,
            [stale],
            frozen_at_block=50_520,
            frozen_at_block_hash="0x" + "12" * 32,
        )

    stale = _entry(policy, miner, pilot_byte="8", uid=8, health_block=120)
    with pytest.raises(ValidationError, match="exceeds the policy TTL"):
        build_bootstrap_eligibility_manifest(
            policy,
            [stale],
            frozen_at_block=131,
            frozen_at_block_hash="0x" + "12" * 32,
        )


def test_coordinator_signature_freezes_manifest_and_submission_freshness() -> None:
    coordinator = dev_wallet("//SigningCoordinator")
    policy = _policy(coordinator)
    entry = _entry(policy, dev_wallet("//SigningMiner"), pilot_byte="9", uid=9)
    manifest = build_bootstrap_eligibility_manifest(
        policy,
        [entry],
        frozen_at_block=125,
        frozen_at_block_hash="0x" + "12" * 32,
    )

    signed = sign_bootstrap_eligibility_manifest(manifest, wallet=coordinator)

    assert isinstance(signed, SignedBootstrapEligibilityManifest)
    assert signed.manifest_sha256 == hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()
    assert (
        verify_signed_bootstrap_eligibility_manifest(
            signed,
            expected_coordinator_hotkey=coordinator.hotkey.ss58_address,
            current_block=130,
        )
        == signed
    )
    with pytest.raises(ValueError, match="manifest TTL"):
        verify_signed_bootstrap_eligibility_manifest(signed, current_block=131)
    with pytest.raises(ValueError, match="active submission interval"):
        verify_signed_bootstrap_eligibility_manifest(signed, current_block=49_080)

    wrong_coordinator = dev_wallet("//WrongCoordinator")
    with pytest.raises(ValueError, match="expected coordinator"):
        verify_signed_bootstrap_eligibility_manifest(
            signed,
            expected_coordinator_hotkey=wrong_coordinator.hotkey.ss58_address,
        )


def test_tampered_manifest_hash_or_coordinator_signature_fails_closed() -> None:
    coordinator = dev_wallet("//TamperCoordinator")
    policy = _policy(coordinator)
    entry = _entry(policy, dev_wallet("//TamperMiner"), pilot_byte="a", uid=10)
    manifest = build_bootstrap_eligibility_manifest(
        policy,
        [entry],
        frozen_at_block=125,
        frozen_at_block_hash="0x" + "12" * 32,
    )
    signed = sign_bootstrap_eligibility_manifest(manifest, wallet=coordinator)

    changed = signed.model_dump(mode="json", by_alias=True)
    changed["manifest_sha256"] = "ff" * 32
    with pytest.raises(ValueError, match="SHA-256"):
        verify_signed_bootstrap_eligibility_manifest(
            SignedBootstrapEligibilityManifest.model_validate(changed)
        )

    changed = signed.model_dump(mode="json", by_alias=True)
    changed["signature"] = "0x" + "ff" * 64
    with pytest.raises(ValueError, match="signature is invalid"):
        verify_signed_bootstrap_eligibility_manifest(
            SignedBootstrapEligibilityManifest.model_validate(changed)
        )


def test_manifest_schema_is_exact_and_quantized_row_cannot_be_rewritten() -> None:
    policy = _policy()
    entry = _entry(policy, dev_wallet("//ExactRowMiner"), pilot_byte="b", uid=11)
    manifest = build_bootstrap_eligibility_manifest(
        policy,
        [entry],
        frozen_at_block=125,
        frozen_at_block_hash="0x" + "12" * 32,
    )
    document = manifest.model_dump(mode="json", by_alias=True)

    assert document["schema"] == BOOTSTRAP_ELIGIBILITY_MANIFEST_SCHEMA
    document["quantized_row"][0]["value"] = U16_MAX - 1
    with pytest.raises(ValidationError):
        BootstrapEligibilityManifest.model_validate(document)
