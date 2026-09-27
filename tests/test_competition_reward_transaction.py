"""Real codec/crypto with an explicit substituted projection boundary.

These tests check the connection to encoded transaction bytes. The complete
history/package/proof path has separate tests; this fixture is not that proof.
"""

import asyncio
import hashlib
from types import SimpleNamespace

import pytest

from umi.competition_cohort_reward_allocation import CohortRewardProjection
from umi.competition_reward_preparation import StandingRewardPreparation
from umi.signed_extrinsic import encode_verified_mortal_call

from .test_signed_extrinsic_native import native_encoding as native_encoding


@pytest.fixture
def transaction(native_encoding):
    item = native_encoding
    context = item.context
    current = SimpleNamespace(
        projection=CohortRewardProjection(
            schema="umi-cohort-reward-projection/1",
            allocation_sha256="aa" * 32,
            snapshot_sha256="ab" * 32,
            recipients=(),
            uids=(1, 2),
            weights=(20000, 45535),
        ),
        current=SimpleNamespace(selection=SimpleNamespace(decision_sha256="ac" * 32)),
        prepared=SimpleNamespace(activation={"test_activation": True}),
    )
    chain = SimpleNamespace(
        runtime=context["runtime"],
        validator_hotkey=context["validator_hotkey"],
        validator_nonce=context["nonce"],
        genesis_hash=context["genesis_hash"],
        weights_version_key=1,
        block=123,
        block_hash=context["runtime"].snapshot.block_hash,
        validator_last_update=100,
        weights_rate_limit=10,
        validator_permit=True,
        mechanism_count=1,
        commit_reveal_enabled=False,
        registered_uid_count=3,
        max_allowed_uids=256,
        min_allowed_weights=1,
        max_weights_limit=65535,
        chain_config_sha256="ad" * 32,
        evidence=b'{"synthetic_chain":true}',
        evidence_sha256=hashlib.sha256(b'{"synthetic_chain":true}').hexdigest(),
    )
    owner = object.__new__(StandingRewardPreparation)
    owner._lock = asyncio.Lock()
    owner.series_sha256 = "ae" * 32
    owner.reader = SimpleNamespace(series=SimpleNamespace(maximum_transaction_lifetime_blocks=128))
    checks = []

    def project(*args):
        checks.append(args)
        return current

    owner._project = project
    options = dict(
        mortality_period=128,
        control=SimpleNamespace(evidence=b'{"synthetic_control":true}'),
        history=object(),
        source=lambda _: b"",
        chain=chain,
        chain_config=object(),
    )
    encoded = encode_verified_mortal_call(item.call, signer=item.signer, **context)
    return SimpleNamespace(
        owner=owner,
        prepared=object(),
        options=options,
        checks=checks,
        encoded=encoded,
        current=current,
        chain=chain,
        native=item,
    )


async def test_checked_projection_binds_full_encoded_call_and_receipt_search(transaction):
    t = transaction
    query = await t.owner.verify_transaction_bytes(t.prepared, t.encoded, **t.options)
    assert query.birth_block == t.chain.block and query.birth_hash == t.chain.block_hash
    assert query.mortality_period == 128 and bytes.fromhex(query.signed_extrinsic) == t.encoded
    assert (
        t.checks
        == [
            (
                t.prepared,
                t.options["control"],
                t.options["history"],
                t.options["source"],
                t.chain,
                t.options["chain_config"],
            )
        ]
        * 2
    )


@pytest.mark.parametrize("fault", ["nonce", "version", "row", "limit", "projection_hold"])
async def test_changed_preflight_cannot_supply_receipt_bounds(transaction, fault):
    t = transaction
    if fault == "nonce":
        t.chain.validator_nonce += 1
    elif fault == "version":
        t.chain.weights_version_key += 1
    elif fault == "row":
        t.current.projection = t.current.projection.model_copy(update={"weights": (20001, 45534)})
    elif fault == "limit":
        t.owner.reader.series.maximum_transaction_lifetime_blocks = 64
    else:

        def held(*args):
            raise ValueError("native selection is held")

        t.owner._project = held
    with pytest.raises(ValueError):
        await t.owner.verify_transaction_bytes(t.prepared, t.encoded, **t.options)


async def test_expiry_during_native_decode_is_rechecked(transaction):
    t = transaction
    project = t.owner._project

    def expired(*args):
        if t.checks:
            raise ValueError("proof expired during verification")
        return project(*args)

    t.owner._project = expired
    with pytest.raises(ValueError, match="expired during"):
        await t.owner.verify_transaction_bytes(t.prepared, t.encoded, **t.options)
    assert not t.owner._lock.locked()
