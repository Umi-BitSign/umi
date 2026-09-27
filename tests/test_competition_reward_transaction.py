"""Real codec/crypto with an explicit substituted projection boundary.

These tests check the connection to encoded transaction bytes. The complete
history/package/proof path has separate tests; this fixture is not that proof.
"""

import asyncio
from types import SimpleNamespace

import pytest

from umi.competition_reward_preparation import StandingRewardPreparation
from umi.signed_extrinsic import encode_verified_mortal_call

from .test_signed_extrinsic_native import native_encoding as native_encoding


@pytest.fixture
def transaction(native_encoding):
    item = native_encoding
    context = item.context
    current = SimpleNamespace(
        projection=SimpleNamespace(uids=(0, 1, 2), weights=(0, 20000, 45535)),
        current=object(),
    )
    chain = SimpleNamespace(
        runtime=context["runtime"],
        validator_hotkey=context["validator_hotkey"],
        validator_nonce=context["nonce"],
        genesis_hash=context["genesis_hash"],
        weights_version_key=1,
        block=123,
        block_hash=context["runtime"].snapshot.block_hash,
    )
    owner = object.__new__(StandingRewardPreparation)
    owner._lock = asyncio.Lock()
    owner.reader = SimpleNamespace(series=SimpleNamespace(maximum_transaction_lifetime_blocks=128))
    checks = []

    def project(*args):
        checks.append(args)
        return current

    owner._project = project
    options = dict(
        mortality_period=128,
        control=object(),
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
        t.current.projection.weights = (0, 20001, 45534)
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
