"""Repeated native signing/proof/storage recovery across cold provider restarts.

Finality/trie ports and reward selection are synthetic. Current collection,
historical proof consumers, SCALE, signatures, preparation and journal I/O are
real. This does not qualify installed reward authority or chain transmission.
"""

import asyncio
import json
from dataclasses import replace
from types import SimpleNamespace

from umi.competition_reward_preparation import StandingRewardPreparation
from umi.competition_reward_transaction_outcome import resolve_standing_transaction
from umi.competition_reward_transactions import standing_weight_call
from umi.protocol import canonical_json_bytes
from umi.signed_extrinsic import encode_verified_mortal_call
from umi.validator_chain import FinalizedProofCollector

from .test_competition_reward_transaction_outcome import at, reopen
from .test_competition_reward_transaction_recovery import chain_config as chain_config
from .test_competition_reward_transaction_recovery import native_encoding as native_encoding
from .test_competition_reward_transaction_recovery import original as original
from .test_competition_reward_transaction_recovery import policy as policy


async def test_three_original_intents_survive_repeated_expiry_and_restart(
    original, native_encoding
):
    t = original
    codec = t.chain.runtime
    storage = {}
    for batch in json.loads(t.chain.evidence)["storage_batches"]:
        storage.update(
            (bytes.fromhex(c["key"][2:]), bytes.fromhex(c["value"][2:])) for c in batch["claims"]
        )
    raw_rpc, states = t.rpc.request, {bytes.fromhex(t.old.state_root[2:]): storage.copy()}
    live = False

    async def request(method, params):
        if method in {"chain_getHeader", "chain_getBlockHash"}:
            return await raw_rpc(method, params)
        assert live and params[-1] == t.finality.ref.block_hash, "historical state RPC disabled"
        if method == "state_getMetadata":
            return "0x" + codec.metadata_bytes.hex()
        if method == "state_getRuntimeVersion":
            return json.loads(codec.runtime_version_bytes)
        if method == "state_getStorageAt":
            return "0x" + storage[bytes.fromhex(params[0][2:])].hex()
        if method == "state_getReadProof":
            return {"at": t.finality.ref.block_hash, "proof": ["0x" + b"fixture-proof".hex()]}
        raise AssertionError(method)

    class Verifier:
        def __call__(self, **kwargs):
            raise AssertionError("unexpected single proof")

        def read_many(self, *, state_root, storage_keys, proof, **limits):
            expected = states.get(state_root, {})
            values = tuple((key, expected.get(key)) for key in storage_keys)
            if not self.verify_many(state_root=state_root, proof=proof, items=values):
                raise ValueError("invalid synthetic proof")
            return values

        def verify_many(self, **kwargs):
            expected = states.get(kwargs["state_root"], {})
            return kwargs["proof"] == (b"fixture-proof",) and all(
                k in expected and expected[k] == v for k, v in kwargs["items"]
            )

    t.rpc.request = request
    proofs = FinalizedProofCollector(t.rpc, finality=t.finality, verifier=Verifier())
    t.provider._proofs = proofs
    originals = [t.journal.recovery_inputs()]

    def encode(pallet, name, params, value):
        storage[codec.storage_key(pallet, name, params)] = bytes(
            codec._runtime.encode(codec._runtime.storage_entry(pallet, name).value_type, value)
        )

    for step in (1, 2):
        end = await resolve_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey)
        assert end.reason == "expired_outcome_unknown"
        t.clock.now += 60_000
        root = "0x" + f"{step + 100:064x}"
        t.finality.ref = replace(t.finality.ref, state_root=root)
        at(t, t.finality.ref.block_number - t.old.height + 1)
        encode("Timestamp", "Now", (), t.finality.timestamp)
        # An unchanged nonce is valid when none of the prior bytes landed.
        states[bytes.fromhex(root[2:])] = storage.copy()
        live = True
        control = await t.provider.collect_control(t.hotkey)
        chain = await t.provider.collect_registered_weights(t.hotkey, at=control.snapshot)
        current = SimpleNamespace(
            projection=t.intent.projection,
            current=SimpleNamespace(
                selection=SimpleNamespace(decision_sha256=control.control_sha256)
            ),
            prepared=SimpleNamespace(activation={"synthetic_selection": step}),
        )
        owner = object.__new__(StandingRewardPreparation)
        owner._lock = asyncio.Lock()
        owner.series_sha256 = t.intent.series_sha256
        owner.reader = SimpleNamespace(
            series=SimpleNamespace(maximum_transaction_lifetime_blocks=128)
        )
        owner._project = lambda *args, selected=current: selected
        options = dict(
            mortality_period=128,
            control=control,
            history=object(),
            source=lambda _: b"",
            chain=chain,
            chain_config=t.provider.config,
        )
        pending = await owner.reserve_transaction(object(), t.journal, previous=end, **options)
        encoded = encode_verified_mortal_call(
            standing_weight_call(current.projection, chain),
            runtime=chain.runtime,
            signer=native_encoding.signer,
            validator_hotkey=t.hotkey,
            nonce=chain.validator_nonce,
            mortality_period=128,
            genesis_hash=chain.genesis_hash,
        )
        signed = await owner.retain_signed_transaction(object(), t.journal, encoded, **options)
        assert signed.intent == pending.intent and signed.signed.signed_extrinsic == encoded.hex()
        originals.append(t.journal.recovery_inputs())
        live = False
        await t.provider.aclose()
        at(t, signed.intent.block - t.old.height + 128)
        t.journal = reopen(t)
        t.provider = t.reopen()
        t.provider._proofs = proofs

    end = await resolve_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey)
    assert end.pending == originals[-1].pending
    assert end.reason == "expired_outcome_unknown"
    assert len(t.journal.journal.keys("standing_weight_intent")) == 3
    assert len(t.journal.journal.keys("standing_weight_successor")) == 2
    for saved in originals:
        assert t.journal._object(saved.pending.intent.chain_evidence_sha256) == saved.chain
        assert t.journal._object(saved.pending.intent.control_evidence_sha256) == saved.control
    assert len({canonical_json_bytes(s.pending.signed) for s in originals}) == 3
