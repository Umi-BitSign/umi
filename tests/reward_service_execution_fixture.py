"""Join the native service, host fence and executor with a simulated ledger.

Package/selection/projection and chain outcome verification remain explicit
ports, inherited from the host fixture. The executor is constructed normally;
writer locks, host binding, transaction reservation, SCALE/signatures, retained
bytes and recurring restart are native. This is not installed-chain evidence.
"""

import asyncio
import copy
import hashlib
from dataclasses import replace
from types import SimpleNamespace

import bittensor as bt

from umi import competition_reward_executor as execution
from umi import competition_reward_service as service
from umi.competition_cohort_reward_allocation import CohortRewardProjection
from umi.competition_reward_manifest import (
    RewardOpportunityTerms,
    RewardReplayRequirement,
    StandingRewardOpportunityManifest,
)
from umi.competition_reward_transactions import _issue_standing_end
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.signed_extrinsic import verify_mortal_call


def connect_executor(c, native, monkeypatch):
    c.preparation.manifest = StandingRewardOpportunityManifest(
        schema="umi-standing-reward-manifest/2",
        policy_sha256=c.preparation.policy_sha256,
        cohorts=tuple(
            RewardReplayRequirement(
                cohort_sha256=digest(plan), terms_sha256="20" * 32, catalog_sha256s=("21" * 32,)
            )
            for plan in c.series.cohorts
        ),
        opportunity=RewardOpportunityTerms(
            runtime_profile_sha256="22" * 32,
            maximum_interval_ms=12_000,
            minimum_validator_ms=86_400_000,
        ),
    )
    c.approval = c.approval.model_copy(update={"manifest_sha256": digest(c.preparation.manifest)})
    c.publish(canonical_json_bytes(c.approval))
    c.preparation.reader.policy = c.provider.policy
    c.preparation._lock = asyncio.Lock()
    runtime = native.context["runtime"]
    runtime = replace(runtime, snapshot=replace(runtime.snapshot, block_number=220))
    c.execution_chain = SimpleNamespace(
        runtime=runtime,
        validator_hotkey=c.item.hotkey,
        validator_nonce=4,
        genesis_hash=native.context["genesis_hash"],
        weights_version_key=1,
        block=220,
        block_hash=runtime.snapshot.block_hash,
        validator_last_update=200,
        weights_rate_limit=10,
        validator_permit=True,
        mechanism_count=1,
        commit_reveal_enabled=False,
        registered_uid_count=3,
        max_allowed_uids=256,
        min_allowed_weights=1,
        max_weights_limit=65535,
        chain_config_sha256=digest(c.provider.config),
        evidence=b'{"fixture_chain":true}',
        evidence_sha256=hashlib.sha256(b'{"fixture_chain":true}').hexdigest(),
    )
    current = SimpleNamespace(
        selection=SimpleNamespace(
            state="selected", activation=c.prepared.activation, decision_sha256="23" * 32
        )
    )
    projection = CohortRewardProjection(
        schema="umi-cohort-reward-projection/1",
        allocation_sha256=c.prepared.activation.allocation_sha256,
        snapshot_sha256="24" * 32,
        recipients=(),
        uids=(1, 2),
        weights=(32768, 32767),
    )
    projected = SimpleNamespace(projection=projection, current=current, prepared=c.prepared)
    c.preparation._selected = lambda *args: current
    c.preparation._project = lambda *args: projected

    async def control(hotkey):
        assert hotkey == c.series.control_hotkey
        return SimpleNamespace(
            evidence=b'{"fixture_control":true}', snapshot=c.execution_chain.runtime.snapshot
        )

    async def weights(hotkey, *, at):
        assert hotkey == c.item.hotkey and at == c.execution_chain.runtime.snapshot
        return copy.copy(c.execution_chain)

    async def prefix(block):
        assert block == c.execution_chain.block
        return object()

    c.provider.collect_control = control
    c.provider.collect_registered_weights = weights
    c.service_options["history"].verified_prefix = prefix
    c.signed, c.sent, c.native_executors = [], [], []
    c.recoveries, c.resolve_expired = [], False
    signer = bt.sp_core.Keypair.from_uri("//Eve", crypto_type=1)
    assert signer.ss58_address == c.item.hotkey

    def sign(payload):
        c.signed.append(payload)
        return signer.sign(payload)

    key = SimpleNamespace(ss58_address=signer.ss58_address, crypto_type=1, sign=sign)
    c.service_options["load_signer"] = lambda: key

    async def recover(provider, journal, *, control_hotkey):
        assert provider is c.provider and control_hotkey == c.series.control_hotkey
        pending = journal.pending()
        c.recoveries.append(pending)
        if not c.resolve_expired:
            c.stop.set()
            return None
        assert c.execution_chain.block >= pending.intent.block + pending.intent.mortality_period
        return _issue_standing_end(
            pending, c.execution_chain.runtime.snapshot, "expired_outcome_unknown"
        )

    monkeypatch.setattr(execution, "resolve_standing_transaction", recover)

    def executor(**inputs):
        value = execution.StandingRewardExecutor(**inputs)
        c.native_executors.append(value)

        async def submit(encoded, signing_key):
            assert signing_key is key
            pending = value.journal.pending()
            assert bytes.fromhex(pending.signed.signed_extrinsic) == encoded
            verify_mortal_call(
                encoded,
                pending.intent.call(),
                runtime=c.execution_chain.runtime,
                validator_hotkey=key.ss58_address,
                nonce=pending.intent.nonce,
                mortality_period=pending.intent.mortality_period,
                genesis_hash=c.execution_chain.genesis_hash,
            )
            c.sent.append(encoded)
            c.stop.set()
            raise ConnectionError("lost fixture submission acknowledgement")

        value.transport = SimpleNamespace(submit=submit)
        return value

    monkeypatch.setattr(service, "StandingRewardExecutor", executor)
    return c
