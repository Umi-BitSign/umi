"""Native weight execution under explicit continuity, with synthetic chain ports."""

import hashlib
import sqlite3
from types import SimpleNamespace

import pytest

from umi.competition_reward_continuity import (
    RewardContinuation,
    RewardContinuityAuthority,
    admit_certified_allocation,
    sign_reward_continuity_authority,
)
from umi.competition_weights import CompetitionWeightWorker, sign_competition_weight_authorization
from umi.protocol import canonical_json_bytes

from .test_competition_reward_continuity import fixture_boundary
from .test_competition_weights import (
    _advance,
    _run,
    _SigningRuntime,
)
from .test_competition_weights import (
    chain as chain,
)
from .test_competition_weights import (
    chain_config as chain_config,
)
from .test_competition_weights import (
    package_case as package_case,
)
from .test_competition_weights import (
    package_limits as package_limits,
)
from .test_competition_weights import (
    policy as policy,
)
from .test_competition_weights import (
    release_identity as release_identity,
)
from .test_competition_weights import (
    replay_limits as replay_limits,
)
from .test_competition_weights import (
    weight_case as weight_case,
)
from .test_competition_weights import (
    worker_capacity as worker_capacity,
)
from .test_open_competition import wallet


def enable(item, block=201):
    package = item.package
    control = RewardContinuityAuthority(
        schema="umi-reward-continuity-authority/1",
        policy_sha256=item.body.policy_sha256,
        first_round_sha256=package.manifest.round_sha256,
        first_round_sequence=1,
        last_round_sequence=10,
        release_identity_sha256=package.manifest.release_identity_sha256,
        chain_pin=item.body.chain_pin,
        issued_at_block=160,
        valid_from_block=160,
        lifetime="until_superseded_or_revoked",
        allocation_rule="latest_on_time_certified_exact_projection/1",
        recipient_change_action="hold_until_valid_certified_replacement",
        revocation_rule="stop_renewal_expire_outstanding_leases/1",
        admission_authority_hotkey=wallet("Ferdie").hotkey.ss58_address,
        maximum_write_authorization_blocks=100,
    )
    signed = sign_reward_continuity_authority(control, [wallet("Ferdie")])
    admission = admit_certified_allocation(signed, package, fixture_boundary(160), wallet("Ferdie"))
    continuation = RewardContinuation(
        schema="umi-reward-continuation/1", authority=signed, admission=admission
    )
    body = item.body.model_copy(
        update={
            "schema_": "umi-competition-weight-authorization/2",
            "continuation": continuation,
            "signed_at_block": block,
            "valid_from_block": block,
            "valid_through_block": block + 100,
        }
    )
    item.body = body
    item.signed = sign_competition_weight_authorization(body, wallet("Ferdie"))
    _advance(item, block)
    return item


def runtime_at(item, monkeypatch):
    class Runtime(_SigningRuntime):
        def signature_payload(self, call, **kwargs):
            assert kwargs["era"]["current"] == item.body.valid_from_block
            assert kwargs["nonce"] == 4
            return hashlib.blake2b(call, digest_size=32).digest()

    monkeypatch.setattr("umi.validator_chain.bittensor_core.Runtime", Runtime)

    async def submit(encoded, signer):
        item.encoded.append(encoded)
        _advance(item, item.body.valid_from_block + 1, applied=True, nonce=5)
        return SimpleNamespace(success=True)

    monkeypatch.setattr(item.transport, "submit", submit)


async def test_expired_round_writes_exact_row_and_restart_does_not_resubmit(
    weight_case, monkeypatch
):
    item = enable(weight_case)
    runtime_at(item, monkeypatch)
    before = canonical_json_bytes(item.package.retained_settlement)
    result = await _run(item)
    assert result.submitted_by_this_attempt and result.exact_row_currently_applied
    assert canonical_json_bytes(item.package.retained_settlement) == before
    old = item.worker
    item.worker = CompetitionWeightWorker(
        old.state_root,
        package_limits=old.package_limits,
        replay_worker=old.replay_worker,
        maximum_attempts=old.maximum_attempts,
        maximum_evidence_bytes=old.maximum_evidence_bytes,
        submission_timeout_seconds=old.submission_timeout_seconds,
    )
    assert not (await _run(item)).submitted_by_this_attempt
    assert len(item.encoded) == 1
    with sqlite3.connect(item.worker.path) as db:
        row = db.execute("SELECT round_sequence, package FROM continuity_highwater").fetchone()
    assert row == (1, item.package.package_sha256)


@pytest.mark.parametrize("change", ["recipient", "permit", "runtime", "nonce"])
async def test_continuity_rechecks_fresh_chain_before_any_weight_write(
    weight_case, monkeypatch, change
):
    item = enable(weight_case)
    runtime_at(item, monkeypatch)
    if change == "recipient":
        entry = item.recipients[0]
        item.rpc.values[("SubtensorModule", "Keys", (78, entry.uid))] = wallet(
            "Charlie"
        ).hotkey.ss58_address
    elif change == "permit":
        item.rpc.values[("SubtensorModule", "ValidatorPermit", (78,))] = [False] * 256
    elif change == "runtime":
        item.rpc.values[("SubtensorModule", "WeightsVersionKey", (78,))] = 123
    else:
        encode = item.transport.encode

        def change_after_signing(*args, **kwargs):
            encoded = encode(*args, **kwargs)
            _advance(item, item.body.valid_from_block + 1, nonce=5)
            return encoded

        monkeypatch.setattr(item.transport, "encode", change_after_signing)
    with pytest.raises(ValueError):
        await _run(item)
    assert not item.encoded
