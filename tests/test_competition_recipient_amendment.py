from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.competition_package import prepare_competition_package
from umi.competition_reward_continuity import (
    RewardContinuation,
    RewardRecipientAmendment,
    authorized_reward_row,
    sign_recipient_amendment,
    verify_recipient_amendment,
)
from umi.competition_weights import CompetitionWeightWorker, sign_competition_weight_authorization
from umi.open_competition import Registration, digest
from umi.protocol import canonical_json_bytes
from umi.weight_storage import subtensor_stored_weights

from .test_competition_model_burn import burn_policy, burn_snapshot
from .test_competition_package import package_limits as package_limits
from .test_competition_package import release_identity as release_identity
from .test_competition_publication import _scenario
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_reward_continuity import automatic as automatic
from .test_competition_reward_continuity import feed_case as feed_case
from .test_competition_reward_continuity import guarded as guarded
from .test_competition_reward_continuity import publication_case as publication_case
from .test_competition_reward_continuity import setup
from .test_competition_reward_continuity import successor_case as successor_case
from .test_competition_reward_continuity import successor_chain as successor_chain
from .test_competition_reward_continuity import successor_release as successor_release
from .test_competition_reward_continuity import v3_predecessor as v3_predecessor
from .test_competition_reward_continuity_weights import enable, runtime_at
from .test_competition_successor_publication import authority_wallets
from .test_competition_two_task_profile import launch_suite
from .test_competition_weights import _advance, _run
from .test_competition_weights import chain as chain
from .test_competition_weights import chain_config as chain_config
from .test_competition_weights import weight_case as weight_case
from .test_competition_worker import worker_capacity as worker_capacity
from .test_open_competition import policy as base_policy  # noqa: F401
from .test_open_competition import wallet


@pytest.fixture
def policy(base_policy):  # noqa: F811
    return burn_policy(base_policy)


@pytest.fixture
def package_case(tmp_path, policy, replay_limits, package_limits, release_identity):
    def snapshot(block=110):
        return burn_snapshot(policy).model_copy(
            update={"block": block, "block_hash": "0x" + f"{block:064x}"}
        )

    scenario = _scenario(
        policy,
        tmp_path / "scenario",
        replay_limits,
        promote_model=False,
        snapshot_factory=snapshot,
        suite_factory=launch_suite,
    )
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
        yield SimpleNamespace(path=path, prepared=prepared, scenario=scenario)
    finally:
        path.chmod(0o700)


@pytest.fixture
def amended(weight_case):
    item = enable(weight_case)
    burn = item.policy.unallocated_model_burn
    recipient = next(a for a in item.recipients if a.uid != burn.uid)
    amendment = RewardRecipientAmendment(
        schema="umi-reward-recipient-amendment/1",
        authority_sha256=digest(item.body.continuation.authority),
        package_sha256=item.package.package_sha256,
        projection_sha256=item.package.manifest.projection_sha256,
        issued_at_block=201,
        action="burn_listed_recipient_allocations/1",
        recipients=[recipient],
        burn_destination=Registration(uid=burn.uid, hotkey=burn.hotkey),
    )
    signed = sign_recipient_amendment(amendment, [wallet("Ferdie")])
    continuation = RewardContinuation(
        schema="umi-reward-continuation/2",
        authority=item.body.continuation.authority,
        admission=item.body.continuation.admission,
        recipient_amendment=signed,
    )
    item.body = item.body.model_copy(update={"continuation": continuation})
    item.signed = sign_competition_weight_authorization(item.body, wallet("Ferdie"))
    item.removed = recipient
    item.rpc.values[("SubtensorModule", "SubnetOwnerHotkey", (78,))] = burn.hotkey
    item.rpc.values[("SubtensorModule", "RecycleOrBurn", (78,))] = "Burn"
    item.rpc.values[("SubtensorModule", "Keys", (78, recipient.uid))] = wallet(
        "Charlie"
    ).hotkey.ss58_address
    item.rpc.values[("SubtensorModule", "Uids", (78, recipient.hotkey))] = None
    return item


def verify(item, signed=None, block=201):
    return verify_recipient_amendment(
        signed or item.body.continuation.recipient_amendment,
        item.body.continuation.authority,
        item.package,
        (wallet("Ferdie").hotkey.ss58_address,),
        threshold=1,
        block=block,
    )


def test_amendment_preserves_certification_and_every_other_weight(amended):
    item = amended
    before = canonical_json_bytes(item.package.retained_settlement)
    verify(item)
    original = item.package.retained_settlement.projection
    row = authorized_reward_row(item.package, item.body)
    burn = item.policy.unallocated_model_burn.uid
    assert row.weights[item.removed.uid] == 0
    assert row.weights[burn] == original.weights[burn] + original.weights[item.removed.uid]
    assert sum(row.weights) == sum(original.weights)
    assert all(
        row.weights[u] == original.weights[u] for u in row.uids if u not in {burn, item.removed.uid}
    )
    assert canonical_json_bytes(item.package.retained_settlement) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("authority_sha256", "aa" * 32),
        ("package_sha256", "bb" * 32),
        ("projection_sha256", "cc" * 32),
        ("issued_at_block", 202),
    ],
)
def test_signed_amendment_cannot_escape_original_scope(amended, field, value):
    body = amended.body.continuation.recipient_amendment.amendment.model_copy(update={field: value})
    signed = sign_recipient_amendment(body, [wallet("Ferdie")])
    with pytest.raises(ValueError):
        verify(amended, signed)


def test_untrusted_amendment_is_rejected(amended):
    signed = sign_recipient_amendment(
        amended.body.continuation.recipient_amendment.amendment, [wallet("Alice")]
    )
    with pytest.raises(ValueError, match="signature set"):
        verify(amended, signed)


def test_original_continuation_serialization_does_not_gain_new_fields(amended):
    c = amended.body.continuation
    original = RewardContinuation(
        schema="umi-reward-continuation/1", authority=c.authority, admission=c.admission
    )
    assert "recipient_amendment" not in original.model_dump(mode="json")
    with pytest.raises(ValueError, match="explicit continuation"):
        RewardContinuation(
            schema="umi-reward-continuation/1",
            authority=c.authority,
            admission=c.admission,
            recipient_amendment=c.recipient_amendment,
        )


async def test_changed_recipient_burns_and_restart_does_not_resubmit(amended, monkeypatch):
    item = amended
    runtime_at(item, monkeypatch)
    row = authorized_reward_row(item.package, item.body)

    async def submit(encoded, signer):
        item.encoded.append(encoded)
        _advance(item, 202, nonce=5)
        item.rpc.values[("SubtensorModule", "Weights", (78, 54))] = list(
            zip(row.uids, subtensor_stored_weights(row.weights), strict=True)
        )
        item.rpc.values[("SubtensorModule", "LastUpdate", (78,))][54] = 202
        return SimpleNamespace(success=True)

    monkeypatch.setattr(item.transport, "submit", submit)
    result = await _run(item)
    assert result.submitted_by_this_attempt and result.exact_row_currently_applied
    previous = item.worker
    item.worker = CompetitionWeightWorker(
        previous.state_root,
        package_limits=previous.package_limits,
        replay_worker=previous.replay_worker,
        maximum_attempts=previous.maximum_attempts,
        maximum_evidence_bytes=previous.maximum_evidence_bytes,
        submission_timeout_seconds=previous.submission_timeout_seconds,
    )
    assert not (await _run(item)).submitted_by_this_attempt
    assert len(item.encoded) == 1


async def test_uncertain_amended_send_never_resubmits(amended, monkeypatch):
    item = amended
    runtime_at(item, monkeypatch)

    async def submit(encoded, signer):
        item.encoded.append(encoded)
        raise ConnectionError("lost acknowledgement")

    monkeypatch.setattr(item.transport, "submit", submit)
    with pytest.raises(ConnectionError):
        await _run(item)
    assert (await _run(item)).status == "unknown"
    assert len(item.encoded) == 1


async def test_burn_destination_change_still_blocks(amended, monkeypatch):
    runtime_at(amended, monkeypatch)
    amended.rpc.values[("SubtensorModule", "RecycleOrBurn", (78,))] = "Recycle"
    with pytest.raises(ValueError, match="burn owner or mode"):
        await _run(amended)
    assert not amended.encoded


async def test_native_publisher_retains_amendment_and_renews_after_restart(
    automatic, package_case, policy, tmp_path
):
    from umi.competition_chain import RegistrationCapture
    from umi.competition_successor_publication import SuccessorRoundPublicationBuilder

    c = setup(automatic, package_case, tmp_path)
    original_capture = c.provider.collect
    changed = False

    async def collect():
        capture = await original_capture()
        snap = burn_snapshot(policy).model_copy(
            update={
                "block": capture.snapshot.block,
                "block_hash": capture.snapshot.block_hash,
            }
        )
        if changed:
            snap = snap.model_copy(
                update={
                    "registrations": tuple(
                        Registration(uid=a.uid, hotkey=wallet("Charlie").hotkey.ss58_address)
                        if a.uid == 247
                        else a
                        for a in snap.registrations
                    )
                }
            )
        return RegistrationCapture(snap, {**capture.provenance, "snapshot_sha256": digest(snap)})

    c.provider.collect = collect
    assert (await c.service.tick())["status"] == "published"
    original = c.feed.history()[0]
    original_bytes = canonical_json_bytes(original)
    package = c.publisher.builder._load(package_case.prepared)
    changed = True
    c.provider.block = 201
    with pytest.raises(ValueError, match="recipient registration changed"):
        await c.service.tick()
    recipient = next(a for a in package.retained_settlement.projection.allocations if a.uid == 247)
    amendment = RewardRecipientAmendment(
        schema="umi-reward-recipient-amendment/1",
        authority_sha256=digest(c.publisher.builder.plan.continuity),
        package_sha256=package.package_sha256,
        projection_sha256=package.manifest.projection_sha256,
        issued_at_block=201,
        action="burn_listed_recipient_allocations/1",
        recipients=[Registration(uid=247, hotkey=recipient.hotkey)],
        burn_destination=Registration(uid=0, hotkey=policy.unallocated_model_burn.hotkey),
    )
    signed = sign_recipient_amendment(amendment, authority_wallets()[:2])
    await c.publisher.amend_recipients(package_case.prepared, signed)
    await c.publisher.amend_recipients(package_case.prepared, signed)
    old = c.publisher.builder
    c.publisher.builder = SuccessorRoundPublicationBuilder(old.journal.root, old.plan)
    for block in (201, 225):
        c.provider.block = block
        assert (await c.service.tick())["status"] == "published"
        current = c.feed.history()[-1]
        continuation = current.intent.authorization.continuation
        assert continuation.recipient_amendment == signed
        assert continuation.admission == original.intent.authorization.continuation.admission
        assert authorized_reward_row(package, current.intent.authorization).weights[247] == 0
    assert canonical_json_bytes(c.feed.history()[0]) == original_bytes
