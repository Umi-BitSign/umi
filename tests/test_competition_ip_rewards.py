"""IP grouping from retained submissions, through signed renewal and native weights."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.competition_ip_rewards import certified_ip_groups, endpoint_ip, grouped_endpoint_weights
from umi.competition_package import prepare_competition_package
from umi.competition_reward_continuity import (
    RewardIPGroup,
    RewardRecipientAmendment,
    authorized_reward_row,
    sign_recipient_amendment,
    verify_recipient_amendment,
)
from umi.competition_weights import CompetitionWeightWorker, sign_competition_weight_authorization
from umi.open_competition import Registration, digest, sign_object
from umi.protocol import canonical_json_bytes
from umi.weight_storage import subtensor_stored_weights

from .test_competition_model_burn import burn_snapshot
from .test_competition_publication import _scenario
from .test_competition_recipient_amendment import (
    automatic as automatic,
)
from .test_competition_recipient_amendment import (
    base_policy as base_policy,
)
from .test_competition_recipient_amendment import (
    chain as chain,
)
from .test_competition_recipient_amendment import (
    chain_config as chain_config,
)
from .test_competition_recipient_amendment import (
    feed_case as feed_case,
)
from .test_competition_recipient_amendment import (
    guarded as guarded,
)
from .test_competition_recipient_amendment import (
    package_limits as package_limits,
)
from .test_competition_recipient_amendment import (
    policy as policy,
)
from .test_competition_recipient_amendment import (
    publication_case as publication_case,
)
from .test_competition_recipient_amendment import (
    release_identity as release_identity,
)
from .test_competition_recipient_amendment import (
    replay_limits as replay_limits,
)
from .test_competition_recipient_amendment import (
    successor_case as successor_case,
)
from .test_competition_recipient_amendment import (
    successor_chain as successor_chain,
)
from .test_competition_recipient_amendment import (
    successor_release as successor_release,
)
from .test_competition_recipient_amendment import (
    v3_predecessor as v3_predecessor,
)
from .test_competition_recipient_amendment import (
    weight_case as weight_case,
)
from .test_competition_recipient_amendment import (
    worker_capacity as worker_capacity,
)
from .test_competition_reward_continuity_weights import enable, runtime_at
from .test_competition_two_task_profile import launch_suite
from .test_competition_weights import _advance, _run
from .test_open_competition import submission, wallet


@pytest.fixture
def package_case(tmp_path, policy, replay_limits, package_limits, release_identity):
    def snapshot(block=110):
        base = burn_snapshot(policy)
        return base.model_copy(
            update={
                "block": block,
                "block_hash": "0x" + f"{block:064x}",
                "registrations": tuple(
                    sorted(
                        (
                            *base.registrations,
                            Registration(uid=10, hotkey=wallet("Alice//ip10").hotkey.ss58_address),
                            Registration(uid=11, hotkey=wallet("Alice//ip11").hotkey.ss58_address),
                        ),
                        key=lambda x: x.uid,
                    )
                ),
            }
        )

    extra = []
    for name, origin in (
        ("Alice", "https://8.8.8.8:8443"),
        ("Alice//ip10", "https://8.8.8.8:9443"),
        ("Alice//ip11", "https://9.9.9.9"),
    ):
        original = submission(policy, name=name)
        body = original.submission.model_copy(update={"endpoint_url": origin})
        extra.append(
            original.model_copy(
                update={"submission": body, "signature": sign_object(body, wallet(name))}
            )
        )
    scenario = _scenario(
        policy,
        tmp_path / "scenario",
        replay_limits,
        promote_model=False,
        snapshot_factory=snapshot,
        suite_factory=launch_suite,
        additional_endpoints=tuple(extra),
        endpoint_origin="https://1.1.1.1",
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


def group_amendment(package, previous, wallets):
    body = previous.amendment
    groups = certified_ip_groups(package, {r.uid for r in body.recipients})
    body = RewardRecipientAmendment.model_validate_json(
        canonical_json_bytes(
            {
                **body.model_dump(mode="json", by_alias=True),
                "schema": "umi-reward-recipient-amendment/2",
                "action": "burn_then_best_score_ip_groups_equal_split/1",
                "predecessor_amendment_sha256": digest(previous),
                "ip_groups": [
                    RewardIPGroup(ip=ip, uids=uids).model_dump(mode="json") for ip, uids in groups
                ],
            }
        )
    )
    return sign_recipient_amendment(body, wallets)


@pytest.fixture
def grouped(amended):
    item = amended
    previous = item.body.continuation.recipient_amendment
    item.previous_amendment = previous
    signed = group_amendment(item.package, previous, [wallet("Ferdie")])
    item.body = item.body.model_copy(
        update={
            "continuation": item.body.continuation.model_copy(
                update={"recipient_amendment": signed}
            )
        }
    )
    item.signed = sign_competition_weight_authorization(item.body, wallet("Ferdie"))
    return item


@pytest.fixture
def amended(weight_case):
    item = enable(weight_case)
    burn = item.policy.unallocated_model_burn
    recipient = next(r for r in item.recipients if r.uid == 247)
    body = RewardRecipientAmendment(
        schema="umi-reward-recipient-amendment/1",
        authority_sha256=digest(item.body.continuation.authority),
        package_sha256=item.package.package_sha256,
        projection_sha256=item.package.manifest.projection_sha256,
        issued_at_block=201,
        action="burn_listed_recipient_allocations/1",
        recipients=[recipient],
        burn_destination=Registration(uid=burn.uid, hotkey=burn.hotkey),
    )
    from umi.competition_reward_continuity import RewardContinuation

    signed = sign_recipient_amendment(body, [wallet("Ferdie")])
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
        "Alice"
    ).hotkey.ss58_address
    item.rpc.values[("SubtensorModule", "Uids", (78, recipient.hotkey))] = None
    return item


def test_group_budget_preserves_burn_and_certified_scores(grouped):
    item = grouped
    before = canonical_json_bytes(item.package)
    row = authorized_reward_row(item.package, item.body)
    old = item.package.retained_settlement.projection
    removed = item.removed.uid
    assert sum(row.weights) == sum(old.weights) == 65535
    assert row.weights[0] == old.weights[0] + old.weights[removed]
    assert row.weights[removed] == 0
    assert abs(row.weights[6] + row.weights[10] - row.weights[11]) <= 1
    assert abs(row.weights[6] - row.weights[10]) <= 1
    assert canonical_json_bytes(item.package) == before


@pytest.mark.parametrize(
    "origin", ["https://8.8.8.8:443", "https://8.8.8.8:9443", "https://[::ffff:8.8.8.8]:8443"]
)
def test_ports_and_mapped_ipv4_have_same_group(origin):
    assert endpoint_ip(origin) == "8.8.8.8"


@pytest.mark.parametrize(
    "origin",
    [
        "https://example.com",
        "http://8.8.8.8",
        "https://127.0.0.1",
        "https://user@8.8.8.8",
        "https://[fe80::1%en0]",
    ],
)
def test_no_dns_credentials_or_private_addresses(origin):
    with pytest.raises(ValueError):
        endpoint_ip(origin)


@pytest.mark.parametrize("change", ["ip", "omit", "duplicate", "extra", "burn"])
def test_signed_grouping_cannot_override_certified_roster(grouped, change):
    item = grouped
    body = item.body.continuation.recipient_amendment.amendment
    groups = list(body.ip_groups)
    if change == "ip":
        groups[0] = groups[0].model_copy(update={"ip": "1.0.0.1"})
    elif change == "omit":
        groups = groups[1:]
    elif change == "duplicate":
        groups.append(groups[-1])
    elif change == "extra":
        groups[-1] = groups[-1].model_copy(update={"uids": (*groups[-1].uids, 200)})
    else:
        groups[-1] = groups[-1].model_copy(update={"uids": (0, *groups[-1].uids)})
    with pytest.raises(ValueError):
        signed = sign_recipient_amendment(
            body.model_copy(update={"ip_groups": tuple(groups)}), [wallet("Ferdie")]
        )
        verify_recipient_amendment(
            signed,
            item.body.continuation.authority,
            item.package,
            (wallet("Ferdie").hotkey.ss58_address,),
            threshold=1,
            block=201,
        )


def test_extra_copies_cannot_increase_group_budget():
    def calculate(copies):
        allocations = [
            SimpleNamespace(uid=uid, numerator="1", denominator="1") for uid in range(1, copies + 2)
        ]
        weights = {0: 30, **{uid: 1 for uid in range(1, copies + 1)}, copies + 1: 70 - copies}
        groups = (("8.8.8.8", tuple(range(1, copies + 1))), ("9.9.9.9", (copies + 1,)))
        row = grouped_endpoint_weights(SimpleNamespace(allocations=allocations), weights, groups, 0)
        return sum(row[u] for u in groups[0][1])

    assert {calculate(n) for n in range(1, 65)} == {35}


async def test_native_grouped_weight_effect_and_restart_recovery(grouped, monkeypatch):
    item = grouped
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


def test_original_burn_amendment_keeps_historical_signed_bytes(amended):
    signed = amended.body.continuation.recipient_amendment
    value = signed.amendment.model_dump(mode="json", by_alias=True)
    assert "ip_groups" not in value
    assert "predecessor_amendment_sha256" not in value
    assert canonical_json_bytes(signed.amendment) == canonical_json_bytes(value)


async def test_publisher_persists_grouping_and_renews_after_restart(
    automatic, package_case, policy, tmp_path
):
    from umi.competition_chain import RegistrationCapture
    from umi.competition_successor_publication import SuccessorRoundPublicationBuilder

    from .test_competition_reward_continuity import setup
    from .test_competition_successor_publication import authority_wallets

    c = setup(automatic, package_case, tmp_path)
    original_capture = c.provider.collect
    package = c.publisher.builder._load(package_case.prepared)

    async def collect():
        capture = await original_capture()
        snap = package.retained_settlement.registration_snapshot.model_copy(
            update={"block": capture.snapshot.block, "block_hash": capture.snapshot.block_hash}
        )
        return RegistrationCapture(snap, {**capture.provenance, "snapshot_sha256": digest(snap)})

    c.provider.collect = collect
    assert (await c.service.tick())["status"] == "published"
    first_bytes = canonical_json_bytes(c.feed.history()[0])
    recipient = next(a for a in package.retained_settlement.projection.allocations if a.uid == 247)
    burn = RewardRecipientAmendment(
        schema="umi-reward-recipient-amendment/1",
        authority_sha256=digest(c.publisher.builder.plan.continuity),
        package_sha256=package.package_sha256,
        projection_sha256=package.manifest.projection_sha256,
        issued_at_block=201,
        action="burn_listed_recipient_allocations/1",
        recipients=[Registration(uid=247, hotkey=recipient.hotkey)],
        burn_destination=Registration(uid=0, hotkey=policy.unallocated_model_burn.hotkey),
    )
    previous = sign_recipient_amendment(burn, authority_wallets()[:2])
    signed = group_amendment(package, previous, authority_wallets()[:2])
    c.provider.block = 201
    with pytest.raises(ValueError, match="retained predecessor"):
        await c.publisher.amend_recipients(package_case.prepared, signed)
    await c.publisher.amend_recipients(package_case.prepared, previous)
    wrong = sign_recipient_amendment(
        signed.amendment.model_copy(update={"predecessor_amendment_sha256": "00" * 32}),
        authority_wallets()[:2],
    )
    with pytest.raises(ValueError, match="retained burn"):
        await c.publisher.amend_recipients(package_case.prepared, wrong)
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
        row = authorized_reward_row(package, current.intent.authorization)
        assert row.weights[247] == 0
        assert abs(row.weights[6] + row.weights[10] - row.weights[11]) <= 1
    assert canonical_json_bytes(c.feed.history()[0]) == first_bytes
