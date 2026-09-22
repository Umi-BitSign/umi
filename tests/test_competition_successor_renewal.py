"""Bounded same-package renewal, without changing single-use transaction authority."""

import json

import pytest

from umi.competition_successor_feed import SuccessorPublicationFeed
from umi.competition_successor_follow import AutomaticSuccessorPublisher
from umi.competition_successor_publication import (
    PublicationWindowUnavailable,
    SuccessorRoundPublicationBuilder,
    SuccessorRoundPublicationPlan,
    publication_round_advances,
)
from umi.competition_successor_publisher import CurrentSuccessorRoundPublisher
from umi.protocol import canonical_json_bytes

from .test_competition_successor_follow import automatic as automatic
from .test_competition_successor_follow import chain_config as chain_config
from .test_competition_successor_follow import completed
from .test_competition_successor_follow import feed_case as feed_case
from .test_competition_successor_follow import guarded as guarded
from .test_competition_successor_follow import next_package as next_package
from .test_competition_successor_follow import package_case as package_case
from .test_competition_successor_follow import package_limits as package_limits
from .test_competition_successor_follow import policy as policy
from .test_competition_successor_follow import publication_case as publication_case
from .test_competition_successor_follow import release_identity as release_identity
from .test_competition_successor_follow import replay_limits as replay_limits
from .test_competition_successor_follow import successor_case as successor_case
from .test_competition_successor_follow import successor_chain as successor_chain
from .test_competition_successor_follow import successor_release as successor_release
from .test_competition_successor_follow import v3_predecessor as v3_predecessor
from .test_competition_successor_follow import worker_capacity as worker_capacity
from .test_competition_successor_publication import build


def renewal_plan(plan, interval=2):
    raw = json.loads(canonical_json_bytes(plan))
    raw.update(schema="umi-successor-round-publication-plan/2", renewal_interval_blocks=interval)
    return SuccessorRoundPublicationPlan.model_validate(raw)


def enable_builder(case, tmp_path):
    case.plan = renewal_plan(case.plan)
    case.root = tmp_path / "renewal-signing"
    case.builder = SuccessorRoundPublicationBuilder(case.root, case.plan)
    return case


def enable_follow(case, tmp_path, plan=None):
    plan = plan or renewal_plan(case.publisher.builder.plan)
    builder = SuccessorRoundPublicationBuilder(tmp_path / "renewal-follow-signing", plan)
    publisher = CurrentSuccessorRoundPublisher(
        builder, case.guarded.store, case.guarded.replay, case.provider
    )
    config = case.feed_config.model_copy(
        update={"plan": plan, "directory": str(tmp_path / "renewal-feed")}
    )
    case.feed = SuccessorPublicationFeed(config)
    case.feed_config, case.publisher = config, publisher
    case.service = AutomaticSuccessorPublisher(publisher, case.feed, case.config, **case.signers)
    return case


def test_legacy_plan_bytes_and_retries_do_not_opt_in(publication_case, package_case):
    case = publication_case
    raw = canonical_json_bytes(case.plan)
    assert b"renewal_interval_blocks" not in raw
    assert b"maximum_settlement_reuse_blocks" not in raw
    assert canonical_json_bytes(SuccessorRoundPublicationPlan.model_validate_json(raw)) == raw
    first = build(case, package_case)
    with pytest.raises(ValueError, match="version 2"):
        build(case, package_case, 162, renew=True)
    assert canonical_json_bytes(build(case, package_case, 163)) == canonical_json_bytes(first)
    assert len(case.builder.history()) == 1


def fresh_reuse_plan(plan, maximum=40):
    raw = json.loads(canonical_json_bytes(renewal_plan(plan)))
    raw.update(
        schema="umi-successor-round-publication-plan/3",
        maximum_settlement_reuse_blocks=maximum,
    )
    return SuccessorRoundPublicationPlan.model_validate(raw)


@pytest.mark.parametrize(
    "schema,maximum",
    [
        ("umi-successor-round-publication-plan/1", 40),
        ("umi-successor-round-publication-plan/2", 40),
        ("umi-successor-round-publication-plan/3", None),
        ("umi-successor-round-publication-plan/3", 0),
        ("umi-successor-round-publication-plan/3", True),
        ("umi-successor-round-publication-plan/3", 3),
        ("umi-successor-round-publication-plan/3", 1_000_001),
    ],
)
def test_settlement_reuse_requires_explicit_bounded_version_3(publication_case, schema, maximum):
    raw = json.loads(canonical_json_bytes(renewal_plan(publication_case.plan)))
    raw.update(schema=schema, maximum_settlement_reuse_blocks=maximum)
    with pytest.raises(ValueError):
        SuccessorRoundPublicationPlan.model_validate(raw)


def test_version_2_keeps_original_bytes_and_snapshot_limit(publication_case, package_case):
    from umi.competition_successor_publication import publication_valid_through

    plan = renewal_plan(publication_case.plan)
    raw = canonical_json_bytes(plan)
    assert b"maximum_settlement_reuse_blocks" not in raw
    assert canonical_json_bytes(SuccessorRoundPublicationPlan.model_validate_json(raw)) == raw
    package = publication_case.builder._load(package_case.prepared)
    assert publication_valid_through(plan, package, 160) == 170
    with pytest.raises(PublicationWindowUnavailable):
        publication_valid_through(plan, package, 172)


def test_reuse_cannot_sign_without_current_recipient_gate(publication_case, package_case, tmp_path):
    case = publication_case
    case.builder = SuccessorRoundPublicationBuilder(
        tmp_path / "fresh-reuse", fresh_reuse_plan(case.plan)
    )
    with pytest.raises(ValueError, match="current recipient gate"):
        build(case, package_case)
    assert not case.builder.journal.keys("intent")
    assert not case.builder.journal.keys("authorization")


@pytest.mark.parametrize("maximum,expires", [(20, 180), (40, 200), (1000, 200)])
async def test_fresh_reuse_survives_old_snapshot_age_but_not_original_limits(
    automatic, package_case, tmp_path, maximum, expires
):
    plan = fresh_reuse_plan(automatic.publisher.builder.plan, maximum)
    c = enable_follow(automatic, tmp_path, plan)
    completed(c, package_case)
    assert (await c.service.tick())["status"] == "published"
    first = c.feed.history()[0]
    assert first.intent.authorization.valid_through_block == expires
    c.provider.block = 172  # Historical settlement snapshot expired at 170.
    assert (await c.service.tick())["status"] == "published"
    second = c.feed.history()[1]
    assert second.intent.package == first.intent.package
    assert second.intent.authorization.valid_through_block == expires
    assert second.intent.authorization.signed_at_block == 172
    assert (
        second.intent.authorization.authorization_id != first.intent.authorization.authorization_id
    )
    c.feed = SuccessorPublicationFeed(c.feed_config)
    assert c.feed.history() == (first, second)
    c.provider.block = expires - 3
    assert (await c.service.tick())["status"] == "waiting_for_current_round"
    assert len(c.publisher.builder.history()) == 2


def change_capture(capture, registrations=None, burn=None):
    from umi.competition_chain import RegistrationCapture
    from umi.open_competition import digest

    changes = {}
    if registrations is not None:
        changes["registrations"] = registrations
    if burn is not None:
        changes["burn_destination"] = burn
    snapshot = capture.snapshot.model_copy(update=changes)
    return RegistrationCapture(
        snapshot, {**capture.provenance, "snapshot_sha256": digest(snapshot)}
    )


async def test_expired_round_resumes_later_certified_round_and_renews_after_restart(
    automatic, package_case, next_package, tmp_path, monkeypatch
):
    """Real retained submissions/replay; synthetic owned heads and signing keys."""
    c = enable_follow(automatic, tmp_path, fresh_reuse_plan(automatic.publisher.builder.plan))
    completed(c, package_case)
    assert (await c.service.tick())["status"] == "published"
    first = canonical_json_bytes(c.feed.history()[0])
    signatures = c.publisher.builder.journal.keys("authorization")
    c.provider.block = 201  # Original round ended at 200, regardless of outer consent.
    assert (await c.service.tick())["status"] == "waiting_for_current_round"
    assert c.publisher.builder.journal.keys("authorization") == signatures
    assert canonical_json_bytes(c.feed.history()[0]) == first

    completed(c, next_package)
    c.provider.block = 245
    original_capture = c.provider.collect

    async def removed_recipient():
        return change_capture(await original_capture(), ())

    monkeypatch.setattr(c.provider, "collect", removed_recipient)
    with pytest.raises(ValueError, match="recipient registration changed"):
        await c.service.tick()
    assert c.publisher.builder.journal.keys("authorization") == signatures
    assert len(c.feed.history()) == 1

    monkeypatch.setattr(c.provider, "collect", original_capture)
    c.service = AutomaticSuccessorPublisher(c.publisher, c.feed, c.config, **c.signers)
    result = await c.service.tick()
    assert result["status"] == "published" and result["round_sequence"] == 2
    later = c.feed.history()[1]
    assert later.intent.authorization.signed_at_block == 245
    assert later.intent.authorization.valid_through_block == 260
    assert later.intent.authorization.predecessor_directive_sha256 == (
        c.feed.history()[0].signed.directive_sha256
    )
    assert canonical_json_bytes(c.feed.history()[0]) == first

    c.feed = SuccessorPublicationFeed(c.feed_config)
    c.service = AutomaticSuccessorPublisher(c.publisher, c.feed, c.config, **c.signers)
    c.provider.block = 252  # Later settlement's historical snapshot expired at 250.
    assert (await c.service.tick())["status"] == "published"
    renewed = c.feed.history()[2]
    assert renewed.intent.package == later.intent.package
    assert renewed.intent.authorization.signed_at_block == 252
    assert renewed.intent.authorization.valid_through_block == 260
    assert canonical_json_bytes(c.feed.history()[0]) == first


@pytest.mark.parametrize("next_package", [340], indirect=True)
async def test_prospectively_longer_round_renews_after_next_cutoff_with_current_recipients(
    automatic, next_package, tmp_path
):
    """A new certified round may cover a future cutoff; no old bytes are extended."""
    c = enable_follow(
        automatic, tmp_path, fresh_reuse_plan(automatic.publisher.builder.plan, maximum=100)
    )
    completed(c, next_package)
    c.provider.block = 245
    assert (await c.service.tick())["status"] == "published"
    first = c.feed.history()[0]
    assert first.intent.authorization.valid_through_block == 295
    c.provider.block = 325  # Beyond the unextended 260 end and next 320 cutoff.
    assert (await c.service.tick())["status"] == "published"
    renewed = c.feed.history()[1]
    assert renewed.intent.package == first.intent.package
    assert renewed.intent.authorization.signed_at_block == 325
    assert renewed.intent.authorization.valid_through_block == 340
    c.provider.block = 337
    assert (await c.service.tick())["status"] == "waiting_for_current_round"
    assert len(c.publisher.builder.history()) == 2


@pytest.mark.parametrize("missing", [False, True])
async def test_fresh_reuse_rechecks_recipient_identity_before_any_signature(
    automatic, package_case, tmp_path, monkeypatch, missing
):
    from .test_open_competition import wallet

    c = enable_follow(automatic, tmp_path, fresh_reuse_plan(automatic.publisher.builder.plan))
    completed(c, package_case)
    original = c.provider.collect

    async def changed():
        capture = await original()
        entries = capture.snapshot.registrations
        entries = (
            entries[1:]
            if missing
            else (
                entries[0].model_copy(update={"hotkey": wallet("Ferdie").hotkey.ss58_address}),
                *entries[1:],
            )
        )
        return change_capture(capture, entries)

    monkeypatch.setattr(c.provider, "collect", changed)
    with pytest.raises(ValueError, match="recipient registration changed"):
        await c.service.tick()
    assert not c.publisher.builder.journal.keys("authorization")
    assert not c.feed.history()


async def test_fresh_reuse_rechecks_recipients_between_partial_signatures(
    automatic, package_case, tmp_path, monkeypatch
):
    c = enable_follow(automatic, tmp_path, fresh_reuse_plan(automatic.publisher.builder.plan))
    completed(c, package_case)
    original = c.provider.collect

    async def changes_after_authorization():
        capture = await original()
        if c.publisher.builder.journal.keys("authorization"):
            return change_capture(capture, ())
        return capture

    monkeypatch.setattr(c.provider, "collect", changes_after_authorization)
    with pytest.raises(ValueError, match="recipient registration changed"):
        await c.service.tick()
    assert c.publisher.builder.journal.keys("authorization") == ["2:1"]
    assert not c.publisher.builder.journal.keys("directive_signature")
    assert not c.feed.history()


async def test_nonrecipient_churn_does_not_stop_unchanged_row_reuse(
    automatic, package_case, tmp_path, monkeypatch
):
    from umi.open_competition import Registration

    from .test_open_competition import wallet

    c = enable_follow(automatic, tmp_path, fresh_reuse_plan(automatic.publisher.builder.plan))
    completed(c, package_case)
    await c.service.tick()
    original = c.provider.collect

    async def nonrecipient():
        capture = await original()
        extra = Registration(uid=71, hotkey=wallet("Ferdie").hotkey.ss58_address)
        return change_capture(
            capture,
            tuple(sorted((*capture.snapshot.registrations, extra), key=lambda entry: entry.uid)),
        )

    monkeypatch.setattr(c.provider, "collect", nonrecipient)
    c.provider.block = 172
    assert (await c.service.tick())["status"] == "published"
    assert len(c.feed.history()) == 2


@pytest.mark.parametrize("burn_state", ["current", "missing", "changed"])
async def test_reuse_of_real_burn_package_requires_current_burn_proof(
    guarded, policy, replay_limits, package_limits, release_identity, tmp_path, burn_state
):
    from pathlib import Path

    from umi.competition_chain import RegistrationCapture
    from umi.competition_package import prepare_competition_package
    from umi.open_competition import BurnDestination, digest

    from .test_competition_model_burn import burn_policy, burn_snapshot
    from .test_competition_publication import _scenario
    from .test_competition_successor_publication import authority_wallets
    from .test_competition_two_task_profile import launch_suite
    from .test_open_competition import wallet

    policy = burn_policy(policy)

    def current_snapshot(block=110):
        return burn_snapshot(policy).model_copy(
            update={"block": block, "block_hash": "0x" + f"{block:064x}"}
        )

    scenario = _scenario(
        policy,
        tmp_path / "burn-scenario",
        replay_limits,
        promote_model=False,
        snapshot_factory=current_snapshot,
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
        destination_root=tmp_path / "burn-packages",
        limits=package_limits,
    )
    try:
        plan = fresh_reuse_plan(guarded.builder.plan).model_copy(
            update={"policy_sha256": digest(policy)}
        )
        builder = SuccessorRoundPublicationBuilder(tmp_path / "burn-signing", plan)
        provider = guarded.provider
        provider.policy = policy
        provider.config = provider.config.model_copy(update={"policy_sha256": digest(policy)})
        provider.block = 172
        original = provider.collect

        async def collect():
            capture = await original()
            snap = current_snapshot(provider.block)
            if burn_state != "current":
                target = (
                    None
                    if burn_state == "missing"
                    else BurnDestination(uid=6, hotkey=wallet("Alice").hotkey.ss58_address)
                )
                snap = snap.model_copy(update={"burn_destination": target})
            return RegistrationCapture(
                snap, {**capture.provenance, "snapshot_sha256": digest(snap)}
            )

        provider.collect = collect
        publisher = CurrentSuccessorRoundPublisher(
            builder, scenario.store, guarded.replay, provider
        )
        kwargs = {
            "authorization_wallet": authority_wallets()[0],
            "directive_wallets": authority_wallets()[:2],
        }
        if burn_state == "current":
            signed = await publisher.build(prepared, **kwargs)
            assert signed.intent.authorization.signed_at_block == 172
            assert signed.intent.authorization.valid_through_block == 200
            assert scenario.settlement.promotion_head.contributor_hotkey is None
            assert scenario.settlement.projection.weights[0] == 19661
            assert scenario.settlement.projection.weights[247] == 45874
        else:
            with pytest.raises(ValueError, match="burn destination changed"):
                await publisher.build(prepared, **kwargs)
            assert not builder.journal.keys("authorization")
    finally:
        Path(prepared.package_path).chmod(0o700)


@pytest.mark.parametrize(
    "schema,interval",
    [
        ("umi-successor-round-publication-plan/1", 2),
        ("umi-successor-round-publication-plan/2", None),
        ("umi-successor-round-publication-plan/2", 0),
        ("umi-successor-round-publication-plan/2", True),
        ("umi-successor-round-publication-plan/2", 48),
    ],
)
def test_renewal_requires_explicit_valid_plan(publication_case, schema, interval):
    raw = json.loads(canonical_json_bytes(publication_case.plan))
    raw.update(schema=schema, renewal_interval_blocks=interval)
    with pytest.raises(ValueError):
        SuccessorRoundPublicationPlan.model_validate(raw)


def test_renewal_interval_respects_weight_rate_limit(publication_case):
    raw = json.loads(canonical_json_bytes(renewal_plan(publication_case.plan)))
    raw["weights"]["required_weights_rate_limit"] = 3
    with pytest.raises(ValueError, match="rate-limit"):
        SuccessorRoundPublicationPlan.model_validate(raw)


def test_renewal_has_distinct_authority_same_package_original_expiry_and_restart(
    publication_case, package_case, tmp_path
):
    case = enable_builder(publication_case, tmp_path)
    with pytest.raises(ValueError, match="latest published round"):
        build(case, package_case, 160, renew=True)
    first = build(case, package_case, 160)
    with pytest.raises(PublicationWindowUnavailable, match="not due"):
        build(case, package_case, 161, renew=True)
    second = build(case, package_case, 162, renew=True)
    assert second.intent.sequence == first.intent.sequence + 1
    assert second.intent.package == first.intent.package
    assert (
        second.intent.authorization.authorization_id != first.intent.authorization.authorization_id
    )
    assert (
        second.intent.authorization.valid_through_block
        == first.intent.authorization.valid_through_block
        == 170
    )
    assert second.signed.directive.previous_directive_sha256 == first.signed.directive_sha256
    assert canonical_json_bytes(build(case, package_case, 163)) == canonical_json_bytes(second)
    case.builder = SuccessorRoundPublicationBuilder(case.root, case.plan)
    assert case.builder.history() == [first, second]
    third = build(case, package_case, 166, renew=True)
    assert third.intent.authorization.valid_through_block == 170
    with pytest.raises(PublicationWindowUnavailable, match="window"):
        build(case, package_case, 168, renew=True)
    assert case.builder.history() == [first, second, third]


def test_older_round_cannot_be_renewed(publication_case, package_case, next_package, tmp_path):
    case = enable_builder(publication_case, tmp_path)
    build(case, package_case, 160)
    build(case, next_package, 245)
    with pytest.raises(ValueError, match="latest published round"):
        build(case, package_case, 246, renew=True)
    assert len(case.builder.history()) == 2


def test_renewal_progression_rejects_changed_package_and_early_authority(
    publication_case, package_case, tmp_path
):
    case = enable_builder(publication_case, tmp_path)
    first = build(case, package_case, 160)
    second = build(case, package_case, 162, renew=True)
    assert publication_round_advances(case.plan, first, second)
    for change in (
        {"package": second.intent.package.model_copy(update={"package_sha256": "12" * 32})},
        {"authorization": second.intent.authorization.model_copy(update={"signed_at_block": 161})},
        {
            "authorization": second.intent.authorization.model_copy(
                update={"authorization_id": first.intent.authorization.authorization_id}
            )
        },
    ):
        altered = second.model_copy(update={"intent": second.intent.model_copy(update=change)})
        assert not publication_round_advances(case.plan, first, altered)


async def test_follow_renews_when_due_and_feed_recovers_without_resigning(
    automatic, package_case, tmp_path, monkeypatch
):
    c = enable_follow(automatic, tmp_path)
    completed(c, package_case)
    assert (await c.service.tick())["status"] == "published"
    first = c.feed.history()[0]
    c.provider.block = 161
    assert (await c.service.tick())["status"] == "waiting_for_completed_round"
    c.provider.block = 162
    retain = c.feed.retain_async

    async def failed_delivery(*args):
        raise ConnectionError("fixture delivery interruption")

    monkeypatch.setattr(c.feed, "retain_async", failed_delivery)
    with pytest.raises(ConnectionError):
        await c.service.tick()
    signed = c.publisher.builder.history()
    assert len(signed) == 2 and len(c.feed.history()) == 1
    monkeypatch.setattr(c.feed, "retain_async", retain)
    assert (await c.service.tick())["status"] == "recovered_signed_history"
    c.feed = SuccessorPublicationFeed(c.feed_config)
    c.service = AutomaticSuccessorPublisher(c.publisher, c.feed, c.config, **c.signers)
    assert c.feed.history() == (first, signed[1])
    assert (await c.service.tick())["status"] == "waiting_for_completed_round"
    assert len(c.publisher.builder.journal.keys("authorization")) == 2
    c.provider.block = 168
    assert (await c.service.tick())["status"] == "waiting_for_current_round"
    assert len(c.feed.history()) == 2


async def test_follow_prefers_newer_round_over_renewal(
    automatic, package_case, next_package, tmp_path
):
    c = enable_follow(automatic, tmp_path)
    completed(c, package_case)
    assert (await c.service.tick())["status"] == "published"
    completed(c, next_package)
    c.provider.block = 245
    assert (await c.service.tick())["round_sequence"] == 2
    assert [item.intent.round_sequence for item in c.feed.history()] == [1, 2]


async def test_conflict_prevents_renewal_and_retains_old_history(automatic, package_case, tmp_path):
    from umi.open_competition import digest

    c = enable_follow(automatic, tmp_path)
    completed(c, package_case)
    await c.service.tick()
    first = canonical_json_bytes(c.feed.history()[0])
    with c.guarded.store._connection() as db:
        db.execute(
            "INSERT INTO round_conflicts VALUES (?,?)", (digest(package_case.scenario.round), 161)
        )
    c.provider.block = 162
    with pytest.raises(ValueError, match="conflicting quorum evidence"):
        await c.service.tick()
    assert canonical_json_bytes(c.feed.history()[0]) == first
    assert len(c.publisher.builder.journal.keys("authorization")) == 1


async def test_partial_renewal_resumes_original_signature_before_newer_round(
    automatic, package_case, next_package, tmp_path, monkeypatch
):
    from umi import competition_successor_publication as publication_module

    c = enable_follow(automatic, tmp_path)
    completed(c, package_case)
    await c.service.tick()
    c.provider.block = 162
    original = publication_module.sign_response_digest

    def interrupted(*args, **kwargs):
        raise RuntimeError("fixture renewal signing interrupted")

    monkeypatch.setattr(publication_module, "sign_response_digest", interrupted)
    with pytest.raises(RuntimeError, match="renewal signing interrupted"):
        await c.service.tick()
    authorization = c.publisher.builder.journal.get("authorization", "3:1")
    assert authorization is not None
    assert len(c.feed.history()) == 1
    completed(c, next_package)
    monkeypatch.setattr(publication_module, "sign_response_digest", original)
    c.publisher.builder = SuccessorRoundPublicationBuilder(
        c.publisher.builder.journal.root, c.publisher.builder.plan
    )
    c.service = AutomaticSuccessorPublisher(c.publisher, c.feed, c.config, **c.signers)
    c.provider.block = 163
    assert (await c.service.tick())["round_sequence"] == 1
    second = c.feed.history()[1]
    assert second.intent.authorization.signed_at_block == 162
    assert second.authorization.model_dump(mode="json", by_alias=True) == authorization
    c.provider.block = 245
    assert (await c.service.tick())["round_sequence"] == 2
    assert [item.intent.sequence for item in c.feed.history()] == [2, 3, 4]


def test_expired_partial_renewal_is_not_resigned(
    publication_case, package_case, next_package, tmp_path, monkeypatch
):
    from umi import competition_successor_publication as publication_module

    case = enable_builder(publication_case, tmp_path)
    first = build(case, package_case, 160)
    original = publication_module.sign_response_digest

    def interrupted(*args, **kwargs):
        raise RuntimeError("fixture renewal signing interrupted")

    monkeypatch.setattr(publication_module, "sign_response_digest", interrupted)
    with pytest.raises(RuntimeError):
        build(case, package_case, 162, renew=True)
    authorization = case.builder.journal.get("authorization", "3:1")
    monkeypatch.setattr(publication_module, "sign_response_digest", original)
    with pytest.raises(ValueError, match="reserved publication expired"):
        build(case, package_case, 171, renew=True)
    assert case.builder.history() == [first]
    later = build(case, next_package, 245)
    assert later.intent.sequence == 3 and later.intent.round_sequence == 2
    assert case.builder.journal.get("authorization", "3:1") == authorization
    assert case.builder.journal.get("expired_intent", "3:1") is not None
