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


def enable_follow(case, tmp_path):
    plan = renewal_plan(case.publisher.builder.plan)
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
    assert canonical_json_bytes(SuccessorRoundPublicationPlan.model_validate_json(raw)) == raw
    first = build(case, package_case)
    with pytest.raises(ValueError, match="version 2"):
        build(case, package_case, 162, renew=True)
    assert canonical_json_bytes(build(case, package_case, 163)) == canonical_json_bytes(first)
    assert len(case.builder.history()) == 1


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
