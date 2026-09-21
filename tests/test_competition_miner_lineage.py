from types import SimpleNamespace

import httpx
import pytest

from umi import miner
from umi.competition_policy_lineage import clear_lineage_registry, registered_lineage
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from . import test_competition_authorization as fixtures
from .test_competition_feed import feed as feed
from .test_competition_miner import post_assignment
from .test_competition_miner_feed import dynamic_runtime
from .test_competition_policy_lineage import successor
from .test_open_competition import policy as policy


def startup_lineage(tmp_path, monkeypatch, live, predecessors):
    paths = []
    for index, item in enumerate((live, *predecessors)):
        path = tmp_path / f"policy-{index}.json"
        path.write_bytes(canonical_json_bytes(item))
        paths.append(str(path))

    class TransportReached(Exception):
        pass

    def reached(_path):
        raise TransportReached

    monkeypatch.setattr(miner, "_load_policy", reached)
    monkeypatch.setattr("bittensor.Wallet", lambda **kw: pytest.fail("wallet opened"))
    with pytest.raises(TransportReached):
        miner.build_runtime(
            SimpleNamespace(
                competition_policy=paths[0],
                competition_predecessor_policy=paths[1:],
                competition_feed="https://assignments.example",
                serving_origin="https://8.8.8.8:443",
                model_revision="aa" * 32,
                policy="unused-transport.json",
            )
        )


@pytest.fixture
def authorization(policy, tmp_path, monkeypatch):
    original = fixtures.build_authorization_fixture(policy)
    prior = original.policy
    middle = successor(prior, maximum_inference_ms=prior.maximum_inference_ms * 2)
    live = successor(middle)
    startup_lineage(tmp_path, monkeypatch, live, [middle, prior])
    make_submission = fixtures.submission
    monkeypatch.setattr(fixtures, "submission", lambda _policy, **kw: make_submission(prior, **kw))
    item = fixtures.build_authorization_fixture(live)
    assert item.policy == live
    assert item.signed_submission.submission.policy_sha256 == digest(prior)
    return item


async def test_startup_lineage_allows_feed_to_deliver_a_carried_submission(feed, tmp_path):
    runtime = dynamic_runtime(feed, tmp_path)
    try:
        await runtime.competition_authority.poll_once()
        assert runtime.competition_authority.status()["cached_publications"] == 1
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=miner.create_app(runtime)),
            base_url=feed.item.serving_origin,
        ) as client:
            reply = await post_assignment(client, feed.item)
            assert reply.status_code == 200, reply.text
            assert runtime.translator.calls == 1
        clear_lineage_registry()
        with pytest.raises(ValueError):
            dynamic_runtime(feed, tmp_path / "without-lineage")
    finally:
        runtime.resource_ledger.close()


@pytest.mark.parametrize("fault", ["missing-hop", "changed-terms", "too-many"])
def test_invalid_reviewed_predecessors_fail_before_wallet_access(
    policy, tmp_path, monkeypatch, fault
):
    prior = policy
    middle = successor(prior)
    live = successor(middle)
    predecessors = [middle, prior]
    if fault == "missing-hop":
        predecessors = [prior]
    elif fault == "changed-terms":
        live = successor(middle, contribution_terms_sha256="bb" * 32)
    else:
        predecessors = [prior] * 9
    with pytest.raises(ValueError):
        startup_lineage(tmp_path, monkeypatch, live, predecessors)


def test_omitting_predecessors_does_not_inherit_a_previous_process_registry(
    policy, tmp_path, monkeypatch
):
    live = successor(policy)
    startup_lineage(tmp_path, monkeypatch, live, [policy])
    assert registered_lineage(live).admits(digest(policy))
    startup_lineage(tmp_path, monkeypatch, live, [])
    assert not registered_lineage(live).admits(digest(policy))
