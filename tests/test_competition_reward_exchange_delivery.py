"""Bounded discovery follows native publications without examining proof payloads."""

import os
from pathlib import Path

import pytest

from umi import competition_reward_exchange_delivery as module
from umi.competition_reward_adoption_feed import RewardAdoptionFeedConfig
from umi.open_competition import digest, identity
from umi.protocol import canonical_json_bytes

from .test_competition_reward_adoption_exchange import exchange_case as exchange_case
from .test_competition_reward_adoption_feed import initial, owner, revision
from .test_competition_reward_opportunity import chain as chain
from .test_competition_reward_opportunity import chain_config as chain_config
from .test_competition_reward_opportunity import control as control
from .test_competition_reward_opportunity import manifest_case as manifest_case
from .test_competition_reward_opportunity import opportunity_case as opportunity_case
from .test_competition_reward_opportunity import policy as policy
from .test_competition_reward_opportunity import series_case as series_case
from .test_open_competition import wallet


def selection(tmp_path, case, *, initial_selection=None, feed=None):
    return module.RewardExchangeSelection(
        tmp_path / "delivery",
        outbox=tmp_path / "outbox",
        source_owner=os.getuid(),
        series=case.series,
        policy=case.policy,
        proposer=wallet("Charlie").hotkey.ss58_address,
        peer=wallet("Dave").hotkey.ss58_address,
        initial=initial_selection,
        source=feed,
    )


def publish(tmp_path, case, *, position=0, cohort=None):
    module.publish_exchange_cursor(
        tmp_path / "outbox",
        series=digest(case.series),
        proposer=identity(wallet("Charlie").hotkey.ss58_address),
        position=position,
        cohort=cohort,
    )


def test_exact_current_ordinary_and_adoption_paths_without_inventory(
    tmp_path, opportunity_case, monkeypatch
):
    c = opportunity_case
    cohort = digest(c.series.cohorts[1])
    selected = selection(tmp_path, c, initial_selection=initial(c))
    publish(tmp_path, c, position=2)
    publish(tmp_path, c, position=2, cohort=cohort)
    # Selection consults only small cursors; no request, proof or vote need be read.
    monkeypatch.setattr(Path, "rglob", lambda *a: pytest.fail("no tree inventory"))
    requests, votes = selected()
    prefix = Path(digest(c.series))
    assert requests == (
        Path("requests") / prefix / "0002.json",
        Path("requests") / prefix / f"adoption-{cohort}-000002.json",
    )
    assert votes == tuple(
        Path("votes")
        / prefix
        / request.stem
        / (identity(wallet("Dave").hotkey.ss58_address) + ".json")
        for request in requests
    )
    # Monotonic current cursor permits an old request's repeat without rollback.
    publish(tmp_path, c, position=1)
    assert selected() == (requests, votes)
    publish(tmp_path, c, position=3)
    assert selected()[0][0].name == "0003.json"


def test_unchanged_restart_does_not_read_or_hash_cursor_or_payload(
    tmp_path, opportunity_case, monkeypatch
):
    c = opportunity_case
    publish(tmp_path, c)
    selected = selection(tmp_path, c)
    expected = selected()
    reopened = selection(tmp_path, c)
    original = module.os.fdopen

    def no_source_read(fd, *args, **kwargs):
        target = os.readlink(f"/proc/self/fd/{fd}")
        assert "/outbox/" not in target, "unchanged cursor was read again"
        return original(fd, *args, **kwargs)

    monkeypatch.setattr(module.os, "fdopen", no_source_read)
    assert selected() == expected
    assert reopened() == expected


@pytest.mark.parametrize("damage", ["missing", "malformed", "rollback", "symlink", "oversize"])
def test_cursor_damage_is_refused_after_restart(tmp_path, opportunity_case, damage):
    c = opportunity_case
    publish(tmp_path, c, position=1)
    selected = selection(tmp_path, c)
    selected()
    path = tmp_path / "outbox/transport" / digest(c.series) / "decision.json"
    if damage == "missing":
        path.unlink()
    elif damage == "malformed":
        path.write_bytes(b"broken")
    elif damage == "rollback":
        cursor = module.RewardExchangeCursor.model_validate_json(path.read_bytes())
        path.write_bytes(canonical_json_bytes(cursor.model_copy(update={"position": 0})))
    elif damage == "symlink":
        raw = path.read_bytes()
        path.unlink()
        target = tmp_path / "unrelated"
        target.write_bytes(raw)
        path.symlink_to(target)
    else:
        path.write_bytes(b"x" * (module.MAX_CURSOR_BYTES + 1))
    with pytest.raises(ValueError):
        selection(tmp_path, c)()


@pytest.mark.parametrize("damage", ["missing", "malformed", "wrong_binding"])
def test_completed_checkpoint_damage_needs_explicit_repair(tmp_path, opportunity_case, damage):
    c = opportunity_case
    publish(tmp_path, c)
    selection(tmp_path, c)()
    path = tmp_path / "delivery/checkpoint.json"
    if damage == "missing":
        path.unlink()
    elif damage == "malformed":
        path.write_bytes(b"broken")
    else:
        saved = module.RewardExchangeCheckpoint.model_validate_json(path.read_bytes())
        path.write_bytes(
            canonical_json_bytes(saved.model_copy(update={"binding_sha256": "f" * 64}))
        )
    with pytest.raises(ValueError):
        selection(tmp_path, c)()


def test_missing_first_cursor_and_exact_publisher_repair(tmp_path, opportunity_case):
    c = opportunity_case
    selected = selection(tmp_path, c)
    assert selected() == ((), ())
    publish(tmp_path, c, position=1)
    expected = selected()
    path = tmp_path / "outbox/transport" / digest(c.series) / "decision.json"
    path.unlink()
    with pytest.raises(ValueError, match="lost its completed"):
        selected()
    publish(tmp_path, c, position=1)
    assert selected() == expected


def test_signed_feed_completion_and_new_revision_need_no_transport_restart(
    tmp_path, opportunity_case
):
    c = opportunity_case
    cohort = digest(c.series.cohorts[1])
    feed = RewardAdoptionFeedConfig(path=str(tmp_path / "selection.json"))
    selected = selection(tmp_path, c, initial_selection=initial(c), feed=feed)
    publish(tmp_path, c, cohort=cohort, position=2)
    assert len(selected()[0]) == 1
    producer = owner(tmp_path, c)
    producer.publish(revision(c))
    assert selected() == ((), ())
    publish(tmp_path, c, cohort=cohort, position=3)
    assert selected()[0][0].name == f"adoption-{cohort}-000003.json"
    publish(tmp_path, c, cohort=cohort, position=5)
    with pytest.raises(ValueError, match="skips"):
        selected()


def test_wrong_publisher_is_not_a_transport_authority(tmp_path, opportunity_case):
    c = opportunity_case
    publish(tmp_path, c)
    path = tmp_path / "outbox/transport" / digest(c.series) / "decision.json"
    cursor = module.RewardExchangeCursor.model_validate_json(path.read_bytes())
    path.write_bytes(canonical_json_bytes(cursor.model_copy(update={"proposer": "e" * 64})))
    with pytest.raises(ValueError, match="series or proposer"):
        selection(tmp_path, c)()
    with pytest.raises(ValueError, match="independent roles"):
        module.RewardExchangeSelection(
            tmp_path / "invalid",
            outbox=tmp_path / "outbox",
            source_owner=os.getuid(),
            series=c.series,
            policy=c.policy,
            proposer=wallet("Charlie").hotkey.ss58_address,
            peer=wallet("Charlie").hotkey.ss58_address,
        )


async def test_adoption_publication_reuse_repairs_cursor_without_proof_rehash(
    exchange_case, monkeypatch
):
    h = exchange_case
    request = await h.prepare()
    proposal = request.intent.proposal
    path = (
        h.leader.outbox
        / "transport"
        / h.leader.series
        / ("adoption-" + proposal.cohort_sha256 + ".json")
    )
    assert path.exists()
    path.unlink()
    from umi import competition_reward_adoption_exchange as exchange

    monkeypatch.setattr(exchange, "_archive", lambda *a: pytest.fail("repeat proof hash"))
    retained = h.leader.publish_request(
        proposal,
        predecessor=h.prior,
        control_evidence=h.evidence,
        control_metadata=h.metadata,
        operator_approval=request.operator_approval,
    )
    assert retained == request and path.exists()
