"""Anchor persistence over isolated native-completion fixtures, not chain proofs."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_reward_coverage_checkpoint as checkpoint_module
from umi.competition_reward_coverage_checkpoint import CoverageCheckpointRepairRequired
from umi.competition_reward_coverage_intervals import _issue_retained_coverage
from umi.competition_reward_coverage_journal import RewardCoverageJournal
from umi.competition_reward_decisions import RewardActivation
from umi.competition_reward_transition_anchor import RewardLiveAnchorMissing
from umi.open_competition import digest, identity

from .test_competition_reward_coverage_export import HOTKEY
from .test_competition_reward_coverage_intervals import point, rule
from .test_open_competition import wallet


@pytest.fixture
def anchors(tmp_path, monkeypatch):
    monkeypatch.setattr(checkpoint_module, "runtime_identity", lambda: "aa" * 32)
    monkeypatch.setattr(checkpoint_module, "coverage_point", lambda endpoint, _: endpoint.point)
    selected = rule()
    activation = RewardActivation(
        cohort_sha256="22" * 32,
        package_sha256="11" * 32,
        allocation_sha256="dd" * 32,
        recovery_tip_sha256="66" * 32,
        prior_opportunity_sha256="77" * 32,
    )

    def reopen():
        return RewardCoverageJournal(
            tmp_path / "coverage", selected, expected_rule_sha256=digest(selected)
        )

    journal = reopen()

    def endpoint(block=100, *, hotkey=HOTKEY, changes=None, row_matches=True, updated=None):
        p = point(
            activation_sha256=digest(activation),
            validator_account_id=identity(hotkey),
            block=block,
            block_hash="0x" + f"{block:064x}",
            parent_hash="0x" + f"{block - 1:064x}",
            timestamp_ms=block * 12_000,
            **(changes or {}),
        )
        synthetic = SimpleNamespace(
            point=p,
            prepared=SimpleNamespace(activation=activation, requirement_sha256="33" * 32),
            eligibility=SimpleNamespace(
                policy_sha256="44" * 32,
                subject=SimpleNamespace(
                    validator_last_update=block if updated is None else updated
                ),
            ),
        )
        if row_matches is not None:
            synthetic.row_matches = row_matches
        source = ("coverage_endpoint", p.key())
        journal.journal.put(*source, {"synthetic_native_source": True})
        journal.checkpoints.remember(synthetic, [source])
        value = journal.checkpoints.load(p.key())
        return _issue_retained_coverage(
            p, activation.package_sha256, digest(value), row_state=value.get("row_state")
        )

    def select(owner=None, **kwargs):
        return (owner or journal).first_live_anchor(
            activation,
            **dict(
                validators=(HOTKEY,),
                chain_config_sha256="11" * 32,
                not_before_block=1,
            )
            | kwargs,
        )

    return SimpleNamespace(
        journal=journal, activation=activation, endpoint=endpoint, select=select, reopen=reopen
    )


async def test_retention_restart_and_retry_preserve_anchor_without_payload_reads(
    anchors, monkeypatch
):
    c = anchors
    endpoint = c.endpoint()
    await c.journal.retain_endpoint(endpoint)
    first = c.select()
    raw = c.journal.journal.get_raw

    def metadata_only(kind, key, **kwargs):
        assert kind not in checkpoint_module.KINDS
        return raw(kind, key, **kwargs)

    monkeypatch.setattr(c.journal.journal, "get_raw", metadata_only)
    await c.journal.retain_endpoint(endpoint)
    assert c.select() == first == endpoint.point.key()
    fresh = c.reopen()
    assert c.select(fresh) == first
    # The lookup returns a hint; the caller still restores native authority.
    completed = fresh.checkpoints.load(first)
    restored = _issue_retained_coverage(
        endpoint.point,
        completed["package_sha256"],
        digest(completed),
        row_state=completed["row_state"],
    )
    assert fresh._validate_retained(restored) == completed


async def test_fresh_head_then_backfill_selects_earliest_without_mutating_old_fact(anchors):
    c = anchors
    later, earlier = c.endpoint(120), c.endpoint(100)
    await c.journal.retain_endpoint(later)
    assert c.select() == later.point.key()
    with c.journal.journal.read_transaction() as db:
        before = db.execute(
            "SELECT kind,id,body FROM records WHERE kind GLOB 'coverage_live_anchor_*'"
        ).fetchone()
    await c.journal.retain_endpoint(earlier)
    await c.journal.retain_endpoint(c.endpoint(130))
    assert c.select() == earlier.point.key()
    assert c.journal.journal.get_raw(before[0], before[1]) == before[2]
    assert c.select(not_before_block=110) == later.point.key()


async def test_validator_tie_and_earliest_selection_do_not_depend_on_arrival_order(anchors):
    c = anchors
    second = wallet("Alice").hotkey.ss58_address
    validators = tuple(sorted((HOTKEY, second), key=identity))
    endpoints = [c.endpoint(hotkey=key) for key in validators]
    for endpoint in reversed(endpoints):
        await c.journal.retain_endpoint(endpoint)
    assert c.select(validators=validators) == endpoints[0].point.key()
    assert c.select(validators=tuple(reversed(validators))) == endpoints[0].point.key()


async def test_credit_path_indexes_matching_actual_write_only(anchors):
    c = anchors
    left, right = c.endpoint(100), c.endpoint(101, updated=100)
    assert await c.journal.credit(left, right) is not None
    assert c.select() == left.point.key()
    with pytest.raises(RewardLiveAnchorMissing):
        c.select(not_before_block=101)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"updated": 99},
        {"row_matches": None},
        {"row_matches": False, "changes": {"covered": False}},
        {"changes": {"covered": False}},
    ],
)
async def test_snapshot_of_existing_row_or_uncovered_row_cannot_start_clock(anchors, kwargs):
    c = anchors
    await c.journal.retain_endpoint(c.endpoint(**kwargs))
    with pytest.raises(RewardLiveAnchorMissing, match="bounded actual row-write"):
        c.select()


async def test_existing_native_completion_is_not_silently_scanned_or_replayed(anchors, monkeypatch):
    c = anchors
    endpoint = c.endpoint()

    def forbidden(*_args, **_kwargs):
        pytest.fail("missing anchor initiated history or payload work")

    monkeypatch.setattr(c.journal.checkpoints, "load", forbidden)
    monkeypatch.setattr(c.journal, "_load", forbidden)
    with pytest.raises(RewardLiveAnchorMissing):
        c.select()
    # Explicitly retaining this one already restored native endpoint is enough.
    monkeypatch.undo()
    await c.journal.retain_endpoint(endpoint)
    assert c.select() == endpoint.point.key()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"chain_config_sha256": "fe" * 32},
        {"validators": (wallet("Alice").hotkey.ss58_address,)},
    ],
)
async def test_selected_chain_and_validator_authority_cannot_borrow_anchor(anchors, kwargs):
    await anchors.journal.retain_endpoint(anchors.endpoint())
    with pytest.raises(CoverageCheckpointRepairRequired, match="anchor changed"):
        anchors.select(**kwargs)


async def test_another_activation_has_no_anchor(anchors):
    c = anchors
    await c.journal.retain_endpoint(c.endpoint())
    changed = c.activation.model_copy(
        update={
            "reward_adoption_sha256": "88" * 32,
            "effective_allocation_sha256": "99" * 32,
        }
    )
    with pytest.raises(RewardLiveAnchorMissing):
        c.journal.first_live_anchor(
            changed, validators=(HOTKEY,), chain_config_sha256="11" * 32, not_before_block=1
        )


@pytest.mark.parametrize("field", ["_issuer", "row_matches", "validator_last_update"])
async def test_unissued_or_modified_endpoint_cannot_become_anchor(anchors, field):
    changed = {"_issuer": None, "row_matches": False, "validator_last_update": 99}
    with pytest.raises(ValueError, match="native provenance"):
        await anchors.journal.retain_endpoint(
            replace(anchors.endpoint(), **{field: changed[field]})
        )
    with pytest.raises(RewardLiveAnchorMissing):
        anchors.select()


async def test_interruption_after_completion_before_anchor_resumes_exact_native_record(
    anchors, monkeypatch
):
    c = anchors
    endpoint = c.endpoint()
    put = c.journal.journal.put

    def interrupted(kind, key, value):
        if kind.startswith("coverage_live_anchor_"):
            raise OSError("interrupted before anchor acknowledgement")
        return put(kind, key, value)

    monkeypatch.setattr(c.journal.journal, "put", interrupted)
    with pytest.raises(OSError, match="interrupted"):
        await c.journal.retain_endpoint(endpoint)
    assert c.journal.checkpoints.load(endpoint.point.key()) is not None
    with pytest.raises(RewardLiveAnchorMissing):
        c.select()
    fresh = c.reopen()
    await fresh.retain_endpoint(endpoint)
    assert c.select(fresh) == endpoint.point.key()


async def test_lost_native_source_cannot_be_replaced_by_anchor_hint(anchors):
    c = anchors
    endpoint = c.endpoint()
    await c.journal.retain_endpoint(endpoint)
    key = c.select()
    with c.journal.journal.transaction() as db:
        db.execute("UPDATE records SET body='{}' WHERE kind='coverage_endpoint' AND id=?", (key,))
    # Hint discovery never confers native authority; restoration refuses damage.
    assert c.select() == key
    with pytest.raises(CoverageCheckpointRepairRequired):
        c.journal._validate_retained(endpoint)
