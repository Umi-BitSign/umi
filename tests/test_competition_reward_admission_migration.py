"""Native completed admission migration; source-owner ports are isolated here.

These cases exercise genuine native history/review, immutable signing records,
original boundary proofs and real checkpoint storage. Synthetic chain ports and
the independent prospective installation-selection boundary are explicit fixtures;
the provenance module has its own kernel/filesystem boundary tests.
"""

import fcntl
import logging
import os
import sqlite3
from contextlib import asynccontextmanager, nullcontext
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_reward_admission_migration as migration
from umi import competition_reward_admission_provenance as provenance
from umi import competition_reward_admission_source as source
from umi.competition_cohort_recovery import SignedCohortRecoveryAuthority
from umi.competition_reward_decision_review import review_reward_decision
from umi.competition_reward_decisions import RewardControlDecision, StandingRewardControlReader
from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from umi.competition_reward_manifest import (
    RewardOpportunityTerms,
    RewardReplayRequirement,
    StandingRewardOpportunityManifest,
)
from umi.competition_reward_signing import RewardDecisionJournal, RewardDecisionSigner
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from . import test_competition_reward_admission_provenance as provenance_fixtures
from . import test_competition_reward_history as history_fixtures
from .test_competition_reward_decisions import signatures
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import make_history_case
from .test_competition_reward_history import policy as policy
from .test_competition_reward_history import series_case as series_case
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
_CONNECT = sqlite3.connect
original_chain = history_fixtures.chain
original_chain_config = history_fixtures.chain_config


@pytest.fixture
def owner(tmp_path, monkeypatch):
    root = tmp_path / "prospective-owner"
    root.mkdir(mode=0o700)
    return provenance_fixtures.owner.__wrapped__(root, monkeypatch)


@pytest.fixture
def chain_config(original_chain_config):
    return original_chain_config.model_copy(
        update={
            "minimum_finalized_block": 150,
            "finality_pin": original_chain_config.finality_pin.model_copy(
                update={"bootstrap_block_number": 149}
            ),
        }
    )


@pytest.fixture
def chain(original_chain):
    original_chain.finality.ref = replace(original_chain.finality.ref, block_number=160)
    return original_chain


@pytest.fixture
async def admission_case(historical, monkeypatch, tmp_path):
    h = historical
    first, boundary = h.old.height, h.old.height + 2
    manifest = StandingRewardOpportunityManifest(
        schema="umi-standing-reward-manifest/2",
        policy_sha256=digest(h.item.policy),
        cohorts=tuple(
            RewardReplayRequirement(
                cohort_sha256=digest(p),
                terms_sha256="ab" * 32,
                catalog_sha256s=("cd" * 32,),
            )
            for p in h.c.series.cohorts
        ),
        opportunity=RewardOpportunityTerms(
            runtime_profile_sha256="ef" * 32,
            maximum_interval_ms=12000,
            minimum_validator_ms=12000,
        ),
    )
    authority = h.c.series.recovery.authority.model_copy(update={"issued_at_block": first})
    series = h.c.series.model_copy(
        update={
            "manifest_sha256": digest(manifest),
            "recovery": SignedCohortRecoveryAuthority(
                authority=authority, signatures=signatures(authority)
            ),
        }
    )
    body = RewardControlDecision(
        schema="umi-reward-control-decision/1",
        series_sha256=digest(series),
        sequence=0,
        predecessor_sha256=None,
        kind="admit_series",
        observed_at_block=boundary,
        activation=None,
    )
    h.c.control_writes = {n: () for n in range(first, first + 5)}
    h.c.control_writes[boundary + 1] = (digest(body),)
    h.c.control_writes[boundary + 2] = ("ef" * 32, digest(body))
    h = await make_history_case(h, monkeypatch, tmp_path)
    reviewed_history = (await h.reader.advance(h.item.provider, through_block=boundary)).history
    control = await h.reader.review_control(h.item.provider, boundary)
    decision_reader = StandingRewardControlReader(
        tmp_path / "decision-reader",
        series,
        h.item.policy,
        expected_series_sha256=digest(series),
        expected_chain_config_sha256=digest(h.item.config),
        maximum_bytes=8 * 1024**2,
    )
    review = review_reward_decision(
        decision_reader,
        manifest,
        (),
        body,
        control=control,
        history=reviewed_history,
        maximum_promotion_bytes=1024**2,
    )
    signer = RewardDecisionJournal(
        tmp_path / "decisions",
        series,
        h.item.policy,
        wallet("Charlie").hotkey.ss58_address,
        expected_chain_config_sha256=digest(h.item.config),
        maximum_bytes=16 * 1024**2,
    )

    async def sign(value):
        return sign_object(value, wallet("Charlie"))

    await RewardDecisionSigner(signer, sign).attest(review)
    # Remove only target-runtime checkpoints to emulate the installed342 raw
    # history schema. Original native source bytes and signing records stay exact.
    journal = h.reader.journal
    with journal.transaction() as db:
        for name in h.reader.checkpoints.triggers:
            db.execute("DROP TRIGGER " + name)
        for name in (
            "history_checkpoint_state",
            "history_checkpoint_index",
            "history_source_identity",
        ):
            db.execute("DROP TABLE " + name)
        db.execute(
            "DELETE FROM records WHERE kind IN ('control_history_verified',"
            "'control_history_checkpoint_owner','control_history_checkpoint_done')"
        )
    selection = {
        "series_sha256": digest(series),
        "policy_sha256": digest(h.item.policy),
        "manifest_sha256": digest(manifest),
        "chain_config_sha256": digest(h.item.config),
        "first_block": first,
        "control_hotkey": h.item.hotkey,
        "signer_hotkey": wallet("Charlie").hotkey.ss58_address,
        "paths": {
            "history_root": str(journal.root),
            "decisions_database": str(signer.journal.path),
        },
    }
    # Substitute only installation/kernel capture, not any native result issuer.
    monkeypatch.setattr(migration, "load_provenance", lambda _: selection)
    monkeypatch.setattr(source, "load_provenance", lambda _: selection)
    monkeypatch.setattr(migration, "validate_provenance", lambda *a, **k: None)
    monkeypatch.setattr(source, "validate_state_identities", lambda _: None)
    monkeypatch.setattr(migration, "open_existing_owner_locks", lambda _: nullcontext())

    async def migrate_result():
        return await migration.migrate_completed_admission(
            tmp_path / "root-selection.json",
            provider=h.item.provider,
            series=series,
            policy=h.item.policy,
            maximum_history_bytes=4 * 1024**2,
        )

    async def migrate():
        return (await migrate_result()).checkpoint

    return SimpleNamespace(
        h=h,
        series=series,
        manifest=manifest,
        body=body,
        boundary=boundary,
        source=signer,
        selection=selection,
        migrate=migrate,
        migrate_result=migrate_result,
        expected=reviewed_history,
    )


async def test_completed_interval_restores_original_digest_and_verifies_all_later_writes(
    admission_case,
):
    c, h = admission_case, admission_case.h
    value = await c.migrate()
    assert value["history_sha256"] == c.expected.evidence_sha256
    h.reader = h.new_reader()
    actual = await h.reader.advance(h.item.provider, through_block=c.boundary)
    assert actual.history == c.expected
    assert h.reader.progress.native_completed == 0
    assert h.reader.progress.latest["completed_admission_blocks"] == 3
    assert h.reader.checkpoints.load(c.boundary) is None
    with pytest.raises(ValueError, match="not been natively verified"):
        await h.reader.verified_prefix(c.boundary - 1)
    later = (await h.reader.advance(h.item.provider, through_block=h.end)).history
    assert [(w.block_number, w.decision_sha256) for w in later.writes] == [
        (c.boundary + 1, digest(c.body)),
        (c.boundary + 2, "ef" * 32),
        (c.boundary + 2, digest(c.body)),
    ]
    assert later.first_block == c.expected.first_block
    h.reader = h.new_reader()
    assert (await h.reader.advance(h.item.provider, through_block=h.end)).history == later
    assert h.reader.progress.native_completed == 0


async def test_repeat_migration_does_not_recheck_completed_boundary(admission_case, monkeypatch):
    c = admission_case
    first = await c.migrate()

    async def forbidden(*a, **k):
        raise AssertionError("completed migration replayed boundary")

    monkeypatch.setattr(c.h.item.provider, "review_control", forbidden)
    assert await c.migrate() == first


@pytest.mark.parametrize("damage", ["intent", "vote", "boundary"])
async def test_incomplete_changed_or_racing_original_result_refuses(admission_case, damage):
    c = admission_case
    with c.source.journal.transaction() as db:
        if damage in {"intent", "vote"}:
            db.execute("DELETE FROM records WHERE kind=?", ("reward_" + damage,))
    if damage == "boundary":
        with c.h.reader.journal.transaction() as db:
            db.execute(
                "DELETE FROM records WHERE kind='control_history_block' AND id=?",
                (str(c.boundary),),
            )
    with pytest.raises(HistoryCheckpointRepairRequired):
        await c.migrate()


@pytest.mark.parametrize("damage", ["result", "marker", "table", "trigger", "raw", "source_vote"])
async def test_damaged_completed_interval_never_becomes_a_cache_miss(admission_case, damage):
    c, h = admission_case, admission_case.h
    await c.migrate()
    if damage == "source_vote":
        with c.source.journal.transaction() as db:
            db.execute("DELETE FROM records WHERE kind='reward_vote'")
    else:
        with sqlite3.connect(h.reader.journal.path) as db:
            db.execute(
                {
                    "result": "DELETE FROM records "
                    "WHERE kind='control_history_completed_admission'",
                    "marker": "DELETE FROM records "
                    "WHERE kind='control_history_completed_admission_done'",
                    "table": "DROP TABLE history_completed_admission",
                    "trigger": "DROP TRIGGER history_completed_admission_update",
                    "raw": "UPDATE records SET body=body WHERE kind='control_history_block'",
                }[damage]
            )
    h.reader = h.new_reader()
    with pytest.raises(HistoryCheckpointRepairRequired):
        await h.reader.advance(h.item.provider, through_block=c.boundary)
    assert h.reader.progress.latest["state"] == "repair_required"


async def test_earlier_prefix_requires_explicit_separate_recovery(admission_case):
    c, h = admission_case, admission_case.h
    await c.migrate()
    h.reader = h.new_reader()
    with pytest.raises(HistoryCheckpointRepairRequired, match="earlier admission prefix"):
        await h.reader.advance(h.item.provider, through_block=c.boundary - 1)


@pytest.mark.parametrize("provider_route", ["existing", "fenced_factory"])
async def test_prospective_seal_real_locks_native_import_and_config_upgrade(
    admission_case, owner, monkeypatch, provider_route
):
    from umi.competition_reward_history import RewardControlHistoryReader

    c, h = admission_case, admission_case.h
    # owner substitutes only the root/process/systemd ports and source allowlist.
    # Restore SQLite now that capture's no-database-access assertion is qualified.
    monkeypatch.setattr(sqlite3, "connect", _CONNECT)
    root = owner.state / digest(c.series)
    root.mkdir(mode=0o700)
    h.reader.journal.root.rename(root / "history")
    c.source.journal.root.rename(root / "decisions")
    (root / "service.lock").write_bytes(b"")
    (root / "service.lock").chmod(0o600)
    config = {
        "role": "coordinator",
        "state_directory": str(owner.state),
        "series": c.series.model_dump(mode="json", by_alias=True),
        "policy": h.item.policy.model_dump(mode="json", by_alias=True),
        "manifest": c.manifest.model_dump(mode="json", by_alias=True),
        "chain": h.item.config.model_dump(mode="json", by_alias=True),
        "signer_hotkey": c.selection["signer_hotkey"],
    }
    owner.config.chmod(0o644)
    owner.config.write_bytes(canonical_json_bytes(config))
    owner.config.chmod(0o444)
    selection = owner.seal()
    owner.running[0] = False
    monkeypatch.setattr(migration, "load_provenance", provenance.load_provenance)
    monkeypatch.setattr(source, "load_provenance", provenance.load_provenance)
    monkeypatch.setattr(migration, "validate_provenance", provenance.validate_provenance)
    monkeypatch.setattr(source, "validate_state_identities", provenance.validate_state_identities)
    monkeypatch.setattr(
        migration, "open_existing_owner_locks", provenance.open_existing_owner_locks
    )
    events = []

    def assert_existing_locks_held():
        for name in ("service_lock", "control_writer_lock", "history_lock", "decisions_lock"):
            fd = os.open(selection["paths"][name], os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)

    @asynccontextmanager
    async def provider_factory(locked_selection):
        assert locked_selection == selection
        assert_existing_locks_held()
        events.append("provider_entered_under_locks")
        try:
            yield h.item.provider
        finally:
            assert_existing_locks_held()
            events.append("provider_closed_under_locks")

    result = await migration.migrate_completed_admission(
        owner.selection,
        series=c.series,
        policy=h.item.policy,
        maximum_history_bytes=4 * 1024**2,
        **(
            {"provider": h.item.provider}
            if provider_route == "existing"
            else {"provider_factory": provider_factory}
        ),
    )
    assert result.checkpoint["provenance_sha256"] == provenance.provenance_selection_digest(
        selection
    )
    if provider_route == "fenced_factory":
        assert events == ["provider_entered_under_locks", "provider_closed_under_locks"]
    # A supported successor config does not rewrite the original native result.
    owner.config.chmod(0o644)
    owner.config.write_bytes(canonical_json_bytes({"new_runtime": True}))
    owner.config.chmod(0o444)
    reopened = RewardControlHistoryReader(
        root / "history",
        control_hotkey=h.item.hotkey,
        chain_config_sha256=digest(h.item.config),
        first_block=c.expected.first_block,
        maximum_bytes=4 * 1024**2,
    )
    assert (await reopened.advance(h.item.provider, through_block=c.boundary)).history == c.expected


@pytest.mark.parametrize("failure", ["before_commit", "after_commit"])
async def test_interrupted_migration_retains_only_an_atomic_completed_result(
    admission_case, monkeypatch, failure
):
    from umi.competition_reward_admission_checkpoint import CompletedAdmissionCheckpoint

    c = admission_case
    remember = CompletedAdmissionCheckpoint.remember
    fired = False

    def interrupt(self, value):
        nonlocal fired
        if fired:
            return remember(self, value)
        fired = True
        if failure == "after_commit":
            remember(self, value)
        raise RuntimeError("simulated interrupted acknowledgement")

    monkeypatch.setattr(CompletedAdmissionCheckpoint, "remember", interrupt)
    with pytest.raises(HistoryCheckpointRepairRequired):
        await c.migrate()
    if failure == "after_commit":

        async def forbidden(*a, **k):
            raise AssertionError("completed boundary replayed after lost acknowledgement")

        monkeypatch.setattr(c.h.item.provider, "review_control", forbidden)
    restored = await c.migrate()
    assert restored["history_sha256"] == c.expected.evidence_sha256


async def test_completed_interval_retains_original_sources_before_remote_release(
    admission_case, monkeypatch
):
    c, h = admission_case, admission_case.h
    await c.migrate()
    h.reader = h.new_reader()

    def forbidden(*a, **k):
        raise AssertionError("completed admission original source was deleted")

    monkeypatch.setattr(h.reader.remote_sources, "externalize_many", forbidden)
    result = await h.reader.externalize_history_sources()
    assert result["state"] == "retained_completed_admission_sources"
    assert result["released_logical_bytes"] == 0
    assert (await h.reader.advance(h.item.provider, through_block=c.boundary)).history == c.expected


async def test_migration_transaction_rolls_back_records_index_and_triggers(
    admission_case, monkeypatch
):
    from umi.competition_round_journal import RoundJournal

    c = admission_case
    put_many = RoundJournal.put_many

    def interrupt(self, records, *, index=None):
        records = tuple(records)
        if records and records[0][0] == "control_history_completed_admission":

            def failing_index(db):
                index(db)
                assert db.execute("SELECT 1 FROM history_completed_admission").fetchone()
                raise RuntimeError("simulated transaction interruption")

            return put_many(self, records, index=failing_index)
        return put_many(self, records, index=index)

    with monkeypatch.context() as patch:
        patch.setattr(RoundJournal, "put_many", interrupt)
        with pytest.raises(HistoryCheckpointRepairRequired):
            await c.migrate()
    with sqlite3.connect(c.h.reader.journal.path) as db:
        assert not db.execute(
            "SELECT 1 FROM records WHERE kind LIKE 'control_history_completed_admission%'"
        ).fetchone()
        assert not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name LIKE 'history_completed_admission%'"
        ).fetchone()
    assert (await c.migrate())["history_sha256"] == c.expected.evidence_sha256


@pytest.mark.parametrize("damage", ["activation", "vote", "boundary"])
async def test_change_during_boundary_verification_cannot_commit(
    admission_case, monkeypatch, damage
):
    c = admission_case
    review = c.h.item.provider.review_control

    async def racing_review(*args, **kwargs):
        result = await review(*args, **kwargs)
        if damage == "boundary":
            with c.h.reader.journal.transaction() as db:
                db.execute(
                    "UPDATE records SET body=body WHERE kind='control_history_block' AND id=?",
                    (str(c.boundary),),
                )
        else:
            with c.source.journal.transaction() as db:
                if damage == "activation":
                    db.execute("INSERT INTO records VALUES ('reward_intent','0001','{}')")
                else:
                    db.execute("DELETE FROM records WHERE kind='reward_vote'")
        return result

    monkeypatch.setattr(c.h.item.provider, "review_control", racing_review)
    with pytest.raises(HistoryCheckpointRepairRequired):
        await c.migrate()
    with sqlite3.connect(c.h.reader.journal.path) as db:
        assert not db.execute(
            "SELECT 1 FROM records WHERE kind='control_history_completed_admission'"
        ).fetchone()


async def test_migration_reports_bounded_progress_and_scope(admission_case, caplog):
    c = admission_case
    caplog.set_level(logging.INFO, logger=migration.__name__)
    await c.migrate()
    values = [r.args for r in caplog.records if r.msg == "reward_admission_migration_progress %s"]
    assert [v["percent"] for v in values] == [0, 25, 50, 75, 100]
    assert all(v["eta_scope"] == "admission_result_migration_only" for v in values)
    assert values[0]["planning_eta_seconds"] == [1, 300]
    assert values[-1]["eta_seconds"] == 0


@pytest.mark.parametrize("damage", ["numeric_vote", "text_vote", "deep_vote", "numeric_binding"])
async def test_malformed_retained_source_is_bounded_explicit_repair(admission_case, damage):
    c = admission_case
    await c.migrate()
    with c.source.journal.transaction() as db:
        if damage == "numeric_binding":
            db.execute("UPDATE binding SET body=?", (10**12,))
        else:
            body = {
                "numeric_vote": 10**12,
                "text_vote": "{}",
                "deep_vote": b"[" * 2000 + b"0" + b"]" * 2000,
            }[damage]
            db.execute("UPDATE records SET body=? WHERE kind='reward_vote'", (body,))
    c.h.reader = c.h.new_reader()
    with pytest.raises(HistoryCheckpointRepairRequired):
        await c.h.reader.advance(c.h.item.provider, through_block=c.boundary)
    assert c.h.reader.progress.latest["state"] == "repair_required"


async def test_orphan_admission_triggers_require_repair(admission_case):
    c = admission_case
    await c.migrate()
    with sqlite3.connect(c.h.reader.journal.path) as db:
        db.execute("DELETE FROM records WHERE kind LIKE 'control_history_completed_admission%'")
        db.execute("DROP TABLE history_completed_admission")
    c.h.reader = c.h.new_reader()
    with pytest.raises(HistoryCheckpointRepairRequired, match="index is missing"):
        await c.h.reader.advance(c.h.item.provider, through_block=c.boundary)


async def test_later_records_preserve_admission_but_never_authorize_publication(admission_case):
    c = admission_case
    # The handoff inventories later records; it deliberately does not attest their
    # economic validity. Native pending/certified decision reconciliation is a
    # separate consuming stage, and these opaque rows must remain unchanged.
    later = (("reward_intent", "0001", {"opaque_later_intent": True}),)
    c.source.journal.put_many(later)
    result = await c.migrate_result()
    assert result.checkpoint["history_sha256"] == c.expected.evidence_sha256
    report = result.reconciliation
    assert report["status"] == "stopped_owner_economics_reconciliation_required"
    assert report["publication_authorized"] is False
    assert report["later_decisions_present"] is True
    assert report["later_records"]["reward_intent"] == {
        "count": 1,
        "first_key": "0001",
        "last_key": "0001",
    }
    assert report["preserved_blocks"] == 3
    assert report["tail_replay_from_block"] == c.boundary + 1
    assert report["tail_target_block"] is None
    assert c.source.journal.get("reward_intent", "0001") == later[0][2]
    c.source.journal.put("reward_certificate", "0001", {"opaque_certificate": True})
    repeated = await c.migrate_result()
    assert repeated.checkpoint == result.checkpoint
    assert repeated.reconciliation["later_records"]["reward_certificate"]["count"] == 1
    c.h.reader = c.h.new_reader()
    assert (
        await c.h.reader.advance(c.h.item.provider, through_block=c.boundary)
    ).history == c.expected


async def test_no_later_records_still_requires_finalized_economics_reconciliation(admission_case):
    result = await admission_case.migrate_result()
    assert result.reconciliation["later_decisions_present"] is False
    assert result.reconciliation["publication_authorized"] is False
