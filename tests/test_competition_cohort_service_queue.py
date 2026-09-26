"""Exercise durable service admission with native history and signed claims."""

import shutil
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.competition_chain import RegistrationCapture
from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_order_signer import CohortOrderParticipant, remember_order_history
from umi.competition_cohort_service_queue import (
    ServiceQueueBackpressure,
    ServiceWorkQueue,
    ServiceWorkQueueConfig,
)
from umi.competition_cohort_service_work import (
    ServiceWorkCatalog,
    ServiceWorkClaim,
    SignedServiceWorkCatalog,
    SignedServiceWorkClaim,
    review_service_catalog,
)
from umi.open_competition import digest, sign_object

from .test_competition_cohort_execution import setup_scenario
from .test_competition_cohort_order_signer import harness as harness
from .test_competition_cohort_order_signer import source_for
from .test_competition_cohort_recovery import signatures
from .test_competition_cohort_roster import base_policy as base_policy
from .test_competition_cohort_roster import legacy_scenario as legacy_scenario
from .test_competition_cohort_roster import policy as policy
from .test_competition_cohort_roster import receipt_scenario as receipt_scenario
from .test_competition_cohort_roster import recovery as recovery
from .test_competition_cohort_roster import runtime as runtime
from .test_open_competition import snapshot, wallet


@pytest.fixture
def scenario(receipt_scenario, tmp_path, runtime):
    return setup_scenario(receipt_scenario, tmp_path, runtime, mode="endpoint_incumbent")


def capture(block=400):
    snap = snapshot(block)
    return RegistrationCapture(
        snap,
        {
            "schema": "umi-competition-registration-provenance/1",
            "evidence_class": "verifier_attested_finality",
            "offline_finality_proof": False,
            "chain_submission_authorized": False,
            "snapshot_sha256": digest(snap),
            "block": snap.block,
            "block_hash": snap.block_hash,
            "state_root": "0x" + "aa" * 32,
            "evidence_sha256": "bb" * 32,
        },
    )


@pytest.fixture
def queue_case(harness, tmp_path):
    h = harness
    round_ = h.order.round
    body = ServiceWorkCatalog(
        schema="umi-cohort-service-work-catalog/1",
        policy_sha256=digest(h.batch["policy"]),
        cohort_sha256=round_.cohort_sha256,
        authority_sha256=digest(h.source.history.authority.authority),
        round_sha256=digest(round_),
        service_terms_sha256="a1" * 32,
        issued_at_block=400,
        work=tuple(
            {
                "case_id": f"{i:064x}",
                "video_sha256": f"{i + 10:064x}",
                "reference_sha256": f"{i + 20:064x}",
                "stratum": "fingerspelling",
            }
            for i in range(1, 5)
        ),
        selection_rule="global_fifo_no_identity_quota",
        credit_rule="verified_terminal_work_only",
    )
    catalog = SignedServiceWorkCatalog(catalog=body, signatures=signatures(body))
    cfg = ServiceWorkQueueConfig(
        schema="umi-cohort-service-work-queue-config/1",
        directory=str(tmp_path / "queue"),
        policy_sha256=digest(h.batch["policy"]),
        catalog_sha256=digest(body),
        service_terms_sha256=body.service_terms_sha256,
    )
    q = ServiceWorkQueue(cfg, h.batch["policy"])
    q.install(
        catalog, round_, h.source, capture(), expected_tip_sha256=history_tip(h.source.history)
    )
    return SimpleNamespace(h=h, catalog=catalog, queue=q, cfg=cfg, round=round_)


def inputs(c, name="Alice", nonce=1):
    p = next(
        p
        for p in c.h.batch["roster"].participants
        if p.record.request.signed_submission.submission.hotkey == wallet(name).hotkey.ss58_address
    )
    submission = p.record.request.signed_submission
    participant = CohortOrderParticipant(
        consent=p.record.request.consent,
        admission=p.admission,
        admission_snapshot=p.record.snapshot,
    )
    body = ServiceWorkClaim(
        schema="umi-cohort-service-work-claim/1",
        catalog_sha256=digest(c.catalog.catalog),
        hotkey=submission.submission.hotkey,
        submission_sha256=digest(submission.submission),
        nonce=f"{nonce:064x}",
    )
    return (
        SignedServiceWorkClaim(claim=body, signature=sign_object(body, wallet(name))),
        submission,
        participant,
    )


def admit(c, name="Alice", nonce=1, **kwargs):
    return c.queue.admit(
        *inputs(c, name, nonce),
        c.h.source,
        capture(),
        expected_tip_sha256=history_tip(c.h.source.history),
        **kwargs,
    )


def test_global_work_order_has_no_per_identity_quota(queue_case):
    c = queue_case
    values = [admit(c, name, i) for i, name in enumerate(("Alice", "Alice", "Bob"), 1)]
    assert [v.ordinal for v in values] == [1, 2, 3]
    assert values[0].predecessor_sha256 is None
    assert [v.predecessor_sha256 for v in values[1:]] == [digest(v) for v in values[:-1]]
    assert not any(v.service_credit_authorized or v.chain_submission_authorized for v in values)
    assert c.queue.entries(after_ordinal=1, limit=1) == (values[1],)
    other = ServiceWorkQueue(
        c.cfg.model_copy(update={"directory": c.cfg.directory + "-other"}), c.h.batch["policy"]
    )
    other.install(
        c.catalog,
        c.round,
        c.h.source,
        capture(),
        expected_tip_sha256=history_tip(c.h.source.history),
    )
    c.queue = other
    relabeled = [admit(c, name, i) for i, name in enumerate(("Bob", "Alice", "Alice"), 1)]
    assert [v.work_sha256 for v in relabeled] == [v.work_sha256 for v in values]


def test_lost_reply_restart_and_long_outage_recover_without_fresh_inputs(queue_case):
    c = queue_case
    value = admit(c)
    c.queue = ServiceWorkQueue(c.cfg, c.h.batch["policy"])
    assert c.queue.lookup(inputs(c)[0]) == value
    # Previously accepted work is recoverable even if current sources are absent.
    assert c.queue.admit(*inputs(c), None, None, expected_tip_sha256="ff" * 32) == value
    closed = source_for(c.h.batch, c.h.batch["history"])
    with pytest.raises(ValueError):
        c.queue.admit(
            *inputs(c, nonce=2),
            closed,
            capture(1000000),
            expected_tip_sha256=history_tip(closed.history),
        )
    assert c.queue.lookup(inputs(c)[0]) == value


@pytest.mark.parametrize("stage", ["before_write", "after_commit"])
def test_crash_recovers_one_claim_without_consuming_another_slot(queue_case, monkeypatch, stage):
    c = queue_case
    original = c.queue.journal.put_many

    def interrupted(records, **kwargs):
        if stage == "after_commit":
            original(records, **kwargs)
        raise OSError("simulated process lost acknowledgement")

    # History is already retained by install, but remember_order_history may write it again.
    def fail_admission(records, **kwargs):
        records = tuple(records)
        if any(kind == "service_admission" for kind, _, _ in records):
            return interrupted(records, **kwargs)
        return original(records, **kwargs)

    monkeypatch.setattr(c.queue.journal, "put_many", fail_admission)
    with pytest.raises(OSError):
        admit(c)
    c.queue = ServiceWorkQueue(c.cfg, c.h.batch["policy"])
    if stage == "before_write":
        assert c.queue.lookup(inputs(c)[0]) is None
        value = admit(c, "Bob")
    else:
        value = admit(c)
    assert value.ordinal == 1
    assert len(c.queue.entries()) == 1


def test_index_and_body_commit_together(queue_case):
    c = queue_case
    with c.queue.journal.transaction() as db:
        db.execute(
            "CREATE TRIGGER fail_claim BEFORE INSERT ON service_claims "
            "BEGIN SELECT RAISE(ABORT, 'interrupted'); END"
        )
    with pytest.raises(sqlite3.IntegrityError):
        admit(c)
    assert c.queue.lookup(inputs(c)[0]) is None
    with c.queue.journal.transaction() as db:
        assert (
            db.execute("SELECT count(*) FROM records WHERE kind='service_admission'").fetchone()[0]
            == 0
        )
        db.execute("DROP TRIGGER fail_claim")
    assert admit(c).ordinal == 1


def test_capacity_can_grow_and_never_removes_accepted_work(queue_case):
    c = queue_case
    c.queue = ServiceWorkQueue(c.cfg.model_copy(update={"maximum_claims": 1}), c.h.batch["policy"])
    first = admit(c)
    with pytest.raises(ServiceQueueBackpressure):
        admit(c, "Bob")
    assert c.queue.lookup(inputs(c, "Bob")[0]) is None
    assert c.queue.lookup(inputs(c)[0]) == first
    c.queue = ServiceWorkQueue(c.cfg.model_copy(update={"maximum_claims": 2}), c.h.batch["policy"])
    assert admit(c, "Bob").ordinal == 2
    assert c.queue.entries()[0] == first


def test_stopped_queue_transfer_preserves_original_namespace_and_claims(queue_case):
    c = queue_case
    first = admit(c)
    saved = c.cfg.directory + "-source"
    # All operations have returned and released their locks/connections.
    # Production must separately fence the old host before copying state.
    Path(c.cfg.directory).rename(saved)
    shutil.copytree(saved, c.cfg.directory)
    c.queue = ServiceWorkQueue(c.cfg, c.h.batch["policy"])
    assert c.queue.lookup(inputs(c)[0]) == first
    assert admit(c, "Bob").ordinal == 2


def test_different_namespace_requires_native_migration_instead_of_rebinding(queue_case):
    c = queue_case
    admit(c)
    target = c.cfg.directory + "-other-path"
    shutil.copytree(c.cfg.directory, target)
    with pytest.raises(ValueError, match="configuration changed"):
        ServiceWorkQueue(c.cfg.model_copy(update={"directory": target}), c.h.batch["policy"])


@pytest.mark.parametrize("damage", ["signature", "submission", "nonce_reuse", "catalog"])
def test_changed_claim_never_overwrites_a_retained_obligation(queue_case, damage):
    c = queue_case
    first = admit(c)
    signed, submission, participant = inputs(c)
    if damage == "signature":
        signed = signed.model_copy(update={"signature": sign_object(signed.claim, wallet("Bob"))})
    elif damage == "submission":
        submission = inputs(c, "Bob")[1]
    else:
        body = signed.claim.model_copy(
            update={"submission_sha256" if damage == "nonce_reuse" else "catalog_sha256": "ff" * 32}
        )
        signed = SignedServiceWorkClaim(claim=body, signature=sign_object(body, wallet("Alice")))
    with pytest.raises(ValueError):
        c.queue.admit(
            signed,
            submission,
            participant,
            c.h.source,
            capture(),
            expected_tip_sha256=history_tip(c.h.source.history),
        )
    assert c.queue.entries() == (first,)


@pytest.mark.parametrize(
    "damage", ["round", "authority", "policy", "issued", "quorum", "duplicate_video", "units"]
)
def test_catalog_authentication_and_fixed_work_are_required(queue_case, damage):
    c = queue_case
    body = c.catalog.catalog
    if damage in ("round", "authority", "policy"):
        body = body.model_copy(update={damage + "_sha256": "ff" * 32})
    elif damage == "issued":
        body = body.model_copy(update={"issued_at_block": 401})
    elif damage in ("duplicate_video", "units"):
        work = list(body.work)
        work[1] = work[1].model_copy(
            update=(
                {"video_sha256": work[0].video_sha256}
                if damage == "duplicate_video"
                else {"units": 2}
            )
        )
        body = body.model_copy(update={"work": tuple(work)})
    signed = c.catalog.model_copy(
        update={
            "catalog": body,
            "signatures": signatures(body)[:1] if damage == "quorum" else signatures(body),
        }
    )
    with pytest.raises(ValueError):
        review_service_catalog(
            signed,
            c.round,
            c.h.batch["policy"],
            c.h.source,
            expected_tip_sha256=history_tip(c.h.source.history),
            current_block=400,
        )


def test_replay_refuses_missing_or_changed_retained_evidence(queue_case):
    c = queue_case
    admit(c)
    with c.queue.journal.transaction() as db:
        db.execute("UPDATE service_claims SET admission=?", ("ff" * 32,))
    with pytest.raises(ValueError, match="index"):
        c.queue.lookup(inputs(c)[0])


def test_current_history_cannot_roll_back_after_closure(queue_case):
    c = queue_case
    closed = source_for(c.h.batch, c.h.batch["history"])
    remember_order_history(
        c.queue.journal,
        {c.catalog.catalog.cohort_sha256: c.catalog.catalog.authority_sha256},
        c.h.batch["policy"],
        closed,
        2000,
    )
    with pytest.raises(ValueError):
        admit(c)
    assert c.queue.entries() == ()


def test_concurrent_claims_have_one_owner_and_recover_losers(queue_case):
    c = queue_case

    def attempt(name):
        try:
            return admit(c, name)
        except BlockingIOError:
            return None

    with ThreadPoolExecutor(max_workers=2) as workers:
        list(workers.map(attempt, ("Alice", "Bob")))
    a, b = admit(c, "Alice"), admit(c, "Bob")
    assert {a.ordinal, b.ordinal} == {1, 2}
    assert len(c.queue.entries()) == 2
