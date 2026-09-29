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
    PrecommittedServiceWorkCatalog,
    ServiceWorkCatalog,
    ServiceWorkClaim,
    SignedServiceWorkCatalog,
    SignedServiceWorkClaim,
    review_service_catalog,
)
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

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
def queue_case(harness, tmp_path, request):
    h = harness
    round_ = h.order.round
    work_count = getattr(request, "param", 4)
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
            for i in range(1, work_count + 1)
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


def precommit(c):
    raw = c.catalog.catalog.model_dump(mode="json", by_alias=True)
    raw.pop("round_sha256")
    raw.pop("issued_at_block")
    raw["schema"] = "umi-cohort-service-work-catalog/2"
    inventory = PrecommittedServiceWorkCatalog.model_validate_json(canonical_json_bytes(raw))
    catalog = SignedServiceWorkCatalog(catalog=inventory, signatures=signatures(inventory))
    config = c.cfg.model_copy(
        update={"directory": c.cfg.directory + "-precommitted", "catalog_sha256": digest(inventory)}
    )
    return SimpleNamespace(
        h=c.h,
        round=c.round,
        catalog=catalog,
        cfg=config,
        queue=ServiceWorkQueue(config, c.h.batch["policy"]),
    )


@pytest.mark.parametrize(
    "receipt_scenario,admission_block",
    [
        pytest.param("extensions", 400, id="extensions-current"),
        pytest.param("standing", 400, id="standing-current"),
        pytest.param("standing", 1000000, id="standing-late"),
    ],
    indirect=["receipt_scenario"],
)
def test_precommitted_inventory_needs_no_future_roster_or_observation(queue_case, admission_block):
    c = precommit(queue_case)
    # All catalog inputs are available before intake opens. Neither the later
    # roster nor any future block number participates in this signed identity.
    # Only standing authority is exercised beyond the original request target.
    raw = canonical_json_bytes(c.catalog)
    assert b"round_sha256" not in raw and b"issued_at_block" not in raw
    source = c.h.source
    c.queue.install(
        c.catalog,
        c.round,
        source,
        capture(admission_block),
        expected_tip_sha256=history_tip(source.history),
    )
    assert canonical_json_bytes(c.queue._catalog()[0]) == raw
    accepted = c.queue.admit(
        *inputs(c),
        source,
        capture(admission_block),
        expected_tip_sha256=history_tip(source.history),
    )
    c.queue = ServiceWorkQueue(c.cfg, c.h.batch["policy"])
    assert c.queue.lookup(inputs(c)[0]) == accepted
    assert c.queue.assignment(inputs(c)[0]).round == c.round
    # Restart needs neither a new catalog nor another quorum signature.
    c.queue.install(c.catalog, c.round, None, None, expected_tip_sha256="00" * 32)
    assert c.queue._catalog() == (c.catalog, c.round)


@pytest.mark.parametrize("damage", ["round", "catalog", "not_prepared"])
def test_precommitted_inventory_still_requires_exact_certified_preparation(queue_case, damage):
    c = precommit(queue_case)
    round_, catalog, source = c.round, c.catalog, c.h.source
    if damage == "round":
        round_ = round_.model_copy(update={"prepared_at_block": round_.prepared_at_block + 1})
    elif damage == "catalog":
        body = catalog.catalog.model_copy(update={"authority_sha256": "00" * 32})
        catalog = SignedServiceWorkCatalog(catalog=body, signatures=signatures(body))
        c.cfg = c.cfg.model_copy(update={"catalog_sha256": digest(body)})
        c.queue = ServiceWorkQueue(
            c.cfg.model_copy(update={"directory": c.cfg.directory + "-bad"}), c.queue.policy
        )
    else:
        history = source.history.model_copy(update={"transitions": ()})
        source = source_for(c.h.batch, history)
    with pytest.raises(ValueError):
        c.queue.install(
            catalog, round_, source, capture(), expected_tip_sha256=history_tip(source.history)
        )
    assert c.queue.journal.get("service_catalog", c.cfg.catalog_sha256) is None


def test_precommitted_round_binding_is_retained_and_cannot_be_replaced(queue_case):
    c = precommit(queue_case)
    c.queue.install(
        c.catalog,
        c.round,
        c.h.source,
        capture(),
        expected_tip_sha256=history_tip(c.h.source.history),
    )
    changed = c.round.model_copy(update={"prepared_at_block": c.round.prepared_at_block + 1})
    with pytest.raises(ValueError, match="cannot be replaced"):
        c.queue.install(
            c.catalog,
            changed,
            c.h.source,
            capture(),
            expected_tip_sha256=history_tip(c.h.source.history),
        )
    assert c.queue._catalog()[1] == c.round
    with c.queue.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='service_catalog_round'")
    c.queue = ServiceWorkQueue(c.cfg, c.queue.policy)
    with pytest.raises(FileNotFoundError, match="original prepared round"):
        c.queue.install(
            c.catalog,
            changed,
            c.h.source,
            capture(),
            expected_tip_sha256=history_tip(c.h.source.history),
        )


def test_original_catalog_bytes_and_journal_need_no_migration(queue_case):
    c = queue_case
    raw = canonical_json_bytes(c.catalog)
    restored = SignedServiceWorkCatalog.model_validate_json(raw)
    assert canonical_json_bytes(restored) == raw
    assert isinstance(restored.catalog, ServiceWorkCatalog)
    assert c.queue.journal.get("service_catalog_round", c.cfg.catalog_sha256) is None
    c.queue = ServiceWorkQueue(c.cfg, c.queue.policy)
    assert c.queue._catalog() == (c.catalog, c.round)
    assert admit(c).ordinal == 1


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


@pytest.mark.parametrize("queue_case", [256], indirect=True)
def test_full_cohort_catalog_survives_uid_mix_restart_and_backpressure(queue_case):
    c = queue_case
    accepted = [admit(c, "Alice" if nonce % 3 else "Bob", nonce) for nonce in range(1, 257)]
    assert [item.ordinal for item in accepted] == list(range(1, 257))
    assert len({item.work_sha256 for item in accepted}) == 256
    c.queue = ServiceWorkQueue(c.cfg, c.h.batch["policy"])
    assert c.queue.entries(limit=256) == tuple(accepted)
    with pytest.raises(ServiceQueueBackpressure, match="no unreserved claim capacity"):
        admit(c, nonce=257)
    assert c.queue.entries(limit=256) == tuple(accepted)


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


def seal(c):
    return c.queue.seal(
        c.h.source, capture(400), expected_tip_sha256=history_tip(c.h.source.history)
    )


def test_seal_freezes_complete_prefix_and_preserves_duplicate_recovery(queue_case):
    c = queue_case
    accepted = [admit(c, nonce=i) for i in (1, 2)]
    sealed = seal(c)
    assert [r.work_sha256 for r in sealed.accepted] == [a.work_sha256 for a in accepted]
    assert len(sealed.accepted) < len(c.catalog.catalog.work)
    c.queue = ServiceWorkQueue(c.cfg, c.h.batch["policy"])
    assert c.queue.seal(None, None, expected_tip_sha256="ff" * 32) == sealed
    assert admit(c) == accepted[0]
    with pytest.raises(ServiceQueueBackpressure, match="sealed"):
        admit(c, nonce=3)
    assert c.queue.entries() == tuple(accepted)


@pytest.mark.parametrize("after_commit", [False, True])
def test_seal_crash_and_ack_loss_preserve_whole_accepted_set(queue_case, monkeypatch, after_commit):
    c = queue_case
    first = admit(c)
    original = c.queue.journal.put

    def interrupt(kind, key, value):
        if kind == "service_work_seal":
            if after_commit:
                original(kind, key, value)
            raise OSError("fixture seal interruption")
        return original(kind, key, value)

    with monkeypatch.context() as patch:
        patch.setattr(c.queue.journal, "put", interrupt)
        with pytest.raises(OSError):
            seal(c)
    c.queue = ServiceWorkQueue(c.cfg, c.h.batch["policy"])
    if after_commit:
        with pytest.raises(ServiceQueueBackpressure):
            admit(c, nonce=2)
    else:
        admit(c, nonce=2)
    result = seal(c)
    assert result.accepted[0].work_sha256 == first.work_sha256
    assert len(result.accepted) == (1 if after_commit else 2)


def test_seal_admission_race_has_no_lost_accepted_work(queue_case):
    from umi.private_files import PrivateStateBusyError

    c = queue_case
    admit(c)

    def claim():
        try:
            return admit(c, nonce=2)
        except ServiceQueueBackpressure:
            return None

    def attempt(fn):
        try:
            return fn()
        except PrivateStateBusyError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = pool.submit(attempt, claim), pool.submit(attempt, lambda: seal(c))
        result, closed = a.result(), b.result()
    # The owner mutex is nonblocking. The losing operation retries after the
    # winner completes; it may observe a closed queue, never a partial seal.
    if isinstance(result, PrivateStateBusyError):
        result = claim()
    if isinstance(closed, PrivateStateBusyError):
        closed = seal(c)
    assert len(closed.accepted) == (1 if result is None else 2)
    assert {x.work_sha256 for x in c.queue.entries()} == {x.work_sha256 for x in closed.accepted}


def test_empty_seal_cannot_admit_later_or_manufacture_credit(queue_case):
    c = queue_case
    result = seal(c)
    assert result.accepted == () and not result.chain_submission_authorized
    with pytest.raises(ServiceQueueBackpressure):
        admit(c)
