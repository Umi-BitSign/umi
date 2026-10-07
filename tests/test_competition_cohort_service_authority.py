"""Native service authority with synthetic RPC, finality, codec and DNS boundaries."""

import errno
import json
from dataclasses import replace

import pytest

from umi.competition_cohort_service_authority import ServiceWorkAuthority
from umi.competition_origin import FinalizedEndpointProvider
from umi.open_competition import digest
from umi.private_files import PrivateStateBusyError

from .test_competition_cohort_order_signer import source_for
from .test_competition_cohort_service_worker import base_policy as base_policy
from .test_competition_cohort_service_worker import chain as chain
from .test_competition_cohort_service_worker import chain_config as chain_config
from .test_competition_cohort_service_worker import endpoint as endpoint
from .test_competition_cohort_service_worker import execution as execution
from .test_competition_cohort_service_worker import granted as granted
from .test_competition_cohort_service_worker import harness as harness
from .test_competition_cohort_service_worker import known_video_bytes as known_video_bytes
from .test_competition_cohort_service_worker import legacy_scenario as legacy_scenario
from .test_competition_cohort_service_worker import miner_policy as miner_policy
from .test_competition_cohort_service_worker import original_harness as original_harness
from .test_competition_cohort_service_worker import policy as policy
from .test_competition_cohort_service_worker import receipt_scenario as receipt_scenario
from .test_competition_cohort_service_worker import recovery as recovery
from .test_competition_cohort_service_worker import recovery_case as recovery_case
from .test_competition_cohort_service_worker import relay as relay
from .test_competition_cohort_service_worker import runtime as runtime
from .test_competition_cohort_service_worker import scenario as scenario
from .test_competition_cohort_service_worker import service_catalog_inputs as service_catalog_inputs
from .test_competition_cohort_service_worker import service_owner as service_owner
from .test_competition_cohort_service_worker import shared_control_group as shared_control_group


@pytest.fixture
def authority(service_owner):
    c, p = service_owner, service_owner.p

    async def history(cohort):
        assert cohort == c.assignment.round.cohort_sha256
        return p.e.r.h.source

    return c, ServiceWorkAuthority(c.queue, p.c.provider, history, p.provider())


async def test_service_origin_uses_native_axon_proof_and_original_scope(authority):
    c, owner = authority
    first = await owner.origin(c.assignment)
    body = json.loads(first.evidence)
    assert body["schema"] == "umi-cohort-service-origin-evidence/1"
    assert body["recovery_scope_sha256"]
    assert len(body["storage_batches"]) == 2 and not body["chain_submission_authorized"]
    assert first.submission_sha256 == digest(c.assignment.admission.submission.submission)
    assert first.block > c.assignment.admission.submission.submission.valid_through_block
    assert await owner.origin(c.assignment) == first
    scope = c.queue.journal.get("service_origin_scope", body["recovery_scope_sha256"])
    assert scope["assignment"]["admission"]["work_sha256"] == c.assignment.admission.work_sha256
    with pytest.raises(ValueError, match="not current"):
        await owner.origins.collect_origin(c.assignment.admission.submission)


async def test_service_origin_rejects_closed_then_rolled_back_history(authority):
    c, owner = authority
    await owner.origin(c.assignment)
    old = c.p.e.r.h.source
    c.p.e.r.h.source = source_for(c.p.e.r.h.batch, c.p.e.r.h.batch["history"])
    with pytest.raises(ValueError):
        await owner.origin(c.assignment)
    c.p.e.r.h.source = old
    with pytest.raises(ValueError, match="rolled back"):
        await owner.origin(c.assignment)


async def test_service_origin_detects_closure_during_native_proof_collection(
    authority, monkeypatch
):
    c, owner = authority
    original = FinalizedEndpointProvider._save_origin

    def closed(provider, *args, **kwargs):
        result = original(provider, *args, **kwargs)
        c.p.e.r.h.source = source_for(c.p.e.r.h.batch, c.p.e.r.h.batch["history"])
        return result

    monkeypatch.setattr(FinalizedEndpointProvider, "_save_origin", closed)
    with pytest.raises(ValueError):
        await owner.origin(c.assignment)


@pytest.mark.parametrize("damage", ["scope", "dns", "registration", "inverse", "proof", "stale"])
async def test_service_origins_enforce_accepted_work_and_live_native_proofs(authority, damage):
    c, owner = authority
    p, assignment = c.p, c.assignment
    sub = assignment.admission.submission.submission
    if damage == "scope":
        assignment = assignment.model_copy(
            update={"admission": assignment.admission.model_copy(update={"work_sha256": "ff" * 32})}
        )
    elif damage == "dns":
        p.answers = ["8.8.8.8", "127.0.0.1"]
    elif damage == "registration":
        del p.c.rpc.values[("SubtensorModule", "Uids", (78, sub.hotkey))]
    elif damage == "inverse":
        uid = p.c.rpc.values[("SubtensorModule", "Uids", (78, sub.hotkey))]
        p.c.rpc.values[("SubtensorModule", "Keys", (78, uid))] = "0x" + "ff" * 32
    elif damage == "proof":
        p.c.rpc.bad_proof = True
    else:
        p.c.clock.now += p.config.maximum_head_age_ms + 1
    with pytest.raises((ValueError, RuntimeError)):
        await owner.origin(assignment)


async def test_service_origin_survives_repeated_long_coordinator_gaps(authority):
    c, owner = authority
    original = c.assignment
    for n in (1, 3000, 6000, 1000000):
        c.p.c.finality.ref = replace(
            c.p.c.finality.ref,
            block_number=c.p.c.finality.ref.block_number + n,
            block_hash="0x" + f"{n + 300:064x}",
        )
        captured = await owner.origin(original)
        assert captured.block == c.p.c.finality.ref.block_number
        assert owner.queue.assignment(c.claim) == original


async def test_contention_recollects_authority_before_persisting(authority, monkeypatch):
    c, owner = authority
    original = owner._remember
    attempts, histories = [], []
    history = owner.history

    async def counted_history(cohort):
        histories.append(cohort)
        return await history(cohort)

    def contended(assignment, source, block):
        attempts.append(block)
        if len(attempts) == 1:
            c.p.e.r.h.source = source_for(c.p.e.r.h.batch, c.p.e.r.h.batch["history"])
            raise PrivateStateBusyError("round_journal_lock", "ab" * 32, errno.EAGAIN)
        return original(assignment, source, block)

    owner.history = counted_history
    monkeypatch.setattr(owner, "_remember", contended)
    with pytest.raises(ValueError):
        await owner.observe(c.assignment)
    assert len(attempts) == 2 and len(histories) == 2


async def test_service_origin_confirms_newer_proof_despite_age_valid_cached_capture(
    authority, monkeypatch
):
    c, owner = authority
    native = owner.provider
    old = await native.collect()
    minima = []

    class CachedRegistration:
        async def collect(self):
            return old

        async def collect_at_least(self, block):
            minima.append(block)
            return await native.collect()

    owner.provider = CachedRegistration()
    original = owner.origins._collect_origin_locked

    async def advanced(*args, **kwargs):
        c.p.c.finality.ref = replace(
            c.p.c.finality.ref,
            block_number=old.snapshot.block + 1,
            block_hash="0x" + f"{old.snapshot.block + 1:064x}",
        )
        return await original(*args, **kwargs)

    monkeypatch.setattr(owner.origins, "_collect_origin_locked", advanced)
    result = await owner.origin(c.assignment)
    assert result.block == old.snapshot.block + 1
    assert minima == [result.block]
