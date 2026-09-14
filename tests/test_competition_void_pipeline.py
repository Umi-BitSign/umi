from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from umi import competition_evaluator as worker
from umi import competition_exchange as exchange
from umi import competition_execution as execution
from umi.competition_endpoint_execution import assemble_endpoint_observations
from umi.competition_evidence import IndependentEvaluationEvidence
from umi.competition_observations import SignedExecutionAnnouncement
from umi.competition_settlement import EvidenceCutoffSchedule
from umi.competition_store import AdmissionCapacity, AdmissionCapacityError, CompetitionStore
from umi.competition_void import (
    AttestedEvaluationVoid,
    VoidEvaluationEvidence,
    void_decision_digest,
)
from umi.drand import DrandPulse
from umi.open_competition import digest, sign_object

from .test_competition_endpoint_execution import authorization as authorization
from .test_competition_endpoint_execution import dispatch as dispatch
from .test_competition_endpoint_execution import feed as feed
from .test_competition_endpoint_execution import make_job, pair
from .test_competition_endpoint_execution import paired_setup as paired_setup
from .test_competition_evaluator import Provider, execute, make_driver, put, signed_order
from .test_competition_exchange import finish
from .test_competition_exchange import model_setup as model_setup
from .test_competition_exchange import policy as policy
from .test_competition_exchange import relay as relay
from .test_competition_execution import chain_config as chain_config
from .test_competition_execution import runtime as runtime
from .test_competition_execution import setup as setup
from .test_competition_void import announce, certify
from .test_competition_void import attempts as attempts
from .test_drand import ROUND, pulse_record
from .test_open_competition import snapshot


def closed_store(path, policy, order, archive):
    store = CompetitionStore(path, policy)
    store.initialize_baseline(order.incumbent, archive)
    store.admit(order.submission, snapshot(), 110)
    store.fix_evidence_cutoff(
        order.round,
        EvidenceCutoffSchedule(
            schema="umi-competition-evidence-cutoff/1",
            policy_sha256=digest(policy),
            round_sha256=digest(order.round),
            evidence_cutoff_block=160,
        ),
        observed_block=120,
    )
    store.close_round(order.round, current_block=120)
    return store


@pytest.fixture
async def retained_void(attempts, setup, tmp_path):
    context, observations, signers = attempts
    certificate = certify(context, observations, signers)
    evidence = VoidEvaluationEvidence(
        schema="umi-competition-void-evidence/1",
        order=context["signed_order"],
        certificate=certificate,
        legacy_policy=None,
    )
    store = closed_store(tmp_path / "intake", context["policy"], evidence.order.order, setup[3])
    return store, evidence, context, signers


async def test_void_retains_actual_first_arrival_even_after_expiry(retained_void):
    store, evidence, context, _ = retained_void
    first = store.record_void_evaluation(
        evidence=evidence, suite=context["suite"], observed_block=161
    )
    assert first["first_observed_block"] == 161
    assert not first["conflicted"] and not first["chain_submission_authorized"]
    restored = CompetitionStore(store.directory, store.policy)
    assert (
        restored.record_void_evaluation(
            evidence=evidence, suite=context["suite"], observed_block=202
        )
        == first
    )
    with restored._connection() as db:
        assert db.execute("SELECT COUNT(*) FROM evaluation_results").fetchone() == (0,)
        assert db.execute("SELECT COUNT(*) FROM void_evaluation_evidence").fetchone() == (1,)


@pytest.mark.parametrize("full", [False, True])
async def test_new_void_decision_commits_conflict_even_when_body_store_full(retained_void, full):
    store, evidence, context, signers = retained_void
    store.record_void_evaluation(evidence=evidence, suite=context["suite"], observed_block=150)
    observations = list(evidence.certificate.void.observations)
    body = observations[0].announcement
    steps = body.evidence.steps
    changed = steps[0].model_copy(
        update={
            "execution": steps[0].execution.model_copy(
                update={"output": steps[0].execution.output.model_copy(update={"elapsed_ms": 11})}
            )
        }
    )
    execution_ = body.evidence.model_copy(update={"steps": (changed, *steps[1:])})
    signer = next(w for w in signers if w.hotkey.ss58_address == body.evaluator_hotkey)
    observations[0] = announce(execution_, evidence.order, signer)
    alternative = evidence.model_copy(
        update={"certificate": certify(context, tuple(observations), signers)}
    )
    assert void_decision_digest(alternative.certificate.void) != void_decision_digest(
        evidence.certificate.void
    )
    if full:
        store.admission_capacity = AdmissionCapacity(maximum_records=1)
        with pytest.raises(AdmissionCapacityError):
            store.record_void_evaluation(
                evidence=alternative, suite=context["suite"], observed_block=201
            )
    else:
        result = store.record_void_evaluation(
            evidence=alternative, suite=context["suite"], observed_block=201
        )
        assert result["conflicted"]
    with store._connection() as db:
        assert db.execute("SELECT round FROM round_conflicts").fetchall() == [
            (digest(evidence.order.order.round),)
        ]
        assert db.execute("SELECT COUNT(*) FROM void_evaluation_evidence").fetchone() == (
            1 if full else 2,
        )


async def test_resigned_identical_observations_do_not_change_void_decision(retained_void):
    store, evidence, context, signers = retained_void
    store.record_void_evaluation(evidence=evidence, suite=context["suite"], observed_block=150)
    by_key = {w.hotkey.ss58_address: w for w in signers}
    observations = tuple(
        SignedExecutionAnnouncement(
            announcement=o.announcement,
            signature=sign_object(o.announcement, by_key[o.announcement.evaluator_hotkey]),
        )
        for o in evidence.certificate.void.observations
    )
    other = evidence.model_copy(update={"certificate": certify(context, observations, signers)})
    assert void_decision_digest(other.certificate.void) == void_decision_digest(
        evidence.certificate.void
    )
    result = store.record_void_evaluation(
        evidence=other, suite=context["suite"], observed_block=151
    )
    assert not result["conflicted"]


async def test_void_worker_relay_restart_and_local_scoring_conflict(relay, monkeypatch, tmp_path):
    original = execution.execute_offline_case

    async def failure(**kwargs):
        value = await original(**kwargs)
        if digest(kwargs["bundle"]) == digest(relay.job.incumbent):
            return value.model_copy(
                update={
                    "reason": "process_failed",
                    "returncode": 1,
                    "stdout_hex": "",
                    "output": value.output.model_copy(
                        update={"status": "miner_failure", "hypothesis": ""}
                    ),
                }
            )
        return value

    monkeypatch.setattr(execution, "execute_offline_case", failure)
    await finish(relay)
    store = closed_store(
        tmp_path / "intake",
        relay.policy,
        relay.order.order,
        Path(relay.drivers[0].config.archive_directory),
    )
    relay_journal = exchange.ExchangeJournal(relay.config, relay.policy)
    relay_journal.collect(store, observed_block=161)
    with store._connection() as db:
        assert db.execute(
            "SELECT first_observed_block FROM void_evaluation_evidence"
        ).fetchall() == [(161,)]
        assert db.execute("SELECT COUNT(*) FROM independent_evaluation_evidence").fetchone() == (0,)
    initial_calls = len(relay.calls)
    for driver in relay.drivers:
        slot = execution.execution_slot(
            relay.job.round, relay.job.submission, driver.config.evaluator_hotkey
        )
        evidence = driver.journal.get(slot, "void", VoidEvaluationEvidence)
        assert evidence.certificate.void.reason == "incumbent_failure"
        receipt = driver.journal.get(slot, "void_observation", worker.VoidEvidenceObservation)
        worker.validate_void_observation(
            receipt, relay.order.order, evidence, driver.config.evaluator_hotkey, cutoff_block=160
        )
        from umi.competition_settlement_signing import IndependentSettlementSigner

        prepared = SimpleNamespace(
            publication=SimpleNamespace(
                round=relay.job.round,
                settlement=SimpleNamespace(
                    suite=relay.suite,
                    cutoff_schedule=SimpleNamespace(evidence_cutoff_block=160),
                ),
            ),
            evidence=SimpleNamespace(
                entries=(
                    SimpleNamespace(
                        submission=relay.job.submission,
                        evidence=evidence,
                    ),
                )
            ),
        )
        IndependentSettlementSigner._local_evidence(SimpleNamespace(worker=driver), prepared, 150)
        with driver.journal.transaction() as db:
            db.execute("DELETE FROM artifacts WHERE slot=? AND kind='void_observation'", (slot,))
        with pytest.raises(ValueError, match="incomplete"):
            IndependentSettlementSigner._local_evidence(
                SimpleNamespace(worker=driver), prepared, 150
            )
        driver.journal.put(slot, "void_observation", receipt)
        assert driver.journal.get(slot, "independent", IndependentEvaluationEvidence) is None
        await driver.aclose()
        driver.provider.block = 201
        restored = worker.ContinuousEvaluator(
            driver.config, driver.policy, driver.wallet, driver.provider
        )
        assert (await restored.poll_once())["complete"] == 1
        assert (
            restored.journal.get(slot, "void_observation", worker.VoidEvidenceObservation)
            == receipt
        )
        with pytest.raises(ValueError, match="conflict"):
            restored.journal.put(slot, "result_intent", {"forged": True})
        assert (await restored.poll_once())["held"] == 1
        await restored.aclose()
    assert len(relay.calls) == initial_calls


async def test_endpoint_503_reaches_void_agreement_over_authenticated_relay(
    paired_setup, chain_config, tmp_path
):
    item = paired_setup.dispatch.feed.item
    paired_setup.dispatch.driver.transport = httpx.MockTransport(
        lambda request: httpx.Response(503)
    )
    await pair(paired_setup, tmp_path, assemble=assemble_endpoint_observations)
    await pair(paired_setup, tmp_path, evaluator=1, assemble=assemble_endpoint_observations)
    wallets = item.evaluator_wallets[:2]
    order = signed_order(make_job(paired_setup), wallets, publication=item.publication)
    config = exchange.ExchangeConfig(
        schema="umi-evaluator-exchange-config/1",
        policy_sha256=digest(item.policy),
        legacy_policy_sha256=exchange.scoring_policy_hash(item.legacy_policy),
        chain=chain_config.model_copy(
            update={
                "policy_sha256": digest(item.policy),
                "state_directory": str(tmp_path / "relay-chain"),
                "collection_timeout_seconds": 10,
            }
        ),
        state_directory=str(tmp_path / "relay-state"),
        order_directory=str(tmp_path / "relay-orders"),
        reveal_directory=str(tmp_path / "relay-reveals"),
    )
    put(Path(config.order_directory) / (digest(order.order) + ".json"), order)
    put(Path(config.reveal_directory) / (digest(item.suite) + ".json"), item.suite)
    provider = Provider(item.request.issued_block)
    app = exchange.create_exchange_app(
        config, item.policy, legacy=item.legacy_policy, provider_factory=lambda *_: provider
    )
    drivers = tuple(
        make_driver(
            tmp_path / f"endpoint-{i}",
            chain_config,
            item.policy,
            paired_setup.archive,
            paired_setup.videos,
            signer,
            legacy=item.legacy_policy,
            dispatch=paired_setup.dispatch.feed.journal.path.parent,
        )
        for i, signer in enumerate(wallets)
    )

    class Pulses:
        async def fetch(self, number):
            assert number == ROUND
            return DrandPulse(**pulse_record())

    clients = tuple(
        exchange.EvaluatorExchangeClient(
            d, "https://relay.example", transport=httpx.ASGITransport(app=app)
        )
        for d in drivers
    )
    for driver, client in zip(drivers, clients, strict=True):
        driver.pulses = Pulses()
        driver.provider.block = item.request.issued_block
        await client.sync_once()
    await execute(drivers)
    provider.block = item.round.reveal_block
    for driver in drivers:
        driver.provider.block = item.round.reveal_block
    await finish(SimpleNamespace(clients=clients, drivers=drivers, provider=provider, order=order))
    certificates = []
    for d in drivers:
        paths = list(Path(d.config.outbox_directory).glob("*.void.json"))
        assert len(paths) == 1
        certificate = worker._read(paths[0], AttestedEvaluationVoid)
        assert certificate.void.reason == "infrastructure_failure"
        assert not list(Path(d.config.outbox_directory).glob("*.independent.json"))
        certificates.append(certificate)
        await d.aclose()
    assert certificates[0] == certificates[1]
    assert paired_setup.dispatch.miner.translator.calls == 0


async def test_signing_rechecks_conflict_after_awaiting_owned_head(relay, monkeypatch):
    driver = relay.drivers[0]
    slot = execution.execution_slot(
        relay.job.round, relay.job.submission, driver.config.evaluator_hotkey
    )
    driver.journal.admit(relay.order, slot)
    driver.provider.block = 150
    original = driver.boundary

    async def conflict_during_capture():
        value = await original()
        with driver.journal.transaction() as db:
            db.execute("UPDATE orders SET conflict=1 WHERE slot=?", (slot,))
        return value

    monkeypatch.setattr(driver, "boundary", conflict_during_capture)
    with pytest.raises(ValueError, match="conflicted"):
        await driver.signing_head(relay.order.order)
    assert not list(Path(driver.config.outbox_directory).glob("*.json"))
    for d in relay.drivers:
        await d.aclose()
