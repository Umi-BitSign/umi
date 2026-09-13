from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_evaluator as worker
from umi.competition_chain import RegistrationCapture
from umi.competition_evidence import replay_independent_evaluation
from umi.competition_execution import execution_key
from umi.open_competition import aggregate_quality, digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_endpoint_execution import authorization as authorization
from .test_competition_endpoint_execution import dispatch as dispatch
from .test_competition_endpoint_execution import feed as feed
from .test_competition_endpoint_execution import paired_setup as paired_setup
from .test_competition_execution import chain_config as chain_config
from .test_competition_execution import policy as policy
from .test_competition_execution import runtime as runtime
from .test_competition_execution import setup as model_setup_fixture
from .test_open_competition import snapshot, wallet

model_setup = model_setup_fixture


class Provider:
    def __init__(self, block=125):
        self.block, self.calls = block, 0

    async def collect(self):
        self.calls += 1
        view = snapshot(self.block)
        return RegistrationCapture(
            view,
            {
                "schema": "umi-competition-registration-provenance/1",
                "evidence_class": "verifier_attested_finality",
                "offline_finality_proof": False,
                "chain_submission_authorized": False,
                "snapshot_sha256": digest(view),
                "block": view.block,
                "block_hash": view.block_hash,
                "state_root": "0x" + "cc" * 32,
                "evidence_sha256": "ee" * 32,
            },
        )


def signed_order(job, wallets, *, publication=None):
    order = worker.EvaluationOrder(
        schema="umi-evaluation-order/1",
        round=job.round,
        submission=job.submission,
        incumbent=job.incumbent,
        runtime=job.runtime,
        cases=job.cases,
        evaluators=tuple(sorted((w.hotkey.ss58_address for w in wallets), key=identity)),
        publication=publication,
    )
    return worker.SignedEvaluationOrder(
        order=order, signatures=tuple(sign_object(order, w) for w in wallets)
    )


def put(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value))
    path.chmod(0o600)


def make_driver(root, chain, policy, archive, videos, signer, *, legacy=None, dispatch=None):
    values = {
        name: str(root / name)
        for name in (
            "wallet_path",
            "state_directory",
            "order_directory",
            "reveal_directory",
            "peer_directory",
            "outbox_directory",
        )
    }
    config = worker.EvaluatorConfig(
        schema="umi-evaluator-config/1",
        policy_sha256=digest(policy),
        chain=chain.model_copy(
            update={
                "policy_sha256": digest(policy),
                "state_directory": str(root / "chain"),
                "collection_timeout_seconds": 10,
            }
        ),
        evaluator_hotkey=signer.hotkey.ss58_address,
        wallet_name="test",
        hotkey_name="test",
        archive_directory=str(archive),
        video_directory=str(videos),
        dispatch_directory=None if dispatch is None else str(dispatch),
        legacy_policy_sha256=None if legacy is None else worker.scoring_policy_hash(legacy),
        **values,
    )
    provider = Provider()
    driver = worker.ContinuousEvaluator(config, policy, signer, provider, legacy=legacy)
    return driver


@pytest.fixture
def setup(model_setup, chain_config, tmp_path):
    policy, job, suite, archive, videos, calls = model_setup
    wallets = (wallet("Charlie"), wallet("Dave"))
    order = signed_order(job, wallets)
    drivers = tuple(
        make_driver(tmp_path / f"eval-{i}", chain_config, policy, archive, videos, w)
        for i, w in enumerate(wallets)
    )
    for driver in drivers:
        put(Path(driver.config.order_directory) / (digest(order.order) + ".json"), order)
    return SimpleNamespace(
        policy=policy,
        job=job,
        suite=suite,
        wallets=wallets,
        order=order,
        drivers=drivers,
        calls=calls,
    )


async def execute(drivers):
    for driver in drivers:
        await driver.poll_once()
        await asyncio.gather(*driver._tasks.values(), return_exceptions=True)
        await driver.poll_once()


def exchange(drivers):
    for src in drivers:
        for target in drivers:
            if target is src:
                continue
            for path in Path(src.config.outbox_directory).glob("*.json"):
                if ".independent." not in path.name:
                    out = Path(target.config.peer_directory) / path.name
                    out.write_bytes(path.read_bytes())
                    out.chmod(0o600)


async def agree(setup):
    for driver in setup.drivers:
        driver.provider.block = setup.order.order.round.reveal_block
        put(Path(driver.config.reveal_directory) / (digest(setup.suite) + ".json"), setup.suite)
    for _ in range(4):
        for driver in setup.drivers:
            await driver.poll_once()
        exchange(setup.drivers)


def completed(driver):
    files = list(Path(driver.config.outbox_directory).glob("*.independent.json"))
    return [worker._read(p, worker.IndependentEvaluationEvidence) for p in files]


@pytest.mark.asyncio
async def test_two_workers_execute_agree_sign_and_continue_into_later_round(setup):
    await execute(setup.drivers)
    assert sum(isinstance(c, dict) for c in setup.calls) == 12
    assert all(not list(Path(d.config.outbox_directory).iterdir()) for d in setup.drivers)
    await agree(setup)
    first, second = (completed(d)[0] for d in setup.drivers)
    assert first == second
    quality, baseline = replay_independent_evaluation(
        first, setup.job.submission, setup.job.round, setup.suite, setup.policy, current_block=150
    )
    assert aggregate_quality(quality) == 1 and aggregate_quality(baseline) == 0

    # A new signed round advances on the same running workers. No CLI/job calls.
    next_round = setup.job.round.model_copy(
        update={
            "sequence": 2,
            "submission_close_block": 160,
            "evaluation_close_block": 180,
            "reveal_block": 190,
            "valid_through_block": 200,
        }
    )
    next_job = setup.job.model_copy(update={"round": next_round})
    next_order = signed_order(next_job, setup.wallets)
    for d in setup.drivers:
        d.provider.block = 165
        put(Path(d.config.order_directory) / (digest(next_order.order) + ".json"), next_order)
    for _ in range(3):
        await execute(setup.drivers)
    assert sum(isinstance(c, dict) for c in setup.calls) == 24
    setup.order = next_order
    await agree(setup)
    assert all(len(completed(d)) == 2 for d in setup.drivers)
    for d in setup.drivers:
        await d.aclose()


@pytest.mark.asyncio
async def test_restart_reuses_signed_bytes_and_retained_peer_inputs(setup):
    await execute(setup.drivers)
    await agree(setup)
    before = tuple(canonical_json_bytes(completed(d)[0]) for d in setup.drivers)
    count = len(setup.calls)
    for i, d in enumerate(setup.drivers):
        for p in Path(d.config.peer_directory).iterdir():
            p.unlink()
        for p in Path(d.config.outbox_directory).iterdir():
            p.unlink()
        fresh = worker.ContinuousEvaluator(d.config, d.policy, d.wallet, d.provider)
        result = await fresh.poll_once()
        assert result["complete"] == 1
        assert canonical_json_bytes(completed(fresh)[0]) == before[i]
        await fresh.aclose()
    assert len(setup.calls) == count


@pytest.mark.asyncio
async def test_missing_peers_do_not_get_replaced_by_local_signatures(setup):
    await execute(setup.drivers[:1])
    first = setup.drivers[0]
    first.provider.block = 150
    put(Path(first.config.reveal_directory) / (digest(setup.suite) + ".json"), setup.suite)
    result = await first.poll_once()
    assert result["waiting"] == 1
    assert not completed(first)
    assert not list(Path(first.config.outbox_directory).glob("*.vote.json"))
    assert len(list(Path(first.config.outbox_directory).glob("*.execution.json"))) == 1


@pytest.mark.parametrize(
    "change", ["one-signature", "duplicate", "wrong-order", "wrong-evaluators"]
)
def test_unsigned_or_nonindependent_orders_cannot_start_work(setup, change):
    signed = setup.order
    if change == "one-signature":
        signed = signed.model_copy(update={"signatures": signed.signatures[:1]})
    elif change == "duplicate":
        signed = signed.model_copy(update={"signatures": (signed.signatures[0],) * 2})
    elif change == "wrong-order":
        signed = signed.model_copy(
            update={
                "order": signed.order.model_copy(
                    update={"cases": tuple(reversed(signed.order.cases))}
                )
            }
        )
    else:
        order = signed.order.model_copy(update={"evaluators": (signed.order.evaluators[0],) * 2})
        signed = worker.SignedEvaluationOrder(
            order=order, signatures=tuple(sign_object(order, w) for w in setup.wallets)
        )
    with pytest.raises(ValueError):
        worker.validate_order(signed, setup.policy)


@pytest.mark.asyncio
async def test_expired_order_never_executes_or_reads_protected_references(setup, monkeypatch):
    first = setup.drivers[0]
    first.provider.block = 141
    result = await first.poll_once()
    assert result["expired"] == 1 and not setup.calls
    assert first.executions.status(execution_key(setup.job)) is None
    first.provider.block = 120
    assert (await first.poll_once())["waiting"] == 1
    assert not setup.calls


@pytest.mark.asyncio
async def test_unknown_execution_cannot_restart_automatically(setup):
    first = setup.drivers[0]
    first.executions.reserve(setup.job)
    for _ in range(2):
        result = await first.poll_once()
        assert result["held"] == 1 and not setup.calls
    await first.aclose()


@pytest.mark.asyncio
async def test_conflicting_order_keeps_hold_across_restart(setup):
    first = setup.drivers[0]
    first.ingest_once()
    changed = setup.job.model_copy(update={"cases": tuple(reversed(setup.job.cases))})
    other = signed_order(changed, setup.wallets)
    with pytest.raises(ValueError, match="conflicting"):
        first.journal.admit(other, execution_key(changed))
    fresh = worker.ContinuousEvaluator(first.config, first.policy, first.wallet, first.provider)
    assert (await fresh.poll_once())["held"] == 1
    assert not setup.calls


@pytest.mark.asyncio
async def test_fresh_owned_head_is_checked_again_before_signing(setup, monkeypatch):
    first = setup.drivers[0]
    await execute((first,))
    put(Path(first.config.reveal_directory) / (digest(setup.suite) + ".json"), setup.suite)
    calls = []
    original = first.provider.collect
    first.provider.block = 150

    async def expires():
        result = await original()
        first.provider.block = 1001
        return result

    monkeypatch.setattr(first.provider, "collect", expires)
    monkeypatch.setattr(worker, "sign_object", lambda *a: calls.append(a))
    assert (await first.poll_once())["held"] == 1
    assert not calls and not list(Path(first.config.outbox_directory).iterdir())


@pytest.mark.asyncio
async def test_signing_intent_survives_failure_without_new_execution(setup, monkeypatch):
    await execute(setup.drivers)
    for d in setup.drivers:
        d.provider.block = 150
        put(Path(d.config.reveal_directory) / (digest(setup.suite) + ".json"), setup.suite)
        await d.poll_once()
    exchange(setup.drivers)
    first = setup.drivers[0]
    count = len(setup.calls)
    original = worker.sign_evaluator_run

    def failed(*args):
        raise RuntimeError("synthetic signer interrupted")

    monkeypatch.setattr(worker, "sign_evaluator_run", failed)
    assert (await first.poll_once())["held"] == 1
    assert first.journal.get(execution_key(setup.job), "result_intent", worker.EvaluationResult)
    assert not list(Path(first.config.outbox_directory).glob("*.vote.json"))
    monkeypatch.setattr(worker, "sign_evaluator_run", original)
    await agree(setup)
    assert all(len(completed(d)) == 1 for d in setup.drivers)
    assert len(setup.calls) == count


@pytest.mark.parametrize(
    "kind", ["symlink", "hardlink", "public", "fifo", "noncanonical", "oversize"]
)
def test_inbox_requires_bounded_private_regular_canonical_bytes(setup, tmp_path, kind, monkeypatch):
    first = setup.drivers[0]
    path = next(Path(first.config.order_directory).iterdir())
    if kind == "symlink":
        target = tmp_path / "elsewhere.json"
        path.rename(target)
        path.symlink_to(target)
    elif kind == "hardlink":
        import os

        os.link(path, tmp_path / "second-link")
    elif kind == "public":
        path.chmod(0o644)
    elif kind == "fifo":
        import os

        path.unlink()
        os.mkfifo(path, 0o600)
    elif kind == "noncanonical":
        path.write_bytes(path.read_bytes() + b"\n")
    else:
        monkeypatch.setattr(worker, "MAX_BYTES", 10)
    with pytest.raises((OSError, ValueError)):
        first.ingest_once()


def test_config_separates_hotkey_state_and_inputs(setup):
    config = setup.drivers[0].config
    for field in ("wallet_path", "peer_directory", "archive_directory", "video_directory"):
        with pytest.raises(ValueError, match="overlap"):
            worker.EvaluatorConfig.model_validate_json(
                canonical_json_bytes(config.model_copy(update={field: config.state_directory}))
            )


def test_capacity_failure_retains_history_and_does_not_execute(setup):
    first = setup.drivers[0]
    first.journal.admit(setup.order, execution_key(setup.job))
    old = first.journal.orders()[0]
    first.journal.config = first.config.model_copy(update={"maximum_journal_bytes": 1024})
    changed = setup.job.model_copy(update={"cases": tuple(reversed(setup.job.cases))})
    with pytest.raises(ValueError, match="conflicting"):
        first.journal.admit(signed_order(changed, setup.wallets), execution_key(changed))
    assert first.journal.orders()[0][:2] == old[:2]
    assert first.journal.orders()[0][2] is True
    assert not setup.calls


@pytest.mark.asyncio
async def test_shutdown_cancels_execution_and_preserves_no_retry_state(setup, monkeypatch):
    from umi import competition_execution

    entered = asyncio.Event()

    async def stalled(**kwargs):
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(competition_execution, "execute_offline_case", stalled)
    first = setup.drivers[0]
    await first.poll_once()
    await asyncio.wait_for(entered.wait(), 2)
    await first.aclose()
    assert first.executions.status(execution_key(setup.job))["status"] == "failed"
    assert (await first.poll_once())["held"] == 1


def test_cli_constructs_fixed_worker_without_loading_a_coldkey(setup, monkeypatch, tmp_path):
    from umi.competition_cli import _parser
    from umi.competition_cli import execute as cli_execute

    first = setup.drivers[0]
    policy_path, config_path = tmp_path / "policy.json", tmp_path / "config.json"
    put(policy_path, setup.policy)
    put(config_path, first.config)
    calls = []

    async def run(config, policy, *, legacy, once, report):
        calls.append((config, policy, legacy, once))
        return {"status": "done", "chain_submission_authorized": False}

    monkeypatch.setattr(worker, "run_evaluator", run)
    result = cli_execute(
        _parser().parse_args(
            ["--policy", str(policy_path), "run-evaluator", "--config", str(config_path), "--once"]
        )
    )
    assert result["status"] == "done"
    assert calls == [(first.config, setup.policy, None, True)]


@pytest.mark.asyncio
async def test_endpoint_workers_pair_actual_signed_responses_and_fetch_verified_pulses(
    paired_setup, chain_config, tmp_path
):
    from umi.drand import DrandPulse

    from .test_competition_endpoint_execution import make_job, pair
    from .test_drand import ROUND, pulse_record

    item = paired_setup.dispatch.feed.item
    # The actual authenticated/sealed ASGI transport populates the dispatcher
    # ledger. Its separate local incumbent helpers are not used by these workers.
    await pair(paired_setup, tmp_path)
    await pair(paired_setup, tmp_path, evaluator=1)
    order = signed_order(
        make_job(paired_setup), item.evaluator_wallets[:2], publication=item.publication
    )
    drivers = tuple(
        make_driver(
            tmp_path / f"endpoint-worker-{i}",
            chain_config,
            item.policy,
            paired_setup.archive,
            paired_setup.videos,
            signer,
            legacy=item.legacy_policy,
            dispatch=paired_setup.dispatch.feed.journal.path.parent,
        )
        for i, signer in enumerate(item.evaluator_wallets[:2])
    )
    fetched = []

    class Pulses:
        async def fetch(self, number):
            fetched.append(number)
            assert number == ROUND
            return DrandPulse(**pulse_record())

    for driver in drivers:
        driver.pulses = Pulses()
        driver.provider.block = item.request.issued_block
        put(Path(driver.config.order_directory) / (digest(order.order) + ".json"), order)
    await execute(drivers)
    setup = SimpleNamespace(drivers=drivers, order=order, suite=item.suite)
    await agree(setup)
    results = [completed(d)[0] for d in drivers]
    assert results[0] == results[1]
    assert fetched == [ROUND, ROUND]
    quality, baseline = replay_independent_evaluation(
        results[0],
        item.signed_submission,
        item.round,
        item.suite,
        item.policy,
        current_block=item.round.reveal_block,
    )
    assert aggregate_quality(quality) == 1 and aggregate_quality(baseline) == 0
    for d in drivers:
        await d.aclose()


@pytest.mark.asyncio
async def test_peer_equivocation_stays_held_even_if_conflicting_file_disappears(setup):
    await execute(setup.drivers)
    for d in setup.drivers:
        d.provider.block = 150
        put(Path(d.config.reveal_directory) / (digest(setup.suite) + ".json"), setup.suite)
        await d.poll_once()
    exchange(setup.drivers)
    first, second = setup.drivers
    await first.poll_once()  # retain the first peer execution and our vote
    peer_file = next(Path(first.config.peer_directory).glob("*.execution.json"))
    peer = worker._read(peer_file, worker.SignedExecutionAnnouncement)
    original = peer_file.read_bytes()
    body = peer.announcement
    steps = body.evidence.steps
    changed_output = steps[0].execution.output.model_copy(update={"elapsed_ms": 11})
    changed_step = steps[0].model_copy(
        update={"execution": steps[0].execution.model_copy(update={"output": changed_output})}
    )
    changed = body.model_copy(
        update={"evidence": body.evidence.model_copy(update={"steps": (changed_step, *steps[1:])})}
    )
    put(
        peer_file,
        worker.SignedExecutionAnnouncement(
            announcement=changed, signature=sign_object(changed, second.wallet)
        ),
    )
    assert (await first.poll_once())["held"] == 1
    peer_file.write_bytes(original)
    fresh = worker.ContinuousEvaluator(first.config, first.policy, first.wallet, first.provider)
    assert (await fresh.poll_once())["held"] == 1
    assert not completed(fresh)


@pytest.mark.asyncio
@pytest.mark.parametrize("startup_delay", [0, 2.05])
async def test_production_entrypoint_owns_provider_and_excludes_a_second_process(
    setup, monkeypatch, startup_delay
):
    import bittensor as bt

    first = setup.drivers[0]
    events = []
    stop = asyncio.Event()

    class Owned(Provider):
        async def start(self):
            events.append("start")
            await asyncio.sleep(startup_delay)

        async def aclose(self):
            events.append("close")

    class HotkeyOnly:
        hotkey = first.wallet.hotkey

        @property
        def coldkey(self):
            pytest.fail("evaluator accessed the coldkey")

        @property
        def coldkeypub(self):
            pytest.fail("evaluator accessed the coldkey public file")

    monkeypatch.setattr(bt, "Wallet", lambda **kw: HotkeyOnly())
    monkeypatch.setattr(worker, "FinalizedRegistrationProvider", lambda *a: Owned())

    def report(result):
        events.append(result["no_weight"])
        stop.set()

    task = asyncio.create_task(worker.run_evaluator(first.config, first.policy, report=report))
    reported = asyncio.create_task(stop.wait())
    try:
        # This checks ownership and exclusion, not two-second startup latency.
        # Watch the worker as well so startup failures surface immediately.
        done, _ = await asyncio.wait(
            (task, reported), timeout=15, return_when=asyncio.FIRST_COMPLETED
        )
        if task in done:
            await task
            pytest.fail("continuous evaluator exited before cancellation")
        assert reported in done, "continuous evaluator did not report its first poll"
        with pytest.raises(BlockingIOError):
            await worker.run_evaluator(first.config, first.policy, once=True)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        task.cancel()
        reported.cancel()
        await asyncio.gather(task, reported, return_exceptions=True)
    assert events[0] == "start" and events[-1] == "close"
    # The original private lease inode remains reusable after cancellation.
    lock = worker._lock_file(Path(first.config.state_directory) / "evaluator.lock")
    import os

    os.close(lock)


@pytest.mark.asyncio
async def test_shutdown_interrupts_a_stalled_once_cycle(setup, monkeypatch):
    import signal

    import bittensor as bt

    from umi import competition_execution

    first = setup.drivers[0]
    entered, closed = asyncio.Event(), asyncio.Event()
    handlers = {}

    class Owned(Provider):
        async def start(self):
            pass

        async def aclose(self):
            closed.set()

    async def stalled(**kwargs):
        entered.set()
        await asyncio.Event().wait()

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "add_signal_handler", lambda sig, fn: handlers.setdefault(sig, fn))
    monkeypatch.setattr(loop, "remove_signal_handler", lambda sig: handlers.pop(sig, None))
    monkeypatch.setattr(bt, "Wallet", lambda **kw: first.wallet)
    monkeypatch.setattr(worker, "FinalizedRegistrationProvider", lambda *a: Owned())
    monkeypatch.setattr(competition_execution, "execute_offline_case", stalled)
    task = asyncio.create_task(worker.run_evaluator(first.config, first.policy, once=True))
    await asyncio.wait_for(entered.wait(), 2)
    handlers[signal.SIGTERM]()
    result = await asyncio.wait_for(task, 2)
    assert result["status"] == "stopped" and closed.is_set()
    assert first.executions.status(execution_key(setup.job))["status"] == "failed"
