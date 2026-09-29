"""Accepted submissions through owned preparation, delivery and original terminals.

Finality and sandbox inference are deterministic ports. No prepared round, order,
execution receipt or completion signature is supplied to the pipeline. This is
not an installed-host or chain-effects qualification.
"""

import asyncio
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from umi import competition_cohort_benchmark_host as benchmark_module
from umi.competition_cohort_benchmark_host import BenchmarkHost, BenchmarkHostConfig
from umi.competition_cohort_execution_journal import CohortExecutionConfig
from umi.competition_cohort_intake import (
    CohortIntake,
    CohortIntakeBinding,
    CohortIntakeConfig,
    history_tip,
)
from umi.competition_cohort_order_host import OrderHostConfig
from umi.competition_cohort_order_inbox import CohortOrderInboxConfig
from umi.competition_cohort_order_queue import CohortOrderQueueConfig
from umi.competition_cohort_order_signer import CohortOrderSignerConfig
from umi.competition_cohort_orders import recoverable_order_job
from umi.competition_cohort_participation import (
    CohortParticipationRequest,
    SignedCohortParticipationConsent,
)
from umi.competition_cohort_request_closure import PendingRequestClosure, build_request_closure
from umi.competition_cohort_request_files import RequestCompletionFiles
from umi.competition_cohort_settlement_delivery import SettlementEvidenceFiles
from umi.competition_execution import execution_boundary
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_executor import output
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_lifecycle_host import host as host
from .test_competition_cohort_lifecycle_host import legacy_scenario as legacy_scenario
from .test_competition_cohort_lifecycle_host import lifecycle as lifecycle
from .test_competition_cohort_lifecycle_host import (
    lifecycle_before_intake as lifecycle_before_intake,
)
from .test_competition_cohort_lifecycle_host import precommit_service_inventory
from .test_competition_cohort_lifecycle_host import recovery as recovery
from .test_competition_cohort_lifecycle_host import scenario as scenario
from .test_competition_runner import runtime as runtime
from .test_open_competition import bundle_at, submission, wallet
from .test_open_competition import policy as base_policy  # noqa: F401


def model_request(scenario, model, *, sequence, block):
    signed = submission(scenario["policy"], bundle=model, sequence=sequence)
    body = scenario["consent"].consent.model_copy(
        update={"submission_sha256": digest(signed.submission), "signed_at_block": block}
    )
    return CohortParticipationRequest(
        signed_submission=signed,
        consent=SignedCohortParticipationConsent(
            consent=body, signature=sign_object(body, wallet("Alice"))
        ),
    )


def precommit_model_inventory(h):
    precommit_service_inventory(h)
    h.model = bundle_at(Path(h.intake.config.directory).parent / "model-submission")
    h.request_for = lambda scenario, **kwargs: model_request(scenario, h.model, **kwargs)


pytestmark = pytest.mark.parametrize(
    "lifecycle_before_intake", [precommit_model_inventory], indirect=True
)


@pytest.fixture
def policy(base_policy, runtime):  # noqa: F811
    return base_policy.model_copy(
        update={
            "evaluation_runtime_sha256": digest(runtime),
            "endpoint_reward_bps": 5000,
            "model_reward_bps": 5000,
        }
    )


@pytest.fixture
def intake(tmp_path, scenario):
    history = scenario["intake_history"]
    config = CohortIntakeConfig(
        directory=str(tmp_path / "cohort-intake"),
        cohorts=(
            CohortIntakeBinding(
                cohort_sha256=digest(history.plan),
                authority_sha256=digest(history.authority.authority),
            ),
        ),
    )
    service = CohortIntake(
        config, scenario["policy"], eligible_tracks=("endpoint", "model"), initialize=True
    )
    service.publish(history, capture_at(210))
    return service


async def accept_model(h, scenario):
    # A newer explicitly signed model submission supersedes the two model
    # submissions retained by the lifecycle fixture, before intake closes.
    h.block += 5
    request = model_request(scenario, h.model, sequence=3, block=h.block)
    capture = h.capture(h.block)
    receipt = h.intake.retain(request, capture)
    h.queue.attach_evidence(
        h.cohort,
        receipt["proposed_admission"]["consent_sha256"],
        *await h.provider.retained_archive(execution_boundary(capture)),
    )
    for worker in h.admissions:
        await worker.poll_once()
    return h.model, request


def evaluator_config(o, name, root):
    common = dict(
        policy_sha256=digest(o.h.intake.policy),
        signer=wallet(name).hotkey.ss58_address,
        cohorts=o.h.intake.config.cohorts,
    )
    return SimpleNamespace(
        policy=o.h.intake.policy,
        series=o.config.series,
        owner_hotkey=o.config.admission_owner.owner_hotkey,
        owner_origin="https://owner.example",
        review_timeout_seconds=30,
        benchmark=BenchmarkHostConfig(
            schema="umi-cohort-benchmark-host/1",
            directory=str(root / "host"),
            orders=CohortOrderSignerConfig(
                schema="umi-cohort-order-signer-config/1",
                directory=str(root / "orders"),
                **common,
            ),
            inbox=CohortOrderInboxConfig(
                schema="umi-cohort-order-inbox-config/1",
                directory=str(root / "inbox"),
                **common,
            ),
            execution=CohortExecutionConfig(
                schema="umi-cohort-execution-config/1",
                directory=str(root / "execution"),
                **common,
            ),
            archive_directory=str(root / "models"),
            videos_directory=str(root / "videos"),
            workspace_directory=str(root / "scratch"),
            request_export_directory=str(root / "exports"),
            poll_seconds=1,
        ),
    )


def deliver_exports(nodes, target):
    """Transport original immutable files; never read another owner's database."""
    for node in nodes.values():
        for original in Path(node.config.request_export_directory).rglob("*.json"):
            destination = target / original.relative_to(node.config.request_export_directory)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if destination.exists():
                assert destination.read_bytes() == original.read_bytes()
            else:
                destination.write_bytes(original.read_bytes())
                destination.chmod(0o600)


@pytest.mark.parametrize("interrupt", [False, True], ids=["normal", "outage-restart"])
async def test_accepted_model_reaches_complete_original_request_closure(
    host, scenario, runtime, tmp_path, monkeypatch, interrupt
):
    o, h = host, host.h
    model, submitted = await accept_model(h, scenario)
    inputs = SettlementEvidenceFiles(Path(o.config.lifecycle.sources.objects_directory))
    for value in (scenario["suite"], runtime, model):
        inputs.publish(digest(value), lambda _, value=value: canonical_json_bytes(value))
    orders = OrderHostConfig(
        schema="umi-cohort-order-host/1",
        queue=CohortOrderQueueConfig(
            schema="umi-cohort-order-queue-config/1",
            directory=str(tmp_path / "owner-orders"),
            policy_sha256=digest(h.intake.policy),
            cohorts=h.intake.config.cohorts,
            reviewers=tuple(
                sorted((p.signer for p in o.config.admission_owner.reviewers), key=identity)
            ),
        ),
        poll_seconds=1,
    )
    o.service.config = o.config.model_copy(
        update={"schema_": "umi-cohort-service-admission-host/7", "orders": orders}
    )
    inference, signatures = Counter(), Counter()

    async def invoke(job, attempt):
        inference[(identity(job.evaluator_hotkey), attempt.step_index)] += 1
        return output(job, attempt)

    async def reconcile(job, attempt):
        raise AssertionError("completed inference must not be discarded")

    monkeypatch.setattr(
        benchmark_module,
        "CohortCpuSandbox",
        lambda *a, **kw: SimpleNamespace(invoke=invoke, reconcile=reconcile),
    )
    configs = {n: evaluator_config(o, n, tmp_path / n) for n in ("Charlie", "Dave")}
    async with httpx.AsyncClient() as client:

        def evaluator(name):
            async def sign(body):
                signatures[(name, digest(body))] += 1
                return sign_object(body, wallet(name))

            return BenchmarkHost(configs[name], h.provider, client, "e" * 32, "v" * 32, sign)

        nodes = {name: evaluator(name) for name in configs}
        for name, node in nodes.items():
            o.apps[name.lower() + ".example"].include_router(node.routes)
        async with o.open() as app:
            o.apps["owner.example"] = app
            lifecycle = await app.state.lifecycle.node(h.cohort)
            for _ in range(100):
                if lifecycle.controller.store.status(h.cohort)[0].phase != "intake":
                    break
                h.block += 5
                await lifecycle.tick()
            assert lifecycle.controller.store.status(h.cohort)[0].phase == "preparation"
            assert (await lifecycle.tick())["status"] == "waiting_request_rest"
            h.timestamp = 2_030_000
            await lifecycle.tick()
            assert lifecycle.controller.store.status(h.cohort)[0].phase == "requests"
            source = await o.service.history(h.cohort)
            prepared = o.service.preparation.retained(
                h.cohort, expected_tip_sha256=history_tip(source.history), current_block=h.block
            )
            assert prepared.roster.intake_seal.record_count == 3
            assert len(prepared.roster.participants) == 1
            assert prepared.roster.participants[0].record.request == submitted
            assert await app.state.orders.select(h.cohort) == 1
            (slot,) = app.state.orders.queue.pending(h.cohort)
            report = await app.state.orders.worker.poll_once()
            assert report["deliveries_acknowledged"] == 2, report
            assignments = {name: n.inbox.assignment(slot) for name, n in nodes.items()}
            frozen_order = canonical_json_bytes(assignments["Charlie"].certificate)
            for node in nodes.values():
                assert (await node.worker.poll_once())["retry_count"] == 1
                assert node.execution.journal.get("assignment", slot) is None
            assert not inference
            h.block += 1
            for node in nodes.values():
                assert (await node.worker.poll_once())["retry_count"] == 0
            first_steps = {
                name: canonical_json_bytes(
                    node.execution.step(
                        recoverable_order_job(
                            assignments[name].certificate.order, node.config.orders.signer
                        ),
                        0,
                    )
                )
                for name, node in nodes.items()
            }

        if interrupt:
            # Ten hours at nominal block cadence, with no owner or renewer.
            h.block += 3000
            o.outages.add("owner.example")
            for name in nodes:
                nodes[name] = evaluator(name)
                assert (await nodes[name].worker.poll_once())["retry_count"] == 1
            assert sum(inference.values()) == 2
            o.outages.clear()

        async with o.open() as app:
            o.apps["owner.example"] = app
            selected_signatures = sum(signatures.values())
            assert await app.state.orders.select(h.cohort) == 1
            assert (await app.state.orders.worker.poll_once())["retry_count"] == 0
            assert sum(signatures.values()) == selected_signatures
            for name, node in nodes.items():
                assignment = node.inbox.assignment(slot)
                assert canonical_json_bytes(assignment.certificate) == frozen_order
                job = recoverable_order_job(assignment.certificate.order, node.config.orders.signer)
                assert canonical_json_bytes(node.execution.step(job, 0)) == first_steps[name]

            # The actual recurring host owns the remaining execution and export
            # work. This loop advances only the synthetic chain, never a stage.
            stop = asyncio.Event()
            tasks = [asyncio.create_task(node.run(stop)) for node in nodes.values()]
            try:

                async def complete():
                    while True:
                        for task in tasks:
                            if task.done():
                                task.result()
                                raise AssertionError("evaluator exited before completion")
                        if all(
                            node.files.terminal(
                                assignments[name].certificate, node.config.orders.signer
                            )
                            is not None
                            for name, node in nodes.items()
                        ):
                            return
                        h.block += 1
                        await asyncio.sleep(0.1)

                await asyncio.wait_for(complete(), 60)
            finally:
                stop.set()
                await asyncio.wait_for(asyncio.gather(*tasks), 30)
            assert all(not node.tasks for node in nodes.values())
            assert all(node.execution.evidence(slot) is not None for node in nodes.values())

            delivered = Path(o.config.lifecycle.request_completion_directory)
            files = RequestCompletionFiles(delivered)

            def close():
                return build_request_closure(
                    prepared.roster,
                    files.orders(prepared.roster),
                    files.terminal,
                    files.objects,
                    h.intake.policy,
                    source.history,
                    execution_boundary(h.capture(h.block)),
                    decision_source=source.inputs().__getitem__,
                    intake_records=h.intake.export_records(
                        h.cohort, maximum_bytes=1024**2, maximum_records=8
                    ),
                    expected_tip_sha256=history_tip(source.history),
                    current_block=h.block,
                )

            with pytest.raises(PendingRequestClosure):
                close()
            deliver_exports({"Charlie": nodes["Charlie"]}, delivered)
            with pytest.raises(PendingRequestClosure):
                close()
            deliver_exports({"Dave": nodes["Dave"]}, delivered)
            closure = close()
            assert len(closure.participants) == 1
            assert len(closure.participants[0].evaluators) == 2
            assert max(inference.values()) == max(signatures.values()) == 1
            assert sum(inference.values()) == 12
            # Reopened workers can recover all completed originals offline.
            h.offline = True
            o.outages.add("owner.example")
            counts = dict(inference), dict(signatures)
            for name in nodes:
                node = evaluator(name)
                assert (await node.worker.poll_once())["jobs_complete"] == 1
                with pytest.raises(OSError):
                    await node.exporter.poll_once()
                # Already published immutable exports remain readable even when
                # finality prevents this worker from creating another terminal.
                assert (
                    node.files.terminal(assignments[name].certificate, node.config.orders.signer)
                    is not None
                )
            assert (dict(inference), dict(signatures)) == counts
