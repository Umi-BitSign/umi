"""Native journals and signatures; synthetic finality and sandbox observations."""

from types import SimpleNamespace

from umi.competition_cohort_endpoint import endpoint_attempt_wire_ids
from umi.competition_cohort_endpoint_archive import JournalEndpointObjects
from umi.competition_cohort_execution_journal import (
    CohortExecutionAssignment,
    CohortExecutionConfig,
    CohortExecutionJournal,
)
from umi.competition_cohort_order_queue import SignedOrderDeliveryReceipt, delivery_receipt
from umi.competition_cohort_order_signer import (
    CohortOrderHistory,
    CohortOrderParticipant,
    order_slot,
)
from umi.competition_cohort_orders import (
    RecoverableEvaluationOrder,
    SignedRecoverableEvaluationOrder,
)
from umi.competition_cohort_request_closure import build_request_closure
from umi.competition_cohort_request_terminal import seal_request_terminal
from umi.config import Limits
from umi.miner import _signed_envelope
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_consumers import tip
from .test_competition_cohort_endpoint_quality import archive
from .test_competition_cohort_recovery import signatures
from .test_competition_cohort_roster import make_round
from .test_competition_execution import boundary
from .test_component_run import response_plaintext
from .test_open_competition import wallet


def endpoint_inputs(original, scenario, miner_name):
    """Rebind real encrypted fixtures to the new complete intake/preparation."""
    results = []
    for old, execution in zip(original["endpoints"], scenario["artifacts"], strict=True):
        job = execution.job
        requests, transcripts = [], []
        miner = SimpleNamespace(
            wallet=wallet(miner_name),
            hotkey_ss58=job.submission.submission.hotkey,
            signature_scheme="sr25519",
            limits=Limits.from_policy(old.transport_policy),
        )
        for case, request, transcript in zip(
            job.cases, old.order.order.requests, old.transcripts, strict=True
        ):
            batch, challenge = endpoint_attempt_wire_ids(job, 1, case.case_id)
            request = request.model_copy(update={"batch_id": batch, "challenge_id": challenge})
            plain = response_plaintext(
                request,
                validator_hotkey=job.evaluator_hotkey,
                miner_hotkey=miner.hotkey_ss58,
            ).model_copy(
                update={
                    "model_revision": job.submission.submission.model_revision,
                    "hypothesis": "hello",
                }
            )
            raw, signature = _signed_envelope(miner, request, plain)
            requests.append(request)
            transcripts.append(
                transcript.model_copy(
                    update={"envelope_hex": raw.hex(), "response_signature": signature}
                )
            )
        body = old.order.order.model_copy(update={"job": job, "requests": tuple(requests)})
        results.append(
            old.model_copy(
                update={
                    "incumbent": execution,
                    "order": old.order.model_copy(
                        update={"order": body, "signatures": signatures(body)}
                    ),
                    "transcripts": tuple(transcripts),
                }
            )
        )
    scenario["endpoints"] = tuple(results)


async def closure_fixture(original, tmp_path, *, prepared=None):
    b = make_round(original, include_outcomes=False) if prepared is None else prepared
    b["history"] = b["history"].model_copy(update={"transitions": b["history"].transitions[:2]})
    source = CohortOrderHistory(
        history=b["history"],
        decisions=tuple(
            b["decisions"][t.transition.evidence_sha256] for t in b["history"].transitions
        ),
    )
    objects, orders, terminals, owners, endpoint_archives = {}, [], {}, {}, {}

    def put(value):
        objects[digest(value)] = canonical_json_bytes(value)
        return digest(value)

    for s in b["scenarios"]:
        s["history"] = b["history"]
        first = s["artifacts"][0].job
        body = RecoverableEvaluationOrder(
            schema="umi-recoverable-evaluation-order/1",
            **{
                k: getattr(first, k)
                for k in (
                    "round",
                    "preparation_closure_sha256",
                    "submission",
                    "incumbent",
                    "runtime",
                    "cases",
                )
            },
            evaluators=tuple(
                sorted((a.job.evaluator_hotkey for a in s["artifacts"]), key=identity)
            ),
        )
        order = SignedRecoverableEvaluationOrder(order=body, signatures=signatures(body))
        orders.append(order)
        put(order)
        miner_name = next(
            n
            for n in ("Alice", "Bob")
            if wallet(n).hotkey.ss58_address == first.submission.submission.hotkey
        )
        if first.mode == "endpoint_incumbent":
            endpoint_inputs(original, s, miner_name)
        for evidence, name in zip(s["artifacts"], ("Charlie", "Dave"), strict=True):
            evaluator = wallet(name).hotkey.ss58_address
            receipt = delivery_receipt(order, evaluator)
            assignment = CohortExecutionAssignment(
                certificate=order,
                participant=CohortOrderParticipant(
                    **{k: s[k] for k in ("consent", "admission", "admission_snapshot")}
                ),
                delivery=SignedOrderDeliveryReceipt(
                    receipt=receipt, signature=sign_object(receipt, wallet(name))
                ),
            )
            cfg = CohortExecutionConfig(
                schema="umi-cohort-execution-config/1",
                directory=str(tmp_path / (digest(order) + name)),
                policy_sha256=digest(b["policy"]),
                signer=evaluator,
                cohorts=(
                    {
                        "cohort_sha256": digest(b["history"].plan),
                        "authority_sha256": digest(b["history"].authority.authority),
                    },
                ),
            )
            owner = CohortExecutionJournal(cfg, b["policy"])
            job = owner.retain(assignment, source, 1500)
            slot = order_slot(order.order)
            for index, step in enumerate(evidence.steps):
                attempt = owner.begin(job, index, source, step.started)
                owner.observe(job, attempt, step.execution)
                owner.finish(job, attempt, step.finished)
            endpoint_root = None
            if first.mode == "endpoint_incumbent":
                endpoint_root, exported, _ = archive(
                    s, evaluator_name=name, miner_name=miner_name, assignment=assignment
                )
                objects.update(exported)

            async def sign(body, name=name):
                return sign_object(body, wallet(name))

            terminal = await seal_request_terminal(
                owner,
                slot,
                sign,
                endpoint_archive=endpoint_root,
                endpoint_objects=objects.__getitem__ if endpoint_root is not None else None,
            )
            local = JournalEndpointObjects(owner.journal)
            with owner.journal.transaction() as db:
                keys = [
                    row[0]
                    for row in db.execute(
                        "SELECT id FROM records WHERE kind='endpoint_replay_object'"
                    )
                ]
            objects.update({key: local(key) for key in keys})
            key = digest(order), identity(evaluator)
            terminals[key], owners[key], endpoint_archives[key] = terminal, owner, endpoint_root
    b.update(
        objects=objects,
        orders=tuple(orders),
        terminals=terminals,
        owners=owners,
        endpoint_archives=endpoint_archives,
    )
    b["closure"] = build(b)
    return b


def build(b, **changes):
    args = dict(
        roster=b["roster"],
        orders=b["orders"],
        terminal_source=lambda order, who: b["terminals"].get((digest(order), identity(who))),
        objects=b["objects"].__getitem__,
        policy=b["policy"],
        history=b["history"],
        observation=boundary(1680),
        decision_source=b["decisions"].__getitem__,
        intake_records=iter(b["records"]),
        expected_tip_sha256=tip(b["history"]),
        current_block=1680,
    )
    args.update(changes)
    return build_request_closure(**args)
