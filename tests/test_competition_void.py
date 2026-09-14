from __future__ import annotations

import json

import httpx
import pytest

from umi import competition_execution as execution
from umi.competition_endpoint_execution import assemble_endpoint_observations
from umi.competition_observations import ExecutionAnnouncement, SignedExecutionAnnouncement
from umi.competition_runner import OfflineCaseExecution
from umi.competition_void import (
    AttestedEvaluationVoid,
    propose_evaluation_void,
    validate_own_void,
    verify_evaluation_void,
)
from umi.open_competition import CaseOutput, digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_endpoint_execution import authorization as authorization
from .test_competition_endpoint_execution import dispatch as dispatch
from .test_competition_endpoint_execution import feed as feed
from .test_competition_endpoint_execution import make_job, pair
from .test_competition_endpoint_execution import paired_setup as paired_setup
from .test_competition_evaluator import signed_order
from .test_competition_execution import policy as policy
from .test_competition_execution import run_job
from .test_competition_execution import runtime as runtime
from .test_competition_execution import setup as setup
from .test_open_competition import wallet


def announce(evidence, order, signer):
    body = ExecutionAnnouncement(
        schema="umi-execution-announcement/1",
        order_sha256=digest(order.order),
        evaluator_hotkey=signer.hotkey.ss58_address,
        evidence=evidence,
    )
    return SignedExecutionAnnouncement(announcement=body, signature=sign_object(body, signer))


def certify(context, observations, signers):
    proposed = propose_evaluation_void(observations=observations, **context)
    by_key = {o.announcement.evaluator_hotkey: o for o in observations}
    for signer in signers:
        assert (
            validate_own_void(
                proposed,
                own_observation=by_key[signer.hotkey.ss58_address],
                evaluator_hotkey=signer.hotkey.ss58_address,
                **context,
            )
            == proposed
        )
    result = AttestedEvaluationVoid(
        void=proposed, signatures=tuple(sign_object(proposed, w) for w in signers)
    )
    assert verify_evaluation_void(result, **context) == result
    return result


@pytest.fixture
async def attempts(setup, tmp_path, monkeypatch, request):
    policy, job, suite, _, _, _ = setup
    kind = getattr(request, "param", "incumbent_failure")
    original = execution.execute_offline_case

    async def run(**kwargs):
        value = await original(**kwargs)
        is_incumbent = digest(kwargs["bundle"]) == digest(job.incumbent)
        if (kind == "incumbent_failure" and is_incumbent) or (
            kind == "miner_failure" and not is_incumbent
        ):
            return OfflineCaseExecution(
                **{
                    **value.model_dump(by_alias=True),
                    "reason": "process_failed",
                    "returncode": 1,
                    "stdout_hex": "",
                    "output": CaseOutput(
                        case_id=kwargs["case_id"],
                        status="miner_failure",
                        hypothesis="",
                        elapsed_ms=10,
                    ),
                }
            )
        return value

    monkeypatch.setattr(execution, "execute_offline_case", run)
    signers = (wallet("Charlie"), wallet("Dave"))
    order = signed_order(job, signers)
    first, _ = await run_job(setup, tmp_path)
    if kind == "observation_disagreement":

        async def disagree(**kwargs):
            value = await original(**kwargs)
            return value.model_copy(
                update={
                    "stdout_hex": b"different\n".hex(),
                    "output": value.output.model_copy(update={"hypothesis": "different"}),
                }
            )

        monkeypatch.setattr(execution, "execute_offline_case", disagree)
    second, _ = await run_job(
        setup,
        tmp_path,
        name="second",
        job=job.model_copy(update={"evaluator_hotkey": signers[1].hotkey.ss58_address}),
    )
    return (
        dict(signed_order=order, suite=suite, policy=policy, current_block=150),
        tuple(announce(e, order, w) for e, w in zip((first, second), signers, strict=True)),
        signers,
    )


@pytest.mark.parametrize(
    "attempts", ["incumbent_failure", "observation_disagreement"], indirect=True
)
async def test_void_is_explicit_signed_and_deterministic(attempts):
    context, observations, signers = attempts
    certificate = certify(context, observations, signers)
    assert (
        propose_evaluation_void(observations=tuple(reversed(observations)), **context)
        == certificate.void
    )
    assert not certificate.void.chain_submission_authorized
    assert certificate.void.reason in {"incumbent_failure", "observation_disagreement"}
    # Existing scoring and promotion-facing aggregation stays strict.
    with pytest.raises(
        ValueError, match=r"incumbent execution failed|independent executions disagree"
    ):
        execution.common_execution_result(
            tuple(o.announcement.evidence for o in observations),
            context["suite"],
            context["policy"],
            current_block=150,
        )


@pytest.mark.parametrize("attempts", ["healthy", "miner_failure"], indirect=True)
async def test_healthy_or_agreed_miner_failure_is_not_a_void(attempts):
    context, observations, _ = attempts
    with pytest.raises(ValueError, match="cannot be voided"):
        propose_evaluation_void(observations=observations, **context)


@pytest.mark.parametrize(
    "mutation", ["missing", "duplicate", "signature", "order", "steps", "stdout"]
)
async def test_bad_or_incomplete_observations_cannot_authorize_exclusion(attempts, mutation):
    context, observations, signers = attempts
    changed = list(observations)
    if mutation == "missing":
        changed.pop()
    elif mutation == "duplicate":
        changed[1] = changed[0]
    else:
        body = changed[0].announcement
        if mutation == "signature":
            changed[0] = changed[0].model_copy(
                update={"signature": sign_object(body, wallet("Eve"))}
            )
        else:
            doc = body.model_dump(mode="json", by_alias=True)
            if mutation == "order":
                doc["order_sha256"] = "00" * 32
            elif mutation == "steps":
                doc["evidence"]["steps"][1]["finished"]["block"] = 1000
            else:
                doc["evidence"]["steps"][0]["execution"]["stdout_hex"] = b"fabricated".hex()
            body = ExecutionAnnouncement.model_validate_json(json.dumps(doc))
            changed[0] = SignedExecutionAnnouncement(
                announcement=body, signature=sign_object(body, signers[0])
            )
    with pytest.raises(ValueError):
        propose_evaluation_void(observations=tuple(changed), **context)


@pytest.mark.parametrize(
    "mutation",
    ["reason", "round", "missing_signer", "duplicate_signer", "foreign_signer", "changed_local"],
)
async def test_void_decision_and_local_execution_are_bound(attempts, mutation):
    context, observations, signers = attempts
    certificate = certify(context, observations, signers)
    if mutation == "changed_local":
        wrong = observations[0].model_copy(update={"signature": observations[1].signature})
        with pytest.raises(ValueError, match="exact local observation"):
            validate_own_void(
                certificate.void,
                own_observation=wrong,
                evaluator_hotkey=signers[0].hotkey.ss58_address,
                **context,
            )
        return
    if mutation in {"reason", "round"}:
        proposed = certificate.void.model_copy(
            update={"reason": "observation_disagreement"}
            if mutation == "reason"
            else {"round_sha256": "00" * 32}
        )
        certificate = AttestedEvaluationVoid(
            void=proposed, signatures=tuple(sign_object(proposed, w) for w in signers)
        )
    else:
        votes = certificate.signatures
        votes = (
            votes[:1]
            if mutation == "missing_signer"
            else (votes[0], votes[0])
            if mutation == "duplicate_signer"
            else (votes[0], sign_object(certificate.void, wallet("Eve")))
        )
        certificate = certificate.model_copy(update={"signatures": votes})
    with pytest.raises(ValueError):
        verify_evaluation_void(certificate, **context)


@pytest.mark.parametrize("block", [True, 149, 201])
async def test_void_cannot_bypass_reveal_or_validity_window(attempts, block):
    context, observations, _ = attempts
    context["current_block"] = block
    with pytest.raises(ValueError, match="premature or expired"):
        propose_evaluation_void(observations=observations, **context)


async def test_real_endpoint_outage_can_be_certified_without_becoming_miner_failure(
    paired_setup, tmp_path
):
    item = paired_setup.dispatch.feed.item
    paired_setup.dispatch.driver.transport = httpx.MockTransport(
        lambda request: httpx.Response(503)
    )
    first = await pair(paired_setup, tmp_path, assemble=assemble_endpoint_observations)
    second = await pair(
        paired_setup, tmp_path, evaluator=1, assemble=assemble_endpoint_observations
    )
    signers = tuple(item.evaluator_wallets[:2])
    order = signed_order(make_job(paired_setup), signers, publication=item.publication)
    context = dict(
        signed_order=order,
        suite=item.suite,
        policy=item.policy,
        current_block=item.round.reveal_block,
        legacy=item.legacy_policy,
    )
    observations = tuple(
        announce(e, order, w) for e, w in zip((first, second), signers, strict=True)
    )
    certificate = certify(context, observations, signers)
    assert certificate.void.reason == "infrastructure_failure"
    assert paired_setup.dispatch.miner.translator.calls == 0
    assert b"miner_failure" not in canonical_json_bytes(certificate)
