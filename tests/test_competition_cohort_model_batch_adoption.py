"""Real retained adoption intents and interrupted actor delivery; no live chain."""

import asyncio
import fcntl
import os
import pwd
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi import competition_cohort_model_batch_adoption_operator as operator
from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_model_batch import (
    SignedModelBatchCertificationAdoption,
    prepare_model_batch_certification_adoption,
    verify_model_batch_certification_adoption,
)
from umi.competition_cohort_model_batch_adoption import (
    ModelBatchAdoptionReviewRequest,
    attest_model_batch_adoption,
)
from umi.competition_cohort_model_review_http import ModelReviewPeer, model_review_routes
from umi.competition_cohort_review_http import CohortReviewPeerConfig
from umi.open_competition import digest, identity
from umi.private_files import ensure_private_directory, publish_private_model, read_private_model

from .test_competition_cohort_model_review import (
    base_policy as base_policy,
)
from .test_competition_cohort_model_review import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_model_review import (
    policy as policy,
)
from .test_competition_cohort_model_review import (
    prepared as prepared,
)
from .test_competition_cohort_model_review import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_model_review import (
    recovery as recovery,
)
from .test_competition_cohort_model_review import (
    reviews as reviews,
)
from .test_competition_cohort_model_review import (
    runtime as runtime,
)
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


@pytest.fixture
def adoption(reviews):
    r = reviews
    history = r.owner.intake.history(r.cohort)
    policy = r.owner.intake.policy
    request = ModelBatchAdoptionReviewRequest(
        adoption=prepare_model_batch_certification_adoption(
            history, policy, expected_tip_sha256=history_tip(history), effective_at_block=225
        ),
        operator_request_reference="retained operator message 0805; prospective cohort batching",
    )

    def create(name, *, approve=True):
        reviewer = r.create(name)
        directory = r.root / name / "batch-adoptions"
        ensure_private_directory(directory)
        reviewer.config = reviewer.config.model_copy(
            update={"batch_certification_adoptions_directory": str(directory)}
        )
        if approve:
            publish_private_model(directory / (r.cohort + ".candidate.json"), request)
        return reviewer

    return SimpleNamespace(r=r, history=history, policy=policy, request=request, create=create)


async def test_batch_adoption_request_cannot_select_itself(adoption):
    a = adoption
    with pytest.raises(FileNotFoundError):
        await attest_model_batch_adoption(a.create("Charlie", approve=False), a.request)
    assert a.r.state.signing == []


async def test_completed_batch_adoption_vote_reuses_intent_without_files_rpc_or_history(adoption):
    a = adoption
    first = await attest_model_batch_adoption(a.create("Charlie"), a.request)
    restarted = a.create("Charlie", approve=False)
    Path(restarted.config.batch_certification_adoptions_directory).rename(a.r.root / "offline")
    a.r.state.online = False
    assert await attest_model_batch_adoption(restarted, a.request) == first
    assert len(a.r.state.signing) == 1


async def test_batch_adoption_rejects_changed_operator_reference_after_reservation(adoption):
    a = adoption
    reviewer = a.create("Charlie")
    await attest_model_batch_adoption(reviewer, a.request)
    changed = a.request.model_copy(update={"operator_request_reference": "another decision"})
    with pytest.raises(ValueError, match="original operator request"):
        await attest_model_batch_adoption(reviewer, changed)
    assert len(a.r.state.signing) == 1


async def test_batch_adoption_resumes_unfinished_signing(adoption):
    a = adoption
    reviewer = a.create("Charlie")

    async def unavailable(_):
        raise OSError("test signer offline")

    reviewer.sign = unavailable
    with pytest.raises(OSError):
        await attest_model_batch_adoption(reviewer, a.request)
    restarted = a.create("Charlie", approve=False)
    Path(restarted.config.batch_certification_adoptions_directory).rename(a.r.root / "offline")
    vote = await attest_model_batch_adoption(restarted, a.request)
    assert vote.adoption == a.request.adoption
    assert len(a.r.state.signing) == 1


@pytest.mark.parametrize("bad", ["future", "different-predecessor", "different-authority"])
async def test_batch_adoption_independent_history_and_time_checks(adoption, bad):
    a = adoption
    reviewer = a.create("Charlie", approve=False)
    fields = {
        "future": {"effective_at_block": 240},
        "different-predecessor": {"predecessor_sha256": "fe" * 32},
        "different-authority": {"authority_sha256": "fd" * 32},
    }[bad]
    request = a.request.model_copy(
        update={"adoption": a.request.adoption.model_copy(update=fields)}
    )
    publish_private_model(
        Path(reviewer.config.batch_certification_adoptions_directory)
        / (a.r.cohort + ".candidate.json"),
        request,
    )
    with pytest.raises(ValueError):
        await attest_model_batch_adoption(reviewer, request)
    assert not a.r.state.signing


async def test_batch_adoption_authenticated_http_route_uses_selected_reviewer(adoption):
    a = adoption
    reviewer = a.create("Charlie")
    app = FastAPI()
    app.include_router(model_review_routes(reviewer, token="t" * 48))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        peer = ModelReviewPeer(
            client,
            "https://review.example",
            policy=a.policy,
            cohorts=reviewer.config.cohorts,
            signer=reviewer.config.signer,
            token="t" * 48,
        )
        vote = await peer.attest_batch_adoption(a.request)
        assert vote.adoption == a.request.adoption
        wrong = ModelReviewPeer(
            client,
            "https://review.example",
            policy=a.policy,
            cohorts=reviewer.config.cohorts,
            signer=reviewer.config.signer,
            token="x" * 48,
        )
        with pytest.raises(OSError):
            await wrong.attest_batch_adoption(a.request)
    assert len(a.r.state.signing) == 1


@pytest.fixture
def adoption_operator(adoption, tmp_path, monkeypatch):
    a = adoption
    account = pwd.getpwuid(os.getuid()).pw_name
    reviewers = {
        identity(wallet(name).hotkey.ss58_address): a.create(name, approve=False)
        for name in ("Charlie", "Dave")
    }
    peers = tuple(
        CohortReviewPeerConfig(
            signer=reviewer.config.signer,
            origin="https://review.example",
            token_file=str(tmp_path / "token"),
            timeout_seconds=30,
        )
        for reviewer in reviewers.values()
    )
    owner = operator.ModelBatchAdoptionTarget(
        role="owner",
        service_unit="owner.service",
        service_account=account,
        config_path=str(tmp_path / "owner-config.json"),
        config_sha256="ab" * 32,
    )
    selected_owner = operator.SelectedBatchAdoptionTarget(
        owner,
        tmp_path / "owner-adoptions",
        digest(a.policy),
        a.r.owner.intake.config.cohorts,
        peers=peers,
        cohort_sequences=((a.r.cohort, a.history.plan.sequence),),
    )
    ensure_private_directory(selected_owner.directory)
    selected = [selected_owner]
    for n, reviewer in enumerate(reviewers.values()):
        target = operator.ModelBatchAdoptionTarget(
            role="reviewer",
            service_unit=f"reviewer{n}.service",
            service_account=account,
            config_path=str(tmp_path / f"reviewer{n}-config.json"),
            config_sha256=f"{n + 1:02x}" * 32,
        )
        selected.append(
            operator.SelectedBatchAdoptionTarget(
                target,
                Path(reviewer.config.batch_certification_adoptions_directory),
                digest(a.policy),
                reviewer.config.cohorts,
                signer=reviewer.config.signer,
            )
        )
    config = operator.ModelBatchAdoptionOperatorConfig(
        schema="umi-model-batch-adoption-operator/1",
        state_directory=str(tmp_path / "operator"),
        policy_file=str(tmp_path / "policy.json"),
        history_file=str(tmp_path / "history.json"),
        expected_tip_sha256=history_tip(a.history),
        effective_at_block=225,
        operator_request_reference=a.request.operator_request_reference,
        owner=owner,
        reviewers=tuple(t.target for t in selected[1:]),
    )
    state = SimpleNamespace(fail_vote=None, fail_delivery=None, calls=[], deliveries=[])
    by_unit = {t.target.service_unit: t for t in selected}
    monkeypatch.setattr(
        operator, "load_adoption_target", lambda target: by_unit[target.service_unit]
    )
    monkeypatch.setattr(operator, "check_target_process", lambda target: {})
    monkeypatch.setattr(operator, "_read_root_control_path", lambda *args, **kwargs: b"t" * 48)

    def peer_factory(*args, signer, **kwargs):
        key = identity(signer)

        async def attest(request):
            state.calls.append(key)
            if state.fail_vote == key:
                raise OSError("test reviewer unavailable")
            return await attest_model_batch_adoption(reviewers[key], request)

        return SimpleNamespace(attest_batch_adoption=attest)

    def publish(target, request, signed=None, *, check_only=False):
        if signed is not None and not check_only:
            if state.fail_delivery == target.service_unit:
                raise OSError("test actor publication unavailable")
            state.deliveries.append(target.service_unit)
        return operator.publish_for_actor(target, request, signed, check_only=check_only)

    async def run():
        return await operator.run_model_batch_adoption(
            config,
            a.policy,
            a.history,
            client=None,
            publish=publish,
            peer_factory=peer_factory,
        )

    return SimpleNamespace(
        a=a,
        config=config,
        state=state,
        selected=selected,
        reviewers=reviewers,
        run=run,
        publish=publish,
        peer_factory=peer_factory,
    )


async def test_operator_retains_votes_across_failure_and_selects_owner_last(adoption_operator):
    o = adoption_operator
    keys = sorted(o.reviewers)
    o.state.fail_vote = keys[1]
    with pytest.raises(OSError):
        await o.run()
    assert not (o.selected[0].directory / (o.a.r.cohort + ".json")).exists()
    assert len(o.a.r.state.signing) == 1
    o.state.fail_vote = None
    result = await o.run()
    assert result["runtime_activation_verified"] is False
    assert result["selected_consumers"] == 3
    assert o.state.deliveries[-1] == "owner.service"
    assert len(o.a.r.state.signing) == 2
    signed = read_private_model(
        Path(o.config.state_directory) / "signed.json", SignedModelBatchCertificationAdoption
    )
    verify_model_batch_certification_adoption(signed, o.a.history, o.a.policy, maximum_block=225)
    before = list(o.state.calls)
    assert await o.run() == result
    assert o.state.calls == before
    assert len(o.a.r.state.signing) == 2


async def test_operator_interrupted_delivery_resumes_without_signing_or_enabling_owner(
    adoption_operator,
):
    o = adoption_operator
    o.state.fail_delivery = o.selected[2].target.service_unit
    with pytest.raises(OSError):
        await o.run()
    assert (Path(o.config.state_directory) / "signed.json").exists()
    assert not (o.selected[0].directory / (o.a.r.cohort + ".json")).exists()
    before = list(o.state.calls)
    o.state.fail_delivery = None
    await o.run()
    assert o.state.calls == before
    assert o.state.deliveries[-1] == "owner.service"


async def test_operator_missing_retained_vote_is_explicit_repair(adoption_operator):
    o = adoption_operator
    await o.run()
    (Path(o.config.state_directory) / ("vote-" + sorted(o.reviewers)[0] + ".json")).unlink()
    before = list(o.state.calls)
    with pytest.raises(ValueError, match="lost a configured vote; repair required"):
        await o.run()
    assert o.state.calls == before


def test_operator_startup_parser_accepts_literal_maintenance_wrapper_only(receipt_scenario):
    script = (
        "import sys,runpy;sys.argv=['umi.competition_cli','serve-intake','--config','/a.json'];"
        "runpy.run_module('umi.competition_cli')"
    )
    assert operator._startup_arguments(["python", "-I", "-B", "-c", script])[-1] == "/a.json"
    with pytest.raises((ValueError, TypeError)):
        operator._startup_arguments(["python", "-c", "import sys;sys.argv=read_secret()"])


def test_actor_publication_refuses_another_service_account(adoption_operator):
    o = adoption_operator
    target = o.config.owner.model_copy(update={"service_account": "unrelated-service"})
    with pytest.raises(ValueError, match="selected service account"):
        operator.publish_for_actor(target, o.a.request)


async def test_operator_cancellation_releases_nonblocking_lock(adoption_operator, monkeypatch):
    o = adoption_operator
    acquired = asyncio.Event()
    original = operator.publish_private_model

    async def controlled_thread(function, *args, **kwargs):
        if function is original and Path(args[0]).name == "plan.json":
            acquired.set()
            await asyncio.Future()
        return await asyncio.to_thread(function, *args, **kwargs)

    monkeypatch.setattr(operator, "run_owned_thread", controlled_thread)
    task = asyncio.create_task(o.run())
    await asyncio.wait_for(acquired.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    descriptor = operator.lock_private_file(Path(o.config.state_directory) / ".operator.lock")
    fcntl.flock(descriptor, fcntl.LOCK_UN)
    os.close(descriptor)
