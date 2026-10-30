"""Real private journals and signed CPU contracts; synthetic finality only."""

import os
import pwd
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi import competition_cohort_model_batch_adoption_operator as shared
from umi import competition_cpu_efficiency_operator as operator
from umi.competition_cohort_intake import CohortIntakeBinding, history_tip
from umi.competition_cohort_model_batch_adoption_series import ModelBatchAdoptionSeriesConfig
from umi.competition_cohort_model_review import ModelArtifactReviewer, ModelReviewConfig
from umi.competition_cohort_model_review_http import ModelReviewPeer, model_review_routes
from umi.competition_cohort_review_http import CohortReviewPeerConfig
from umi.competition_cpu_efficiency_adoption import (
    CpuEfficiencyReviewRequest,
    attest_cpu_efficiency,
)
from umi.competition_cpu_efficiency_policy import (
    default_cpu_efficiency_proposal,
)
from umi.open_competition import digest, identity, sign_object
from umi.private_files import ensure_private_directory, publish_private_model

from .test_competition_cohort_intake import capture_at
from .test_competition_cpu_efficiency_policy import (
    base_policy as base_policy,
)
from .test_competition_cpu_efficiency_policy import (
    original_runtime as original_runtime,
)
from .test_competition_cpu_efficiency_policy import (
    policy as policy,
)
from .test_competition_cpu_efficiency_policy import (
    recovery as recovery,
)
from .test_competition_cpu_efficiency_policy import (
    runtime as runtime,
)
from .test_competition_cpu_efficiency_policy import (
    runtime_adoption as runtime_adoption,
)
from .test_competition_cpu_efficiency_policy import (
    scenario as scenario,
)
from .test_open_competition import wallet


@pytest.fixture
def cpu_review(scenario, policy, runtime_adoption, tmp_path):
    history = scenario["intake_history"]
    cohort, authority = digest(history.plan), history.authority.authority
    body = default_cpu_efficiency_proposal(
        policy=policy,
        authority=authority,
        runtime_sha256=digest(runtime_adoption.adoption.runtime),
        issued_at_block=200,
        reason=operator.CPU_DEFAULT_REASON,
    )
    request = CpuEfficiencyReviewRequest(
        adoption=body,
        anchor_cohort_sha256=cohort,
        runtime_adoption=runtime_adoption,
        operator_request_reference="retained standing C8 and later CPU efficiency decision",
    )
    binding = CohortIntakeBinding(cohort_sha256=cohort, authority_sha256=digest(authority))
    state = SimpleNamespace(online=True, votes=[], history_reads=0, captures=0)

    async def capture():
        assert state.online, "completed vote must not contact finality"
        state.captures += 1
        return capture_at(230)

    async def read_history(key):
        assert state.online, "completed vote must not reread history"
        assert key == cohort
        state.history_reads += 1
        return SimpleNamespace(history=history)

    def create(name, *, approve=False):
        root = tmp_path / name
        config = ModelReviewConfig(
            schema="umi-cohort-model-review-config/1",
            directory=str(root / "journal"),
            approvals_directory=str(root / "approvals"),
            archive_directory=str(root / "archive"),
            policy_sha256=digest(policy),
            signer=wallet(name).hotkey.ss58_address,
            cohorts=(binding,),
            cpu_efficiency_adoptions_directory=str(root / "cpu-adoptions"),
        )

        async def sign(body):
            state.votes.append((name, digest(body)))
            return sign_object(body, wallet(name))

        reviewer = ModelArtifactReviewer(config, policy, capture, read_history, sign)
        directory = Path(config.cpu_efficiency_adoptions_directory)
        ensure_private_directory(directory)
        if approve:
            publish_private_model(directory / (digest(authority) + ".candidate.json"), request)
        return reviewer

    return SimpleNamespace(
        history=history,
        cohort=cohort,
        authority=authority,
        policy=policy,
        request=request,
        binding=binding,
        state=state,
        create=create,
        runtime=runtime_adoption,
    )


async def test_cpu_request_cannot_approve_itself(cpu_review):
    c = cpu_review
    with pytest.raises(FileNotFoundError):
        await attest_cpu_efficiency(c.create("Charlie"), c.request)
    assert not c.state.votes


async def test_completed_cpu_vote_reuses_original_without_candidate_history_or_rpc(cpu_review):
    c = cpu_review
    reviewer = c.create("Charlie", approve=True)
    vote = await attest_cpu_efficiency(reviewer, c.request)
    Path(reviewer.config.cpu_efficiency_adoptions_directory).rename(
        Path(reviewer.config.cpu_efficiency_adoptions_directory).with_name("offline")
    )
    restarted = c.create("Charlie")
    c.state.online = False
    assert await attest_cpu_efficiency(restarted, c.request) == vote
    assert len(c.state.votes) == 1


async def test_cpu_vote_resumes_reserved_intent_and_refuses_another_request(cpu_review):
    c = cpu_review
    reviewer = c.create("Charlie", approve=True)

    async def offline(_):
        raise OSError("synthetic signer outage")

    reviewer.sign = offline
    with pytest.raises(OSError):
        await attest_cpu_efficiency(reviewer, c.request)
    Path(reviewer.config.cpu_efficiency_adoptions_directory).rename(
        Path(reviewer.config.cpu_efficiency_adoptions_directory).with_name("offline")
    )
    restarted = c.create("Charlie")
    await attest_cpu_efficiency(restarted, c.request)
    changed = c.request.model_copy(update={"operator_request_reference": "different decision"})
    with pytest.raises(ValueError, match="original operator request"):
        await attest_cpu_efficiency(restarted, changed)
    assert len(c.state.votes) == 1


@pytest.mark.parametrize("change", ["runtime", "authority", "scope", "future", "rule"])
async def test_cpu_review_independently_refuses_changed_contract(cpu_review, change):
    c = cpu_review
    fields = {
        "runtime": {"runtime_sha256": "aa" * 32},
        "authority": {"authority_sha256": "ab" * 32},
        "scope": {"cohort_sha256s": ("ac" * 32,)},
        "future": {"issued_at_block": 240},
        "rule": {"first_cohort_sequence": 9},
    }[change]
    request = c.request.model_copy(
        update={"adoption": c.request.adoption.model_copy(update=fields)}
    )
    reviewer = c.create("Charlie")
    publish_private_model(
        Path(reviewer.config.cpu_efficiency_adoptions_directory)
        / (request.adoption.authority_sha256 + ".candidate.json"),
        request,
    )
    with pytest.raises(ValueError):
        await attest_cpu_efficiency(reviewer, request)
    assert not c.state.votes


async def test_cpu_vote_route_uses_existing_authentication_and_selected_identity(cpu_review):
    c = cpu_review
    reviewer = c.create("Charlie", approve=True)
    app = FastAPI()
    app.include_router(model_review_routes(reviewer, token="t" * 48))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        peer = ModelReviewPeer(
            client,
            "https://review.example",
            policy=c.policy,
            cohorts=(c.binding,),
            signer=reviewer.config.signer,
            token="t" * 48,
        )
        assert (await peer.attest_cpu_efficiency(c.request)).adoption == c.request.adoption
        wrong = ModelReviewPeer(
            client,
            "https://review.example",
            policy=c.policy,
            cohorts=(c.binding,),
            signer=reviewer.config.signer,
            token="x" * 48,
        )
        with pytest.raises(OSError):
            await wrong.attest_cpu_efficiency(c.request)
    assert len(c.state.votes) == 1


@pytest.fixture
def cpu_operator(cpu_review, tmp_path, monkeypatch):
    c = cpu_review
    account = pwd.getpwuid(os.getuid()).pw_name
    reviewers = {identity(wallet(n).hotkey.ss58_address): c.create(n) for n in ("Charlie", "Dave")}
    peers = tuple(
        CohortReviewPeerConfig(
            signer=r.config.signer,
            origin="https://review.example",
            token_file=str(tmp_path / "token"),
            timeout_seconds=30,
        )
        for r in reviewers.values()
    )
    selected = []
    for n, (role, r) in enumerate(
        [("owner", None), *[("reviewer", r) for r in reviewers.values()]]
    ):
        target = shared.ModelBatchAdoptionTarget(
            role=role,
            service_unit=f"{role}{n}.service",
            service_account=account,
            config_path=str(tmp_path / f"{role}{n}.json"),
            config_sha256=f"{n + 1:02x}" * 32,
        )
        directory = (
            tmp_path / "owner-adoptions"
            if r is None
            else Path(r.config.cpu_efficiency_adoptions_directory)
        )
        ensure_private_directory(directory)
        selected.append(
            shared.SelectedBatchAdoptionTarget(
                target,
                directory,
                digest(c.policy),
                (c.binding,),
                signer=None if r is None else r.config.signer,
                peers=peers if r is None else (),
                cohort_sequences=((c.cohort, 8),),
                authority=c.authority,
                runtime_adoption=c.runtime if r is None else None,
                plans=(c.history.plan,),
            )
        )
    selected = tuple(selected)
    targets = {t.target.service_unit: t for t in selected}
    monkeypatch.setattr(shared, "load_adoption_target", lambda t, **kw: targets[t.service_unit])
    monkeypatch.setattr(operator, "load_adoption_target", lambda t, **kw: targets[t.service_unit])
    monkeypatch.setattr(shared, "check_target_process", lambda t: {})
    monkeypatch.setattr(shared, "_read_root_control_path", lambda *a, **kw: b"t" * 48)
    config = operator.CpuEfficiencyOperatorConfig(
        schema="umi-cpu-efficiency-adoption-operator/1",
        state_directory=str(tmp_path / "operator"),
        policy_file=str(tmp_path / "policy.json"),
        history_file=str(tmp_path / "history.json"),
        expected_tip_sha256=history_tip(c.history),
        effective_at_block=200,
        operator_request_reference=c.request.operator_request_reference,
        request=c.request,
        owner=selected[0].target,
        reviewers=tuple(t.target for t in selected[1:]),
    )
    state = SimpleNamespace(calls=[], deliveries=[], fail_vote=None, fail_delivery=None)

    def peer_factory(*args, signer, **kw):
        key = identity(signer)

        async def attest(request):
            state.calls.append(key)
            if state.fail_vote == key:
                raise OSError("synthetic unavailable reviewer")
            return await attest_cpu_efficiency(reviewers[key], request)

        return SimpleNamespace(attest_cpu_efficiency=attest)

    def publish(target, request, signed=None, *, check_only=False):
        if signed is not None and not check_only:
            if state.fail_delivery == target.service_unit:
                raise OSError("synthetic publication failure")
            state.deliveries.append(target.service_unit)
        return shared.publish_for_actor(
            target, request, signed, check_only=check_only, _cpu_efficiency=True
        )

    async def run_job(job, policy, history, *, client):
        return await operator.run_cpu_efficiency_adoption(
            job,
            policy,
            history,
            client=client,
            publish=publish,
            peer_factory=peer_factory,
        )

    async def run():
        return await run_job(config, c.policy, c.history, client=None)

    return SimpleNamespace(
        c=c,
        config=config,
        selected=selected,
        targets=targets,
        state=state,
        publish=publish,
        run_job=run_job,
        run=run,
    )


async def test_cpu_quorum_reuses_votes_after_interruption_and_selects_owner_last(cpu_operator):
    o = cpu_operator
    o.state.fail_vote = sorted(identity(t.signer) for t in o.selected[1:])[1]
    with pytest.raises(OSError):
        await o.run()
    assert len(o.c.state.votes) == 1
    assert not (o.selected[0].directory / (digest(o.c.authority) + ".json")).exists()
    o.state.fail_vote = None
    first = await o.run()
    assert o.state.deliveries[-1] == o.config.owner.service_unit
    assert first["reviewer_votes"] == 2
    assert first["runtime_activation_verified"] is False
    before = list(o.state.calls)
    assert await o.run() == first
    assert o.state.calls == before
    assert len(o.c.state.votes) == 2


async def test_cpu_signed_delivery_failure_and_lost_vote_require_exact_recovery(cpu_operator):
    o = cpu_operator
    o.state.fail_delivery = o.selected[2].target.service_unit
    with pytest.raises(OSError):
        await o.run()
    before = list(o.state.calls)
    assert not (o.selected[0].directory / (digest(o.c.authority) + ".json")).exists()
    o.state.fail_delivery = None
    await o.run()
    assert o.state.calls == before
    vote = Path(o.config.state_directory) / ("vote-" + identity(o.selected[1].signer) + ".json")
    vote.unlink()
    with pytest.raises(ValueError, match="lost a configured vote; repair required"):
        await o.run()
    assert o.state.calls == before


@pytest.mark.parametrize("change", ["missing-peer", "authority", "runtime"])
async def test_cpu_operator_refuses_changed_selected_consumers(cpu_operator, change):
    o = cpu_operator
    owner = o.selected[0]
    if change == "missing-peer":
        changed = replace(owner, peers=owner.peers[:1])
    elif change == "runtime":
        changed = replace(owner, runtime_adoption=None)
    else:
        changed = replace(
            owner, authority=o.c.authority.model_copy(update={"issued_at_block": 151})
        )
    o.targets[owner.target.service_unit] = changed
    with pytest.raises(ValueError):
        await o.run()
    assert not o.c.state.votes
    assert not o.state.deliveries


async def test_cpu_series_once_per_authority_reuses_and_repairs_without_source_history(
    cpu_operator, tmp_path
):
    o = cpu_operator
    config = ModelBatchAdoptionSeriesConfig(
        schema="umi-model-batch-adoption-series/1",
        state_directory=str(tmp_path / "series"),
        policy_file=o.config.policy_file,
        histories_directory=str(tmp_path / "histories"),
        standing_operator_request_reference="retained batch-format decision",
        cpu_efficiency_operator_request_reference=o.c.request.operator_request_reference,
        cpu_efficiency_anchor_history_file=str(tmp_path / "cpu-history.json"),
        owner=o.config.owner,
        reviewers=o.config.reviewers,
    )
    reads = []

    def history(path):
        reads.append(path)
        assert len(reads) == 1, "completed authority must not reread mutable history"
        return o.c.history

    async def run():
        return await operator.run_cpu_efficiency_series(
            config,
            o.c.policy,
            client=None,
            load_history=history,
            run_job=o.run_job,
            select=lambda t: o.targets[t.service_unit],
            publish=o.publish,
        )

    first = await run()
    assert first["completed"] == first["total"] == 1
    assert first["authority_sha256"] == digest(o.c.authority)
    assert (await run())["status"] == "reused"
    assert len(o.c.state.votes) == 2
    path = o.selected[1].directory / (digest(o.c.authority) + ".json")
    original = path.read_bytes()
    path.unlink()
    assert (await run())["status"] == "repaired"
    assert path.read_bytes() == original
    assert len(o.c.state.votes) == 2
    upgraded = tuple(
        replace(
            t,
            target=t.target.model_copy(
                update={
                    "config_path": str(tmp_path / ("upgraded-" + str(i) + ".json")),
                    "config_sha256": f"{i + 20:02x}" * 32,
                }
            ),
        )
        for i, t in enumerate(o.selected)
    )
    for target in upgraded:
        o.targets[target.target.service_unit] = target
    config = config.model_copy(
        update={
            "owner": upgraded[0].target,
            "reviewers": tuple(t.target for t in upgraded[1:]),
        }
    )
    assert (await run())["status"] == "reused"
    assert len(o.c.state.votes) == 2


def test_cpu_selection_preserves_old_reviewer_config_bytes(cpu_review):
    from umi.protocol import canonical_json_bytes

    new = cpu_review.create("Charlie").config
    old = new.model_copy(update={"cpu_efficiency_adoptions_directory": None})
    raw = canonical_json_bytes(old)
    assert b"cpu_efficiency" not in raw
    assert canonical_json_bytes(ModelReviewConfig.model_validate_json(raw)) == raw


def test_cpu_selection_root_cannot_overlap_journal(cpu_review):
    reviewer = cpu_review.create("Charlie")
    body = reviewer.config.model_dump(by_alias=True)
    body["cpu_efficiency_adoptions_directory"] = reviewer.config.directory
    with pytest.raises(ValueError, match="disjoint"):
        ModelReviewConfig.model_validate(body)
