from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_work_plans as plans
from umi.competition_authorization import SignedEndpointAuthorization, validate_publication
from umi.competition_evaluator import SignedEvaluationOrder, validate_order
from umi.competition_publication import (
    PublicationReplayLimits,
    SignedCutoffPublication,
    build_cutoff_publication,
    sign_cutoff_publication,
)
from umi.competition_settlement import EvidenceCutoffSchedule
from umi.open_competition import Registration, RegistrationSnapshot, digest, identity, sign_object
from umi.protocol import canonical_json_bytes
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .test_competition_authorization import build_authorization_fixture
from .test_competition_runner import runtime as runtime
from .test_open_competition import bundle_at, submission, wallet
from .test_open_competition import policy as policy


@pytest.fixture(params=("umi-open-competition-policy/1", "umi-open-competition-policy/2"))
def setup(policy, runtime, tmp_path, request):
    policy = policy.model_copy(update={"schema_": request.param})
    incumbent = bundle_at(tmp_path / "incumbent")
    candidate = bundle_at(tmp_path / "candidate", "candidate", digest(incumbent))
    item = build_authorization_fixture(
        policy.model_copy(update={"evaluation_runtime_sha256": digest(runtime)}),
        incumbent_sha256=digest(incumbent),
    )
    policy = item.policy
    roster = tuple(
        sorted(
            (
                item.signed_submission,
                submission(
                    policy,
                    name="Bob",
                    bundle=candidate,
                    start=1000,
                    end=1900,
                ),
            ),
            key=lambda s: digest(s.submission),
        )
    )
    round_ = item.round.model_copy(
        update={
            "eligible_tracks": tuple(sorted({s.submission.track for s in roster})),
            "roster": tuple(digest(s.submission) for s in roster),
        }
    )
    snapshot = RegistrationSnapshot(
        network="finney",
        netuid=78,
        block=round_.submission_close_block,
        block_hash="0x" + "31" * 32,
        registrations=(
            Registration(uid=6, hotkey=wallet("Alice").hotkey.ss58_address),
            Registration(uid=247, hotkey=wallet("Bob").hotkey.ss58_address),
        ),
    )
    cutoff = build_cutoff_publication(
        round_=round_,
        submissions=roster,
        registration_snapshot=snapshot,
        policy=policy,
        cutoff_schedule=EvidenceCutoffSchedule(
            schema="umi-competition-evidence-cutoff/1",
            policy_sha256=digest(policy),
            round_sha256=digest(round_),
            evidence_cutoff_block=round_.public_schedule.evidence_cutoff_block,
        ),
        limits=PublicationReplayLimits(
            maximum_roster_bytes=plans.MAX_BYTES,
            maximum_certificate_bytes=plans.MAX_BYTES,
            maximum_evidence_bytes=plans.MAX_BYTES,
        ),
    )
    certificate = SignedCutoffPublication(
        publication=cutoff,
        signatures=tuple(sign_cutoff_publication(cutoff, w) for w in item.evaluator_wallets[:2]),
    )
    plan = plans.prepare_work_plan(
        cutoff=certificate,
        submissions=roster,
        suite=item.suite,
        incumbent=incumbent,
        runtime=runtime,
        policy=policy,
    )
    by_key = {identity(w.hotkey.ss58_address): w for w in item.evaluator_wallets}
    signers = tuple(by_key[identity(key)] for key in plan.evaluators)
    videos = tuple(a.request.video for a in item.publication.publication.assignments[:3])
    return SimpleNamespace(
        policy=policy,
        item=item,
        plan=plan,
        signers=signers,
        options=dict(
            plan=plan,
            policy=policy,
            legacy=item.legacy_policy,
            videos=videos,
            announcement=item.finalized_blocks.blocks[1000],
            issuance=item.finalized_blocks.blocks[item.request.issued_block],
            now_ms=item.finalized_blocks.blocks[item.request.issued_block].timestamp_ms,
            minimum_issue_ms=1000,
        ),
    )


def sign_publications(setup, proposals):
    return tuple(
        SignedEndpointAuthorization(
            publication=p, signatures=tuple(sign_object(p, w) for w in setup.signers)
        )
        for p in proposals
    )


def two_endpoint_work(work):
    """Use the same registered Alice/Bob cutoff with both serving endpoints."""
    roster = tuple(
        sorted(
            (
                next(s for s in work.plan.submissions if s.submission.track == "endpoint"),
                submission(work.policy, name="Bob", start=1000, end=1900),
            ),
            key=lambda s: digest(s.submission),
        )
    )
    old = work.plan.cutoff.publication
    round_ = old.round.model_copy(
        update={
            "roster": tuple(digest(s.submission) for s in roster),
            "eligible_tracks": ("endpoint",),
        }
    )
    cutoff = build_cutoff_publication(
        round_=round_,
        submissions=roster,
        registration_snapshot=old.registration_snapshot,
        policy=work.policy,
        cutoff_schedule=old.cutoff_schedule.model_copy(update={"round_sha256": digest(round_)}),
        limits=PublicationReplayLimits(
            maximum_roster_bytes=plans.MAX_BYTES,
            maximum_certificate_bytes=plans.MAX_BYTES,
            maximum_evidence_bytes=plans.MAX_BYTES,
        ),
    )
    work.plan = plans.validate_work_plan(
        work.plan.model_copy(
            update={
                "submissions": roster,
                "cutoff": SignedCutoffPublication(
                    publication=cutoff,
                    signatures=tuple(sign_cutoff_publication(cutoff, w) for w in work.signers),
                ),
            }
        ),
        work.policy,
    )
    work.options["plan"] = work.plan
    return work


def test_both_tracks_derive_from_one_cutoff_without_signing_or_references(setup):
    assert b'"references"' not in canonical_json_bytes(setup.plan)
    proposals = plans.endpoint_proposals(**setup.options)
    assert len(proposals) == 1
    body = proposals[0]
    assert len(body.submissions) == 1 and len(body.assignments) == 6
    assert body.round == setup.plan.cutoff.publication.round
    assert all(
        a.request.issued_block_hash == setup.options["issuance"].block_hash
        for a in body.assignments
    )
    with pytest.raises(ValueError):
        validate_publication(body, setup.policy, setup.item.legacy_policy)
    model_only = plans.evaluation_order_proposals(plan=setup.plan, policy=setup.policy)
    assert [o.submission.submission.track for o in model_only] == ["model"]
    publications = sign_publications(setup, proposals)
    orders = plans.evaluation_order_proposals(
        plan=setup.plan,
        policy=setup.policy,
        publications=publications,
        legacy=setup.item.legacy_policy,
    )
    assert sorted(o.submission.submission.track for o in orders) == ["endpoint", "model"]
    for order in orders:
        assert order.no_weight and b'"references"' not in canonical_json_bytes(order)
        with pytest.raises(ValueError):
            validate_order(order, setup.policy, setup.item.legacy_policy)
        signed = SignedEvaluationOrder(
            order=order, signatures=tuple(sign_object(order, w) for w in setup.signers)
        )
        assert validate_order(signed, setup.policy, setup.item.legacy_policy) == signed


def test_missing_independent_cutoff_is_rejected(setup):
    changed = setup.plan.model_copy(
        update={
            "cutoff": setup.plan.cutoff.model_copy(
                update={
                    "signatures": setup.plan.cutoff.signatures[:1],
                }
            )
        }
    )
    with pytest.raises(ValueError, match="insufficient independent publication signatures"):
        plans.validate_work_plan(changed, setup.policy)


def test_work_nominates_only_evaluators_who_endorsed_the_frozen_cutoff(setup):
    signers = {identity(s.hotkey) for s in setup.plan.cutoff.signatures}
    assert {identity(k) for k in setup.plan.evaluators} <= signers
    assert len(setup.plan.evaluators) == setup.policy.required_evaluator_groups


@pytest.mark.parametrize(
    "field,change",
    [
        ("runtime", lambda p: p.runtime.model_copy(update={"cpus": p.runtime.cpus + 1})),
        (
            "incumbent",
            lambda p: p.incumbent.model_copy(update={"parent_baseline_sha256": "ff" * 32}),
        ),
        ("evaluators", lambda p: tuple(reversed(p.evaluators))),
        ("cases", lambda p: (p.cases[0], p.cases[0], p.cases[0])),
    ],
)
def test_changed_work_input_is_refused(setup, field, change):
    with pytest.raises(ValueError):
        plans.validate_work_plan(
            setup.plan.model_copy(update={field: change(setup.plan)}), setup.policy
        )


def test_different_private_suite_cannot_reuse_cutoff(setup):
    changed = setup.item.suite.model_copy(
        update={
            "cases": tuple(
                c.model_copy(
                    update={
                        "references": ("changed",)
                        if len(c.references) == 1
                        else ("changed", "wrong", "other")
                    }
                )
                for c in setup.item.suite.cases
            )
        }
    )
    with pytest.raises(ValueError, match="suite differs"):
        plans.prepare_work_plan(
            cutoff=setup.plan.cutoff,
            submissions=setup.plan.submissions,
            suite=changed,
            incumbent=setup.plan.incumbent,
            runtime=setup.plan.runtime,
            policy=setup.policy,
        )


@pytest.mark.parametrize(
    "field,change",
    [
        ("announcement", lambda s: replace(s.options["announcement"], height=1001)),
        (
            "announcement",
            lambda s: replace(s.options["announcement"], scoring_policy_hash="ff" * 32),
        ),
        ("issuance", lambda s: replace(s.options["issuance"], finality_verifier_sha256="ff" * 32)),
        (
            "issuance",
            lambda s: replace(s.options["issuance"], timestamp_ms=s.options["now_ms"] - 60_001),
        ),
        (
            "issuance",
            lambda s: replace(s.options["issuance"], timestamp_ms=s.options["now_ms"] + 5_001),
        ),
        ("issuance", lambda s: {"height": s.options["issuance"].height}),
        ("minimum_issue_ms", lambda _: 0),
        ("minimum_issue_ms", lambda _: True),
        ("videos", lambda s: s.options["videos"][:1]),
        ("videos", lambda s: tuple(reversed(s.options["videos"]))),
        (
            "videos",
            lambda s: (
                s.options["videos"][0].model_copy(update={"url": "http://example.com/v.mp4"}),
                *s.options["videos"][1:],
            ),
        ),
    ],
)
def test_endpoint_inputs_require_owned_matching_fresh_transport(setup, field, change):
    with pytest.raises((TypeError, ValueError)):
        plans.endpoint_proposals(**{**setup.options, field: change(setup)})


def test_expired_issue_window_is_never_retimed(setup):
    before = canonical_json_bytes(setup.plan)
    close = QUICKNET_GENESIS_MS + (setup.item.schedule.issue_close_round - 1) * QUICKNET_PERIOD_MS
    # Keep issuance fresh so the specific window check is exercised.
    options = {
        **setup.options,
        "now_ms": close,
        "issuance": replace(setup.options["issuance"], timestamp_ms=close),
    }
    with pytest.raises(ValueError, match="usable original issue window"):
        plans.endpoint_proposals(**options)
    assert canonical_json_bytes(setup.plan) == before


@pytest.mark.parametrize("recheck", [False, True])
def test_issuance_before_selection_cannot_be_signed_or_blessed_by_later_head(setup, recheck):
    before = canonical_json_bytes(setup.plan)
    selection = QUICKNET_GENESIS_MS + (setup.item.schedule.selection_round - 1) * QUICKNET_PERIOD_MS
    early = replace(setup.options["issuance"], timestamp_ms=selection - 1)
    options = {**setup.options, "issuance": early, "now_ms": selection - 1}
    if recheck:
        options.update(
            now_ms=selection + 90_000,
            verification_head=replace(
                early, height=early.height + 8, timestamp_ms=selection + 90_000
            ),
        )
    with pytest.raises(ValueError, match="usable original issue window"):
        plans.endpoint_proposals(**options)
    assert canonical_json_bytes(setup.plan) == before


def test_issuance_at_selection_boundary_preserves_original_time_and_height(setup):
    selection = QUICKNET_GENESIS_MS + (setup.item.schedule.selection_round - 1) * QUICKNET_PERIOD_MS
    issuance = replace(setup.options["issuance"], timestamp_ms=selection)
    result = plans.endpoint_proposals(
        **{**setup.options, "issuance": issuance, "now_ms": selection}
    )
    assert result
    assert all(a.request.issued_block == issuance.height for p in result for a in p.assignments)


@pytest.mark.parametrize(
    "fault", [None, "stale", "future", "earlier", "policy", "unowned", "same_height", "expired"]
)
def test_original_proposal_recheck_requires_fresh_owned_head_and_open_window(setup, fault):
    options = setup.options
    original = plans.endpoint_proposals(**options)
    now = options["now_ms"] + 90_000
    head = replace(options["issuance"], height=options["issuance"].height + 8, timestamp_ms=now)
    if fault == "stale":
        head = replace(head, timestamp_ms=now - 60_001)
    elif fault == "future":
        head = replace(head, timestamp_ms=now + 5_001)
    elif fault == "earlier":
        head = replace(head, height=options["issuance"].height - 1)
    elif fault == "policy":
        head = replace(head, scoring_policy_hash="ff" * 32)
    elif fault == "unowned":
        head = {"height": head.height}
    elif fault == "same_height":
        head = replace(head, height=options["issuance"].height)
    elif fault == "expired":
        now = QUICKNET_GENESIS_MS + (setup.item.schedule.issue_close_round - 1) * QUICKNET_PERIOD_MS
        head = replace(head, timestamp_ms=now)
    changed = {**options, "now_ms": now, "verification_head": head}
    if fault is not None:
        with pytest.raises((ValueError, TypeError)):
            plans.endpoint_proposals(**changed)
    else:
        assert plans.endpoint_proposals(**changed) == original
        # Creating new work still requires a fresh issuance block.
        with pytest.raises(ValueError, match="issuance is not fresh"):
            plans.endpoint_proposals(**{**options, "now_ms": now})


def test_endpoint_order_waits_for_quorum_and_rejects_duplicate_publication(setup):
    publications = sign_publications(setup, plans.endpoint_proposals(**setup.options))
    with pytest.raises(ValueError, match="duplicate"):
        plans.evaluation_order_proposals(
            plan=setup.plan,
            policy=setup.policy,
            publications=publications * 2,
            legacy=setup.item.legacy_policy,
        )
    with pytest.raises(ValueError, match="quorum"):
        plans.evaluation_order_proposals(
            plan=setup.plan,
            policy=setup.policy,
            publications=(
                publications[0].model_copy(update={"signatures": publications[0].signatures[:1]}),
            ),
            legacy=setup.item.legacy_policy,
        )
