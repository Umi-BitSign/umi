"""Native full-roster replay and local artifacts for model payout eligibility.

Finality and inference are fixture boundaries. Admission, phase closure, all
quality signatures, bundle hashes and model selection use native consumers.
"""

from fractions import Fraction

import pytest

from umi.competition_artifacts import preserve_bundle
from umi.competition_cohort_model_acceptance import (
    CertifiedModelArtifactAcceptance,
    ModelArtifactAcceptance,
)
from umi.competition_cohort_model_award import (
    PendingModelAward,
    build_model_award,
)
from umi.competition_cohort_quality_signing import build_quality_manifest
from umi.open_competition import digest, model_content_digest
from umi.protocol import canonical_json_bytes

from .cohort_request_closure_fixture import closure_fixture
from .test_competition_cohort_execution import setup_scenario
from .test_competition_cohort_quality import base_policy as base_policy
from .test_competition_cohort_quality import certificates_for, reviewer
from .test_competition_cohort_quality import legacy_scenario as legacy_scenario
from .test_competition_cohort_quality import policy as policy
from .test_competition_cohort_quality import receipt_scenario as receipt_scenario
from .test_competition_cohort_quality import recovery as recovery
from .test_competition_cohort_quality import runtime as runtime
from .test_competition_cohort_recovery import signatures
from .test_competition_cohort_roster import make_round
from .test_open_competition import bundle_at, wallet

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


@pytest.fixture
async def model_case(receipt_scenario, tmp_path, runtime, request):
    mode, count = getattr(request, "param", ("equal", 1))
    source = tmp_path / "model-source"
    s = setup_scenario(receipt_scenario, source, runtime, baseline_entry=mode == "baseline")
    alternate = bundle_at(source / "alternate", "alternate") if mode == "best" else None
    b = make_round(
        s,
        include_outcomes=False,
        participant_names=("Alice", "Bob")[:count],
        participant_bundles={"Bob": alternate} if alternate else None,
    )
    for scenario in b["scenarios"]:
        artifacts = []
        for a in scenario["artifacts"]:
            steps = []
            for step in a.steps:
                text = (
                    ""
                    if mode == "zero"
                    or (mode == "below" and step.role == "candidate")
                    or (mode == "above" and step.role == "incumbent")
                    else "hello"
                )
                if mode in {"best", "duplicate-disagree"}:
                    text = (
                        "hello"
                        if step.role == "candidate"
                        and scenario["signed"].submission.hotkey
                        == wallet("Bob").hotkey.ss58_address
                        else ""
                    )
                execution = step.execution.model_copy(
                    update={
                        "output": step.execution.output.model_copy(update={"hypothesis": text}),
                        "stdout_hex": (text + "\n").encode().hex(),
                    }
                )
                steps.append(step.model_copy(update={"execution": execution}))
            artifacts.append(a.model_copy(update={"steps": tuple(steps)}))
        scenario["artifacts"] = tuple(artifacts)
    b = await closure_fixture(s, tmp_path / "execution", prepared=b)
    review = reviewer(b)
    certificates = await certificates_for(b, review, tmp_path / "certificates")
    manifest = build_quality_manifest(review, certificates.get)
    archive = tmp_path / "preserved"
    preserve_bundle(
        s["signed"].submission.model_bundle,
        source / ("incumbent" if mode == "baseline" else "candidate"),
        archive,
        s["policy"],
    )
    preserve_bundle(s["artifacts"][0].job.incumbent, source / "incumbent", archive, s["policy"])
    if alternate:
        preserve_bundle(alternate, source / "alternate", archive, s["policy"])
    accepted = []
    for index, participant in enumerate(b["roster"].participants):
        sub = participant.record.request.signed_submission.submission
        rights = {"fixture": "independent-rights-review", "submission_sha256": digest(sub)}
        reconstruction = {"fixture": "reconstruction-review", "model_sha256": sub.model_revision}
        for evidence in (rights, reconstruction):
            b["objects"][digest(evidence)] = canonical_json_bytes(evidence)
        body = ModelArtifactAcceptance(
            schema="umi-cohort-model-artifact-acceptance/1",
            policy_sha256=digest(b["policy"]),
            cohort_sha256=digest(b["history"].plan),
            authority_sha256=digest(b["history"].authority.authority),
            submission_sha256=digest(sub),
            model_sha256=digest(sub.model_bundle),
            content_sha256=model_content_digest(sub.model_bundle),
            recipient_hotkey=sub.hotkey,
            rights_evidence_sha256=digest(rights),
            reconstruction_evidence_sha256=digest(reconstruction),
            accepted_at_block=220,
            accepted_ordinal=count - index,
            rights_and_reconstruction_passed=True,
        )
        accepted.append(
            CertifiedModelArtifactAcceptance(acceptance=body, signatures=signatures(body))
        )
    return b, review, manifest, tuple(accepted), archive


def award(c, **changes):
    _, review, manifest, accepted, archive = c
    return build_model_award(
        changes.get("manifest", manifest),
        changes.get("review", review),
        changes.get("acceptances", accepted),
        changes.get("archive", archive),
    )


@pytest.mark.parametrize(
    "model_case",
    [("equal", 1), ("zero", 1), ("above", 1), ("below", 1), ("baseline", 1)],
    indirect=True,
)
def test_sole_model_uses_exact_baseline_floor_without_promotion_threshold(model_case):
    result = award(model_case)
    candidate = result.candidates[0]
    assert candidate.eligible == (
        Fraction(int(candidate.aggregate.numerator), int(candidate.aggregate.denominator))
        >= Fraction(
            int(candidate.baseline_aggregate.numerator),
            int(candidate.baseline_aggregate.denominator),
        )
    )
    assert result.recipient_hotkey == (candidate.recipient_hotkey if candidate.eligible else None)
    assert not result.reference_promotion_authorized
    assert not result.chain_submission_authorized
    if candidate.model_sha256 == result.baseline_model_sha256:
        assert candidate.eligible


@pytest.mark.parametrize("model_case", [("equal", 2)], indirect=True)
def test_duplicate_baseline_equivalent_entries_share_one_award_by_complete_acceptance(model_case):
    result = award(model_case)
    assert len(result.candidates) == 2
    assert len({c.content_sha256 for c in result.candidates}) == 1
    expected = min(result.acceptances, key=lambda a: a.acceptance.accepted_ordinal).acceptance
    assert result.recipient_hotkey == expected.recipient_hotkey
    assert result.winner_submission_sha256 == expected.submission_sha256


@pytest.mark.parametrize("model_case", [("best", 2)], indirect=True)
def test_higher_exact_quality_wins_over_artifact_acceptance_priority(model_case):
    result = award(model_case)
    assert result.recipient_hotkey == wallet("Bob").hotkey.ss58_address
    assert len({c.content_sha256 for c in result.candidates}) == 2


@pytest.mark.parametrize("model_case", [("duplicate-disagree", 2)], indirect=True)
def test_same_model_cannot_shop_for_different_quality_observations(model_case):
    with pytest.raises(PendingModelAward, match="inconsistent quality"):
        award(model_case)


@pytest.mark.parametrize("model_case", [("equal", 2)], indirect=True)
def test_pending_competitor_is_never_dropped_to_make_a_sole_entrant(model_case):
    _, _, manifest, accepted, _ = model_case
    with pytest.raises(PendingModelAward, match="entire sealed"):
        award(model_case, acceptances=accepted[:1])
    with pytest.raises(ValueError, match="exact certified roster"):
        award(
            model_case,
            manifest=manifest.model_copy(update={"participants": manifest.participants[:1]}),
        )


@pytest.mark.parametrize(
    "field",
    [
        "policy_sha256",
        "cohort_sha256",
        "authority_sha256",
        "model_sha256",
        "content_sha256",
        "recipient_hotkey",
        "accepted_at_block",
        "rights_evidence_sha256",
    ],
)
def test_even_signed_artifact_acceptance_cannot_change_original_entry(model_case, field):
    from .test_open_competition import wallet

    accepted = model_case[3][0]
    value = (
        wallet("Eve").hotkey.ss58_address
        if field == "recipient_hotkey"
        else 301
        if field == "accepted_at_block"
        else "0" * 64
    )
    body = accepted.acceptance.model_copy(update={field: value})
    changed = CertifiedModelArtifactAcceptance(acceptance=body, signatures=signatures(body))
    with pytest.raises(ValueError, match="original complete entry"):
        award(model_case, acceptances=(changed,))


def test_missing_local_artifact_blocks_award_and_restores_without_new_quality(model_case, tmp_path):
    with pytest.raises(FileNotFoundError):
        award(model_case, archive=tmp_path / "unavailable-archive")
    result = award(model_case)
    b = model_case[0]
    late = reviewer(b, current_block=2**53 - 1)
    assert canonical_json_bytes(award(model_case, review=late)) == canonical_json_bytes(result)


def test_quality_object_cannot_be_replaced_by_a_signed_score_only(model_case):
    b, _, manifest, _, _ = model_case
    b["objects"].pop(manifest.participants[0].certificate_sha256)
    with pytest.raises(KeyError):
        award(model_case, review=reviewer(b))


def test_missing_independent_artifact_quorum_is_pending(model_case):
    original = model_case[3][0]
    partial = original.model_copy(update={"signatures": original.signatures[:1]})
    with pytest.raises(ValueError, match="quorum"):
        award(model_case, acceptances=(partial,))


@pytest.mark.parametrize("field", ["rights_evidence_sha256", "reconstruction_evidence_sha256"])
def test_signed_review_digest_without_original_evidence_remains_pending(model_case, field):
    b, _, _, accepted, _ = model_case
    key = getattr(accepted[0].acceptance, field)
    original = b["objects"].pop(key)
    with pytest.raises(KeyError):
        award(model_case)
    b["objects"][key] = original
    assert award(model_case).recipient_hotkey is not None


def service_boundary(c, service_pool_bps):
    """Fixed service result fixture; these tests cover model integration only.

    Paid service execution has separate encrypted-response integration coverage.
    Keep real allocation signature verification here, with no patched verifier.
    """
    from umi.competition_cohort_service_allocation import ServiceAllocation
    from umi.competition_cohort_service_certification import (
        CertifiedServiceAllocation,
        ServiceAllocationReview,
        ServiceAllocationStatement,
    )
    from umi.open_competition import identity

    b, _, manifest, _, _ = c
    service, model, fingerspelling, continuous = {
        5000: (32767, 32768, 7562, 25205),
        7000: (45874, 19661, 10586, 35288),
    }[service_pool_bps]
    review = object.__new__(ServiceAllocationReview)
    review.policy = b["policy"]
    review.statement = ServiceAllocationStatement(
        schema="umi-cohort-service-allocation-statement/1",
        policy_sha256=digest(review.policy),
        round_sha256=digest(b["roster"].round),
        allocation=ServiceAllocation(
            schema="umi-cohort-service-allocation/1",
            terms_sha256="f1" * 32,
            request_closure_sha256=manifest.request_closure_sha256,
            quality_sha256="f2" * 32,
            service_budget=service,
            model_budget=model,
            stratum_budgets={"fingerspelling": fingerspelling, "continuous": continuous},
            recipients=(),
            burn_weight=service,
        ),
    )
    review.slot = digest(
        ["umi-service-allocation-slot/1", digest(review.policy), review.statement.round_sha256]
    )
    review.groups = {identity(e.hotkey): e.control_group for e in review.policy.evaluators}
    review.recipients = set()
    certificate = CertifiedServiceAllocation(
        schema="umi-cohort-certified-service-allocation/1",
        statement=review.statement,
        signatures=signatures(review.statement),
    )
    return review, certificate


@pytest.mark.parametrize("model_case", [("baseline", 1), ("below", 1)], indirect=True)
@pytest.mark.parametrize("service_pool_bps", [5000, 7000])
async def test_full_model_pool_retained_and_independently_replayed_after_lost_reply(
    model_case, tmp_path, monkeypatch, service_pool_bps
):
    import shutil

    from umi.competition_cohort_reward_allocation import retain_reward_allocation
    from umi.competition_cohort_reward_certification import (
        replay_reward_allocation,
        verify_certified_reward_allocation,
    )
    from umi.competition_round_journal import RoundJournal
    from umi.competition_store import CompetitionStore
    from umi.private_files import publish_private_model

    from .test_competition_cohort_consumers import tip
    from .test_competition_cohort_roster import close
    from .test_open_competition import wallet

    b, br, benchmark, accepted, archive = model_case
    sr, service = service_boundary(model_case, service_pool_bps)
    store = CompetitionStore(tmp_path / "native-model-store", b["policy"])
    shutil.copytree(archive, store.directory / "model-reward-artifacts")
    acceptance_path = (
        store.directory
        / "model-reward-acceptances"
        / digest(b["history"].plan)
        / (accepted[0].acceptance.submission_sha256 + ".json")
    )
    publish_private_model(acceptance_path, accepted[0])
    root = tmp_path / "reward-owner"
    journal = RoundJournal(root, {"scope": "model-award-test"})

    def retain(owner=journal):
        return retain_reward_allocation(
            owner, store, service, sr, benchmark, br, maximum_promotion_bytes=1_000_000
        )

    put = journal.put

    def lose_reply(kind, key, value):
        put(kind, key, value)
        if kind == "cohort_reward_allocation":
            raise OSError("lost allocation reply")

    with monkeypatch.context() as patch:
        patch.setattr(journal, "put", lose_reply)
        with pytest.raises(OSError, match="lost allocation reply"):
            retain()
    saved = journal.get("cohort_reward_allocation", sr.slot)
    acceptance_path.unlink()  # Exact attestations now travel with the immutable allocation.
    result = retain(RoundJournal(root, {"scope": "model-award-test"}))
    assert canonical_json_bytes(result) == canonical_json_bytes(saved)
    assert result.schema_ == "umi-cohort-reward-allocation/2"
    assert result.promotion_head is None
    if result.model_award.recipient_hotkey is None:
        assert result.recipients == () and result.burn_weight == 65535
    else:
        assert len(result.recipients) == 1
        assert result.recipients[0].raw_weight == service.statement.allocation.model_budget
        assert result.burn_weight == service.statement.allocation.service_budget

    def replay(value=result):
        return replay_reward_allocation(
            value, store, service, sr, benchmark, br, maximum_promotion_bytes=1_000_000
        )

    assert replay() == result
    changed = result.model_copy(
        update={
            "model_award": result.model_award.model_copy(
                update={"recipient_hotkey": wallet("Eve").hotkey.ss58_address}
            )
        }
    )
    with pytest.raises(ValueError, match="independently replayed"):
        replay(changed)
    h = b["quality_history"]
    for block, evidence in (
        (2000, digest(benchmark)),
        (2100, digest(service)),
        (2200, digest(result)),
    ):
        h = close(h, b["policy"], b["decisions"], block, evidence)
    assert (
        verify_certified_reward_allocation(
            result,
            store,
            service,
            sr,
            benchmark,
            br,
            h,
            b["decisions"].__getitem__,
            expected_tip_sha256=tip(h),
            current_block=2**53 - 1,
            maximum_promotion_bytes=1_000_000,
        )
        == result
    )
