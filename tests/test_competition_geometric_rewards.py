"""Exact two-level arithmetic and original certified-input preservation."""

from fractions import Fraction
from itertools import pairwise
from types import SimpleNamespace

import pytest

from umi.competition_cohort_model_acceptance import (
    CertifiedModelArtifactAcceptance,
    ModelArtifactAcceptance,
)
from umi.competition_cohort_model_award import (
    CohortModelAward,
    GeometricModelAward,
    ModelAwardCandidate,
    ModelAwardEvidence,
    derive_geometric_model_award,
)
from umi.competition_cohort_quality import ExactQuality
from umi.competition_cohort_quality_signing import CohortQualityManifest, QualityCertificateRef
from umi.competition_cohort_recovery import ModelRewardCohortAuthority
from umi.competition_cohort_reward_allocation import (
    CohortRewardAllocation,
    derive_effective_reward_allocation,
)
from umi.competition_cohort_service_allocation import ServiceAllocation, ServiceRecipientAmount
from umi.competition_cohort_service_certification import (
    CertifiedServiceAllocation,
    ServiceAllocationStatement,
)
from umi.competition_geometric_rewards import (
    GeometricRewardParameters,
    normalized_geometric_weights,
)
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .test_open_competition import wallet


def exact(value):
    value = Fraction(value)
    return ExactQuality(numerator=str(value.numerator), denominator=str(value.denominator))


def fraction(value):
    return Fraction(int(value.numerator), int(value.denominator))


def original_evidence(scores, *, contents=None, hotkeys=None, baseline=0, authority=None):
    """Synthetic signed receipts test math; native replay is qualified separately."""
    authority = authority or ModelRewardCohortAuthority(
        schema="umi-cohort-recovery-authority/3",
        policy_sha256="11" * 32,
        cohort_sha256s=("22" * 32,),
        issued_at_block=10,
        lifetime="until_completed_or_revoked",
        closure_rule="quorum_certified_phase_completion",
        timing_rule="targets_without_extension_signatures",
        model_reward_rule="baseline_or_better_best_score_first_complete/1",
    )
    candidates, certificates = [], []
    for index, score in enumerate(scores):
        who = (
            hotkeys
            or [
                wallet("Alice" if i % 2 == 0 else "Bob").hotkey.ss58_address
                for i in range(len(scores))
            ]
        )[index]
        acceptance = ModelArtifactAcceptance(
            schema="umi-cohort-model-artifact-acceptance/1",
            policy_sha256=authority.policy_sha256,
            cohort_sha256=authority.cohort_sha256s[0],
            authority_sha256=digest(authority),
            submission_sha256=digest(["submission", index]),
            model_sha256=digest(["model", index]),
            content_sha256=digest(["content", (contents or list(range(len(scores))))[index]]),
            recipient_hotkey=who,
            rights_evidence_sha256="33" * 32,
            reconstruction_evidence_sha256="44" * 32,
            accepted_at_block=11 + index,
            accepted_ordinal=index + 1,
            rights_and_reconstruction_passed=True,
        )
        certificate = CertifiedModelArtifactAcceptance(
            acceptance=acceptance, signatures=(sign_object(acceptance, wallet("Alice")),)
        )
        certificates.append(certificate)
        candidates.append(
            ModelAwardCandidate(
                submission_sha256=acceptance.submission_sha256,
                model_sha256=acceptance.model_sha256,
                content_sha256=acceptance.content_sha256,
                recipient_hotkey=who,
                acceptance_sha256=digest(certificate),
                quality_sha256=digest(["quality", index]),
                aggregate=exact(score),
                baseline_aggregate=exact(baseline),
                eligible=Fraction(score) >= Fraction(baseline),
            )
        )
    evidence = ModelAwardEvidence(
        policy_sha256=authority.policy_sha256,
        authority_sha256=digest(authority),
        round_sha256="55" * 32,
        roster_sha256="66" * 32,
        quality_manifest_sha256="77" * 32,
        baseline_model_sha256="88" * 32,
        runtime_sha256="99" * 32,
        suite_sha256="aa" * 32,
        candidates=tuple(reversed(candidates)),
        acceptances=tuple(reversed(certificates)),
    )
    return evidence, authority


def package_boundary(scores, *, model_budget=32768, service_credit=100, **kwargs):
    """Only the pure adoption boundary; this deliberately does not claim replay."""
    evidence, authority = original_evidence(scores, **kwargs)
    manifest = CohortQualityManifest(
        schema="umi-cohort-quality-manifest/1",
        request_closure_sha256="bb" * 32,
        participants=tuple(
            QualityCertificateRef(
                submission_sha256=c.submission_sha256, certificate_sha256=c.quality_sha256
            )
            for c in evidence.candidates
        ),
    )
    evidence = evidence.model_copy(update={"quality_manifest_sha256": digest(manifest)})
    eligible = [c for c in evidence.candidates if c.eligible]
    winner = max(eligible, key=lambda c: fraction(c.aggregate)) if eligible else None
    award = CohortModelAward(
        schema="umi-cohort-model-award/1",
        **evidence.model_dump(by_alias=True),
        rule=authority.model_reward_rule,
        winner_submission_sha256=None if winner is None else winner.submission_sha256,
        recipient_hotkey=None if winner is None else winner.recipient_hotkey,
    )
    service_who = wallet("Charlie").hotkey.ss58_address
    service_budget = 65535 - model_budget
    statement = ServiceAllocationStatement(
        schema="umi-cohort-service-allocation-statement/1",
        policy_sha256=evidence.policy_sha256,
        round_sha256=evidence.round_sha256,
        allocation=ServiceAllocation(
            schema="umi-cohort-service-allocation/1",
            terms_sha256="cc" * 32,
            request_closure_sha256=manifest.request_closure_sha256,
            quality_sha256="dd" * 32,
            service_budget=service_budget,
            model_budget=model_budget,
            stratum_budgets={"continuous": service_budget},
            recipients=(ServiceRecipientAmount(hotkey=service_who, raw_weight=service_credit),)
            if service_credit
            else (),
            burn_weight=service_budget - service_credit,
        ),
    )
    service = CertifiedServiceAllocation(
        schema="umi-cohort-certified-service-allocation/1",
        statement=statement,
        signatures=(sign_object(statement, wallet("Alice")),),
    )
    recipients = list(statement.allocation.recipients)
    if winner is not None and model_budget:
        recipients.append(
            ServiceRecipientAmount(hotkey=winner.recipient_hotkey, raw_weight=model_budget)
        )
    allocation = CohortRewardAllocation(
        schema="umi-cohort-reward-allocation/2",
        policy_sha256=evidence.policy_sha256,
        round_sha256=evidence.round_sha256,
        service_certificate_sha256=digest(service),
        quality_manifest_sha256=digest(manifest),
        model_award=award,
        recipients=tuple(sorted(recipients, key=lambda r: identity(r.hotkey))),
        burn_weight=statement.allocation.burn_weight + (model_budget if winner is None else 0),
    )
    return SimpleNamespace(
        policy_sha256=evidence.policy_sha256,
        allocation=allocation,
        service=service,
        benchmark=manifest,
        inputs=SimpleNamespace(
            history=SimpleNamespace(authority=SimpleNamespace(authority=authority))
        ),
    )


@pytest.mark.parametrize("count", [0, 1, 7, 512, 1024])
@pytest.mark.parametrize("decay", [0, 1, 7500, 9999, 10000])
def test_normalization_is_exact_and_supports_boundaries_without_rank_cap(count, decay):
    weights = normalized_geometric_weights(count, decay)
    assert len(weights) == count
    assert sum(weights, Fraction()) == int(bool(count))
    if count > 1:
        assert all(b == a * Fraction(decay, 10000) for a, b in pairwise(weights))


@pytest.mark.parametrize(
    "values",
    [
        {"band_width_bps": 0},
        {"band_width_bps": 10001},
        {"band_decay_bps": -1},
        {"within_band_decay_bps": 10001},
        {"band_width_bps": True},
        {"band_decay_bps": 7500.0},
    ],
)
def test_parameters_reject_out_of_domain_or_noninteger_values(values):
    with pytest.raises(ValueError):
        GeometricRewardParameters(**values)


def test_two_levels_normalize_independently_and_skip_empty_bands():
    evidence, _ = original_evidence(["0.99", "0.97", "0.21", "0.20", "0.01"])
    result = derive_geometric_model_award(evidence, GeometricRewardParameters())
    assert [c.band_index for c in result.credits] == [19, 19, 4, 4, 0]
    assert [fraction(c.weight) for c in result.credits] == [
        Fraction(64, 259),
        Fraction(48, 259),
        Fraction(48, 259),
        Fraction(36, 259),
        Fraction(9, 37),
    ]
    assert sum(fraction(c.weight) for c in result.credits) == 1


def test_configurable_width_and_decays_are_independent():
    evidence, _ = original_evidence(["0.99", "0.97", "0.20"])
    params = GeometricRewardParameters(
        band_width_bps=500, band_decay_bps=5000, within_band_decay_bps=2500
    )
    award = derive_geometric_model_award(evidence, params)
    assert [fraction(c.weight) for c in award.credits] == [
        Fraction(8, 15),
        Fraction(2, 15),
        Fraction(1, 3),
    ]
    full = derive_geometric_model_award(
        evidence, params.model_copy(update={"band_width_bps": 10000})
    )
    assert [fraction(c.weight) for c in full.credits] == [
        Fraction(16, 21),
        Fraction(4, 21),
        Fraction(1, 21),
    ]
    assert all(c.band_index == 0 for c in full.credits)


@pytest.mark.parametrize(
    "width,expected",
    [(1, [9999, 500, 0]), (500, [19, 1, 0]), (3333, [3, 0, 0]), (10000, [0, 0, 0])],
)
def test_exact_band_boundaries_include_full_scale(width, expected):
    evidence, _ = original_evidence([1, "0.9999", "0.05", 0])
    award = derive_geometric_model_award(evidence, GeometricRewardParameters(band_width_bps=width))
    assert [c.band_index for c in award.credits] == expected


def test_deduplication_precedes_eligibility_and_preserves_first_acceptance():
    evidence, _ = original_evidence(
        ["0.2", "0.99", "0.6", "0.98"], contents=[0, 0, 1, 1], baseline="0.5"
    )
    result = derive_geometric_model_award(evidence, GeometricRewardParameters())
    assert len(result.credits) == 1
    assert result.credits[0].submission_sha256 == digest(["submission", 2])
    assert fraction(result.credits[0].score) == Fraction(3, 5)
    assert len(result.candidates) == 4


def test_exact_score_ties_use_certified_acceptance_order():
    evidence, _ = original_evidence(["0.5", "0.5", "0.5"])
    result = derive_geometric_model_award(evidence, GeometricRewardParameters())
    assert [c.submission_sha256 for c in result.credits] == [digest(["submission", 0])]


@pytest.mark.parametrize(
    "band,within,expected",
    [
        (0, 0, [1, 0, 0]),
        (0, 10000, [Fraction(1, 2), Fraction(1, 2), 0]),
        (10000, 0, [Fraction(1, 2), 0, Fraction(1, 2)]),
        (10000, 10000, [Fraction(1, 4), Fraction(1, 4), Fraction(1, 2)]),
    ],
)
def test_zero_and_full_decay_have_explicit_finite_meaning(band, within, expected):
    evidence, _ = original_evidence(["0.99", "0.97", "0.2"])
    award = derive_geometric_model_award(
        evidence, GeometricRewardParameters(band_decay_bps=band, within_band_decay_bps=within)
    )
    assert [fraction(c.weight) for c in award.credits] == expected


def test_one_global_rounding_pass_precedes_hotkey_aggregation():
    keys = [wallet(n).hotkey.ss58_address for n in ("Alice", "Bob", "Dave")]
    package = package_boundary(
        ["0.99", "0.97", "0.2"], model_budget=1, service_credit=0, hotkeys=keys
    )
    result = derive_effective_reward_allocation(
        package, GeometricRewardParameters(band_decay_bps=10000, within_band_decay_bps=10000)
    )
    # Ideals .25, .25, .5 award the single unit to the lower band's model.
    # Integer band rounding first would instead assign it to the top band.
    assert result.recipients == (ServiceRecipientAmount(hotkey=keys[2], raw_weight=1),)
    assert result.burn_weight == 65534


def test_service_and_signed_originals_preserved_and_shared_hotkeys_aggregate():
    package = package_boundary(["0.99", "0.97", "0.2"])
    before = [
        canonical_json_bytes(x)
        for x in (
            package.allocation,
            package.service,
            package.benchmark,
            package.inputs.history.authority.authority,
        )
    ]
    result = derive_effective_reward_allocation(package, GeometricRewardParameters())
    assert result.schema_ == "umi-cohort-reward-allocation/5"
    amounts = {identity(r.hotkey): r.raw_weight for r in result.recipients}
    assert amounts[identity(wallet("Alice").hotkey.ss58_address)] == 24743
    assert amounts[identity(wallet("Bob").hotkey.ss58_address)] == 8025
    assert amounts[identity(wallet("Charlie").hotkey.ss58_address)] == 100
    assert result.burn_weight == 32667
    assert before == [
        canonical_json_bytes(x)
        for x in (
            package.allocation,
            package.service,
            package.benchmark,
            package.inputs.history.authority.authority,
        )
    ]
    assert canonical_json_bytes(
        CohortRewardAllocation.model_validate_json(canonical_json_bytes(result))
    ) == canonical_json_bytes(result)
    assert derive_effective_reward_allocation(package, GeometricRewardParameters()) == result


def test_no_eligible_content_burns_only_the_unchanged_model_budget():
    package = package_boundary(["0.1", "0.2"], baseline="0.5")
    result = derive_effective_reward_allocation(package, GeometricRewardParameters())
    assert result.recipients == package.service.statement.allocation.recipients
    assert result.burn_weight == 65435
    assert result.model_award.credits == ()


@pytest.mark.parametrize(
    "field", ["acceptance_sha256", "eligible", "aggregate", "recipient_hotkey"]
)
def test_tampered_candidate_evidence_is_rejected(field):
    evidence, _ = original_evidence(["0.5", "0.6"])
    changes = {
        "acceptance_sha256": "ee" * 32,
        "eligible": False,
        "aggregate": exact(2),
        "recipient_hotkey": wallet("Dave").hotkey.ss58_address,
    }
    broken = evidence.model_copy(
        update={
            "candidates": (
                evidence.candidates[0].model_copy(update={field: changes[field]}),
                evidence.candidates[1],
            )
        }
    )
    with pytest.raises(ValueError):
        derive_geometric_model_award(broken, GeometricRewardParameters())


def test_tampered_derived_weights_and_original_context_are_rejected():
    package = package_boundary(["0.99", "0.97", "0.2"])
    result = derive_effective_reward_allocation(package, GeometricRewardParameters())
    credit = result.model_award.credits[0].model_copy(update={"weight": exact(1)})
    bad = result.model_award.model_copy(
        update={"credits": (credit, *result.model_award.credits[1:])}
    )
    with pytest.raises(ValueError, match="canonical evidence"):
        GeometricModelAward.model_validate_json(canonical_json_bytes(bad))
    package.allocation = package.allocation.model_copy(
        update={"service_certificate_sha256": "ff" * 32}
    )
    with pytest.raises(ValueError, match="inconsistent bindings"):
        derive_effective_reward_allocation(package, GeometricRewardParameters())


def test_effective_award_cannot_replace_the_original_certified_allocation():
    package = package_boundary(["0.99", "0.97", "0.2"])
    package.allocation = derive_effective_reward_allocation(package, GeometricRewardParameters())
    with pytest.raises(ValueError, match="inconsistent bindings"):
        derive_effective_reward_allocation(package, GeometricRewardParameters())


def test_new_revision_always_derives_from_original_inputs_without_payload_access():
    package = package_boundary(["0.99", "0.97", "0.2"])

    class SelectedOriginalPackage:
        allocation = package.allocation
        service = package.service
        benchmark = package.benchmark
        inputs = package.inputs
        policy_sha256 = package.policy_sha256

        @property
        def objects(self):
            raise AssertionError("effective arithmetic must not reread payload inventory")

    selected = SelectedOriginalPackage()
    first = derive_effective_reward_allocation(selected, GeometricRewardParameters())
    revised = derive_effective_reward_allocation(
        selected,
        GeometricRewardParameters(band_width_bps=10000, within_band_decay_bps=5000),
    )
    assert digest(revised) != digest(first)
    assert revised.service_certificate_sha256 == first.service_certificate_sha256
    assert revised.burn_weight == first.burn_weight
    assert revised.model_award.candidates == first.model_award.candidates
