"""Work-first service allocation, separate from promotion and chain projection.

The arithmetic accepts replayed observations. The native builder obtains those
observations through complete request, reference and response verification.
Neither a JSON allocation nor a quality digest authorizes weight submission.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from fractions import Fraction
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_service_quality import (
    ClosedServiceQuality,
    ServiceTerms,
    replay_closed_service_quality,
)
from .open_competition import Hotkey, digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

RawWeight = Annotated[int, Field(ge=0, le=65535)]


class ServiceRecipientAmount(StrictProtocolModel):
    hotkey: Hotkey
    raw_weight: RawWeight


class ServiceAllocation(StrictProtocolModel):
    schema_: Literal["umi-cohort-service-allocation/1"] = Field(alias="schema")
    terms_sha256: Hex32
    request_closure_sha256: Hex32
    quality_sha256: Hex32
    service_budget: RawWeight
    model_budget: RawWeight
    stratum_budgets: dict[str, RawWeight]
    recipients: Annotated[tuple[ServiceRecipientAmount, ...], Field(max_length=65535)]
    burn_weight: RawWeight
    chain_submission_authorized: Literal[False] = False


def apportion_work_budget(budget: int, credits: Mapping[str, Fraction]) -> dict[str, int]:
    """Largest remainder with stable work/budget identifiers for exact ties."""
    if type(budget) is not int or not 0 <= budget <= 65535:
        raise ValueError("invalid raw weight budget")
    if any(not isinstance(v, Fraction) or v < 0 for v in credits.values()):
        raise ValueError("credits must be nonnegative exact fractions")
    positive = {key: value for key, value in credits.items() if value > 0}
    if not positive:
        if budget:
            raise ValueError("positive budget has no positive credit")
        return {}
    total = sum(positive.values(), Fraction())
    ideal = {key: budget * value / total for key, value in positive.items()}
    result = {key: int(value) for key, value in ideal.items()}
    order = sorted(ideal, key=lambda key: (-(ideal[key] - result[key]), key))
    for key in order[: budget - sum(result.values())]:
        result[key] += 1
    return result


def allocate_service_quality(
    quality: ClosedServiceQuality, terms: ServiceTerms
) -> ServiceAllocation:
    """Pure arithmetic; callers must replay complete evidence before certification.

    Model attribution is deliberately not chosen here. Its fixed pool remains
    explicit for settlement to bind to a promotion or the selected cohort award.
    """
    quality = ClosedServiceQuality.model_validate_json(canonical_json_bytes(quality))
    terms = ServiceTerms.model_validate_json(canonical_json_bytes(terms))
    if quality.terms_sha256 != digest(terms):
        raise ValueError("allocation terms differ from replayed service quality")
    pools = apportion_work_budget(
        terms.total_raw_weight,
        {
            "service": Fraction(terms.service_pool_bps),
            "model": Fraction(10000 - terms.service_pool_bps),
        },
    )
    service, model = pools.get("service", 0), pools.get("model", 0)
    budgets = apportion_work_budget(
        service, {key: Fraction(value) for key, value in terms.stratum_weights.items()}
    )
    jobs = {}
    for work in quality.work:
        credit = Fraction(int(work.credit.numerator), int(work.credit.denominator))
        score = Fraction(int(work.quality.numerator), int(work.quality.denominator))
        if (
            work.work_sha256 in jobs
            or not 0 <= score <= 1
            or credit != work.units * score
            or (work.status == "miner_failure" and score != 0)
        ):
            raise ValueError("service work has duplicate or inconsistent credit")
        jobs[work.work_sha256] = (work, credit)
    by_identity = defaultdict(int)
    hotkeys = {}
    burn = 0
    for stratum, budget in sorted(budgets.items()):
        credits = {key: c for key, (w, c) in jobs.items() if w.stratum == stratum}
        if not any(credits.values()):
            burn += budget
            continue
        amounts = apportion_work_budget(budget, credits)
        for key, amount in amounts.items():
            if not amount:
                continue
            hotkey = jobs[key][0].recipient_hotkey
            who = identity(hotkey)
            hotkeys[who] = min(hotkeys.get(who, hotkey), hotkey)
            by_identity[who] += amount
    return ServiceAllocation(
        schema="umi-cohort-service-allocation/1",
        terms_sha256=digest(terms),
        request_closure_sha256=quality.request_closure_sha256,
        quality_sha256=digest(quality),
        service_budget=service,
        model_budget=model,
        stratum_budgets=budgets,
        recipients=tuple(
            ServiceRecipientAmount(hotkey=hotkeys[key], raw_weight=amount)
            for key, amount in sorted(by_identity.items())
        ),
        burn_weight=burn,
    )


def replay_service_allocation(
    closure,
    roster,
    objects,
    policy,
    history,
    transport,
    terms,
    reveal,
    *,
    expected_catalogs,
    expected_seals,
    expected_terms_sha256,
    decision_source,
    intake_records,
    pulses,
    expected_tip_sha256,
    current_block,
) -> ServiceAllocation:
    """Build from native evidence, never from an operator-selected score list."""
    quality = replay_closed_service_quality(
        closure,
        roster,
        objects,
        policy,
        history,
        transport,
        terms,
        reveal,
        expected_catalogs=expected_catalogs,
        expected_seals=expected_seals,
        expected_terms_sha256=expected_terms_sha256,
        decision_source=decision_source,
        intake_records=intake_records,
        pulses=pulses,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    return allocate_service_quality(quality, terms)
