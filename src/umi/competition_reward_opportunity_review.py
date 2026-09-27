"""Retain completion candidates and replay every designated validator's evidence."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from .competition_evidence_codec import checked_size
from .competition_reward_coverage import OwnedRewardCoverageEndpoint
from .competition_reward_coverage_intervals import coverage_interval, coverage_point
from .competition_reward_coverage_journal import RewardCoverageJournal
from .competition_reward_decisions import DecisionSource, RewardActivation, StandingRewardSeries
from .competition_reward_manifest import RewardManifest
from .competition_reward_opportunity import (
    RewardOpportunityCertificate,
    RewardOpportunityContribution,
    RewardOpportunityWitness,
    VerifiedRewardOpportunity,
    _issue_opportunity,
    check_opportunity_claim,
    opportunity_rule,
)
from .concurrency import run_owned_thread
from .open_competition import CompetitionPolicy, digest
from .private_files import MAX_CONFIGURED_PRIVATE_BYTES
from .protocol import canonical_json_bytes

MAX_CERTIFICATE_BYTES = 128 * 1024
DEFAULT_WITNESS_BYTES = 16 * 1024**2
EndpointReview = Callable[[str], Awaitable[OwnedRewardCoverageEndpoint]]


async def prepare_opportunity_certificate(
    journal: RewardCoverageJournal,
    *,
    manifest: RewardManifest,
    series: StandingRewardSeries,
    policy: CompetitionPolicy,
    activation: RewardActivation,
    maximum_witness_bytes: int = DEFAULT_WITNESS_BYTES,
) -> RewardOpportunityCertificate:
    """Retain a candidate and its witnesses atomically, before acknowledging it.

    This is content, not proof authority. A reader replays it before signing or
    accepting the successor decision. A changed/larger later witness does not
    replace a candidate already bound by a signed decision.
    """
    checked_size(maximum_witness_bytes, MAX_CONFIGURED_PRIVATE_BYTES)
    rule = opportunity_rule(manifest, series, policy)
    if type(journal) is not RewardCoverageJournal or journal.rule != rule:
        raise ValueError("opportunity journal differs from approved series terms")
    witnesses, contributions = [], []
    for hotkey in series.validators:
        witness, contribution = await journal.verified_witness(
            activation_sha256=digest(activation), validator_hotkey=hotkey
        )
        if len(canonical_json_bytes(witness)) > maximum_witness_bytes:
            raise ValueError("opportunity witness exceeds host byte capacity")
        witnesses.append(witness)
        contributions.append(contribution)
    certificate = RewardOpportunityCertificate(
        schema="umi-reward-opportunity-certificate/1",
        series_sha256=digest(series),
        manifest_sha256=digest(manifest),
        rule_sha256=digest(rule),
        activation_sha256=digest(activation),
        contributions=tuple(contributions),
    )
    check_opportunity_claim(
        certificate, manifest=manifest, series=series, policy=policy, activation=activation
    )
    if len(canonical_json_bytes(certificate)) > MAX_CERTIFICATE_BYTES:
        raise ValueError("opportunity certificate exceeds its byte bound")
    records = [("opportunity_witness", digest(w), w) for w in witnesses]
    records.append(("opportunity_certificate", digest(certificate), certificate))
    # Ordinary journal transactions retain the complete record set or nothing.
    # Cancellation drains the owner; a lost acknowledgement retries these bytes.
    await run_owned_thread(journal.journal.put_many, records)
    return certificate


async def review_opportunity_certificate(
    raw: bytes,
    *,
    expected_sha256: str,
    journal: RewardCoverageJournal,
    witness_source: DecisionSource,
    review_endpoint: EndpointReview,
    manifest: RewardManifest,
    series: StandingRewardSeries,
    policy: CompetitionPolicy,
    activation: RewardActivation,
    maximum_witness_bytes: int = DEFAULT_WITNESS_BYTES,
) -> VerifiedRewardOpportunity:
    """Native endpoint replay establishes every claim, with no age deadline.

    Callbacks fetch/review content-addressed inputs, never asserted totals. Each
    returned endpoint must have native coverage provenance. Consecutive intervals
    reuse their shared endpoint; missing evidence holds without inventing time.
    """
    checked_size(maximum_witness_bytes, MAX_CONFIGURED_PRIVATE_BYTES)
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_CERTIFICATE_BYTES:
        raise ValueError("opportunity certificate exceeds its byte bound")
    certificate = RewardOpportunityCertificate.model_validate_json(raw)
    if canonical_json_bytes(certificate) != raw or digest(certificate) != expected_sha256:
        raise ValueError("opportunity certificate differs from the selected identity")
    rule = check_opportunity_claim(
        certificate, manifest=manifest, series=series, policy=policy, activation=activation
    )
    if type(journal) is not RewardCoverageJournal or journal.rule != rule:
        raise ValueError("opportunity journal differs from approved series terms")
    for contribution in certificate.contributions:
        wire = witness_source(contribution.witness_sha256)
        if type(wire) is not bytes or not 0 < len(wire) <= maximum_witness_bytes:
            raise ValueError("opportunity witness exceeds host byte capacity")
        witness = RewardOpportunityWitness.model_validate_json(wire)
        if (
            canonical_json_bytes(witness) != wire
            or digest(witness) != contribution.witness_sha256
            or witness.rule_sha256 != digest(rule)
            or witness.activation_sha256 != digest(activation)
            or witness.validator_account_id != contribution.validator_account_id
        ):
            raise ValueError("opportunity witness changed its selected domain")
        total, through, previous = 0, 0, None
        for key in witness.interval_keys:
            hint = await journal.retained_interval(key)
            left = (
                previous
                if previous is not None and coverage_point(previous, rule).key() == hint.left
                else await review_endpoint(hint.left)
            )
            right = await review_endpoint(hint.right)
            interval = coverage_interval(left, right, rule)
            block = coverage_point(right, rule).block
            if (
                interval is None
                or interval != hint
                or interval.key() != key
                or interval.activation_sha256 != digest(activation)
                or interval.validator_account_id != contribution.validator_account_id
                or block <= through
            ):
                raise ValueError("opportunity interval lacks ordered native coverage")
            await journal.credit(left, right)
            total += interval.credited_ms
            through, previous = block, right
        if contribution != RewardOpportunityContribution(
            validator_account_id=witness.validator_account_id,
            witness_sha256=digest(witness),
            credited_ms=total,
            through_block=through,
        ):
            raise ValueError("opportunity contribution differs from native replay")
    return _issue_opportunity(certificate)
