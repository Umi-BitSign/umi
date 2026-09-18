"""Deterministic matched-swap evidence for continuous-sign evaluation.

Each scored continuous clip has a second request whose video comes from a
different clip in the same duration bin while the original reference stays
fixed. Eligibility depends on the score loss under that real input swap, not
on whether the output string merely changes.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
from typing import Annotated

from pydantic import Field

from .competition_scoring import score_single_reference
from .protocol import Hex32, ReferenceText, StrictProtocolModel


class MatchedSwapPair(StrictProtocolModel):
    """Bind a scored case, its swapped request, and the swap-source case."""

    case_id: Hex32
    control_case_id: Hex32
    source_case_id: Hex32


@dataclass(frozen=True, slots=True)
class DependenceCaseProfile:
    role: str
    video_sha256: str
    duration_ms: int
    reference: ReferenceText


@dataclass(frozen=True, slots=True)
class DependenceReport:
    complete: bool
    correct_score: Fraction
    swapped_score: Fraction
    observed_margin: Fraction
    bootstrap_lower_bound: Fraction
    byte_identical_fraction: Fraction


def _duration_bins(scored: Mapping[str, DependenceCaseProfile], count: int) -> dict[str, int]:
    ordered = sorted(scored, key=lambda case_id: (scored[case_id].duration_ms, case_id))
    if count < 1 or len(ordered) < count * 2:
        raise ValueError("matched-swap profile needs at least two scored cases per duration bin")
    return {case_id: rank * count // len(ordered) for rank, case_id in enumerate(ordered)}


def validate_matched_swap_pairs(
    *,
    profiles: Mapping[str, DependenceCaseProfile],
    pairs: Sequence[MatchedSwapPair],
    minimum_pairs: Annotated[int, Field(ge=3, le=1024)],
    duration_bin_count: Annotated[int, Field(ge=1, le=512)],
    maximum_duration_delta_ms: Annotated[int, Field(ge=0, le=3_600_000)],
) -> None:
    """Require a canonical within-bin derangement and exact control construction."""

    scored = {case_id: item for case_id, item in profiles.items() if item.role == "scored"}
    controls = {case_id: item for case_id, item in profiles.items() if item.role == "matched_swap"}
    if len(scored) < minimum_pairs:
        raise ValueError("matched-swap profile has too few scored continuous cases")
    if list(pairs) != sorted(pairs, key=lambda pair: pair.case_id):
        raise ValueError("matched-swap pairs must be sorted by scored case ID")
    anchors = [pair.case_id for pair in pairs]
    control_ids = [pair.control_case_id for pair in pairs]
    sources = [pair.source_case_id for pair in pairs]
    if set(anchors) != set(scored) or len(anchors) != len(scored):
        raise ValueError("matched-swap anchors must cover each scored continuous case once")
    if set(control_ids) != set(controls) or len(control_ids) != len(controls):
        raise ValueError("matched-swap controls must cover each control case once")
    if set(sources) != set(scored) or len(sources) != len(scored):
        raise ValueError("matched-swap sources must permute the scored continuous cases")
    bins = _duration_bins(scored, duration_bin_count)
    for pair in pairs:
        if pair.case_id == pair.source_case_id:
            raise ValueError("matched-swap sources must form a derangement")
        anchor = scored[pair.case_id]
        source = scored[pair.source_case_id]
        control = controls[pair.control_case_id]
        if bins[pair.case_id] != bins[pair.source_case_id]:
            raise ValueError("matched-swap source is outside the anchor duration bin")
        if abs(anchor.duration_ms - source.duration_ms) > maximum_duration_delta_ms:
            raise ValueError("matched-swap pair exceeds the signed duration tolerance")
        if (
            control.video_sha256 != source.video_sha256
            or control.duration_ms != source.duration_ms
            or control.reference != anchor.reference
        ):
            raise ValueError("matched-swap control does not preserve reference and swap video")


def _bootstrap_lower_bound(
    margins: Sequence[Fraction], *, seed_sha256: str, replicates: int, confidence_bps: int
) -> Fraction:
    if not margins or replicates < 100 or not 5_000 <= confidence_bps < 10_000:
        raise ValueError("invalid matched-swap bootstrap profile")
    if len(seed_sha256) != 64 or any(c not in "0123456789abcdef" for c in seed_sha256):
        raise ValueError("bootstrap seed must be a lowercase SHA-256 digest")
    seed = bytes.fromhex(seed_sha256)
    samples: list[Fraction] = []
    count = len(margins)
    for replicate in range(replicates):
        stream = hashlib.shake_256(
            b"umi-matched-swap-bootstrap-v1\0" + seed + replicate.to_bytes(8, "big")
        ).digest(8 * count)
        sample = (
            sum(
                (
                    margins[int.from_bytes(stream[offset : offset + 8], "big") % count]
                    for offset in range(0, len(stream), 8)
                ),
                Fraction(0),
            )
            / count
        )
        samples.append(sample)
    samples.sort()
    tail_bps = 10_000 - confidence_bps
    rank = max(0, (tail_bps * replicates + 9_999) // 10_000 - 1)
    return samples[rank]


def matched_swap_report(
    *,
    hypotheses: Mapping[str, str | None],
    profiles: Mapping[str, DependenceCaseProfile],
    pairs: Sequence[MatchedSwapPair],
    seed_sha256: str,
    bootstrap_replicates: int,
    confidence_bps: int,
) -> DependenceReport:
    """Score correct and swapped requests and derive a deterministic lower bound."""

    if set(hypotheses) != set(profiles):
        raise ValueError("matched-swap hypotheses and case profiles differ")
    margins: list[Fraction] = []
    correct_scores: list[Fraction] = []
    swapped_scores: list[Fraction] = []
    identical = 0
    complete = True
    for pair in pairs:
        anchor = hypotheses[pair.case_id]
        control = hypotheses[pair.control_case_id]
        reference = profiles[pair.case_id].reference
        if anchor is None or control is None:
            complete = False
            correct = swapped = Fraction(0)
        else:
            correct = score_single_reference("wer", anchor, reference)
            swapped = score_single_reference("wer", control, reference)
            identical += anchor.encode("utf-8") == control.encode("utf-8")
        correct_scores.append(correct)
        swapped_scores.append(swapped)
        margins.append(correct - swapped)
    if not margins:
        raise ValueError("matched-swap evidence is empty")
    correct_mean = sum(correct_scores, Fraction(0)) / len(margins)
    swapped_mean = sum(swapped_scores, Fraction(0)) / len(margins)
    observed = sum(margins, Fraction(0)) / len(margins)
    lower = _bootstrap_lower_bound(
        margins,
        seed_sha256=seed_sha256,
        replicates=bootstrap_replicates,
        confidence_bps=confidence_bps,
    )
    return DependenceReport(
        complete=complete,
        correct_score=correct_mean,
        swapped_score=swapped_mean,
        observed_margin=observed,
        bootstrap_lower_bound=lower,
        byte_identical_fraction=Fraction(identical, len(margins)),
    )


__all__ = (
    "DependenceCaseProfile",
    "DependenceReport",
    "MatchedSwapPair",
    "matched_swap_report",
    "validate_matched_swap_pairs",
)
