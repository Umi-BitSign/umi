"""Explicit request-tail evidence, certified by the ordinary phase quorum.

The original preparation and roster stay unchanged. Only obligations still
unfinished at the new closure observation may be skipped. These records never
supply an execution terminal, a quality score, or a certification exception.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_cohort_coordinator import CohortDecisionInput
from .competition_execution import ExecutionBoundary
from .competition_historical_registration import HistoricalRegistration
from .open_competition import digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MINIMUM_REQUEST_OPEN_MS = 12 * 60 * 60 * 1000
Timestamp = Annotated[int, Field(ge=1, le=2**53 - 1)]


class RequestTailObservation(StrictProtocolModel):
    schema_: Literal["umi-cohort-request-tail-observation/1"] = Field(alias="schema")
    rule: Literal["original_request_12h_at_most_tenth/1"] = "original_request_12h_at_most_tenth/1"
    opened_observation: ExecutionBoundary
    opened_timestamp_ms: Timestamp
    observation: ExecutionBoundary
    observed_timestamp_ms: Timestamp
    selected_observation: ExecutionBoundary | None = None
    selected_timestamp_ms: Timestamp | None = None
    original_hotkeys: Annotated[tuple[Hex32, ...], Field(min_length=1, max_length=512)]
    unfinished_hotkeys: Annotated[tuple[Hex32, ...], Field(max_length=512)]

    @model_serializer(mode="wrap")
    def omit_unselected_cutoff(self, handler):
        value = handler(self)
        if self.selected_observation is None:
            value.pop("selected_observation", None)
            value.pop("selected_timestamp_ms", None)
        return value

    @model_validator(mode="after")
    def canonical_threshold(self):
        for values in (self.original_hotkeys, self.unfinished_hotkeys):
            if values != tuple(sorted(set(values))):
                raise ValueError("request tail miner identities must be unique and ordered")
        if not set(self.unfinished_hotkeys) <= set(self.original_hotkeys):
            raise ValueError("request tail includes an unselected unfinished miner")
        if len(self.unfinished_hotkeys) * 10 > len(self.original_hotkeys):
            raise ValueError("request tail permits at most ten percent unfinished")
        if (self.selected_observation is None) != (self.selected_timestamp_ms is None):
            raise ValueError("request tail selection boundary requires its timestamp")
        selected = self.selected_observation or self.observation
        timestamp = self.selected_timestamp_ms or self.observed_timestamp_ms
        if (
            selected.block <= self.opened_observation.block
            or selected.block > self.observation.block
            or timestamp > self.observed_timestamp_ms
            or timestamp - self.opened_timestamp_ms < MINIMUM_REQUEST_OPEN_MS
        ):
            raise ValueError("request tail requires twelve hours from original request opening")
        return self


def original_request_miners(roster, service_assignments=()) -> tuple[str, ...]:
    """Distinct original selected hotkeys; paid claims cannot enlarge that roster."""
    original = {
        identity(p.record.request.signed_submission.submission.hotkey) for p in roster.participants
    }
    paid = {identity(a.admission.submission.submission.hotkey) for a in service_assignments}
    if not paid <= original:
        raise ValueError("accepted service recipient is outside the original selected roster")
    return tuple(sorted(original | paid))


def _miner_identity(who: str) -> str:
    if len(who) == 64 and all(c in "0123456789abcdef" for c in who):
        return who
    return identity(who)


def review_request_tail(
    tail: RequestTailObservation,
    *,
    roster,
    history,
    decision_source,
    observation: ExecutionBoundary,
    required_unfinished_hotkeys: Iterable[str] = (),
    unfinished_hotkeys: Iterable[str] | None = None,
    service_assignments=(),
) -> RequestTailObservation:
    """Replay the original population and opening; owners separately prove clocks.

    A benchmark checks its incomplete miners are included. The enclosing service
    closure supplies the exact union across benchmark and accepted paid work.
    Independent phase reviewers call ``verify_request_tail_clock`` before any
    signature; downstream consumers require that certified closure unchanged.
    """
    tail = RequestTailObservation.model_validate_json(canonical_json_bytes(tail))
    opened = next(
        (
            item.transition
            for item in history.transitions
            if item.transition.phase == "preparation" and item.transition.operation == "close_phase"
        ),
        None,
    )
    if opened is None:
        raise ValueError("request tail lacks its original certified preparation")
    decision = CohortDecisionInput.model_validate_json(
        canonical_json_bytes(decision_source(opened.evidence_sha256))
    )
    if (
        digest(decision) != opened.evidence_sha256
        or decision.observation.block != opened.observed_at_block
        or tail.opened_observation != decision.observation
        or tail.observation != observation
        or tail.original_hotkeys != original_request_miners(roster, service_assignments)
        or not {_miner_identity(who) for who in required_unfinished_hotkeys}
        <= set(tail.unfinished_hotkeys)
    ):
        raise ValueError("request tail differs from original preparation, roster or obligations")
    if unfinished_hotkeys is not None and tail.unfinished_hotkeys != tuple(
        sorted({_miner_identity(who) for who in unfinished_hotkeys})
    ):
        raise ValueError("request tail must cover the exact unfinished miner union")
    return tail


def verify_request_tail_clock(
    tail: RequestTailObservation,
    opened: HistoricalRegistration,
    observed: HistoricalRegistration,
    selected: HistoricalRegistration | None = None,
) -> None:
    """Use timestamps exposed only after the native registration archive replay."""
    tail = RequestTailObservation.model_validate_json(canonical_json_bytes(tail))
    proofs = [
        (opened, tail.opened_observation, tail.opened_timestamp_ms),
        (observed, tail.observation, tail.observed_timestamp_ms),
    ]
    if tail.selected_observation is not None:
        proofs.append((selected, tail.selected_observation, tail.selected_timestamp_ms))
    for proof, boundary, timestamp in proofs:
        if (
            not isinstance(proof, HistoricalRegistration)
            or proof.original != boundary
            or proof.timestamp_ms != timestamp
            or proof.replayed_at.block_number < boundary.block
        ):
            raise ValueError("request tail clock differs from native original timestamp proof")
