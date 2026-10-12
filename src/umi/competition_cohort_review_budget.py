"""Local, policy-bound allowances for complete serial phase review.

Signed inference clocks do not measure aggregate proof replay speed. Operators
select these allowances from the supported deployment's retained measurements;
the profile does not change protocol deadlines or certify resource capacity.
"""

from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_capacity import AggregateEvidenceCapacity
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

# JSON's exact integer range is the representation limit, not a short runtime
# deadline. Composite values are checked too, before they reach asyncio/HTTP.
MAX_REVIEW_SECONDS = 2**53 - 1
ReviewSeconds = Annotated[int, Field(strict=True, ge=1, le=MAX_REVIEW_SECONDS)]


def check_review_seconds(value: int) -> None:
    if type(value) is not int or not 1 <= value <= MAX_REVIEW_SECONDS:
        raise ValueError("phase review timeout is outside bounds")


class PhaseReviewBudget(StrictProtocolModel):
    schema_: Literal["umi-cohort-phase-review-budget/1"] = Field(alias="schema")
    policy_sha256: Hex32
    evaluation_runtime_sha256: Hex32
    maximum_aggregate_evidence_bytes: AggregateEvidenceCapacity
    export_seconds: ReviewSeconds
    replay_seconds: ReviewSeconds
    authority_seconds: ReviewSeconds
    signing_seconds: ReviewSeconds
    transport_seconds: ReviewSeconds
    vote_queue_seconds: ReviewSeconds
    export_queue_slots: Annotated[int, Field(strict=True, ge=1, le=64)]

    @property
    def export_exchange_seconds(self) -> int:
        return self.export_queue_slots * self.export_seconds + self.transport_seconds

    def vote_seconds(self, kind: Literal["progress", "decision", "adoption"]) -> int:
        if kind not in ("progress", "decision", "adoption"):
            raise ValueError("unsupported phase review operation")
        # Adoption has three exchanges, but only two history validation/replay
        # allowances. Reservation is a small signed proof, not a third history
        # replay; its verification belongs to the additional authority work.
        reads = 2 if kind == "progress" else 3
        replays = 2 if kind == "adoption" else reads
        return (
            reads * self.export_exchange_seconds
            + replays * self.replay_seconds
            + self.authority_seconds
            + self.signing_seconds
            + self.vote_queue_seconds
        )

    def vote_exchange_seconds(self, kind: Literal["progress", "decision", "adoption"]) -> int:
        # The route queues before its operation timer; the signer's serial
        # queue is inside it. Give each queue its explicit selected allowance.
        return self.vote_seconds(kind) + self.vote_queue_seconds + self.transport_seconds

    @model_validator(mode="after")
    def supported(self):
        for value in (
            self.export_exchange_seconds,
            self.vote_exchange_seconds("progress"),
            self.vote_exchange_seconds("decision"),
            self.vote_exchange_seconds("adoption"),
        ):
            check_review_seconds(value)
        return self

    def verify(self, policy, maximum_bytes, *, reviewers=None, signing_seconds=None):
        if (
            self.policy_sha256 != digest(policy)
            or self.evaluation_runtime_sha256 != policy.evaluation_runtime_sha256
            or maximum_bytes > self.maximum_aggregate_evidence_bytes
        ):
            raise ValueError(
                "phase review budget differs from selected policy, runtime or capacity"
            )
        if reviewers is not None and reviewers > self.export_queue_slots:
            raise ValueError("phase review export queue allowance omits selected reviewers")
        if signing_seconds is not None and signing_seconds > self.signing_seconds:
            raise ValueError("phase review budget shortens the selected signing allowance")

    def effective(self) -> dict[str, int | str]:
        return {
            "profile": self.schema_,
            "owner_export_seconds": self.export_seconds,
            "export_exchange_seconds": self.export_exchange_seconds,
            "progress_vote_seconds": self.vote_seconds("progress"),
            "decision_vote_seconds": self.vote_seconds("decision"),
            "progress_exchange_seconds": self.vote_exchange_seconds("progress"),
            "decision_exchange_seconds": self.vote_exchange_seconds("decision"),
            "adoption_vote_seconds": self.vote_seconds("adoption"),
            "adoption_exchange_seconds": self.vote_exchange_seconds("adoption"),
        }


def checked_budget(value: PhaseReviewBudget | None, policy, maximum_bytes, **limits):
    if value is None:
        return None
    value = PhaseReviewBudget.model_validate_json(canonical_json_bytes(value))
    value.verify(policy, maximum_bytes, **limits)
    return value


def _proxy_budget(value, direct):
    if direct:
        if value is not None:
            raise ValueError("direct phase review path cannot also select a managed proxy")
    else:
        check_review_seconds(value)


def _pins(value):
    return (
        value.policy_sha256,
        value.evaluation_runtime_sha256,
        value.maximum_aggregate_evidence_bytes,
    )


def validate_phase_export_path(*, owner, reviewer, owner_proxy_seconds=None, direct_owner=False):
    """Compare an owner export with its selected reviewer exchange allowance."""
    _proxy_budget(owner_proxy_seconds, direct_owner)
    if _pins(owner) != _pins(reviewer):
        raise ValueError("phase review path changes policy, runtime or capacity")
    if reviewer.export_exchange_seconds < owner.export_exchange_seconds:
        raise ValueError("reviewer export exchange shortens the owner allowance")
    if not direct_owner and owner_proxy_seconds < reviewer.export_exchange_seconds:
        raise ValueError("managed owner proxy shortens the review export allowance")


def validate_phase_review_path(
    *,
    owner,
    reviewer,
    peer,
    owner_proxy_seconds=None,
    vote_proxy_seconds=None,
    direct_owner=False,
    direct_vote=False,
):
    """Refuse an independently shorter selected hop before deployment.

    Proxy allowances must come from the actual managed route's supported
    configuration. A missing value is not evidence of an unlimited route.
    """
    validate_phase_export_path(
        owner=owner,
        reviewer=reviewer,
        owner_proxy_seconds=owner_proxy_seconds,
        direct_owner=direct_owner,
    )
    _proxy_budget(vote_proxy_seconds, direct_vote)
    if _pins(reviewer) != _pins(peer):
        raise ValueError("phase review path changes policy, runtime or capacity")
    for kind in ("progress", "decision", "adoption"):
        if peer.vote_exchange_seconds(kind) < reviewer.vote_exchange_seconds(kind):
            raise ValueError("coordinator peer shortens the complete reviewer allowance")
        if not direct_vote and vote_proxy_seconds < peer.vote_exchange_seconds(kind):
            raise ValueError("managed vote proxy shortens the complete reviewer allowance")
