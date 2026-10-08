"""Authenticate exact signed work before reserving a shared miner window.

This is a scheduling boundary only. Dispatch and miners still check current
authority, original clocks and execution fences. Successful immutable grant
checks are retained privately; an owner restart does not repeat their proofs.
"""

from collections.abc import Mapping
from typing import Annotated, Literal

from pydantic import Field

from .canonical_reuse import canonical_json_reuse
from .competition_cohort_endpoint import validate_recoverable_endpoint_transport
from .competition_cohort_miner_case import (
    CohortCaseMinerGrant,
    MinerGrant,
    grant_requests,
    validate_case_attempt,
)
from .competition_cohort_order_queue import check_delivery_receipt
from .competition_cohort_orders import recoverable_order_job
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_cohort_service_grant import ServiceMinerGrant, verify_service_grant
from .competition_cohort_window_store import CohortMinerWindowStore, WindowRequest
from .config import Limits
from .endpoint_retirement import SignedEndpointRetirementReceipt
from .open_competition import CompetitionPolicy, digest, identity, verify_signature
from .policy import ScoringPolicy, scoring_policy_hash
from .private_files import Directory
from .protocol import (
    Hex32,
    StrictProtocolModel,
    TranslationRequest,
    canonical_json_bytes,
    request_digest,
)


class WindowOperation(StrictProtocolModel):
    schema_: Literal["umi-cohort-window-operation/1"] = Field(alias="schema")
    grant: MinerGrant
    request: TranslationRequest
    retirement: SignedEndpointRetirementReceipt | None = None


class WindowResult(StrictProtocolModel):
    schema_: Literal["umi-cohort-window-result/1"] = Field(alias="schema")
    operation_sha256: Hex32
    status: Literal["reserved", "retired"]


class WindowOwnerConfig(StrictProtocolModel):
    directory: Directory
    transports: Annotated[tuple[ScoringPolicy, ...], Field(min_length=1, max_length=512)]
    bootstrap_sources: Annotated[tuple[str, ...], Field(min_length=1, max_length=128)]


class CohortWindowOwner:
    def __init__(
        self,
        store: CohortMinerWindowStore,
        policy: CompetitionPolicy,
        transports: tuple[ScoringPolicy, ...],
        authorities: Mapping[str, str],
    ):
        self.store = store
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self.policy_sha256 = digest(self.policy)
        self.transports = {scoring_policy_hash(p): p for p in transports}
        self.authorities = dict(authorities)
        if (
            set(self.authorities) != store.cohorts
            or len(self.transports) != len(transports)
            or {
                key: Limits.from_policy(value).maximum_active_windows
                for key, value in self.transports.items()
            }
            != store.windows
            or not store.evaluators <= {identity(e.hotkey) for e in self.policy.evaluators}
        ):
            raise ValueError("window owner differs from its retained scheduling scope")
        store.journal.put(
            "window_authority_binding",
            digest(["umi-cohort-window-authority/1"]),
            {"policy": self.policy_sha256, "authorities": self.authorities},
        )

    def _verify(self, operation: WindowOperation) -> WindowRequest:
        grant, request = operation.grant, operation.request
        transport = self.transports.get(request.scoring_policy_hash)
        if transport is None or request not in grant_requests(grant):
            raise ValueError("window request is not covered by the selected transport and grant")
        if isinstance(grant, ServiceMinerGrant):
            verify_service_grant(grant, self.policy, transport)
            assignment = grant.body.assignment
            cohort = assignment.round.cohort_sha256
            authority = assignment.catalog.catalog.authority_sha256
            miner = assignment.admission.submission.submission.hotkey
            evaluator = grant.body.evaluator_hotkey
        else:
            assignment, attempt = grant.assignment, grant.attempt
            order = assignment.certificate.order
            verify_recovery_quorum(order, assignment.certificate.signatures, self.policy)
            miner = order.submission.submission.hotkey
            if any(
                identity(s.hotkey) == identity(miner) for s in assignment.certificate.signatures
            ):
                raise ValueError("miner cannot authorize its own window assignment")
            receipt = check_delivery_receipt(assignment.certificate, assignment.delivery)
            evaluator = receipt.receipt.evaluator_hotkey
            job = recoverable_order_job(order, evaluator)
            if isinstance(grant, CohortCaseMinerGrant):
                validate_case_attempt(attempt, self.policy, transport)
            else:
                validate_recoverable_endpoint_transport(attempt, self.policy, transport)
                if attempt.order.attempt_number != 1:
                    raise ValueError("replacement requires its certified case grant")
            if attempt.order.job != job or job.mode != "endpoint_incumbent":
                raise ValueError("window grant differs from its delivered assignment")
            consent = assignment.participant.consent
            verify_signature(consent.consent, consent.signature)
            cohort, authority = job.round.cohort_sha256, consent.consent.authority_sha256
            if (
                consent.consent.cohort_sha256 != cohort
                or consent.consent.submission_sha256 != digest(order.submission.submission)
                or identity(consent.signature.hotkey) != identity(miner)
                or identity(consent.consent.hotkey) != identity(miner)
                or job.round.policy_sha256 != self.policy_sha256
            ):
                raise ValueError("window assignment consent differs from its miner or cohort")
        if self.authorities.get(cohort) != authority:
            raise ValueError("window grant has a different cohort authority")
        result = WindowRequest(
            schema="umi-cohort-window-request/1",
            cohort_sha256=cohort,
            miner_hotkey=miner,
            evaluator_hotkey=evaluator,
            grant_sha256=digest(grant),
            request=request,
        )
        self.store._selected(result)
        return result

    @canonical_json_reuse()
    def selected(self, operation: WindowOperation) -> WindowRequest:
        if operation.request not in grant_requests(operation.grant):
            raise ValueError("window request is not present in its exact signed grant")
        key = digest(
            [
                "umi-cohort-verified-window-request/1",
                self.policy_sha256,
                digest(operation.grant),
                request_digest(operation.request),
            ]
        )
        prior = self.store.journal.get("verified_window_request", key)
        if prior is not None:
            result = WindowRequest.model_validate_json(canonical_json_bytes(prior))
            if (
                result.grant_sha256 != digest(operation.grant)
                or result.request != operation.request
            ):
                raise ValueError("retained window verification changed its exact input")
            self.store._selected(result)
            return result
        result = self._verify(operation)
        self.store.journal.put("verified_window_request", key, result)
        return result

    @canonical_json_reuse()
    def apply(self, operation: WindowOperation) -> WindowResult:
        # Enforce wire parsing even for a local in-process consumer.
        operation = WindowOperation.model_validate_json(canonical_json_bytes(operation))
        selected = self.selected(operation)
        status = (
            self.store.reserve(selected)
            if operation.retirement is None
            else self.store.retire(selected, operation.retirement)
        )
        return WindowResult(
            schema="umi-cohort-window-result/1", operation_sha256=digest(operation), status=status
        )
