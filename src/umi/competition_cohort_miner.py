"""Durable miner admission for exact recoverable cohort requests.

A retained grant acknowledges storage. Each inference request still requires
current phase authority and the miner's own finalized transport window.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, TypeAdapter

from .competition_authorization import validate_runtime_binding
from .competition_cohort_endpoint import (
    validate_recoverable_endpoint_transport,
)
from .competition_cohort_intake import CohortIntakeConfig
from .competition_cohort_miner_case import (
    CohortCaseMinerGrant,
    grant_requests,
    grant_slot,
    parse_miner_grant,
    validate_case_attempt,
    verify_replacement_parent,
)
from .competition_cohort_miner_contracts import (
    CohortMinerGrant as CohortMinerGrant,
)
from .competition_cohort_miner_contracts import (
    CohortMinerGrantReceipt as CohortMinerGrantReceipt,
)
from .competition_cohort_miner_contracts import (
    SignedCohortMinerGrantReceipt as SignedCohortMinerGrantReceipt,
)
from .competition_cohort_order_queue import check_delivery_receipt
from .competition_cohort_order_signer import (
    CohortOrderHistory,
    remember_order_history,
    review_order,
)
from .competition_cohort_orders import recoverable_order_job
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_cohort_request_admission import CohortRequestWindowAuthority
from .competition_cohort_service_grant import (
    ServiceMinerGrant,
    review_service_request_current,
    verify_service_grant,
    verify_service_parent,
)
from .competition_origin import public_https_origin
from .competition_round_journal import RoundJournal
from .concurrency import run_owned_thread, wait_for_owned
from .miner_admission import MinerAdmissionError, ProofBackedMinerWindowAuthority
from .open_competition import (
    CompetitionPolicy,
    Hotkey,
    digest,
    identity,
    sign_object,
    verify_signature,
)
from .policy import SINGLE_EVALUATOR_TRANSPORT_SCHEMA, ScoringPolicy, scoring_policy_hash
from .protocol import (
    Hex32,
    TranslationRequest,
    canonical_json_bytes,
    request_digest,
)
from .validator_plans import VerifiedFinalizedAnnouncementPort

MAX_COHORT_GRANT_BYTES = 16 * 1024**2
_CAPACITY_ERRORS = frozenset(
    {
        "round journal capacity exhausted",
        "round journal record capacity exhausted",
        "cohort miner grant capacity exhausted",
    }
)


class CohortMinerConfig(CohortIntakeConfig):
    schema_: Literal["umi-cohort-miner-config/1"] = Field(alias="schema")
    policy_sha256: Hex32
    transport_policy_sha256: Hex32
    miner_hotkey: Hotkey
    model_revision: Hex32
    serving_origin: Annotated[str, Field(min_length=1, max_length=4096)]
    maximum_grants: Annotated[int, Field(ge=1, le=65536)] = 4096
    maximum_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)] = 1024**3
    read_timeout_seconds: Annotated[int, Field(ge=1, le=3600)] = 2400


class CohortServiceMinerConfig(CohortMinerConfig):
    schema_: Literal["umi-cohort-service-miner-config/1"] = Field(alias="schema")
    service_terms_sha256: Hex32


_MINER_CONFIG = TypeAdapter(
    Annotated[CohortMinerConfig | CohortServiceMinerConfig, Field(discriminator="schema_")]
)


class CohortMinerAuthorizationAuthority:
    """The host owns the authenticated current history source and finality port."""

    def __init__(
        self,
        config: CohortMinerConfig,
        policy: CompetitionPolicy,
        transport: ScoringPolicy,
        finalized_blocks: VerifiedFinalizedAnnouncementPort,
        history: Callable[[str], Awaitable[CohortOrderHistory]],
    ):
        self.config = _MINER_CONFIG.validate_json(canonical_json_bytes(config))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self.transport = ScoringPolicy.model_validate_json(canonical_json_bytes(transport))
        if self.config.policy_sha256 != digest(
            self.policy
        ) or self.config.transport_policy_sha256 != scoring_policy_hash(self.transport):
            raise ValueError("cohort miner policy bindings differ")
        public_https_origin(self.config.serving_origin)
        self.finalized_blocks, self.history = finalized_blocks, history
        self.legacy = ProofBackedMinerWindowAuthority(
            policy=self.transport, finalized_blocks=finalized_blocks
        )
        self.cohorts = {c.cohort_sha256: c.authority_sha256 for c in self.config.cohorts}
        self.serial = asyncio.Lock()
        self.journal = RoundJournal(
            Path(self.config.directory),
            self.config.model_dump(
                mode="json",
                by_alias=True,
                exclude={"maximum_grants", "maximum_bytes", "read_timeout_seconds"},
            ),
            maximum_rounds=self.config.maximum_grants,
            maximum_bytes=self.config.maximum_bytes,
            maximum_record_bytes=MAX_COHORT_GRANT_BYTES,
        )
        with self.journal.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS order_heads "
                "(cohort TEXT PRIMARY KEY, history TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS miner_grant_requests "
                "(request_key TEXT PRIMARY KEY, grant_id TEXT NOT NULL)"
            )

    @property
    def policy_sha256(self):
        return self.config.policy_sha256

    @property
    def publication_sha256(self):
        # Multiple immutable grants; no single publication is implied.
        return None

    @property
    def allowed_validator_hotkeys(self):
        if self.transport.schema_ == SINGLE_EVALUATOR_TRANSPORT_SCHEMA:
            return frozenset(e.validator_hotkey for e in self.transport.validator_registry)
        return frozenset(e.hotkey for e in self.policy.evaluators)

    def validate_runtime(self, **runtime):
        validate_runtime_binding(
            policy=self.policy,
            legacy_policy=self.transport,
            expected_miner=self.config.miner_hotkey,
            expected_revision=self.config.model_revision,
            required_validators=self.allowed_validator_hotkeys,
            **runtime,
        )

    def _validate_one(self, grant, validator_hotkey):
        raw = canonical_json_bytes(grant)
        if len(raw) > MAX_COHORT_GRANT_BYTES:
            raise ValueError("cohort miner grant exceeds its byte bound")
        grant = parse_miner_grant(raw)
        if isinstance(grant, ServiceMinerGrant):
            if not isinstance(self.config, CohortServiceMinerConfig):
                raise ValueError("service grants require explicit miner terms configuration")
            grant = verify_service_grant(grant, self.policy, self.transport)
            body = grant.body
            sub = body.assignment.admission.submission.submission
            if (
                identity(validator_hotkey) != identity(body.evaluator_hotkey)
                or identity(sub.hotkey) != identity(self.config.miner_hotkey)
                or sub.model_revision != self.config.model_revision
                or public_https_origin(sub.endpoint_url)
                != public_https_origin(self.config.serving_origin)
                or body.assignment.catalog.catalog.service_terms_sha256
                != self.config.service_terms_sha256
                or self.cohorts.get(body.assignment.round.cohort_sha256)
                != body.assignment.catalog.catalog.authority_sha256
            ):
                raise ValueError("service grant differs from miner configuration")
            return grant
        assignment, attempt = grant.assignment, grant.attempt
        order = assignment.certificate.order
        verify_recovery_quorum(order, assignment.certificate.signatures, self.policy)
        if any(
            identity(s.hotkey) == identity(order.submission.submission.hotkey)
            for s in assignment.certificate.signatures
        ):
            raise ValueError("miner cannot authorize its own assignment")
        delivery = check_delivery_receipt(assignment.certificate, assignment.delivery)
        evaluator = delivery.receipt.evaluator_hotkey
        if identity(validator_hotkey) != identity(evaluator):
            raise ValueError("cohort grant caller is not its assigned evaluator")
        job = recoverable_order_job(order, evaluator)
        if isinstance(grant, CohortCaseMinerGrant):
            validate_case_attempt(attempt, self.policy, self.transport)
        else:
            validate_recoverable_endpoint_transport(attempt, self.policy, self.transport)
        sub = job.submission.submission
        if (
            attempt.order.job != job
            or job.mode != "endpoint_incumbent"
            or identity(sub.hotkey) != identity(self.config.miner_hotkey)
            or sub.model_revision != self.config.model_revision
            or public_https_origin(sub.endpoint_url)
            != public_https_origin(self.config.serving_origin)
        ):
            raise ValueError("cohort grant differs from miner assignment or serving configuration")
        if isinstance(grant, CohortMinerGrant) and attempt.order.attempt_number != 1:
            raise ValueError("replacement attempt requires certified remote reconciliation")
        if job.round.cohort_sha256 not in self.cohorts:
            raise ValueError("cohort grant has no configured authority")
        return grant

    def _validate(self, grant, validator_hotkey):
        grant = self._validate_one(grant, validator_hotkey)
        if isinstance(grant, ServiceMinerGrant):
            current, seen = grant, set()
            while current.body.attempt_number > 1:
                slot = current.body.parent_grant_slot
                if slot in seen:
                    raise ValueError("service replacement lineage is cyclic")
                seen.add(slot)
                raw = self.journal.get("miner_grant", slot)
                if raw is None:
                    raise ValueError("service replacement parent grant is not retained")
                parent = self._validate_one(
                    parse_miner_grant(canonical_json_bytes(raw)), validator_hotkey
                )
                if not isinstance(parent, ServiceMinerGrant) or grant_slot(parent) != slot:
                    raise ValueError("service replacement parent changed its archive key")
                verify_service_parent(current, parent)
                current = parent
            return grant
        current, seen = grant, set()
        # Parent records remain separate immutable objects. Replay iteratively
        # so repeated outages cannot exhaust Python recursion or grow the wire
        # request by embedding its entire history.
        while isinstance(current, CohortCaseMinerGrant):
            order = current.attempt.order
            if order.parent_grant_slot in seen:
                raise ValueError("cohort replacement lineage is cyclic")
            seen.add(order.parent_grant_slot)
            raw = self.journal.get("miner_grant", order.parent_grant_slot)
            if raw is None:
                raise ValueError("cohort replacement parent grant is not retained")
            parent = self._validate_one(
                parse_miner_grant(canonical_json_bytes(raw)), validator_hotkey
            )
            if grant_slot(parent) != order.parent_grant_slot:
                raise ValueError("cohort replacement parent changed its archive key")
            verify_replacement_parent(current, parent)
            current = parent
        return grant

    async def _current(self, grant):
        timeout = self.config.read_timeout_seconds
        cohort = (
            grant.body.assignment.round.cohort_sha256
            if isinstance(grant, ServiceMinerGrant)
            else grant.attempt.order.job.round.cohort_sha256
        )
        try:
            source = await wait_for_owned(self.history(cohort), timeout=timeout)
            head = await wait_for_owned(
                self.finalized_blocks.finalized_head_height(), timeout=timeout
            )
        except RuntimeError as error:
            raise OSError("cohort miner authority source unavailable") from error
        if type(head) is not int or head < 0:
            raise ValueError("cohort miner finalized head is invalid")
        await run_owned_thread(
            remember_order_history, self.journal, self.cohorts, self.policy, source, head
        )
        if isinstance(grant, ServiceMinerGrant):
            await run_owned_thread(
                review_service_request_current, grant.body, self.policy, source, head
            )
        else:
            await run_owned_thread(
                review_order,
                grant.assignment.certificate.order,
                grant.assignment.participant,
                source,
                self.policy,
                head,
            )
        try:
            current = await wait_for_owned(self.history(cohort), timeout=timeout)
        except RuntimeError as error:
            raise OSError("cohort miner authority source unavailable") from error
        if current != source:
            # Persist a valid closure or revocation so a restart cannot forget it.
            await run_owned_thread(
                remember_order_history, self.journal, self.cohorts, self.policy, current, head
            )
            raise OSError("cohort authority changed during miner admission")
        return source, head

    def _receipt(self, grant):
        raw = self.journal.get("miner_grant_receipt", digest(grant))
        if raw is None:
            return None
        value = SignedCohortMinerGrantReceipt.model_validate_json(canonical_json_bytes(raw))
        body = self.journal.get("miner_grant_receipt_intent", digest(grant))
        if (
            canonical_json_bytes(value.receipt) != canonical_json_bytes(body)
            or value.receipt.grant_sha256 != digest(grant)
            or identity(value.receipt.miner_hotkey) != identity(self.config.miner_hotkey)
            or identity(value.signature.hotkey) != identity(self.config.miner_hotkey)
        ):
            raise ValueError("retained cohort grant receipt changed its binding")
        verify_signature(value.receipt, value.signature)
        return value

    async def accept(self, grant, *, validator_hotkey: str, wallet: Any):
        try:
            return await self._accept(grant, validator_hotkey=validator_hotkey, wallet=wallet)
        except ValueError as error:
            if str(error) in _CAPACITY_ERRORS:
                raise OSError("cohort miner capacity unavailable") from error
            raise

    async def _accept(self, grant, *, validator_hotkey: str, wallet: Any):
        """Commit exact grant and acknowledgement intent before signing a receipt."""
        grant = await run_owned_thread(self._validate, grant, validator_hotkey)
        key, slot = digest(grant), grant_slot(grant)
        async with self.serial:
            with self.journal.locked():
                old = self.journal.get("miner_grant", slot)
                if old is not None:
                    if canonical_json_bytes(old) != canonical_json_bytes(grant):
                        raise ValueError("cohort grant slot already has another request selection")
                    receipt = self._receipt(grant)
                    if receipt is not None:
                        return receipt
                    body = CohortMinerGrantReceipt.model_validate_json(
                        canonical_json_bytes(self.journal.get("miner_grant_receipt_intent", key))
                    )
                else:
                    _, block = await self._current(grant)
                    body = CohortMinerGrantReceipt(
                        schema="umi-cohort-miner-grant-receipt/1",
                        grant_sha256=key,
                        miner_hotkey=self.config.miner_hotkey,
                        observed_block=block,
                    )

                    def retain():
                        def index(db):
                            count = db.execute(
                                "SELECT COUNT(*) FROM records WHERE kind='miner_grant'"
                            ).fetchone()[0]
                            if count > self.config.maximum_grants:
                                raise ValueError("cohort miner grant capacity exhausted")
                            for request in grant_requests(grant):
                                request_key = self._request_key(request, validator_hotkey)
                                old_key = db.execute(
                                    "SELECT grant_id FROM miner_grant_requests WHERE request_key=?",
                                    (request_key,),
                                ).fetchone()
                                if old_key is not None and old_key != (slot,):
                                    raise ValueError(
                                        "cohort request is already bound to another grant"
                                    )
                                db.execute(
                                    "INSERT OR IGNORE INTO miner_grant_requests VALUES (?,?)",
                                    (request_key, slot),
                                )

                        self.journal.put_many(
                            (
                                ("miner_grant", slot, grant),
                                ("miner_grant_receipt_intent", key, body),
                            ),
                            index=index,
                        )

                    await run_owned_thread(retain)

                async def sign_and_commit():
                    signature = await run_owned_thread(sign_object, body, wallet)
                    if identity(signature.hotkey) != identity(self.config.miner_hotkey):
                        raise ValueError("cohort grant receipt signer differs from miner")
                    verify_signature(body, signature)
                    result = SignedCohortMinerGrantReceipt(receipt=body, signature=signature)
                    await run_owned_thread(self.journal.put, "miner_grant_receipt", key, result)
                    return result

                return await sign_and_commit()

    @staticmethod
    def _request_key(request, validator_hotkey):
        return digest(
            {
                "schema": "umi-cohort-miner-request-key/1",
                "evaluator": identity(validator_hotkey),
                "request": request_digest(request),
            }
        )

    def _lookup(self, request, validator_hotkey):
        with self.journal.transaction() as db:
            row = db.execute(
                "SELECT grant_id FROM miner_grant_requests WHERE request_key=?",
                (self._request_key(request, validator_hotkey),),
            ).fetchone()
            if row is None:
                raise MinerAdmissionError("cohort_request_not_authorized")
            raw = self.journal.get("miner_grant", row[0], db=db)
        grant = self._validate(parse_miner_grant(canonical_json_bytes(raw)), validator_hotkey)
        if (
            grant_slot(grant) != row[0]
            or sum(
                canonical_json_bytes(r) == canonical_json_bytes(request)
                for r in grant_requests(grant)
            )
            != 1
        ):
            raise ValueError("cohort request lookup differs from retained grant")
        return grant

    async def authorize(self, request: TranslationRequest, *, validator_hotkey: str):
        request = TranslationRequest.model_validate_json(canonical_json_bytes(request))
        try:
            async with self.serial:
                with self.journal.locked():
                    grant = await run_owned_thread(self._lookup, request, validator_hotkey)
                    before, _ = await self._current(grant)
                    if isinstance(grant, ServiceMinerGrant):
                        window_authority = CohortRequestWindowAuthority(
                            policy=self.transport,
                            finalized_blocks=self.finalized_blocks,
                            legacy_authorize=self.legacy.authorize,
                            job=grant.body.assignment,
                            attempt_number=grant.body.attempt_number,
                        )
                    else:
                        window_authority = CohortRequestWindowAuthority(
                            policy=self.transport,
                            finalized_blocks=self.finalized_blocks,
                            legacy_authorize=self.legacy.authorize,
                            job=grant.attempt.order.job,
                            attempt_number=grant.attempt.order.attempt_number,
                        )
                    admission = await wait_for_owned(
                        window_authority.authorize(request),
                        timeout=self.config.read_timeout_seconds,
                    )
                    after, head = await self._current(grant)
                    if before != after:
                        raise OSError("cohort authority changed during request validation")
                    if head < admission.observed_finalized_height:
                        raise ValueError("cohort finalized head regressed")
                    if head > request.deadline_block:
                        raise MinerAdmissionError("request_block_deadline_elapsed")
                    return admission
        except MinerAdmissionError:
            raise
        except (OSError, asyncio.TimeoutError, TimeoutError) as error:
            raise MinerAdmissionError("cohort_authority_unavailable", retryable=True) from error
        except ValueError as error:
            if str(error) in _CAPACITY_ERRORS:
                raise MinerAdmissionError("cohort_capacity_unavailable", retryable=True) from error
            raise MinerAdmissionError("cohort_authority_invalid") from error

    async def retirement_grant(self, request: TranslationRequest, *, validator_hotkey: str):
        """Recover exact original authority for fencing only, including after closure."""
        async with self.serial:
            with self.journal.locked():
                return await run_owned_thread(self._lookup, request, validator_hotkey)
