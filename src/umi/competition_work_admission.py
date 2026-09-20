"""Private full-cohort capacity admission before a new work endorsement.

Native journals own their credit and consumption. This journal records the
immutable plan and completion receipts across their separate transactions.
Partial commits remain pending and an exact retry can complete admission.
Nothing here signs, publishes work, claims execution or releases obligations.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .competition_authorization import EndpointAuthorizationPublication
from .competition_evaluator_budget import (
    OrderBudget,
    json_size,
    object_bound,
    order_budget_for_validated_plan,
    signature_bound,
)
from .competition_evaluator_capacity import order_binding
from .competition_evaluator_orders import EvaluationOrder
from .competition_review_history import ReviewReservation
from .competition_round_journal import MAX_BYTES, RecordReservation, RoundJournal
from .open_competition import SignedSubmission, digest, identity
from .protocol import canonical_json_bytes, sha256_hex

if TYPE_CHECKING:
    from .competition_evaluator import ContinuousEvaluator
    from .competition_work_plans import WorkPlan


def _slot(plan: WorkPlan, submission: SignedSubmission, kind: str) -> str:
    round_ = plan.cutoff.publication.round
    return digest(
        {
            "policy": round_.policy_sha256,
            "sequence": round_.sequence,
            "submission": digest(submission.submission),
            "kind": kind,
        }
    )


def _statement_bytes(plan_bytes: int, body_bytes: int) -> int:
    size = object_bound(
        {
            "schema": json_size("umi-work-statement/1"),
            "plan": plan_bytes,
            "body": body_bytes,
            "chain_submission_authorized": json_size(False),
        }
    )
    if size > MAX_BYTES:
        raise ValueError("reserved work statement exceeds its byte bound")
    return size


class WorkAdmission:
    def __init__(self, worker: ContinuousEvaluator, signing_journal: RoundJournal) -> None:
        self.worker, self.signing = worker, signing_journal
        self.journal = RoundJournal(
            Path(worker.config.state_directory) / "work-admission",
            {
                "schema": "umi-private-work-admission/1",
                "policy": digest(worker.policy),
                "evaluator": identity(worker.config.evaluator_hotkey),
            },
            maximum_rounds=worker.config.maximum_orders,
            maximum_bytes=worker.config.maximum_journal_bytes,
        )
        # One pure derivation, owned by this signer. Never cache native receipts
        # or mutable models; every use still checks the retained manifest and
        # all native journals. A restart or changed input derives from scratch.
        self._completed_derivation: tuple[str, bytes] | None = None

    def _paths(self) -> dict[str, str | None]:
        worker = self.worker
        return {
            "signing": str(self.signing.path.resolve()),
            "evaluator": str(worker.journal.path.resolve()),
            "execution": str(worker.executions.path.resolve()),
            "dispatch": None if worker.dispatch is None else str(worker.dispatch.path.resolve()),
            "review": None
            if worker.review_store is None
            else str(worker.review_store.path.resolve()),
        }

    def _derivation_key(
        self, plan: WorkPlan, publications: tuple[EndpointAuthorizationPublication, ...]
    ) -> str:
        return digest(
            {
                "plan": digest(plan),
                "publications": [digest(p) for p in publications],
                "policy": digest(self.worker.policy),
                "legacy": digest(self.worker.legacy),
                "config": digest(self.worker.config),
                "paths": self._paths(),
            }
        )

    def _remember_completed(
        self,
        key: str,
        plan: WorkPlan,
        publications: tuple[EndpointAuthorizationPublication, ...],
        manifest: dict[str, Any],
    ) -> None:
        if self._completed_derivation is not None and self._completed_derivation[0] == key:
            return
        if key == self._derivation_key(plan, publications):
            self._completed_derivation = key, canonical_json_bytes(manifest)

    def publications(self, plan: WorkPlan) -> tuple[EndpointAuthorizationPublication, ...]:
        """Recover only the original retained unsigned cohort, never retime it."""
        manifest = self.journal.get("manifest", digest(plan))
        if manifest is None:
            if any(s.submission.track == "endpoint" for s in plan.submissions):
                raise ValueError("whole-round admission requires endpoint assignments first")
            return ()
        if manifest.get("plan_sha256") != digest(plan):
            raise ValueError("work admission plan binding changed")
        if manifest["publications"] and not any(
            self.signing.get("vote", _slot(plan, sub, "umi-endpoint-authorization-publication/1"))
            is not None
            for sub in plan.submissions
            if sub.submission.track == "endpoint"
        ):
            # A partial private reservation cannot authorize model-first recovery
            # after the original endpoint issue window has elapsed. Let the client
            # retry the endpoint statement, which rechecks that original window.
            raise ValueError("whole-round admission requires its first endpoint endorsement")
        result: list[EndpointAuthorizationPublication] = []
        for key in manifest["publications"]:
            raw = self.journal.get("publication", key)
            if raw is None or digest(raw) != key:
                raise ValueError("work admission lost its original publication")
            result.append(
                EndpointAuthorizationPublication.model_validate_json(canonical_json_bytes(raw))
            )
        return tuple(result)

    def _derive(
        self,
        plan: WorkPlan,
        publications: tuple[EndpointAuthorizationPublication, ...],
    ) -> tuple[dict[str, Any], tuple[OrderBudget, ...], tuple[RecordReservation, ...]]:
        worker = self.worker
        plan_id, plan_bytes = digest(plan), json_size(plan)
        by_submission: dict[str, EndpointAuthorizationPublication] = {}
        for publication in publications:
            if len(publication.submissions) != 1:
                raise ValueError("work admission needs single-submission publications")
            sub_id = digest(publication.submissions[0].submission)
            if sub_id in by_submission:
                raise ValueError("work admission repeats an endpoint publication")
            by_submission[sub_id] = publication
        expected = {
            digest(s.submission) for s in plan.submissions if s.submission.track == "endpoint"
        }
        if set(by_submission) != expected:
            raise ValueError("work admission omits or adds endpoint assignments")
        budgets: list[OrderBudget] = []
        records: list[RecordReservation] = []
        vote_bytes = object_bound(
            {
                "statement_sha256": json_size("0" * 64),
                "signature": signature_bound(),
            }
        )
        for sub in plan.submissions:
            body = by_submission.get(digest(sub.submission))
            budget = order_budget_for_validated_plan(
                plan=plan,
                submission=sub,
                policy=worker.policy,
                evaluator_hotkey=worker.config.evaluator_hotkey,
                endpoint_publication_body=body,
                legacy_policy=worker.legacy,
                retain_settlement_review=worker.review_store is not None,
            )
            budgets.append(budget)
            slot = _slot(plan, sub, "umi-evaluation-order/1")
            records.extend(
                (
                    RecordReservation(
                        "intent", slot, _statement_bytes(plan_bytes, budget.order_body_bytes)
                    ),
                    RecordReservation("vote", slot, vote_bytes),
                )
            )
            if body is not None:
                slot = _slot(plan, sub, body.schema_)
                raw = canonical_json_bytes(
                    {
                        "schema": "umi-work-statement/1",
                        "plan": plan.model_dump(mode="json", by_alias=True),
                        "body": body.model_dump(mode="json", by_alias=True),
                        "chain_submission_authorized": False,
                    }
                )
                records.extend(
                    (
                        RecordReservation(
                            "intent",
                            slot,
                            _statement_bytes(plan_bytes, json_size(body)),
                            sha256_hex(raw),
                        ),
                        RecordReservation("vote", slot, vote_bytes),
                    )
                )
        suite_value = {"plan": plan_id}
        records.append(
            RecordReservation(
                "suite",
                plan.cutoff.publication.round.suite_sha256,
                json_size(suite_value),
                sha256_hex(canonical_json_bytes(suite_value)),
            )
        )
        manifest = {
            "schema": "umi-private-work-admission/1",
            "plan_sha256": plan_id,
            "evaluator": identity(worker.config.evaluator_hotkey),
            "publications": sorted(digest(p) for p in publications),
            "signing_records": [asdict(r) for r in sorted(records, key=lambda r: (r.kind, r.key))],
            "orders": [asdict(b.reservation) for b in budgets],
            "jobs": [sha256_hex(canonical_json_bytes(b.job)) for b in budgets],
            "review_reservations": []
            if worker.review_store is None
            else [
                {
                    "round_sha256": digest(plan.cutoff.publication.round),
                    "submission_sha256": digest(sub.submission),
                    "maximum_certificate_bytes": budget.maximum_certificate_bytes,
                    "maximum_independent_bytes": budget.maximum_independent_bytes,
                    "maximum_void_bytes": budget.maximum_void_bytes,
                }
                for sub, budget in zip(plan.submissions, budgets, strict=True)
            ],
            "paths": self._paths(),
        }
        return json.loads(canonical_json_bytes(manifest)), tuple(budgets), tuple(records)

    def _native_receipts(self, plan_id: str, *, endpoints: bool) -> dict[str, str]:
        worker = self.worker
        values = {
            "signing": self.signing.reservation(plan_id),
            "execution": worker.executions.reservation(plan_id),
            "evaluator": worker.journal.reservation(plan_id),
        }
        if worker.review_store is not None:
            values["review"] = worker.review_store.reservation(plan_id)
        if endpoints:
            values["dispatch"] = worker.dispatch.reservation(
                plan_id, evaluator_hotkey=worker.config.evaluator_hotkey
            )
        if any(v is None for v in values.values()):
            raise ValueError("work admission lacks a native reservation receipt")
        return {key: digest(value) for key, value in values.items()}

    def reserve(
        self,
        plan: WorkPlan,
        publications: tuple[EndpointAuthorizationPublication, ...],
        statement_body: EndpointAuthorizationPublication | EvaluationOrder,
    ) -> dict[str, Any]:
        """Caller validates the plan and holds its signing lease throughout."""
        plan_id = digest(plan)
        key = self._derivation_key(plan, publications)
        completed = self.journal.get("complete", plan_id)
        cached = self._completed_derivation
        budgets: tuple[OrderBudget, ...] = ()
        records: tuple[RecordReservation, ...] = ()
        if completed is not None and cached is not None and cached[0] == key:
            manifest = json.loads(cached[1])
        else:
            self._completed_derivation = None
            manifest, budgets, records = self._derive(plan, publications)
        if isinstance(statement_body, EvaluationOrder):
            if order_binding(statement_body) not in {b["order_sha256"] for b in manifest["orders"]}:
                raise ValueError("work order differs from admitted whole-round assignments")
        elif digest(statement_body) not in manifest["publications"]:
            raise ValueError("work authorization is absent from admitted assignments")
        retained = self.journal.get("manifest", plan_id)
        if retained is not None and retained != manifest:
            raise ValueError("whole-round admission manifest changed")
        if completed is not None:
            if retained is None:
                raise ValueError("work admission completion lost its manifest")
            receipts = self._native_receipts(plan_id, endpoints=bool(publications))
            if completed != {"manifest_sha256": digest(manifest), "receipts": receipts}:
                raise ValueError("work admission completion receipt changed")
            self._remember_completed(key, plan, publications, manifest)
            return completed
        # Reserve the completion row before committing any downstream promise.
        # It contains only a fixed set of native receipt digests, not their bodies.
        completion_bytes = json_size(
            {
                "manifest_sha256": "0" * 64,
                "receipts": {
                    key: "0" * 64
                    for key in ("signing", "execution", "evaluator", "dispatch", "review")
                },
            }
        )
        values = [("manifest", plan_id, manifest)] + [
            ("publication", digest(p), p) for p in publications
        ]
        self.journal.reserve_records(
            plan_id,
            [
                *(
                    RecordReservation(
                        kind, key, json_size(value), sha256_hex(canonical_json_bytes(value))
                    )
                    for kind, key, value in values
                ),
                RecordReservation("complete", plan_id, completion_bytes),
            ],
        )
        self.journal.put_many(values)
        self.signing.reserve_records(plan_id, records)
        self.worker.executions.reserve_jobs(plan_id, (b.job for b in budgets))
        self.worker.journal.reserve_orders(plan_id, (b.reservation for b in budgets))
        if self.worker.review_store is not None:
            self.worker.review_store.reserve_evidence(
                plan_id, (ReviewReservation(**spec) for spec in manifest["review_reservations"])
            )
        receipts = self._native_receipts(plan_id, endpoints=bool(publications))
        completed = {"manifest_sha256": digest(manifest), "receipts": receipts}
        self.journal.put("complete", plan_id, completed)
        self._remember_completed(key, plan, publications, manifest)
        return completed

    def verify(self, plan: WorkPlan) -> dict[str, Any]:
        """Recheck every native promise after the caller's last awaited proof."""
        plan_id = digest(plan)
        manifest = self.journal.get("manifest", plan_id)
        complete = self.journal.get("complete", plan_id)
        if manifest is None or complete is None:
            raise ValueError("whole-round admission is incomplete")
        if complete != {
            "manifest_sha256": digest(manifest),
            "receipts": self._native_receipts(plan_id, endpoints=bool(manifest["publications"])),
        }:
            raise ValueError("whole-round native admission receipt changed")
        return complete
