"""Bounded retained-state preflight for a later explicit miner revision migration.

A locally retired inventory is not a distributed cutover fence. This module
never signs, changes a journal binding, starts/stops a service or authorizes a
four-cohort replacement. Live authority and service qualification remain outside.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_miner import MAX_COHORT_GRANT_BYTES, validate_miner_grant
from .competition_cohort_miner_case import (
    CohortCaseMinerGrant,
    grant_requests,
    grant_slot,
    parse_miner_grant,
)
from .competition_cohort_miner_contracts import (
    CohortMinerGrantReceipt,
    SignedCohortMinerGrantReceipt,
)
from .competition_cohort_miner_startup import CohortMinerStartupConfig
from .competition_cohort_service_grant import ServiceMinerGrant
from .competition_cohort_service_work import SignedServiceWorkClaim, verify_service_claim
from .competition_miner_transition_io import (
    MAX_CHECKPOINT_BYTES,
    PreflightCheckpoints,
    TransitionPreflightRefused,
    bounded_read,
    directory_inventory,
    file_identity,
    stopped_snapshots,
)
from .competition_verification_rules import runtime_identity
from .competition_work_progress import WorkProgress
from .config import Limits
from .crypto import verify_response_signature
from .endpoint_retirement import SignedEndpointRetirementReceipt, verify_retirement_receipt
from .miner import _parser
from .miner_resources import MinerAssignmentBinding
from .open_competition import CompetitionPolicy, digest, identity, verify_signature
from .policy import ScoringPolicy, scoring_policy_hash
from .private_files import Directory
from .protocol import (
    Hex32,
    ResponseEnvelope,
    StrictProtocolModel,
    TranslationRequest,
    canonical_json_bytes,
    request_digest,
)


class TransitionEnrollmentDirectory(StrictProtocolModel):
    cohort_sha256: Hex32
    directory: Directory


class MinerRevisionPreflightRequest(StrictProtocolModel):
    schema_: Literal["umi-miner-revision-preflight-request/1"] = Field(alias="schema")
    original_argv: Annotated[tuple[str, ...], Field(min_length=1, max_length=512)]
    proposed_argv: Annotated[tuple[str, ...], Field(min_length=1, max_length=512)]
    service_uid: Annotated[int, Field(ge=0)]
    launch_kind: Literal["systemd", "container"]
    enrollments: Annotated[tuple[TransitionEnrollmentDirectory, ...], Field(max_length=512)]
    verification_directory: Directory
    maximum_inventory_items: Annotated[int, Field(ge=1, le=1048576)] = 65536
    maximum_summary_bytes: Annotated[int, Field(ge=1024, le=MAX_CHECKPOINT_BYTES)] = (
        MAX_CHECKPOINT_BYTES
    )


TRANSITION_VERIFIER_SEMANTICS = "umi-miner-revision-preflight-verifier/1"


class PreflightProgress(WorkProgress):
    """Observable substage estimates, including explicit cold-start assumptions."""

    def emit(self, state: str) -> None:
        elapsed = max(0.0, time.monotonic() - self.started)
        eta = (
            elapsed * (self.total - self.completed) / self.completed
            if state == "running" and self.completed and elapsed >= 1
            else None
        )
        remaining = max(0, self.total - self.completed)
        logging.getLogger("umi.competition.progress").info(
            json.dumps(
                {
                    "schema": "umi-miner-revision-preflight-progress/1",
                    "stage": self.stage,
                    "state": state,
                    "completed": self.completed,
                    "total": self.total,
                    "unit": self.unit,
                    "percent": 100.0
                    if state == "completed"
                    else min(99.9, 100 * self.completed / self.total)
                    if self.total
                    else 0.0,
                    "elapsed_seconds": round(elapsed, 3),
                    "eta_seconds": 0.0 if state == "completed" else eta,
                    "eta_planning_range_seconds": None
                    if eta is not None or state == "completed"
                    else [remaining * 0.01, remaining * 30.0],
                    "eta_basis": "completed"
                    if state == "completed"
                    else "measured_work_rate"
                    if eta is not None
                    else "planning_assumption",
                    "eta_assumption": "0.01-30 seconds/item until measured samples",
                    "scope": "current_preflight_substage_only",
                    "retrying": False,
                    "stalled": state == "interrupted",
                    "runtime_migration_authorized": False,
                },
                separators=(",", ":"),
            )
        )
        self.last_emitted = time.monotonic()


def _key(*parts) -> str:
    return hashlib.sha256(canonical_json_bytes(parts)).hexdigest()


def _arguments(command: tuple[str, ...]):
    """Recognize both real console-script argv and explicit module invocation."""
    if Path(command[0]).name == "umi-miner":
        arguments = command[1:]
    elif len(command) >= 2 and Path(command[1]).name == "umi-miner":
        arguments = command[2:]
    elif command[1:3] == ("-m", "umi.miner"):
        arguments = command[3:]
    else:
        raise TransitionPreflightRefused("unsupported_miner_entrypoint")
    if not Path(command[0]).is_absolute():
        raise TransitionPreflightRefused("interpreter_requires_absolute_selection")
    repeated = {"--video-origin", "--competition-predecessor-policy"}
    options = [part.split("=", 1)[0] for part in arguments if part.startswith("--")]
    if any(options.count(option) > 1 for option in set(options) - repeated):
        raise TransitionPreflightRefused("ambiguous_repeated_launch_option")
    try:
        return _parser().parse_args(arguments)
    except SystemExit as error:
        raise TransitionPreflightRefused("unsupported_miner_arguments") from error


def _read_model(path: str, model, maximum: int = MAX_COHORT_GRANT_BYTES):
    raw = bounded_read(Path(path), maximum, private=False)
    value = model.model_validate_json(raw)
    if canonical_json_bytes(value) != raw:
        raise TransitionPreflightRefused("noncanonical_input: " + path)
    return value


def _inputs(request: MinerRevisionPreflightRequest):
    if request.service_uid != os.getuid():
        raise TransitionPreflightRefused("run_preflight_as_original_service_account")
    old, new = _arguments(request.original_argv), _arguments(request.proposed_argv)
    changed = {name for name in vars(old) if getattr(old, name) != getattr(new, name)}
    if changed - {"model_revision", "competition_cohort_config"}:
        raise TransitionPreflightRefused(
            "launch_changes_state_wallet_policy_or_execution: " + ",".join(sorted(changed))
        )
    if (
        not old.competition_cohort_config
        or not new.competition_cohort_config
        or not old.competition_policy
    ):
        raise TransitionPreflightRefused("explicit_cohort_startup_and_policy_required")
    if not old.model_revision or old.model_revision == new.model_revision:
        raise TransitionPreflightRefused("transition_requires_distinct_explicit_revisions")
    if old.competition_predecessor_policy:
        raise TransitionPreflightRefused("predecessor_policy_transition_not_yet_qualified")
    input_paths = {
        Path(value)
        for value in (
            old.competition_cohort_config,
            new.competition_cohort_config,
            old.competition_policy,
            old.policy,
        )
    }
    input_snapshots = {str(path): file_identity(path, private=False) for path in input_paths}
    original = _read_model(old.competition_cohort_config, CohortMinerStartupConfig)
    proposed = _read_model(new.competition_cohort_config, CohortMinerStartupConfig)
    policy = _read_model(old.competition_policy, CompetitionPolicy)
    transport = _read_model(old.policy, ScoringPolicy)
    for arguments, startup in ((old, original), (new, proposed)):
        startup.check(
            policy=policy,
            transport=transport,
            miner_hotkey=startup.authority.miner_hotkey,
            model_revision=arguments.model_revision,
            serving_origin=arguments.serving_origin,
            state_files=[arguments.nonce_db, arguments.assignment_db, arguments.finality_state],
        )
    original_body, proposed_body = (
        original.model_dump(mode="json", by_alias=True),
        proposed.model_dump(mode="json", by_alias=True),
    )
    proposed_body["authority"]["model_revision"] = original.authority.model_revision
    if proposed_body != original_body:
        raise TransitionPreflightRefused("proposed_startup_changes_original_roster_or_binding")
    limits = Limits.from_policy(
        transport,
        competition_policy=policy,
        inference_timeout_seconds=old.inference_timeout,
        backend_lifecycle_timeout_seconds=old.backend_lifecycle_timeout,
        inference_admission_timeout_seconds=old.inference_admission_timeout,
        request_body_timeout_seconds=old.request_body_timeout,
        maximum_inference_concurrency=old.max_inference_concurrency or len(policy.evaluators),
    )
    return old, original, proposed, policy, transport, limits, input_snapshots


def _record(db, kind: str, key: str, maximum: int = MAX_COHORT_GRANT_BYTES):
    row = db.execute(
        "SELECT LENGTH(body) AS size FROM records WHERE kind=? AND id=?", (kind, key)
    ).fetchone()
    if row is None:
        return None
    if not 0 < row["size"] <= maximum:
        raise TransitionPreflightRefused("retained_record_exceeds_native_bound")
    return db.execute("SELECT body FROM records WHERE kind=? AND id=?", (kind, key)).fetchone()[0]


def _canonical(raw: bytes, model):
    value = model.model_validate_json(raw)
    if canonical_json_bytes(value) != raw:
        raise TransitionPreflightRefused("retained_record_noncanonical")
    return value


def _grant_fact(db, slot: str, startup, policy, transport) -> dict:
    raw = _record(db, "miner_grant", slot)
    grant = parse_miner_grant(raw)
    if canonical_json_bytes(grant) != raw or grant_slot(grant) != slot:
        raise TransitionPreflightRefused("grant_slot_or_canonical_bytes_changed")
    if isinstance(grant, ServiceMinerGrant):
        body = grant.body
        validator = body.evaluator_hotkey
        submission = body.assignment.admission.submission.submission
        cohort = body.assignment.round.cohort_sha256
        assignment = body.assignment
        attempt = body.attempt_number
        case_ids = [body.assignment.admission.work_sha256]
        parent_slot, parent_sha256 = body.parent_grant_slot, body.parent_grant_sha256
        parent_decision = (
            None if body.prior_decision is None else body.prior_decision.decision.request_sha256
        )
        parent_retirement = body.prior_retirement
        claim = digest(body.assignment.admission.claim.claim)
        job_sha256 = None
    else:
        body = grant.attempt.order
        validator = body.job.evaluator_hotkey
        submission = body.job.submission.submission
        cohort = body.job.round.cohort_sha256
        assignment = grant.assignment
        attempt = body.attempt_number
        case_ids = (
            [body.case_id]
            if isinstance(grant, CohortCaseMinerGrant)
            else [case.case_id for case in body.job.cases]
        )
        parent_slot = body.parent_grant_slot if isinstance(grant, CohortCaseMinerGrant) else None
        parent_sha256 = (
            body.parent_grant_sha256 if isinstance(grant, CohortCaseMinerGrant) else None
        )
        parent_decision = (
            body.prior_decision.decision.request_sha256
            if isinstance(grant, CohortCaseMinerGrant)
            else None
        )
        parent_retirement = (
            body.prior_retirement if isinstance(grant, CohortCaseMinerGrant) else None
        )
        claim = None
        job_sha256 = digest(body.job)
    validate_miner_grant(
        grant, validator, config=startup.authority, policy=policy, transport=transport
    )
    grant_sha256 = digest(grant)
    intent = _record(db, "miner_grant_receipt_intent", grant_sha256)
    receipt_raw = _record(db, "miner_grant_receipt", grant_sha256)
    if intent is None:
        raise TransitionPreflightRefused("retained_grant_receipt_intent_missing")
    intent_value = _canonical(intent, CohortMinerGrantReceipt)
    if intent_value.grant_sha256 != grant_sha256 or identity(intent_value.miner_hotkey) != identity(
        startup.authority.miner_hotkey
    ):
        raise TransitionPreflightRefused("retained_grant_receipt_intent_binding_changed")
    receipt_pending = receipt_raw is None
    if receipt_raw is not None:
        receipt = _canonical(receipt_raw, SignedCohortMinerGrantReceipt)
        if (
            canonical_json_bytes(receipt.receipt) != intent
            or receipt.receipt.grant_sha256 != grant_sha256
            or identity(receipt.receipt.miner_hotkey) != identity(startup.authority.miner_hotkey)
            or identity(receipt.signature.hotkey) != identity(startup.authority.miner_hotkey)
        ):
            raise TransitionPreflightRefused("retained_grant_receipt_binding_changed")
        verify_signature(receipt.receipt, receipt.signature)
    requests = list(grant_requests(grant))
    if len(requests) != len(case_ids):
        raise TransitionPreflightRefused("grant_request_case_coverage_changed")
    return {
        "slot": slot,
        "grant_sha256": grant_sha256,
        "cohort_sha256": cohort,
        "validator_hotkey": validator,
        "submission_sha256": digest(submission),
        "model_revision": submission.model_revision,
        "assignment_sha256": digest(assignment),
        "job_sha256": job_sha256,
        "kind": "service" if isinstance(grant, ServiceMinerGrant) else "evaluation",
        "attempt": attempt,
        "case_ids": case_ids,
        "parent_slot": parent_slot,
        "parent_sha256": parent_sha256,
        "parent_decision_request_sha256": parent_decision,
        "parent_retirement": None
        if parent_retirement is None
        else parent_retirement.model_dump(mode="json", by_alias=True),
        "requests": [item.model_dump(mode="json", by_alias=True) for item in requests],
        "claim_sha256": claim,
        "receipt_pending": receipt_pending,
    }


def _lineage(facts: dict[str, dict], miner: str) -> None:
    """Replay native parent predicates using only independently verified facts."""
    for child in facts.values():
        slot = child["parent_slot"]
        if slot is None:
            if child["attempt"] != 1:
                raise TransitionPreflightRefused("missing_original_grant_parent")
            continue
        parent = facts.get(slot)
        if (
            parent is None
            or parent["kind"] != child["kind"]
            or parent["grant_sha256"] != child["parent_sha256"]
            or parent["assignment_sha256"] != child["assignment_sha256"]
            or parent["job_sha256"] != child["job_sha256"]
            or identity(parent["validator_hotkey"]) != identity(child["validator_hotkey"])
            or parent["attempt"] + 1 != child["attempt"]
        ):
            raise TransitionPreflightRefused("replacement_parent_binding_changed")
        case = child["case_ids"][0]
        if parent["case_ids"].count(case) != 1:
            raise TransitionPreflightRefused("replacement_parent_case_changed")
        old = TranslationRequest.model_validate(parent["requests"][parent["case_ids"].index(case)])
        new = TranslationRequest.model_validate(child["requests"][0])
        if (
            child["parent_decision_request_sha256"] != request_digest(old)
            or new.issued_block <= old.deadline_block
        ):
            raise TransitionPreflightRefused("replacement_parent_request_or_window_changed")
        verify_retirement_receipt(
            SignedEndpointRetirementReceipt.model_validate(child["parent_retirement"]),
            request=old,
            grant_sha256=parent["grant_sha256"],
            miner_hotkey=miner,
            evaluator_hotkey=parent["validator_hotkey"],
        )
        # Positive, strictly increasing attempts prohibit a finite retained cycle.


def _retirement(db, request: TranslationRequest, fact: dict, miner: str, limits: Limits) -> dict:
    binding = MinerAssignmentBinding.from_request(
        request, validator_hotkey=fact["validator_hotkey"]
    )
    result = {
        "assignment_id": binding.assignment_id,
        "request_sha256": binding.request_digest,
        "grant_sha256": fact["grant_sha256"],
        "cohort_sha256": fact["cohort_sha256"],
        "state": "retirement_missing",
    }
    sizes = db.execute(
        "SELECT LENGTH(receipt_intent),LENGTH(receipt) FROM request_retirements "
        "WHERE assignment_id=?",
        (binding.assignment_id,),
    ).fetchone()
    if sizes is not None and any(
        value is not None and not 0 < value <= MAX_COHORT_GRANT_BYTES for value in sizes
    ):
        raise TransitionPreflightRefused("retirement_receipt_exceeds_native_bound")
    row = db.execute(
        "SELECT * FROM request_retirements WHERE assignment_id=?", (binding.assignment_id,)
    ).fetchone()
    if row is None:
        return result
    if (
        row["request_digest"] != binding.request_digest
        or row["validator_account_hex"] != binding.validator_account_hex
        or row["grant_sha256"] != fact["grant_sha256"]
    ):
        raise TransitionPreflightRefused("retirement_selection_changed")
    if row["receipt"] is None:
        result["state"] = "retirement_receipt_pending"
        return result
    receipt = _canonical(row["receipt"], SignedEndpointRetirementReceipt)
    if canonical_json_bytes(receipt.receipt) != row["receipt_intent"]:
        raise TransitionPreflightRefused("retirement_intent_changed")
    verify_retirement_receipt(
        receipt,
        request=request,
        grant_sha256=fact["grant_sha256"],
        miner_hotkey=miner,
        evaluator_hotkey=fact["validator_hotkey"],
    )
    sizes = db.execute(
        "SELECT LENGTH(body),LENGTH(signature) FROM response_recovery WHERE assignment_id=?",
        (binding.assignment_id,),
    ).fetchone()
    if sizes is not None and (
        (sizes[0] is not None and not 0 < sizes[0] <= limits.maximum_response_body_bytes)
        or (sizes[1] is not None and not 0 < sizes[1] <= 1024)
    ):
        raise TransitionPreflightRefused("retained_response_exceeds_native_bound")
    archive = db.execute(
        "SELECT * FROM response_recovery WHERE assignment_id=?", (binding.assignment_id,)
    ).fetchone()
    if (
        archive is None
        or archive["request_digest"] != binding.request_digest
        or archive["validator_account_hex"] != binding.validator_account_hex
    ):
        raise TransitionPreflightRefused("retirement_response_archive_missing_or_changed")
    if receipt.receipt.result == "response_retained":
        body = archive["body"]
        if not isinstance(body, bytes) or not 0 < len(body) <= limits.maximum_response_body_bytes:
            raise TransitionPreflightRefused("retained_response_exceeds_native_bound")
        response = _canonical(body, ResponseEnvelope)
        sha256 = hashlib.sha256(body).hexdigest()
        if (
            sha256 != archive["sha256"]
            or sha256 != receipt.receipt.response_sha256
            or response.window_id != request.window_id
            or response.batch_id != request.batch_id
            or response.challenge_id != request.challenge_id
            or response.request_digest != binding.request_digest
            or response.issued_block_hash != request.issued_block_hash
            or response.validator_hotkey != fact["validator_hotkey"]
            or response.serving_hotkey != miner
            or response.response_reveal_round != request.reveal_round
            or not verify_response_signature(
                response,
                hotkey_ss58=miner,
                scheme=response.signature_scheme,
                signature=archive["signature"],
            )
        ):
            raise TransitionPreflightRefused("retained_response_binding_or_signature_changed")
    elif any(archive[name] is not None for name in ("body", "signature", "sha256")):
        raise TransitionPreflightRefused("absence_receipt_has_response_archive")
    if db.execute(
        "SELECT 1 FROM operations WHERE assignment_id=? AND status='pending' LIMIT 1",
        (binding.assignment_id,),
    ).fetchone():
        raise TransitionPreflightRefused("retired_request_has_pending_operation")
    result["state"] = "retired"
    result["retirement_result"] = receipt.receipt.result
    return result


def _enrollment_fact(path: Path, miner: str) -> dict:
    raw = bounded_read(path, MAX_COHORT_GRANT_BYTES, private=False)
    value = json.loads(raw)
    if (
        isinstance(value, dict)
        and isinstance(value.get("claim"), dict)
        and value["claim"].get("schema") == "umi-cohort-service-work-claim/1"
    ):
        claim = verify_service_claim(_canonical(raw, SignedServiceWorkClaim))
        if identity(claim.claim.hotkey) != identity(miner):
            raise TransitionPreflightRefused("retained_claim_miner_changed")
        return {
            "kind": "claim",
            "claim_sha256": digest(claim.claim),
            "submission_sha256": claim.claim.submission_sha256,
        }
    return {
        "kind": "unverified",
        "recognized_shape": isinstance(value, dict)
        and any(
            name in value for name in ("consent", "proposed_admission", "admission", "certificate")
        ),
    }


def _enrollment_files(request, startup):
    configured = {item.cohort_sha256 for item in startup.authority.cohorts}
    supplied = [item.cohort_sha256 for item in request.enrollments]
    if len(set(supplied)) != len(supplied) or not set(supplied) <= configured:
        raise TransitionPreflightRefused("enrollment_directory_roster_differs")
    files = []
    directories = {}
    for item in request.enrollments:
        directory = Path(item.directory)
        inventory = directory_inventory(directory, maximum_entries=request.maximum_inventory_items)
        directories[str(directory)] = inventory
        for name in inventory[1]:
            path = directory / name
            facts = file_identity(path, private=False)
            if not 0 < int(facts[2]) <= MAX_COHORT_GRANT_BYTES:
                raise TransitionPreflightRefused("enrollment_artifact_exceeds_native_bound")
            files.append((item.cohort_sha256, path, facts))
            if len(files) > request.maximum_inventory_items:
                raise TransitionPreflightRefused(
                    "enrollment_inventory_exceeds_selected_grant_capacity"
                )
    return files, sorted(configured - set(supplied)), directories


def preflight_revision_transition(
    request: MinerRevisionPreflightRequest, *, repair_reason: str | None = None
) -> dict:
    request = MinerRevisionPreflightRequest.model_validate_json(canonical_json_bytes(request))
    with PreflightProgress("miner_revision_inputs", 1, unit="configurations") as progress:
        arguments, original, proposed, policy, transport, limits, input_snapshots = _inputs(request)
        progress.advance()
    root = Path(original.authority.directory)
    database = root / "rounds.sqlite3"
    assignments = Path(arguments.assignment_db)
    enrollments, missing_enrollments, enrollment_directories = _enrollment_files(request, original)
    paths = {
        database,
        assignments,
        Path(arguments.nonce_db),
        Path(arguments.finality_state),
        root / "rounds.lock",
        Path(str(assignments) + ".lock"),
    }
    cache_directory = Path(request.verification_directory)
    state_directories = {
        root,
        assignments.parent,
        Path(arguments.nonce_db).parent,
        Path(arguments.finality_state).parent,
        *[Path(item.directory) for item in request.enrollments],
    }
    if any(
        cache_directory == directory
        or directory in cache_directory.parents
        or cache_directory in directory.parents
        for directory in state_directories
    ):
        raise TransitionPreflightRefused(
            "verification_directory_must_be_separate_from_original_state"
        )
    snapshots = {str(path): file_identity(path) for path in sorted(paths)}
    verification_context = [
        TRANSITION_VERIFIER_SEMANTICS,
        runtime_identity(),
        digest(original),
        digest(policy),
        scoring_policy_hash(transport),
    ]
    complete_key = _key(
        "complete",
        verification_context,
        digest(proposed),
        snapshots,
        input_snapshots,
        enrollment_directories,
        [(cohort, str(path), facts) for cohort, path, facts in enrollments],
        request.model_dump(mode="json"),
    )
    cache = PreflightCheckpoints(cache_directory, repair_reason=repair_reason)
    with stopped_snapshots(
        ((database, root / "rounds.lock"), (assignments, Path(str(assignments) + ".lock"))),
        maximum_value_bytes=max(MAX_COHORT_GRANT_BYTES, limits.maximum_response_body_bytes) + 65536,
    ) as (grants, ledger):
        found = cache.get(complete_key)
        if found is not None:
            result = dict(found)
        else:
            expected = canonical_json_bytes(
                original.authority.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude={"maximum_grants", "maximum_bytes", "read_timeout_seconds"},
                )
            )
            binding_sizes = grants.execute("SELECT LENGTH(body) FROM binding LIMIT 2").fetchall()
            if len(binding_sizes) != 1 or not 0 < binding_sizes[0][0] <= MAX_COHORT_GRANT_BYTES:
                raise TransitionPreflightRefused("original_grant_binding_exceeds_bound")
            bindings = grants.execute("SELECT body FROM binding LIMIT 2").fetchall()
            if len(bindings) != 1 or bindings[0][0] != expected:
                raise TransitionPreflightRefused("original_grant_binding_changed")
            if ledger.execute("SELECT COUNT(*) FROM metadata").fetchone()[0] > 128:
                raise TransitionPreflightRefused("assignment_metadata_exceeds_supported_schema")
            metadata = dict(ledger.execute("SELECT key,value FROM metadata"))
            if (
                metadata.get("schema")
                not in {"umi-miner-resource-ledger/1", "umi-miner-resource-ledger/2"}
                or metadata.get("miner_account_hex") != identity(original.authority.miner_hotkey)
                or metadata.get("scoring_policy_sha256") != scoring_policy_hash(transport)
            ):
                raise TransitionPreflightRefused("original_assignment_identity_changed")
            if (
                metadata.get("schema") == "umi-miner-resource-ledger/1"
                and ledger.execute("SELECT 1 FROM request_retirements LIMIT 1").fetchone()
            ):
                raise TransitionPreflightRefused("retirement_schema_invalid")
            for name, value in metadata.items():
                if hasattr(limits, name) and str(getattr(limits, name)) != value:
                    raise TransitionPreflightRefused("original_assignment_limit_changed: " + name)
            count, used = grants.execute(
                "SELECT COUNT(*),COALESCE(SUM(LENGTH(body)),0) FROM records "
                "WHERE kind='miner_grant'"
            ).fetchone()
            if (
                count > original.authority.maximum_grants
                or count > request.maximum_inventory_items
                or used > original.authority.maximum_bytes
            ):
                raise TransitionPreflightRefused("grant_inventory_exceeds_original_capacity")
            slots = [
                row[0]
                for row in grants.execute(
                    "SELECT id FROM records WHERE kind='miner_grant' ORDER BY id"
                )
            ]
            facts = {}
            summary_bytes = 0
            with PreflightProgress("miner_revision_grants", len(slots), unit="grants") as progress:
                for slot in slots:
                    key = _key("grant", verification_context, snapshots[str(database)], slot)
                    fact = cache.get(key)
                    if fact is None:
                        fact = _grant_fact(grants, slot, original, policy, transport)
                        cache.put(key, fact)
                    summary_bytes += len(canonical_json_bytes(fact))
                    if summary_bytes > request.maximum_summary_bytes:
                        raise TransitionPreflightRefused(
                            "grant_summary_exceeds_selected_memory_budget"
                        )
                    facts[slot] = fact
                    progress.advance()
            lineage_key = _key("lineage", verification_context, snapshots[str(database)])
            if cache.get(lineage_key) is None:
                _lineage(facts, original.authority.miner_hotkey)
                cache.put(lineage_key, {"parent_lineage_verified": True})
            expected_index = {}
            requests = []
            for fact in facts.values():
                for raw in fact["requests"]:
                    item = TranslationRequest.model_validate(raw)
                    request_key = digest(
                        {
                            "schema": "umi-cohort-miner-request-key/1",
                            "evaluator": identity(fact["validator_hotkey"]),
                            "request": request_digest(item),
                        }
                    )
                    if request_key in expected_index:
                        raise TransitionPreflightRefused("duplicate_retained_request_selection")
                    if len(expected_index) >= request.maximum_inventory_items:
                        raise TransitionPreflightRefused("request_inventory_exceeds_selected_bound")
                    expected_index[request_key] = fact["slot"]
                    requests.append((fact, item))
            index_count = grants.execute("SELECT COUNT(*) FROM miner_grant_requests").fetchone()[0]
            if (
                index_count != len(expected_index)
                or dict(grants.execute("SELECT request_key,grant_id FROM miner_grant_requests"))
                != expected_index
            ):
                raise TransitionPreflightRefused("retained_request_index_incomplete_or_changed")
            results = []
            with PreflightProgress(
                "miner_revision_retirements", len(requests), unit="requests"
            ) as progress:
                for fact, item in requests:
                    key = _key(
                        "retirement",
                        verification_context,
                        limits.maximum_response_body_bytes,
                        snapshots[str(assignments)],
                        fact["grant_sha256"],
                        request_digest(item),
                    )
                    value = cache.get(key)
                    if value is None:
                        value = _retirement(
                            ledger, item, fact, original.authority.miner_hotkey, limits
                        )
                        cache.put(key, value)
                    results.append(value)
                    progress.advance()
            known = {item["assignment_id"] for item in results}
            unselected = set()
            for table in ("assignments", "response_recovery", "request_retirements", "operations"):
                row_count = ledger.execute(
                    "SELECT COUNT(DISTINCT assignment_id) FROM " + table
                ).fetchone()[0]
                if (
                    row_count > max(len(known), arguments.max_recovery_assignments)
                    or row_count > request.maximum_inventory_items
                ):
                    raise TransitionPreflightRefused(
                        "assignment_inventory_exceeds_selected_coverage"
                    )
                unselected.update(
                    row[0]
                    for row in ledger.execute("SELECT DISTINCT assignment_id FROM " + table)
                    if row[0] not in known
                )
            claims = []
            unclassified = []
            unverified_artifacts = []
            with PreflightProgress(
                "miner_revision_enrollment", len(enrollments), unit="artifacts"
            ) as progress:
                for cohort, path, file_facts in enrollments:
                    key = _key("enrollment", verification_context, cohort, str(path), file_facts)
                    artifact = cache.get(key)
                    if artifact is None:
                        artifact = _enrollment_fact(path, original.authority.miner_hotkey)
                        cache.put(key, artifact)
                    if artifact["kind"] == "claim":
                        matching = [
                            fact
                            for fact in facts.values()
                            if fact["claim_sha256"] == artifact["claim_sha256"]
                        ]
                        if any(
                            fact["cohort_sha256"] != cohort
                            or fact["submission_sha256"] != artifact["submission_sha256"]
                            for fact in matching
                        ):
                            raise TransitionPreflightRefused("retained_claim_submission_changed")
                        claims.append(
                            {
                                "cohort_sha256": cohort,
                                "claim_sha256": artifact["claim_sha256"],
                                "submission_sha256": artifact["submission_sha256"],
                                "local_grant_slots": [fact["slot"] for fact in matching],
                                "remote_disposition_verified": False,
                            }
                        )
                    else:
                        unverified_artifacts.append(str(path))
                        if not artifact["recognized_shape"]:
                            unclassified.append(str(path))
                    progress.advance()
            pending = [item for item in results if item["state"] != "retired"]
            receipts_pending = [fact["slot"] for fact in facts.values() if fact["receipt_pending"]]
            result = {
                "schema": "umi-miner-revision-transition-preflight/1",
                "old_revision": original.authority.model_revision,
                "new_revision": proposed.authority.model_revision,
                "cohorts": [item.model_dump(mode="json") for item in original.authority.cohorts],
                "known_requests_retired": not pending,
                "local_inventory_complete": not unselected
                and not missing_enrollments
                and not unclassified,
                "native_startup_compatibility_verified": False,
                "enrollment_authority_verified": False,
                "wallet_runtime_identity_verified": False,
                "counts": {
                    "grants": len(facts),
                    "requests": len(results),
                    "retired": len(results) - len(pending),
                    "claims": len(claims),
                },
                "requests": results,
                "claims": claims,
                "pending_grant_receipts": receipts_pending,
                "unselected_assignment_ids": sorted(unselected),
                "unverified_enrollment_artifacts": unverified_artifacts,
                "missing_enrollment_cohorts": missing_enrollments,
                "unclassified_enrollment_artifacts": unclassified,
                "verification_reused": False,
                "runtime_migration_authorized": False,
                "live_authority_verified": False,
                "service_drain_verified": False,
                "required_before_switch": [
                    "native assignment ledger audit and wallet/runtime startup qualification",
                    "verify retained enrollment artifacts and original submission bindings",
                    "authoritative replacement selection or request closure for each cohort",
                    "authoritative disposition of every original submission-bound paid claim",
                    "supported archive migration preserving old recovery and retirement routes",
                    "qualify actual process drain, runtime, service UID and container mounts",
                ],
                "unchanged_state_paths": {
                    "grants": str(root),
                    "assignments": arguments.assignment_db,
                    "nonces": arguments.nonce_db,
                    "finality": arguments.finality_state,
                },
            }
        if (
            any(file_identity(Path(path)) != value for path, value in snapshots.items())
            or any(
                file_identity(Path(path), private=False) != value
                for path, value in input_snapshots.items()
            )
            or any(file_identity(path, private=False) != value for _, path, value in enrollments)
            or any(
                directory_inventory(
                    Path(path),
                    maximum_entries=request.maximum_inventory_items,
                )
                != value
                for path, value in enrollment_directories.items()
            )
        ):
            raise TransitionPreflightRefused("source_changed_during_preflight")
    if len(canonical_json_bytes(result)) > request.maximum_summary_bytes:
        raise TransitionPreflightRefused("result_exceeds_selected_summary_budget")
    if found is None:
        cache.put(complete_key, result)
    return {**result, "verification_reused": found is not None}
