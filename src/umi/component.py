"""Preparation and binding checks for local, no-weight component cases."""

from __future__ import annotations

import json
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .audit import EvidenceStore, ObjectRef
from .config import SAFETY_BOUNDARY
from .crypto import SealedResponse, parse_sealed_response, seal_response
from .protocol import (
    GroundTruthPayload,
    ResponsePlaintext,
    TranslationRequest,
    base64url_decode,
    base64url_encode,
    canonical_json_bytes,
)
from .scoring import (
    mean_score,
    score_cer_with_trace,
    score_wer_with_trace,
    weighted_accuracy_with_trace,
)

CASE_SCHEMA = "umi-component-case/1"
BUNDLE_SCHEMA = "umi-component-bundle/1"
MAX_COMPONENT_REQUESTS = 14

NOT_REACHED = (
    "publisher_independence",
    "availability_certificate",
    "candidate_pool_selection",
    "receipt_block_deadline_proof",
    "chain_assignment_anchor",
    "chain_request_anchor",
    "chain_response_anchor",
    "spent_and_publisher_fault_transitions",
    "rolling_weight_eligibility",
    "weight_build",
    "weight_submission",
)


@dataclass(frozen=True)
class PreparedCase:
    root: Path
    requests: tuple[TranslationRequest, ...]
    request_refs: tuple[ObjectRef, ...]
    ground_truth_ref: ObjectRef
    ground_truth: SealedResponse


def _object_ref(value: Any) -> ObjectRef:
    if not isinstance(value, dict):
        raise ValueError("object reference must be a JSON object")
    return ObjectRef(
        sha256=str(value["sha256"]),
        media_type=str(value["media_type"]),
        size_bytes=int(value["size_bytes"]),
    )


def _parse_requests(data: bytes) -> tuple[TranslationRequest, ...]:
    try:
        decoded = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("requests file is not valid JSON") from error
    if isinstance(decoded, dict) and set(decoded) == {"requests"}:
        decoded = decoded["requests"]
    if isinstance(decoded, dict):
        decoded = [decoded]
    if not isinstance(decoded, list) or not decoded:
        raise ValueError("requests file must contain one request or a non-empty request array")
    if len(decoded) > MAX_COMPONENT_REQUESTS:
        raise ValueError(f"component case exceeds the {MAX_COMPONENT_REQUESTS}-request ceiling")
    try:
        requests = tuple(TranslationRequest.model_validate(value) for value in decoded)
    except ValidationError as error:
        raise ValueError("requests file contains an invalid UMI request") from error
    ordered = tuple(sorted(requests, key=lambda item: base64url_decode(item.challenge_id)))
    if len({request.challenge_id for request in ordered}) != len(ordered):
        raise ValueError("component requests contain a duplicate challenge ID")
    return ordered


def validate_case_bindings(
    requests: tuple[TranslationRequest, ...],
    ground_truth: GroundTruthPayload,
) -> None:
    if not requests:
        raise ValueError("component case has no requests")
    if len(requests) > MAX_COMPONENT_REQUESTS:
        raise ValueError(f"component case exceeds the {MAX_COMPONENT_REQUESTS}-request ceiling")
    challenge_ids = [request.challenge_id for request in requests]
    if len(set(challenge_ids)) != len(challenge_ids):
        raise ValueError("component requests contain a duplicate challenge ID")
    first = requests[0]
    shared_fields = (
        "window_id",
        "batch_id",
        "scoring_policy_hash",
        "response_close_round",
        "reveal_round",
    )
    for request in requests:
        for field in shared_fields:
            if getattr(request, field) != getattr(first, field):
                raise ValueError(f"requests disagree on shared field {field}")
    for field in shared_fields:
        if getattr(ground_truth, field) != getattr(first, field):
            raise ValueError(f"ground truth does not bind request field {field}")

    request_by_id = {request.challenge_id: request for request in requests}
    truth_by_id = {item.challenge_id: item for item in ground_truth.items}
    if request_by_id.keys() != truth_by_id.keys():
        raise ValueError("ground-truth items are not a bijection with component requests")
    for challenge_id, request in request_by_id.items():
        item = truth_by_id[challenge_id]
        if item.canary:
            raise ValueError("the initial component runner does not score canary items")
        expected_metric = "cer" if request.task.stratum == "fingerspelling" else "wer"
        if item.metric != expected_metric:
            raise ValueError("ground-truth metric does not match the request stratum")


def prepare_case(requests_path: Path, ground_truth_path: Path, output: Path) -> Path:
    """Seal ground truth and emit a public component case with no plaintext answers."""

    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise FileExistsError(f"output path is not an empty directory: {output}")
    requests = _parse_requests(requests_path.read_bytes())
    try:
        ground_truth = GroundTruthPayload.model_validate_json(ground_truth_path.read_bytes())
    except ValidationError as error:
        raise ValueError("ground-truth file is not a valid umi-ground-truth/1 object") from error
    validate_case_bindings(requests, ground_truth)

    sealed = seal_response(
        canonical_json_bytes(ground_truth),
        reveal_round=ground_truth.reveal_round,
    )
    store = EvidenceStore(output)
    request_refs = tuple(store.add_json(request) for request in requests)
    ground_truth_ref = store.add_bytes(sealed.portable_bytes, "application/octet-stream")
    manifest = {
        "schema": CASE_SCHEMA,
        "terminal_code": SAFETY_BOUNDARY.terminal_code,
        "netuid": SAFETY_BOUNDARY.netuid,
        "mechanism_id": SAFETY_BOUNDARY.mechanism_id,
        "translation_weights_active": False,
        "protocol_conformance": False,
        "activation_evidence": False,
        "request_objects": [reference.as_dict() for reference in request_refs],
        "ground_truth_envelope": ground_truth_ref.as_dict(),
        "ground_truth_reveal_round": sealed.reveal_round,
        "ground_truth_envelope_sha256": sealed.sha256_hex,
        "not_reached": list(NOT_REACHED),
    }
    return store.write_manifest(manifest)


def load_case(root: Path) -> PreparedCase:
    store = EvidenceStore(root)
    manifest = store.load_manifest()
    expected_boundary = {
        "schema": CASE_SCHEMA,
        "terminal_code": SAFETY_BOUNDARY.terminal_code,
        "netuid": 78,
        "mechanism_id": 0,
        "translation_weights_active": False,
        "protocol_conformance": False,
        "activation_evidence": False,
    }
    for field, expected in expected_boundary.items():
        if manifest.get(field) != expected:
            raise ValueError(f"component case has an invalid safety field: {field}")

    raw_request_refs = manifest.get("request_objects")
    if not isinstance(raw_request_refs, list) or not raw_request_refs:
        raise ValueError("component case has no request objects")
    request_refs = tuple(_object_ref(value) for value in raw_request_refs)
    loaded_requests: list[TranslationRequest] = []
    for reference in request_refs:
        request_bytes = store.read(reference)
        request = TranslationRequest.model_validate_json(request_bytes)
        if canonical_json_bytes(request) != request_bytes:
            raise ValueError("component request object is not canonical JSON")
        loaded_requests.append(request)
    requests = tuple(loaded_requests)
    if len(requests) > MAX_COMPONENT_REQUESTS:
        raise ValueError(f"component case exceeds the {MAX_COMPONENT_REQUESTS}-request ceiling")
    if len({request.challenge_id for request in requests}) != len(requests):
        raise ValueError("component requests contain a duplicate challenge ID")
    ground_truth_ref = _object_ref(manifest.get("ground_truth_envelope"))
    portable = store.read(ground_truth_ref)
    reveal_round = int(manifest["ground_truth_reveal_round"])
    ground_truth = parse_sealed_response(
        base64url_encode(portable),
        reveal_round=reveal_round,
        sha256_hex=str(manifest["ground_truth_envelope_sha256"]),
    )
    if tuple(sorted(requests, key=lambda item: base64url_decode(item.challenge_id))) != requests:
        raise ValueError("component request objects are not canonically ordered")
    if ground_truth.reveal_round != requests[0].reveal_round:
        raise ValueError("ground-truth envelope round does not match the component requests")
    return PreparedCase(
        root=root,
        requests=requests,
        request_refs=request_refs,
        ground_truth_ref=ground_truth_ref,
        ground_truth=ground_truth,
    )


def _fraction_record(value: Fraction) -> dict[str, int]:
    return {"numerator": value.numerator, "denominator": value.denominator}


def score_component_responses(
    requests: tuple[TranslationRequest, ...],
    ground_truth: GroundTruthPayload,
    responses: dict[str, ResponsePlaintext | None],
    failure_codes: dict[str, str | None] | None = None,
) -> dict[str, Any]:
    """Score every issued component request, preserving failures as exact zeroes."""

    validate_case_bindings(requests, ground_truth)
    item_by_id = {item.challenge_id: item for item in ground_truth.items}
    failures = failure_codes or {}
    per_clip: list[dict[str, Any]] = []
    per_stratum: dict[str, list[Fraction]] = {
        "fingerspelling": [],
        "short_utterance": [],
        "continuous": [],
    }

    for request in requests:
        item = item_by_id[request.challenge_id]
        response = responses.get(request.challenge_id)
        failure_code = failures.get(request.challenge_id)
        if failure_code is not None or response is None or response.status != "ok":
            score = Fraction(0, 1)
            trace: dict[str, Any] | None = None
            if failure_code is None and response is not None:
                failure_code = response.error_code
            failure_code = failure_code or "missing_response"
        else:
            if response.hypothesis is None:
                raise ValueError("an ok response is missing its hypothesis")
            metric_trace = (
                score_cer_with_trace(response.hypothesis, item.references)
                if item.metric == "cer"
                else score_wer_with_trace(response.hypothesis, item.references)
            )
            score = metric_trace.score
            trace = metric_trace.to_record()
        per_stratum[request.task.stratum].append(score)
        per_clip.append(
            {
                "challenge_id": request.challenge_id,
                "stratum": request.task.stratum,
                "metric": item.metric,
                "score": _fraction_record(score),
                "failure_code": failure_code,
                "trace": trace,
            }
        )

    stratum_means: dict[str, Fraction | None] = {
        name: mean_score(scores) if scores else None for name, scores in per_stratum.items()
    }
    diagnostic_accuracy = None
    if all(value is not None for value in stratum_means.values()):
        accuracy = weighted_accuracy_with_trace(
            stratum_means["fingerspelling"],  # type: ignore[arg-type]
            stratum_means["short_utterance"],  # type: ignore[arg-type]
            stratum_means["continuous"],  # type: ignore[arg-type]
        )
        diagnostic_accuracy = accuracy.to_record()

    return {
        "per_clip": per_clip,
        "stratum_means": {
            name: _fraction_record(value) if value is not None else None
            for name, value in stratum_means.items()
        },
        "diagnostic_accuracy": diagnostic_accuracy,
        "assigned_clip_count": len(requests),
        "weight_eligible": False,
        "weight_eligibility_reason": "component tests do not establish rolling eligibility",
    }


__all__ = [
    "BUNDLE_SCHEMA",
    "CASE_SCHEMA",
    "MAX_COMPONENT_REQUESTS",
    "NOT_REACHED",
    "PreparedCase",
    "load_case",
    "prepare_case",
    "score_component_responses",
    "validate_case_bindings",
]
