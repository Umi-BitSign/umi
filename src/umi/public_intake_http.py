"""Bounded, read-only HTTP collection for the public intake monitor."""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Any

import httpx

from .observer_models import ParticipantsResponse
from .open_competition import CompetitionPolicy, digest
from .protocol import canonical_json_bytes
from .public_intake_monitor import (
    AdmissionPage,
    PublicIntakeMonitorConfig,
    PublicIntakeMonitorError,
    PublicRouteCapture,
    capture_fence,
    document_sha256,
    parse_readiness,
    parse_status,
)


class PublicIntakeHttpError(RuntimeError):
    """A bounded public read failed without returning a trusted capture."""


class _CaptureBudget:
    def __init__(self, maximum_bytes: int, deadline: float, clock) -> None:
        self.maximum_bytes = maximum_bytes
        self.deadline = deadline
        self.clock = clock
        self.consumed_bytes = 0
        self._lock = threading.Lock()

    def check_deadline(self) -> None:
        if self.clock() >= self.deadline:
            raise PublicIntakeHttpError("public_capture_deadline_exceeded")

    def remaining_seconds(self) -> float:
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise PublicIntakeHttpError("public_capture_deadline_exceeded")
        return remaining

    def consume(self, size: int) -> None:
        with self._lock:
            self.check_deadline()
            self.consumed_bytes += size
            if self.consumed_bytes > self.maximum_bytes:
                raise PublicIntakeHttpError("public_capture_response_budget_exceeded")


def _reject_constant(_value: str):
    raise ValueError("non-finite JSON number")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _decode_json(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError):
        raise PublicIntakeHttpError("public_route_returned_invalid_json") from None
    if not isinstance(value, dict):
        raise PublicIntakeHttpError("public_route_returned_non_object_json")
    return value


class PublicIntakeHttpSource:
    """Fetch one admission-fenced snapshot from fixed public GET routes."""

    def __init__(
        self,
        config: PublicIntakeMonitorConfig,
        *,
        client: httpx.Client | None = None,
        sleeper=time.sleep,
        monotonic=time.monotonic,
    ) -> None:
        self.config = config
        self._owned_client = client is None
        self.client = client or httpx.Client(
            timeout=httpx.Timeout(config.request_timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            headers={
                "accept": "application/json",
                "accept-encoding": "identity",
                "user-agent": "umi-public-intake-monitor/1",
            },
        )
        self.sleeper = sleeper
        self.monotonic = monotonic

    def close(self) -> None:
        if self._owned_client:
            self.client.close()

    def __enter__(self) -> PublicIntakeHttpSource:
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def _get(
        self,
        origin: str,
        path: str,
        *,
        params: dict[str, str | int] | None = None,
        budget: _CaptureBudget,
    ) -> dict[str, Any]:
        if not path.startswith("/") or "?" in path or "#" in path:
            raise ValueError("monitor route must be one fixed absolute path")
        last_code = "public_route_request_failed"
        for attempt in range(self.config.request_attempts):
            budget.check_deadline()
            request_timeout = min(budget.remaining_seconds(), self.config.request_timeout_seconds)
            request_deadline = self.monotonic() + request_timeout
            try:
                with self.client.stream(
                    "GET",
                    origin + path,
                    params=params,
                    timeout=httpx.Timeout(request_timeout),
                ) as response:
                    if response.status_code != 200:
                        last_code = f"public_route_http_{response.status_code}"
                        if response.status_code not in {408, 409, 425, 429, 500, 502, 503, 504}:
                            break
                        raise httpx.HTTPStatusError(
                            "retryable public response",
                            request=response.request,
                            response=response,
                        )
                    content_type = response.headers.get("content-type", "").split(";", 1)[0]
                    if content_type.strip().lower() != "application/json":
                        raise PublicIntakeHttpError("public_route_content_type_invalid")
                    if response.headers.get("content-encoding", "identity").lower() != "identity":
                        raise PublicIntakeHttpError("public_route_content_encoding_invalid")
                    declared = response.headers.get("content-length")
                    if declared is not None:
                        try:
                            declared_bytes = int(declared)
                        except ValueError:
                            raise PublicIntakeHttpError(
                                "public_route_content_length_invalid"
                            ) from None
                        if not 0 <= declared_bytes <= self.config.maximum_response_bytes:
                            raise PublicIntakeHttpError("public_route_response_too_large")
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        if self.monotonic() >= request_deadline:
                            raise PublicIntakeHttpError("public_route_elapsed_deadline_exceeded")
                        budget.consume(len(chunk))
                        if len(body) + len(chunk) > self.config.maximum_response_bytes:
                            raise PublicIntakeHttpError("public_route_response_too_large")
                        body.extend(chunk)
                    if self.monotonic() >= request_deadline:
                        raise PublicIntakeHttpError("public_route_elapsed_deadline_exceeded")
                    return _decode_json(bytes(body))
            except PublicIntakeHttpError:
                raise
            except (httpx.HTTPError, OSError):
                budget.check_deadline()
                if attempt + 1 == self.config.request_attempts:
                    break
                self.sleeper(min(0.25 * (2**attempt), budget.remaining_seconds()))
                budget.check_deadline()
        raise PublicIntakeHttpError(last_code)

    def _submission_pages(
        self, expected_count: int, budget: _CaptureBudget
    ) -> tuple[dict[str, Any], ...]:
        pages = []
        offset = 0
        while offset < expected_count or not pages:
            raw = self._get(
                self.config.competition_origin,
                "/v1/competition/submissions",
                params={"offset": offset, "limit": self.config.submission_page_size},
                budget=budget,
            )
            try:
                page = AdmissionPage.model_validate_json(canonical_json_bytes(raw))
            except ValueError:
                raise PublicIntakeHttpError("invalid_submission_page") from None
            if page.offset != offset:
                raise PublicIntakeHttpError("submission_page_offset_mismatch")
            if len(page.items) > page.limit:
                raise PublicIntakeHttpError("submission_page_item_count_exceeds_limit")
            next_offset = offset + len(page.items)
            if next_offset > expected_count:
                raise PublicIntakeHttpError("submission_pages_exceed_checkpoint_count")
            pages.append(raw)
            if not page.items:
                break
            offset = next_offset
        return tuple(pages)

    def _submission_records(
        self, pages: tuple[dict[str, Any], ...], budget: _CaptureBudget
    ) -> dict[str, dict[str, Any]]:
        digests = []
        for raw in pages:
            page = AdmissionPage.model_validate_json(canonical_json_bytes(raw))
            digests.extend(item.submission_sha256 for item in page.items)
        if len(set(digests)) != len(digests):
            raise PublicIntakeHttpError("duplicate_submission_digest")

        def fetch(submission_sha256: str):
            return submission_sha256, self._get(
                self.config.competition_origin,
                f"/v1/competition/submissions/{submission_sha256}",
                budget=budget,
            )

        records: dict[str, dict[str, Any]] = {}
        executor = ThreadPoolExecutor(
            max_workers=self.config.record_request_workers,
            thread_name_prefix="umi-public-record",
        )
        try:
            for start in range(0, len(digests), self.config.record_request_workers):
                batch = digests[start : start + self.config.record_request_workers]
                futures = {executor.submit(fetch, item): item for item in batch}
                for future in as_completed(futures, timeout=budget.remaining_seconds()):
                    submission_sha256, record = future.result()
                    records[submission_sha256] = record
        except FuturesTimeoutError:
            executor.shutdown(wait=False, cancel_futures=True)
            raise PublicIntakeHttpError("public_capture_deadline_exceeded") from None
        except BaseException:
            executor.shutdown(wait=False, cancel_futures=True)
            raise
        executor.shutdown(wait=True)
        return {key: records[key] for key in sorted(records)}

    def _participant_pages(self, budget: _CaptureBudget) -> tuple[dict[str, Any], ...]:
        pages = []
        cursor: str | None = None
        for _ in range(256):
            params: dict[str, str | int] = {
                "role": "all",
                "limit": self.config.participant_page_size,
            }
            if cursor is not None:
                params["cursor"] = cursor
            raw = self._get(
                self.config.observer_origin,
                "/api/v1/participants",
                params=params,
                budget=budget,
            )
            try:
                page = ParticipantsResponse.model_validate_json(canonical_json_bytes(raw))
            except ValueError:
                raise PublicIntakeHttpError("invalid_participant_page") from None
            pages.append(raw)
            cursor = page.page.next_cursor
            if cursor is None:
                return tuple(pages)
        raise PublicIntakeHttpError("participant_page_limit_exceeded")

    def _capture_once(self, budget: _CaptureBudget) -> PublicRouteCapture:
        status_before = self._get(
            self.config.competition_origin, "/v1/competition/status", budget=budget
        )
        readiness_before = self._get(
            self.config.competition_origin, "/v1/competition/readiness", budget=budget
        )
        accepted_count = parse_status(status_before).accepted_submission_count
        if accepted_count > self.config.maximum_accepted_submission_count:
            raise PublicIntakeHttpError("accepted_submission_count_exceeds_monitor_bound")
        pages = self._submission_pages(accepted_count, budget)
        records = self._submission_records(pages, budget)
        participant_pages = self._participant_pages(budget)
        readiness = self._get(
            self.config.competition_origin, "/v1/competition/readiness", budget=budget
        )
        status = self._get(self.config.competition_origin, "/v1/competition/status", budget=budget)
        return PublicRouteCapture(
            status_before=status_before,
            readiness_before=readiness_before,
            submission_pages=pages,
            submission_records=records,
            participant_pages=participant_pages,
            readiness=readiness,
            status=status,
        )

    def capture(self) -> PublicRouteCapture:
        budget = _CaptureBudget(
            self.config.maximum_capture_bytes,
            self.monotonic() + self.config.maximum_poll_seconds,
            self.monotonic,
        )
        for attempt in range(self.config.snapshot_attempts):
            capture = self._capture_once(budget)
            try:
                capture_fence(capture)
            except PublicIntakeMonitorError as error:
                if str(error) != "capture_admission_fence_changed":
                    raise
                if attempt + 1 == self.config.snapshot_attempts:
                    raise PublicIntakeHttpError("public_admission_head_kept_moving") from None
                self.sleeper(min(0.25 * (2**attempt), budget.remaining_seconds()))
                budget.check_deadline()
                continue
            return capture
        raise AssertionError("snapshot attempt loop did not return")

    def observed_identity(self) -> dict[str, Any]:
        """Report an identity candidate without trusting or writing it."""

        budget = _CaptureBudget(
            self.config.maximum_capture_bytes,
            self.monotonic() + self.config.maximum_poll_seconds,
            self.monotonic,
        )
        status_before = self._get(
            self.config.competition_origin, "/v1/competition/status", budget=budget
        )
        readiness = self._get(
            self.config.competition_origin, "/v1/competition/readiness", budget=budget
        )
        status = self._get(self.config.competition_origin, "/v1/competition/status", budget=budget)
        before = parse_status(status_before)
        after = parse_status(status)
        ready = parse_readiness(readiness)
        before_fence = (
            before.policy_sha256,
            document_sha256(status_before["deployment"]),
            before.retained_submission_head.head_sha256,
            before.accepted_submission_count,
        )
        after_fence = (
            after.policy_sha256,
            document_sha256(status["deployment"]),
            after.retained_submission_head.head_sha256,
            after.accepted_submission_count,
        )
        if before_fence != after_fence or before_fence != (
            ready.policy_sha256,
            document_sha256(readiness["deployment"]),
            ready.retained_submission_head.head_sha256,
            ready.retained_submission_head.record_count,
        ):
            raise PublicIntakeHttpError("public_identity_changed_during_observation")
        policy = status["policy"]
        try:
            parsed_policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        except ValueError:
            raise PublicIntakeHttpError("invalid_public_policy") from None
        if digest(parsed_policy) != after.policy_sha256:
            raise PublicIntakeHttpError("public_policy_digest_mismatch")
        required_submission_ids = sorted(ready.retained_state.required_submission_sha256s)
        return {
            "schema": "umi-public-intake-monitor-observed-identity/1",
            "policy_sha256": after.policy_sha256,
            "policy_sequence": policy.get("sequence"),
            "policy_predecessor_sha256": policy.get("predecessor_sha256"),
            "policy": policy,
            "deployment_document_sha256": after_fence[1],
            "deployment": status["deployment"],
            "admission_checked_block": after.admission_checked_block,
            "accepted_submission_count": after.accepted_submission_count,
            "retained_head_sha256": after.retained_submission_head.head_sha256,
            "required_submission_sha256s": required_submission_ids,
            "required_submission_set_sha256": document_sha256(required_submission_ids),
            "suggested_reviewed_bootstrap": {
                "schema": "umi-public-intake-monitor-bootstrap/1",
                "identity_name": "REVIEW_REQUIRED",
                "accepted_submission_count": after.accepted_submission_count,
                "retained_head_sha256": after.retained_submission_head.head_sha256,
            },
            "identity_template_requires_review": {
                "schema": "umi-public-intake-monitor-identity/1",
                "name": "REVIEW_REQUIRED",
                "policy_sha256": after.policy_sha256,
                "deployment_document_sha256": after_fence[1],
                "not_before_checked_block": after.admission_checked_block,
                "acceptance_not_before_block": "REVIEW_REQUIRED",
                "minimum_accepted_submission_count": after.accepted_submission_count,
                "required_submission_count": len(required_submission_ids),
                "required_submission_set_sha256": document_sha256(required_submission_ids),
                "admission_writer_generation": 2,
            },
            "acceptance_floor_review": {
                "first_bootstrap": "use the actual deployment admission activation block",
                "successor_rollover": "use the exact reviewed rollout activation block",
                "current_checked_block": after.admission_checked_block,
                "round_intake_opened_block": after.round_schedule.intake_opened_block,
            },
        }


__all__ = ("PublicIntakeHttpError", "PublicIntakeHttpSource")
