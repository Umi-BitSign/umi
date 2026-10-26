"""Pending latest models cannot be buried behind hash-ordered cohort batches."""

from types import SimpleNamespace

import pytest

from umi.competition_chain import RegistrationProviderTimeout
from umi.competition_cohort_model_acceptance_worker import ModelAcceptanceWorker


@pytest.mark.asyncio
async def test_one_pending_latest_model_per_cohort_and_rotating_first_cohort(tmp_path):
    cohorts = tuple(letter * 64 for letter in "abcd")
    remaining = {cohort: [f"{cohort[0]}1", f"{cohort[0]}2"] for cohort in cohorts}
    probes = []
    scans = []
    calls = []

    class Owner:
        intake = SimpleNamespace(
            config=SimpleNamespace(
                cohorts=tuple(SimpleNamespace(cohort_sha256=cohort) for cohort in cohorts)
            )
        )

        def pending_latest_entries(self, cohort, *, limit, offset):
            probes.append((cohort, limit, offset))
            return tuple((key, key) for key in remaining[cohort][offset : offset + limit])

        def entries(self, cohort, *, after, limit):
            scans.append((cohort, after, limit))
            return ()

    # A released earlier cohort may still have a configured priority. Once
    # several cohorts need acceptance, that hint cannot defeat rotation.
    worker = ModelAcceptanceWorker(
        Owner(), None, tmp_path, tmp_path, priority_cohorts=(cohorts[0],)
    )

    async def accept(cohort, submission):
        calls.append((cohort, submission))
        remaining[cohort].remove(submission)

    worker._one = accept
    first = await worker.poll_once()
    second = await worker.poll_once()

    assert [cohort for cohort, _ in calls[:4]] == list(cohorts)
    assert [cohort for cohort, _ in calls[4:]] == [*cohorts[1:], cohorts[0]]
    assert [submission for _, submission in calls] == [
        "a1",
        "b1",
        "c1",
        "d1",
        "b2",
        "c2",
        "d2",
        "a2",
    ]
    assert len(probes) == 8 and {limit for _, limit, _ in probes} == {16}
    assert [offset for _, _, offset in probes] == [0] * 8
    assert scans == []
    assert first["pending_latest_cohorts"] == list(cohorts)
    assert second["pending_latest_cohorts"] == [*cohorts[1:], cohorts[0]]
    assert first["entries_exported"] == second["entries_exported"] == 4
    assert first["fair_rotation_next"] == 1
    assert second["fair_rotation_next"] == 2

    third = await worker.poll_once()
    assert third["pending_latest_cohorts"] == []
    assert {limit for _, _, limit in scans} == {16}


@pytest.mark.asyncio
async def test_unfinished_models_leave_one_old_export_slot_per_other_cohort(tmp_path):
    cohorts = tuple(letter * 64 for letter in "abc")
    pending = {
        cohorts[0]: [("new-a", "new-a")],
        cohorts[1]: [("new-b", "new-b")],
        cohorts[2]: [],
    }
    scans = []
    calls = []

    class Owner:
        intake = SimpleNamespace(
            config=SimpleNamespace(
                cohorts=tuple(SimpleNamespace(cohort_sha256=cohort) for cohort in cohorts)
            )
        )

        def pending_latest_entries(self, cohort, *, limit, offset):
            assert limit == 16
            return tuple(pending[cohort][offset : offset + limit])

        def entries(self, cohort, *, after, limit):
            scans.append((cohort, after, limit))
            return ((f"old-{cohort[0]}", f"old-{cohort[0]}"),)

    worker = ModelAcceptanceWorker(Owner(), None, tmp_path, tmp_path)

    async def accept(cohort, submission):
        calls.append((cohort, submission))

    worker._one = accept
    result = await worker.poll_once()

    assert calls == [(cohorts[0], "new-a"), (cohorts[1], "new-b"), (cohorts[2], "old-c")]
    assert scans == [(cohorts[2], "", 1)]
    assert result["entries_exported"] == 3


@pytest.mark.asyncio
async def test_failed_pending_model_does_not_hide_later_entries_beyond_first_page(tmp_path):
    first, other = "a" * 64, "b" * 64
    attempts = []

    class Owner:
        intake = SimpleNamespace(
            config=SimpleNamespace(
                cohorts=tuple(SimpleNamespace(cohort_sha256=c) for c in (first, other))
            )
        )

        def pending_latest_entries(self, cohort, *, limit, offset):
            keys = [f"a{n}" for n in range(18)] if cohort == first else ["b0"]
            return tuple((key, key) for key in keys[offset : offset + limit])

        def entries(self, cohort, *, after, limit):
            raise AssertionError("contended latest work must not rescan ordinary entries")

    worker = ModelAcceptanceWorker(Owner(), None, tmp_path, tmp_path)

    async def accept(cohort, submission):
        if cohort == first:
            attempts.append(submission)
            raise OSError("review still pending")

    worker._one = accept
    for _ in range(18):
        report = await worker.poll_once()
        assert report["entries_pending"] == 1

    assert attempts == [f"a{n}" for n in range(18)]


@pytest.mark.asyncio
async def test_registration_provider_timeout_gets_bounded_retry_without_starving_peers(tmp_path):
    first, other = "a" * 64, "b" * 64
    pending = {first: [f"a{n}" for n in range(8)], other: [f"b{n}" for n in range(12)]}
    attempts = []

    class Owner:
        intake = SimpleNamespace(
            config=SimpleNamespace(
                cohorts=tuple(SimpleNamespace(cohort_sha256=c) for c in (first, other))
            )
        )

        def pending_latest_entries(self, cohort, *, limit, offset):
            return tuple((key, key) for key in pending[cohort][offset : offset + limit])

        def entries(self, cohort, *, after, limit):
            raise AssertionError("contended pending work must not rescan old entries")

    worker = ModelAcceptanceWorker(Owner(), None, tmp_path, tmp_path)
    failures = 0

    async def accept(cohort, submission):
        nonlocal failures
        attempts.append((cohort, submission))
        if cohort == first and submission == "a0" and failures < 2:
            failures += 1
            raise RegistrationProviderTimeout("registration collection timed out")
        pending[cohort].remove(submission)

    worker._one = accept
    reports = [await worker.poll_once() for _ in range(6)]

    assert [key for cohort, key in attempts if cohort == first] == [
        "a0",
        "a1",
        "a2",
        "a3",
        "a0",
        "a4",
    ]
    assert [key for cohort, key in attempts if cohort == other] == [
        "b0",
        "b1",
        "b2",
        "b3",
        "b4",
        "b5",
    ]
    assert reports[0]["registration_provider_retries"][0]["next_retry_after_other_attempts"] == 3
    assert reports[3]["registration_provider_retries"][0]["next_retry_after_other_attempts"] == 0
    assert reports[4]["registration_provider_retries"][0]["next_retry_after_other_attempts"] == 3
    assert reports[5]["registration_provider_retries"][0]["next_retry_after_other_attempts"] == 2

    for _ in range(2):
        await worker.poll_once()
    report = await worker.poll_once()
    assert (first, "a0") in attempts
    assert "a0" not in pending[first]
    assert report["registration_provider_retries"] == []


@pytest.mark.asyncio
async def test_replaced_timeout_submission_is_not_retried(tmp_path):
    first, other = "a" * 64, "b" * 64
    pending = {first: ["old", "next", "last"], other: ["peer"] * 4}
    attempts = []

    class Owner:
        intake = SimpleNamespace(
            config=SimpleNamespace(
                cohorts=tuple(SimpleNamespace(cohort_sha256=c) for c in (first, other))
            )
        )

        def pending_latest_entries(self, cohort, *, limit, offset):
            return tuple((key, key) for key in pending[cohort][offset : offset + limit])

        def entries(self, cohort, *, after, limit):
            return ()

    worker = ModelAcceptanceWorker(Owner(), None, tmp_path, tmp_path)

    async def accept(cohort, submission):
        attempts.append((cohort, submission))
        if submission == "old":
            raise RegistrationProviderTimeout("registration collection timed out")
        if cohort == first:
            pending[cohort].remove(submission)

    worker._one = accept
    first_report = await worker.poll_once()
    assert first_report["registration_provider_retries"][0]["submission_sha256"] == "old"
    pending[first][0] = "replacement"
    for _ in range(4):
        report = await worker.poll_once()

    assert attempts.count((first, "old")) == 1
    assert report["registration_provider_retries"] == []


@pytest.mark.asyncio
async def test_changed_failure_does_not_keep_provider_retry(tmp_path):
    first, other = "a" * 64, "b" * 64
    pending = {first: [f"a{n}" for n in range(7)], other: [f"b{n}" for n in range(7)]}
    attempted = []

    class Owner:
        intake = SimpleNamespace(
            config=SimpleNamespace(
                cohorts=tuple(SimpleNamespace(cohort_sha256=c) for c in (first, other))
            )
        )

        def pending_latest_entries(self, cohort, *, limit, offset):
            return tuple((key, key) for key in pending[cohort][offset : offset + limit])

        def entries(self, cohort, *, after, limit):
            return ()

    worker = ModelAcceptanceWorker(Owner(), None, tmp_path, tmp_path)

    async def accept(cohort, submission):
        attempted.append((cohort, submission))
        if submission == "a0":
            if attempted.count((first, "a0")) == 1:
                raise RegistrationProviderTimeout("registration collection timed out")
            raise OSError("review input unavailable")
        pending[cohort].remove(submission)

    worker._one = accept
    reports = [await worker.poll_once() for _ in range(5)]
    assert [key for cohort, key in attempted if cohort == first] == ["a0", "a1", "a2", "a3", "a0"]
    assert reports[4]["registration_provider_retries"] == []
    await worker.poll_once()
    assert set(attempted[-2:]) == {(first, "a4"), (other, "b5")}
