"""A closed new-upload route does not acquire unnecessary registration proofs."""

from types import SimpleNamespace

import pytest

from umi import competition_cohort_service_host as host
from umi.competition_cohort_intake import CohortAdmissionClosed


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["closed", "open", "unconfigured"])
async def test_direct_admission_cached_cutoff_precedes_finality_capture(monkeypatch, status):
    cohort = "a1" * 32
    request = SimpleNamespace(
        consent=SimpleNamespace(consent=SimpleNamespace(cohort_sha256=cohort))
    )
    calls = []
    observation = object()

    def admission_status(selected):
        assert selected == cohort
        calls.append("cached_status")
        return None if status == "unconfigured" else {"new_admissions_open": status == "open"}

    intake = SimpleNamespace(admission_status=admission_status)

    async def capture():
        calls.append("capture")
        return observation

    def authorize(owner, signed, observed, *, mechanism):
        assert owner is intake
        assert signed is request
        assert observed is observation
        assert mechanism == "direct_r2_multipart_v1"
        calls.append("native_authorize")

    monkeypatch.setattr(host, "authorize_model_delivery", authorize)
    if status == "closed":
        with pytest.raises(CohortAdmissionClosed):
            await host._authorize_direct_model_delivery(intake, request, capture)
        assert calls == ["cached_status"]
    else:
        await host._authorize_direct_model_delivery(intake, request, capture)
        assert calls == ["cached_status", "capture", "native_authorize"]
