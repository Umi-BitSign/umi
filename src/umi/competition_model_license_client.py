"""Bounded read-only discovery of a cohort's signed optional license route."""

import httpx

from .competition_client import CompetitionSubmissionError, validate_intake_origin
from .competition_cohort_history import verify_cohort_history
from .competition_cohort_public_licenses import (
    MAX_LICENSE_METADATA_BYTES,
    PublicModelLicenseAdoptions,
)
from .competition_model_license import verify_model_license_selection
from .open_competition import digest


def fetch_model_license_adoptions(
    *, origin, history, policy, expected_tip_sha256, current_block, transport=None
):
    view = verify_cohort_history(
        history, policy, expected_tip_sha256=expected_tip_sha256, current_block=current_block
    )
    origin = validate_intake_origin(origin)
    url = (
        origin + "/v1/competition/cohorts/" + view.state.cohort_sha256 + "/model-license-adoptions"
    )
    try:
        with (
            httpx.Client(
                transport=transport, timeout=30, follow_redirects=False, trust_env=False
            ) as client,
            client.stream(
                "GET", url, headers={"Accept": "application/json", "Accept-Encoding": "identity"}
            ) as response,
        ):
            if response.status_code != 200:
                raise CompetitionSubmissionError(
                    "model_license_metadata_unavailable", status_code=response.status_code
                )
            if (
                response.headers.get("content-type", "").split(";", 1)[0] != "application/json"
                or response.headers.get("content-encoding", "identity") != "identity"
            ):
                raise CompetitionSubmissionError("invalid_model_license_metadata_encoding")
            raw = bytearray()
            for chunk in response.iter_bytes():
                if len(raw) + len(chunk) > MAX_LICENSE_METADATA_BYTES:
                    raise CompetitionSubmissionError("model_license_metadata_too_large")
                raw.extend(chunk)
    except httpx.HTTPError:
        raise CompetitionSubmissionError("model_license_metadata_transport_unavailable") from None
    result = PublicModelLicenseAdoptions.model_validate_json(bytes(raw))
    if (
        result.cohort_sha256 != view.state.cohort_sha256
        or result.policy_sha256 not in (None, digest(policy))
        or result.authority_sha256 not in (None, view.state.authority_sha256)
    ):
        raise ValueError("public model license metadata belongs to another selected cohort")
    for item in result.items:
        body = verify_model_license_selection(
            item.signed_adoption, policy=policy, authority=history.authority.authority
        )
        if (
            history.plan.sequence < body.first_cohort_sequence
            or body.issued_at_block > current_block
        ):
            raise ValueError("model license adoption is not current for the selected cohort")
    return result
