"""Batch policy snapshots must preserve full validation for every publication."""

import json

import pytest

from umi.competition_authorization import _PublicationBodyValidator, validate_publication_body
from umi.protocol import canonical_json_bytes

from .test_competition_authorization import authorization as authorization
from .test_open_competition import policy as policy


@pytest.mark.parametrize("changed", ["runtime", "wire_id", "missing_assignment"])
def test_later_batch_body_is_fully_validated(authorization, changed):
    fixture = authorization
    body = fixture.publication.publication
    validator = _PublicationBodyValidator(fixture.policy, fixture.legacy_policy)
    assert validator.validate(body) == body
    malformed = json.loads(canonical_json_bytes(body))
    if changed == "runtime":
        malformed["round"]["runtime_sha256"] = "ff" * 32
    elif changed == "wire_id":
        malformed["assignments"][0]["request"]["batch_id"] = "ff" * 32
    else:
        malformed["assignments"].pop()
    with pytest.raises(ValueError):
        validator.validate(malformed)


def test_batch_owns_policy_snapshots_and_returns_fresh_bodies(authorization):
    fixture = authorization
    body = fixture.publication.publication
    policy_input = json.loads(canonical_json_bytes(fixture.policy))
    validator = _PublicationBodyValidator(policy_input, fixture.legacy_policy)
    first = validator.validate(body)
    policy_input["sequence"] += 1
    second = validator.validate(body)
    assert second == first == body
    assert second is not first and second.round is not first.round
    assert second.assignments[0] is not first.assignments[0]
    # A later operation sees the caller's changed policy, rather than reusing
    # the previous batch's context.
    with pytest.raises(ValueError):
        validate_publication_body(body, policy_input, fixture.legacy_policy)
