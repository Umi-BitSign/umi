"""An NC bundle reaches actual native execution, settlement and reward replay.

The existing direct-delivery fixture owns the full lifecycle. Only model
documents, signed license adoption and fresh miner consent differ. Provider,
finality, filesystem-capacity and inference ports remain explicit fixtures;
no real dataset, production database or chain row is used.
"""

# Imported pytest fixtures are resolved by their parameter names.
# ruff: noqa: F401, F811
import hashlib
import json
from pathlib import Path

import pytest

from umi.competition_geometric_rewards import cohort_reward_parameters
from umi.competition_model_license import prepare_model_license_adoption
from umi.competition_model_training_rights import (
    CONDITIONAL_TRAINING_RIGHTS_SHA256,
    NC_CONTRIBUTION_TERMS_SHA256,
)
from umi.open_competition import (
    BundleFile,
    ModelBundle,
    SignedModelLicenseTermsAdoption,
    digest,
    sign_object,
)
from umi.protocol import canonical_json_bytes

from . import test_competition_cohort_native_direct as direct_fixture
from .test_competition_cohort_native_direct import (
    NativeDirect,
    base_policy,
    chain_config,
    direct_inventory,
    host,
    intake,
    legacy_scenario,
    lifecycle,
    lifecycle_before_intake,
    native_policy,
    policy,
    recovery,
    runtime,
    scenario,
    single_scenario,
)
from .test_competition_cohort_native_pipeline import model_request, run_pipeline
from .test_competition_cohort_recovery import signatures
from .test_competition_model_training_rights import documents
from .test_open_competition import wallet


@pytest.fixture(autouse=True)
def current_c7_economics(monkeypatch):
    """Construct this new synthetic C7 authority with its announced defaults."""
    standing = direct_fixture.standing

    def current(plan, policy, **kwargs):
        kwargs["model_reward_parameters"] = cohort_reward_parameters(plan.sequence)
        return standing(plan, policy, **kwargs)

    monkeypatch.setattr(direct_fixture, "standing", current)


def nc_model_request(scenario, model, **kwargs):
    request = model_request(scenario, model, **kwargs)
    body = request.signed_submission.submission.model_copy(
        update={"accepted_terms_sha256": NC_CONTRIBUTION_TERMS_SHA256}
    )
    signed = request.signed_submission.model_copy(
        update={"submission": body, "signature": sign_object(body, wallet("Alice"))}
    )
    consent = request.consent.consent.model_copy(update={"submission_sha256": digest(body)})
    return request.model_copy(
        update={
            "signed_submission": signed,
            "consent": request.consent.model_copy(
                update={"consent": consent, "signature": sign_object(consent, wallet("Alice"))}
            ),
        }
    )


def nc_inventory(h):
    direct_inventory(h)
    original = h.model
    source = Path(h.intake.config.directory).parent / "model-submission"
    records = [r for r in original.files if r.role not in ("license", "provenance")]
    for record in original.files:
        if record.role in ("license", "provenance"):
            (source / record.path).unlink()
    for name, body in documents().items():
        (source / name).write_bytes(body)
        records.append(
            BundleFile(
                path=name,
                role="license" if name in ("NOTICE", "LICENSE-WEIGHTS") else "provenance",
                sha256=hashlib.sha256(body).hexdigest(),
                size_bytes=len(body),
            )
        )
    proposal = prepare_model_license_adoption(
        policy=h.intake.policy,
        authority=h.history.authority,
        noncommercial_terms_sha256=NC_CONTRIBUTION_TERMS_SHA256,
        training_rights_policy_sha256=CONDITIONAL_TRAINING_RIGHTS_SHA256,
        operator_decision_sha256="be" * 32,
        issued_at_block=200,
        reason="Synthetic C7 conditional license full native pipeline qualification",
    )
    h.model = ModelBundle.model_validate_json(
        canonical_json_bytes(
            original.model_copy(
                update={
                    "schema_": "umi-model-bundle/2",
                    "license_id": "CC-BY-NC-SA-4.0",
                    "files": tuple(sorted(records, key=lambda item: item.path)),
                    "license_adoption": SignedModelLicenseTermsAdoption(
                        adoption=proposal, signatures=signatures(proposal)
                    ),
                }
            )
        )
    )
    h.request_for = lambda scenario, **kw: nc_model_request(scenario, h.model, **kw)


@pytest.mark.parametrize("lifecycle_before_intake", [nc_inventory], indirect=True)
@pytest.mark.parametrize("scenario", [{"adopted": True}], indirect=True)
async def test_nc_bundle_executes_certifies_and_replays_native_reward_package(
    host, scenario, runtime, tmp_path, monkeypatch, chain_config
):
    h = host.h
    baseline_before = h.owner.promotion.baseline()["model_sha256"]
    assert h.history.plan.sequence == 7
    assert h.model.schema_ == "umi-model-bundle/2"
    monkeypatch.setattr(direct_fixture, "model_request", nc_model_request)
    direct = NativeDirect(tmp_path / "direct", h.intake.policy, monkeypatch)
    settled = await run_pipeline(
        host,
        scenario,
        runtime,
        tmp_path,
        monkeypatch,
        chain_config,
        interrupt=True,
        mixed=False,
        direct=direct,
    )
    assert set(direct.candidate_jobs) == {"Charlie", "Dave"}
    for name, job in direct.candidate_jobs.items():
        assert job.submission.submission.model_bundle == h.model
        assert job.submission.submission.accepted_terms_sha256 == NC_CONTRIBUTION_TERMS_SHA256
        assert job.incumbent.schema_ == "umi-model-bundle/1"
        assert job.incumbent.license_adoption is None
        assert digest(job.incumbent) == baseline_before
        assert direct.candidate_invocations[name] == len(job.cases)
    assert settled.package.allocation.model_award.candidates[0].eligible
    assert sum(row.raw_weight for row in settled.package.allocation.recipients) == 65535
    assert not settled.package.chain_submission_authorized
    result = json.loads((tmp_path / "native-rewards" / "result.json").read_bytes())
    assert result["validator_preparation"] == "native_initial_package_replayed"
