from __future__ import annotations

import argparse

import bittensor as bt
import httpx
import pytest

from umi.competition_client import CompetitionSubmissionError
from umi.competition_cohort_client import submit_cohort_participation
from umi.competition_cohort_intake import CohortIntake, history_tip
from umi.competition_cohort_participation import CohortParticipationRequest
from umi.competition_commands import cohorts
from umi.competition_commands.arguments import build_parser
from umi.competition_service import create_intake_app
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain_config as chain_config
from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_consumers import transition
from .test_competition_cohort_intake import capture_at, request_for
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_service import Provider
from .test_competition_service import config as config
from .test_competition_service import public_deployment as public_deployment
from .test_open_competition import policy as policy
from .test_open_competition import wallet


async def test_native_service_client_survives_restart_and_lost_ack(
    config, policy, intake, scenario
):
    request = request_for(scenario)
    config = config.model_copy(update={"recoverable_intake": intake.config})
    first = None
    for _ in range(2):
        provider = Provider(config.chain, policy)
        provider.capture = capture_at(210)
        app = create_intake_app(config, policy, provider_factory=lambda *_, p=provider: p)
        async with app.router.lifespan_context(app):
            current = await submit_cohort_participation(
                origin="https://intake.example",
                policy=policy,
                request=request,
                transport=httpx.ASGITransport(app),
            )
        if first is None:
            first = current
        assert first == current
        assert current.status == "pending_attestation"
        assert current.certified is current.chain_submission_authorized is False
        assert provider.closed


@pytest.mark.parametrize(
    "field,value",
    [
        ("consent_sha256", "ff" * 32),
        ("submission_sha256", "ff" * 32),
        ("cohort_sha256", "ff" * 32),
        ("admitted_at_block", 150),
        ("rewards_active", True),
        ("certified", True),
    ],
)
async def test_client_rejects_wrong_binding_or_reward_claim(intake, scenario, field, value):
    request = request_for(scenario)
    receipt = intake.retain(request, capture_at(210))
    if field in ("rewards_active", "certified"):
        receipt[field] = value
    else:
        receipt["proposed_admission"][field] = value
    with pytest.raises(CompetitionSubmissionError):
        await submit_cohort_participation(
            origin="https://intake.example",
            policy=scenario["policy"],
            request=request,
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=receipt)),
        )


async def test_client_retry_preserves_every_signed_byte(intake, scenario):
    request = request_for(scenario)
    observed = []
    receipt = intake.retain(request, capture_at(210))

    def serve(wire):
        observed.append(wire.content)
        assert (
            wire.url.path
            == f"/v1/competition/cohorts/{request.consent.consent.cohort_sha256}/participation"
        )
        if len(observed) == 1:
            raise httpx.ReadError("PRIVATE response lost after commit")
        return httpx.Response(200, json=receipt)

    options = dict(
        origin="https://intake.example",
        policy=scenario["policy"],
        request=request,
        transport=httpx.MockTransport(serve),
    )
    with pytest.raises(CompetitionSubmissionError, match="transport_unavailable"):
        await submit_cohort_participation(**options)
    assert (await submit_cohort_participation(**options)).record_sha256 == receipt["record_sha256"]
    assert observed == [canonical_json_bytes(request)] * 2


def test_signing_command_uses_only_hotkey_and_preserves_original_submission(
    tmp_path, scenario, monkeypatch
):
    request = request_for(scenario)
    files = {}
    for name, value in (
        ("consent", request.consent.consent),
        ("submission", request.signed_submission),
        ("history", scenario["intake_history"]),
    ):
        files[name] = str(tmp_path / (name + ".json"))
        (tmp_path / (name + ".json")).write_bytes(canonical_json_bytes(value))
    used = []

    def resolve_wallet(**kwargs):
        used.append(kwargs)
        return wallet("Alice")

    monkeypatch.setattr(bt, "Wallet", resolve_wallet)
    arguments = [
        "--policy",
        "policy.json",
        "sign-cohort-consent",
        "--current-block",
        "210",
        "--expected-tip-sha256",
        history_tip(scenario["intake_history"]),
        "--wallet-name",
        "miner",
        "--hotkey-name",
        "hotkey",
        "--wallet-path",
        "unused",
    ]
    for name, path in files.items():
        arguments += ["--" + name, path]
    args = build_parser().parse_args(arguments)
    actual = CohortParticipationRequest.model_validate(
        cohorts.sign_consent(args, scenario["policy"])
    )
    assert canonical_json_bytes(actual.signed_submission) == canonical_json_bytes(
        request.signed_submission
    )
    assert actual.consent.consent == request.consent.consent
    assert used == [{"name": "miner", "hotkey": "hotkey", "path": "unused"}]
    args.expected_tip_sha256 = "ff" * 32
    with pytest.raises(ValueError, match="current tip"):
        cohorts.sign_consent(args, scenario["policy"])
    assert len(used) == 1


def test_initialization_is_explicit_and_policy_bound(config, intake, policy, tmp_path):
    config = config.model_copy(update={"recoverable_intake": intake.config})
    path = tmp_path / "config.json"
    path.write_bytes(canonical_json_bytes(config))
    args = argparse.Namespace(config=str(path))
    assert cohorts.initialize_intake(args, policy)["status"] == "cohort_intake_initialized"
    assert CohortIntake(intake.config, policy).config == intake.config
    with pytest.raises(ValueError, match="does not select"):
        cohorts.initialize_intake(args, policy.model_copy(update={"sequence": 2}))


async def test_native_service_accepts_recovery_after_policy_expiry(
    config, policy, intake, scenario
):
    history = transition(scenario["intake_history"], policy, "extend", 1600, extension=1200)
    intake.publish(history, capture_at(1610))
    request = request_for(scenario, block=1610)
    config = config.model_copy(update={"recoverable_intake": intake.config})
    provider = Provider(config.chain, policy)
    provider.capture = capture_at(1610)
    app = create_intake_app(config, policy, provider_factory=lambda *_: provider)
    async with app.router.lifespan_context(app):
        receipt = await submit_cohort_participation(
            origin="https://intake.example",
            policy=policy,
            request=request,
            transport=httpx.ASGITransport(app),
        )
        assert receipt.proposed_admission.admitted_at_block > policy.valid_through_block
        with pytest.raises(ValueError, match="not current"):
            await app.state.registration_snapshot_cache.collect_fresh()
    assert provider.closed


@pytest.mark.parametrize("damage", ["stale", "ancestry", "snapshot"])
async def test_extended_service_keeps_owned_freshness_requirements(
    config, policy, intake, scenario, damage
):
    history = transition(scenario["intake_history"], policy, "extend", 1600, extension=1200)
    intake.publish(history, capture_at(1610))
    config = config.model_copy(update={"recoverable_intake": intake.config})
    provider = Provider(config.chain, policy)
    provider.capture = capture_at(1610)
    if damage == "stale":
        provider.capture.provenance["timestamp_ms"] = 1
    elif damage == "ancestry":
        provider.capture.provenance["evidence_class"] = "verified_finalized_ancestry"
    else:
        provider.capture.provenance["snapshot_sha256"] = "ff" * 32
    app = create_intake_app(config, policy, provider_factory=lambda *_: provider)
    request = request_for(scenario, block=1610)
    async with app.router.lifespan_context(app):
        with pytest.raises(CompetitionSubmissionError) as error:
            await submit_cohort_participation(
                origin="https://intake.example",
                policy=policy,
                request=request,
                transport=httpx.ASGITransport(app),
            )
        assert error.value.status_code == 503
        assert intake.receipt(request) is None
