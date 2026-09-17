"""Per-round publication with synthetic keys and fully replayed packages."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_successor_publication as publication_module
from umi.competition_launch import PublicRoundSchedule
from umi.competition_package import prepare_competition_package
from umi.competition_publication import build_cutoff_publication, build_settlement_publication
from umi.competition_settlement import CompetitionSettlement, EvidenceCutoffSchedule
from umi.competition_successor_publication import (
    SuccessorPublicationWeightParameters,
    SuccessorRoundPublicationBuilder,
    SuccessorRoundPublicationPlan,
)
from umi.competition_supervisor import verify_signed_successor_supervisor_directive
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_package import package_case as package_case
from .test_competition_package import package_limits as package_limits
from .test_competition_package import release_identity as release_identity
from .test_competition_publication import _certificate, _independent
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_supervisor import successor_case as successor_case
from .test_competition_supervisor import successor_chain as successor_chain
from .test_competition_supervisor import successor_release as successor_release
from .test_competition_supervisor import v3_predecessor as v3_predecessor
from .test_open_competition import attested, result_for, round_for, snapshot, submission, wallet
from .test_open_competition import policy as policy
from .test_validator_supervisor import _wallets as authority_wallets


@pytest.fixture
def publication_case(tmp_path, successor_case, package_limits, policy):
    s = successor_case
    target = s.release.replay_release_identity.target_triple
    plan = SuccessorRoundPublicationPlan(
        schema="umi-successor-round-publication-plan/1",
        policy_sha256=digest(policy),
        supervisor=s.predecessor.config,
        consent=s.consent,
        chain=s.chain,
        release=s.release.model_copy(
            update={"entrypoint_profile": "umi-competition-weight-worker/1"}
        ),
        package_limits=package_limits,
        weights=SuccessorPublicationWeightParameters(
            required_finality_verifier_sha256_by_target={target: "21" * 32},
            required_storage_proof_verifier_sha256_by_target={target: "22" * 32},
            weights_version_key=2**32,
            required_min_allowed_weights=256,
            required_max_allowed_uids=256,
            required_max_weights_limit=65535,
            required_weights_rate_limit=0,
            mortality_period=4,
        ),
        valid_from_block=125,
        valid_through_block=1000,
        maximum_lifetime_blocks=50,
        minimum_activation_headroom_blocks=2,
    )
    root = tmp_path / "publisher"
    builder = SuccessorRoundPublicationBuilder(root, plan)
    return SimpleNamespace(root=root, plan=plan, builder=builder)


def build(case, package, block=160, **changes):
    args = {
        "finalized_block": block,
        "authorization_wallet": authority_wallets()[0],
        "directive_wallets": authority_wallets()[:2],
    }
    args.update(changes)
    return case.builder.build(package.prepared, **args)


def test_publication_explicitly_signs_executor_pin(publication_case, package_case, tmp_path):
    case = publication_case
    target = case.plan.release.replay_release_identity.target_triple
    assert b"required_runtime_metadata_executor_sha256_by_target" not in canonical_json_bytes(
        case.plan
    )
    pins = {target: "23" * 32}
    parameters = case.plan.weights.model_copy(
        update={"required_runtime_metadata_executor_sha256_by_target": pins}
    )
    plan = case.plan.model_copy(update={"weights": parameters})
    builder = SuccessorRoundPublicationBuilder(tmp_path / "executed-publication", plan)
    case.builder = builder
    signed = build(case, package_case)
    assert signed.intent.authorization.required_runtime_metadata_executor_sha256_by_target == pins
    assert (
        signed.authorization.authorization.required_runtime_metadata_executor_sha256_by_target
        == pins
    )
    builder = SuccessorRoundPublicationBuilder(tmp_path / "executed-publication", plan)
    assert canonical_json_bytes(builder.history()[0]) == canonical_json_bytes(signed)


@pytest.mark.parametrize("pins", [{}, {"other": "23" * 32}])
def test_publication_rejects_incomplete_executor_targets(publication_case, pins):
    parameters = publication_case.plan.weights.model_dump()
    parameters["required_runtime_metadata_executor_sha256_by_target"] = pins
    with pytest.raises(ValueError):
        SuccessorPublicationWeightParameters.model_validate(parameters)


@pytest.fixture
def next_package(package_case, policy, replay_limits, package_limits, release_identity):
    """A later real settlement keeps the first round's promoted beneficiary."""
    previous = package_case.scenario
    store = previous.store
    model = next(s for s in previous.submissions if s.submission.track == "model")
    store.admit(
        submission(policy, bundle=model.submission.model_bundle, sequence=2, start=175, end=185),
        snapshot(175),
        175,
    )
    endpoint = submission(policy, name="Bob", sequence=2, start=190, end=260)
    store.admit(endpoint, snapshot(190), 190)
    suite = previous.suite.model_copy(
        update={
            "cases": tuple(
                c.model_copy(update={"video_sha256": f"{index + 1000:064x}"})
                for index, c in enumerate(previous.suite.cases)
            )
        }
    )
    round_ = round_for(policy, suite, (endpoint,), previous.promotion["model_sha256"]).model_copy(
        update={
            "sequence": 2,
            "public_schedule": PublicRoundSchedule(
                schema="umi-public-round-schedule/1",
                intake_opened_block=175,
                roster_close_earliest_block=200,
                roster_close_latest_block=200,
                work_signing_close_block=210,
                evaluation_close_block=220,
                protected_reference_reveal_block=230,
                evidence_cutoff_block=240,
                round_valid_through_block=260,
            ),
            "submission_close_block": 200,
            "evaluation_close_block": 220,
            "reveal_block": 230,
            "valid_through_block": 260,
        }
    )
    schedule = EvidenceCutoffSchedule(
        schema="umi-competition-evidence-cutoff/1",
        policy_sha256=digest(policy),
        round_sha256=digest(round_),
        evidence_cutoff_block=240,
    )
    store.fix_evidence_cutoff(round_, schedule, observed_block=200)
    store.close_round(round_, current_block=200)
    common = result_for(endpoint, round_, suite, baseline="hello").result.model_copy(
        update={"finished_block": 210}
    )
    evidence = ((endpoint, _independent(policy, endpoint, round_, suite, attested(common))),)
    store.record_independent_evaluation(
        signed=endpoint,
        evidence=evidence[0][1],
        round_=round_,
        suite=suite,
        observed_block=230,
    )
    settlement = CompetitionSettlement.model_validate_json(
        canonical_json_bytes(
            store.settle(
                round_=round_,
                suite=suite,
                evidence=evidence,
                snapshot=snapshot(240),
                current_block=240,
            )
        )
    )
    cutoff = _certificate(
        build_cutoff_publication(
            round_=round_,
            cutoff_schedule=schedule,
            registration_snapshot=snapshot(200),
            submissions=(endpoint,),
            policy=policy,
            limits=replay_limits,
        )
    )
    settled = _certificate(
        build_settlement_publication(
            cutoff_certificate=cutoff,
            retained_settlement=settlement,
            submissions=(endpoint,),
            evidence=evidence,
            policy=policy,
            limits=replay_limits,
        )
    )
    prepared = prepare_competition_package(
        policy=policy,
        cutoff_certificate=cutoff,
        settlement_certificate=settled,
        retained_settlement=settlement,
        roster=(endpoint,),
        evidence=evidence,
        replay_limits=replay_limits,
        release_identity=release_identity,
        destination_root=package_case.path.parent,
        limits=package_limits,
    )
    try:
        yield SimpleNamespace(prepared=prepared)
    finally:
        Path(prepared.package_path).chmod(0o700)


def test_exact_publication_replays_across_restart_and_remains_historical(
    publication_case, package_case
):
    case = publication_case
    signed = build(case, package_case)
    assert signed.intent.sequence == case.plan.consent.predecessor_sequence + 1
    assert signed.intent.round_sequence == package_case.scenario.round.sequence
    assert signed.intent.authorization.valid_through_block == 170
    assert signed.signed.directive.mode == "competition_weights"
    verify_signed_successor_supervisor_directive(
        signed.signed,
        config=case.plan.supervisor,
        operator_consent=case.plan.consent,
        finalized_block=160,
    )
    original = canonical_json_bytes(signed)
    case.builder = SuccessorRoundPublicationBuilder(case.root, case.plan)
    assert canonical_json_bytes(build(case, package_case, 161)) == original
    # An expired publication stays available for cursor catch-up. It is not
    # re-signed or extended to make an expired round active again.
    assert canonical_json_bytes(build(case, package_case, 180)) == original
    page = case.builder.page(
        after_version=3,
        after_sequence=case.plan.consent.predecessor_sequence,
        after_directive_sha256=case.plan.consent.predecessor_directive_sha256,
    )
    assert page.directives == [signed.signed] and not page.more
    caught_up = case.builder.page(
        after_version=4,
        after_sequence=signed.intent.sequence,
        after_directive_sha256=signed.signed.directive_sha256,
    )
    assert caught_up.directives == [] and caught_up.head == signed.signed
    with pytest.raises(ValueError, match=r"unknown.*cursor"):
        case.builder.page(
            after_version=4,
            after_sequence=signed.intent.sequence,
            after_directive_sha256="ff" * 32,
        )


@pytest.mark.parametrize("bad", ["authority", "quorum", "duplicate", "scheme"])
def test_bad_signers_do_not_reserve_an_intent(publication_case, package_case, bad):
    case = publication_case
    changes = {}
    if bad == "authority":
        changes["authorization_wallet"] = wallet("Alice")
    elif bad == "quorum":
        changes["directive_wallets"] = authority_wallets()[:1]
    elif bad == "duplicate":
        changes["directive_wallets"] = [authority_wallets()[0]] * 2
    else:
        signer = authority_wallets()[0].hotkey
        changes["authorization_wallet"] = SimpleNamespace(
            hotkey=SimpleNamespace(ss58_address=signer.ss58_address, crypto_type=99)
        )
    with pytest.raises((ValueError, TypeError)):
        build(case, package_case, **changes)
    assert case.builder.journal.keys("intent") == []
    assert case.builder.journal.keys("round") == []
    assert case.builder.history() == []
    assert build(case, package_case).signed.directive.sequence == 2


def test_insufficient_original_window_is_not_extended(publication_case, package_case):
    with pytest.raises(ValueError, match="activation and mortality window"):
        build(publication_case, package_case, 168)
    assert publication_case.builder.history() == []


def test_tampered_package_fails_before_signing(publication_case, package_case):
    package_case.prepared = package_case.prepared.model_copy(update={"manifest_sha256": "ff" * 32})
    with pytest.raises(ValueError, match="manifest differs"):
        build(publication_case, package_case)
    assert publication_case.builder.journal.keys("intent") == []


def test_plan_changes_are_rejected_on_restart(publication_case):
    case = publication_case
    changed = case.plan.model_copy(update={"maximum_lifetime_blocks": 49})
    with pytest.raises(ValueError, match="configuration changed"):
        SuccessorRoundPublicationBuilder(case.root, changed)


def test_consecutive_rounds_extend_the_exact_signed_predecessor(
    publication_case, package_case, next_package
):
    case = publication_case
    first = build(case, package_case)
    original = canonical_json_bytes(first)
    case.builder = SuccessorRoundPublicationBuilder(case.root, case.plan)
    second = build(case, next_package, 240)
    assert second.intent.sequence == first.intent.sequence + 1
    assert second.intent.predecessor_version == 4
    assert second.intent.authorization.predecessor_directive_sha256 == first.signed.directive_sha256
    assert second.intent.authorization.signed_at_block == 240
    assert second.intent.authorization.valid_through_block == 250
    history = case.builder.history()
    assert len(history) == 2 and canonical_json_bytes(history[0]) == original


def test_expired_partial_signing_preserves_bytes_and_allows_a_later_round(
    publication_case, package_case, next_package, monkeypatch
):
    case = publication_case
    real_sign = publication_module.sign_response_digest

    def interrupted(*args, **kwargs):
        raise RuntimeError("injected signing interruption")

    monkeypatch.setattr(publication_module, "sign_response_digest", interrupted)
    with pytest.raises(RuntimeError, match="injected signing interruption"):
        build(case, package_case)
    intent = case.builder.journal.get("intent", "2:1")
    authorization = case.builder.journal.get("authorization", "2:1")
    assert authorization is not None and case.builder.history() == []
    # Equality is still inside the authorization's window, even without headroom.
    with pytest.raises(ValueError, match="unfinished publication"):
        case.builder._reserved_intent(
            sequence=2,
            round_sequence=2,
            predecessor=case.plan.consent.predecessor_directive_sha256,
            block=170,
        )
    assert not case.builder.journal.keys("expired_intent")
    monkeypatch.setattr(publication_module, "sign_response_digest", real_sign)
    case.builder = SuccessorRoundPublicationBuilder(case.root, case.plan)
    with pytest.raises(ValueError, match="reserved publication expired"):
        build(case, package_case, 240)
    second = build(case, next_package, 240)
    assert second.intent.sequence == 2 and second.intent.round_sequence == 2
    assert second.intent.predecessor_version == 3
    assert second.intent.authorization.signed_at_block == 240
    assert case.builder.journal.get("intent", "2:1") == intent
    assert case.builder.journal.get("authorization", "2:1") == authorization
    assert case.builder.journal.get("expired_intent", "2:1") == {
        "schema": "umi-expired-successor-publication-intent/1",
        "intent_sha256": digest(
            publication_module.SuccessorRoundPublicationIntent.model_validate(intent)
        ),
        "first_observed_expired_block": 240,
    }
    assert canonical_json_bytes(build(case, next_package, 241)) == canonical_json_bytes(second)
    assert len(case.builder.history()) == 1


def test_partial_signing_retries_the_original_authorization_before_expiry(
    publication_case, package_case, monkeypatch
):
    case = publication_case
    real_sign = publication_module.sign_response_digest

    def interrupted(*args, **kwargs):
        raise RuntimeError("injected signing interruption")

    monkeypatch.setattr(publication_module, "sign_response_digest", interrupted)
    with pytest.raises(RuntimeError, match="injected signing interruption"):
        build(case, package_case)
    authorization = case.builder.journal.get("authorization", "2:1")
    monkeypatch.setattr(publication_module, "sign_response_digest", real_sign)
    case.builder = SuccessorRoundPublicationBuilder(case.root, case.plan)
    recovered = build(case, package_case, 161)
    assert recovered.intent.authorization.signed_at_block == 160
    assert recovered.intent.authorization.valid_through_block == 170
    assert recovered.authorization.model_dump(mode="json", by_alias=True) == authorization


def test_partial_quorum_reuses_each_retained_directive_signature(
    publication_case, package_case, monkeypatch
):
    case = publication_case
    real_sign = publication_module.sign_response_digest
    calls = []

    def interrupted(wallet, body):
        calls.append(wallet.hotkey.ss58_address)
        if len(calls) == 2:
            raise RuntimeError("interrupted before second signature")
        return real_sign(wallet, body)

    monkeypatch.setattr(publication_module, "sign_response_digest", interrupted)
    with pytest.raises(RuntimeError, match="interrupted before second signature"):
        build(case, package_case)
    keys = case.builder.journal.keys("directive_signature")
    assert len(keys) == 1 and not case.builder.history()
    first = case.builder.journal.get("directive_signature", keys[0])
    calls.clear()

    def resumed(wallet, body):
        calls.append(wallet.hotkey.ss58_address)
        return real_sign(wallet, body)

    monkeypatch.setattr(publication_module, "sign_response_digest", resumed)
    case.builder = SuccessorRoundPublicationBuilder(case.root, case.plan)
    recovered = build(case, package_case, 161)
    assert calls == [authority_wallets()[1].hotkey.ss58_address]
    assert first in [s.model_dump(mode="json", by_alias=True) for s in recovered.signed.signatures]
    assert recovered.intent.authorization.signed_at_block == 160
