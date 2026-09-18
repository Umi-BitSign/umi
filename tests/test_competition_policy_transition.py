from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import bittensor as bt
import pytest

from umi.competition_cli import _parser, execute
from umi.competition_client import AdmissionReceipt
from umi.competition_launch import PublicIntakeDeployment, PublicRoundSchedule
from umi.competition_policy_transition import prepare_endpoint_policy_transition
from umi.open_competition import (
    BurnDestination,
    CompetitionPolicy,
    Evaluator,
    Registration,
    RegistrationSnapshot,
    SignedSubmission,
    Submission,
    digest,
    sign_object,
    validate_admission,
)
from umi.protocol import canonical_json_bytes

ROOT = Path(__file__).parents[1]


def wallet(name: str):
    key = bt.sp_core.Keypair.create_from_uri("//" + name, crypto_type=bt.sp_core.CRYPTO_SR25519)
    return SimpleNamespace(hotkey=key, coldkey=key, coldkeypub=key)


def policies() -> tuple[CompetitionPolicy, CompetitionPolicy]:
    evaluator = wallet("Charlie").hotkey.ss58_address
    burn = wallet("Bob").hotkey.ss58_address
    prior = CompetitionPolicy(
        schema="umi-open-competition-policy/3",
        network="finney",
        netuid=78,
        sequence=4,
        predecessor_sha256="01" * 32,
        valid_from_block=100,
        valid_through_block=1000,
        endpoint_reward_bps=7000,
        model_reward_bps=3000,
        minimum_score_bps=1000,
        promotion_margin_bps=100,
        minimum_cases_per_stratum=3,
        maximum_inference_ms=120_000,
        maximum_output_bytes=4096,
        maximum_bundle_bytes=10_000,
        maximum_bundle_files=20,
        minimum_submission_interval_blocks=5,
        maximum_submission_lifetime_blocks=900,
        maximum_snapshot_age_blocks=10,
        maximum_uids=256,
        evaluators=(Evaluator(hotkey=evaluator, control_group="operator"),),
        required_evaluator_groups=1,
        contribution_terms_sha256="a1" * 32,
        accepted_model_licenses=("MIT",),
        evaluation_runtime_sha256="a2" * 32,
        unallocated_model_burn=BurnDestination(uid=0, hotkey=burn),
    )
    successor = prior.model_copy(
        update={
            "schema_": "umi-open-competition-policy/4",
            "sequence": 5,
            "predecessor_sha256": digest(prior),
            "contribution_terms_sha256": "b2" * 32,
            "minimum_continuous_observed_margin_bps": 31,
            "continuous_dependence_lower_bound_floor_bps": 0,
            "minimum_continuous_dependence_pairs": 12,
            "continuous_dependence_duration_bins": 6,
            "maximum_counterfactual_duration_delta_ms": 500,
            "continuous_dependence_bootstrap_replicates": 4096,
            "continuous_dependence_confidence_bps": 9500,
            "positive_control_model_sha256": "f2" * 32,
            "minimum_positive_control_dependence_bps": 5000,
        }
    )
    return prior, CompetitionPolicy.model_validate_json(canonical_json_bytes(successor))


def deployment() -> PublicIntakeDeployment:
    return PublicIntakeDeployment(
        schema="umi-competition-intake-deployment/2",
        repository="https://github.com/Umi-BitSign/umi",
        umi_git_revision="01" * 20,
        umi_source_tree_sha256="02" * 32,
        deployed_at_utc="2026-09-18T00:00:00Z",
        round_schedule=PublicRoundSchedule(
            schema="umi-public-round-schedule/1",
            intake_opened_block=100,
            roster_close_earliest_block=300,
            roster_close_latest_block=310,
            work_signing_close_block=320,
            evaluation_close_block=500,
            protected_reference_reveal_block=510,
            evidence_cutoff_block=520,
            round_valid_through_block=600,
        ),
        eligible_tracks=("endpoint",),
        assignment_delivery_ready=False,
        model_intake_ready=False,
    )


def accepted_predecessor(prior: CompetitionPolicy) -> tuple[SignedSubmission, AdmissionReceipt]:
    miner = wallet("Alice")
    submission = Submission(
        schema="umi-competition-submission/1",
        network="finney",
        netuid=78,
        policy_sha256=digest(prior),
        hotkey=miner.hotkey.ss58_address,
        track="endpoint",
        sequence=2,
        valid_from_block=100,
        valid_through_block=500,
        model_revision="b1" * 32,
        endpoint_url="https://miner.example",
        model_bundle=None,
        accepted_terms_sha256=prior.contribution_terms_sha256,
    )
    signed = SignedSubmission(
        submission=submission,
        signature=sign_object(submission, miner),
    )
    snapshot = RegistrationSnapshot(
        network="finney",
        netuid=78,
        block=150,
        block_hash="0x" + "03" * 32,
        registrations=(Registration(uid=6, hotkey=miner.hotkey.ss58_address),),
    )
    receipt = AdmissionReceipt(
        schema="umi-competition-admission/2",
        policy_sha256=digest(prior),
        submission_sha256=digest(submission),
        accepted_block=150,
        registration_snapshot_sha256=digest(snapshot),
        registration_snapshot=snapshot,
        registration_source="verifier_attested_finality",
        observed_uid=6,
        status="accepted_no_weight",
        chain_submission_authorized=False,
    )
    return signed, receipt


def test_transition_requires_new_signature_and_preserves_predecessor_bytes():
    prior, successor = policies()
    signed, receipt = accepted_predecessor(prior)
    prior_bytes = canonical_json_bytes(signed)

    prepared = prepare_endpoint_policy_transition(
        prior_policy=prior,
        successor_policy=successor,
        prior_submission=signed,
        prior_receipt=receipt,
        deployment=deployment(),
        current_block=200,
    )

    assert canonical_json_bytes(signed) == prior_bytes
    assert prepared.policy_sha256 == digest(successor)
    assert prepared.accepted_terms_sha256 == successor.contribution_terms_sha256
    assert prepared.sequence == signed.submission.sequence + 1
    assert prepared.endpoint_url == signed.submission.endpoint_url
    assert prepared.model_revision == signed.submission.model_revision
    assert prepared.valid_from_block == 200
    assert prepared.valid_through_block == 500

    resigned = SignedSubmission(
        submission=prepared,
        signature=sign_object(prepared, wallet("Alice")),
    )
    current = RegistrationSnapshot(
        network="finney",
        netuid=78,
        block=200,
        block_hash="0x" + "04" * 32,
        registrations=(Registration(uid=6, hotkey=prepared.hotkey),),
    )
    assert validate_admission(resigned, successor, current, 200) == 6


@pytest.mark.parametrize(
    "change",
    (
        {"predecessor_sha256": "ff" * 32},
        {"sequence": 6},
        {"endpoint_reward_bps": 6999, "model_reward_bps": 3001},
        {"contribution_terms_sha256": "a1" * 32},
    ),
)
def test_transition_rejects_policy_drift(change):
    prior, successor = policies()
    signed, receipt = accepted_predecessor(prior)
    successor = CompetitionPolicy.model_validate_json(
        canonical_json_bytes(successor.model_copy(update=change))
    )
    with pytest.raises(ValueError, match="successor changes more"):
        prepare_endpoint_policy_transition(
            prior_policy=prior,
            successor_policy=successor,
            prior_submission=signed,
            prior_receipt=receipt,
            deployment=deployment(),
            current_block=200,
        )


def test_transition_rejects_tampered_receipt_and_late_resign():
    prior, successor = policies()
    signed, receipt = accepted_predecessor(prior)
    changed = receipt.model_copy(update={"submission_sha256": "ff" * 32})
    with pytest.raises(ValueError, match="does not bind"):
        prepare_endpoint_policy_transition(
            prior_policy=prior,
            successor_policy=successor,
            prior_submission=signed,
            prior_receipt=changed,
            deployment=deployment(),
            current_block=200,
        )
    with pytest.raises(ValueError, match="no longer guaranteed"):
        prepare_endpoint_policy_transition(
            prior_policy=prior,
            successor_policy=successor,
            prior_submission=signed,
            prior_receipt=receipt,
            deployment=deployment(),
            current_block=301,
        )


@pytest.mark.parametrize("accepted_block", (201, 311))
def test_transition_rejects_receipt_after_observation_or_roster_close(accepted_block):
    prior, successor = policies()
    signed, receipt = accepted_predecessor(prior)
    snapshot = receipt.registration_snapshot.model_copy(
        update={"block": accepted_block, "block_hash": "0x" + f"{accepted_block:064x}"}
    )
    receipt = receipt.model_copy(
        update={
            "accepted_block": accepted_block,
            "registration_snapshot": snapshot,
            "registration_snapshot_sha256": digest(snapshot),
        }
    )
    with pytest.raises(ValueError, match="outside the endpoint launch"):
        prepare_endpoint_policy_transition(
            prior_policy=prior,
            successor_policy=successor,
            prior_submission=signed,
            prior_receipt=receipt,
            deployment=deployment(),
            current_block=200 if accepted_block == 201 else 400,
        )


def test_published_terms_and_successor_policy_have_fixed_digests():
    version_1 = (ROOT / "docs/MODEL_CONTRIBUTION_TERMS.md").read_bytes()
    version_2 = (ROOT / "docs/MODEL_CONTRIBUTION_TERMS_V2.md").read_bytes()
    raw_prior = (ROOT / "docs/competition/FIRST_ROUND_INTAKE_POLICY_V1.json").read_bytes()
    raw_policy = (ROOT / "docs/competition/FIRST_ROUND_STAGED_POLICY.json").read_bytes()
    prior = CompetitionPolicy.model_validate_json(raw_prior)
    policy = CompetitionPolicy.model_validate_json(raw_policy)

    assert hashlib.sha256(version_1).hexdigest() == (
        "61f333f6105c8e8a06db9d51a7a47a3cf0c5c0c72d7794fe1e5e6744eafcca62"
    )
    assert hashlib.sha256(version_2).hexdigest() == (
        "c8efb288f648e26f178e2e253c9c282a7500107371866f1ab7d62a9e80ef935b"
    )
    assert raw_policy == canonical_json_bytes(policy) + b"\n"
    assert raw_prior == canonical_json_bytes(prior) + b"\n"
    assert digest(prior) == "81c118c5b45527650d7f304a6574d04223de30fbad76c69df09e7f2ae4897fa0"
    assert digest(policy) == "eae2a709bd54468d7ea42c370867be77144115ec709c22e976320828a0e90e56"
    assert policy.predecessor_sha256 == digest(prior)
    assert policy.contribution_terms_sha256 == hashlib.sha256(version_2).hexdigest()
    assert policy.endpoint_reward_bps == 7000
    assert policy.model_reward_bps == 3000
    assert policy.unallocated_model_burn is not None


def test_transition_command_reads_retained_files_and_emits_unsigned_successor(tmp_path: Path):
    prior, successor = policies()
    signed, receipt = accepted_predecessor(prior)
    values = {
        "policy": successor,
        "prior-policy": prior,
        "prior-submission": signed,
        "prior-receipt": receipt,
        "deployment": deployment(),
    }
    paths = {}
    for name, value in values.items():
        path = tmp_path / f"{name}.json"
        path.write_bytes(canonical_json_bytes(value) + b"\n")
        paths[name] = path

    args = _parser().parse_args(
        [
            "--policy",
            str(paths["policy"]),
            "prepare-endpoint-policy-transition",
            "--prior-policy",
            str(paths["prior-policy"]),
            "--prior-submission",
            str(paths["prior-submission"]),
            "--prior-receipt",
            str(paths["prior-receipt"]),
            "--deployment",
            str(paths["deployment"]),
            "--current-block",
            "200",
        ]
    )
    prepared = Submission.model_validate(execute(args))

    assert prepared.policy_sha256 == digest(successor)
    assert prepared.accepted_terms_sha256 == successor.contribution_terms_sha256
    assert prepared.endpoint_url == signed.submission.endpoint_url
    assert prepared.sequence == signed.submission.sequence + 1
