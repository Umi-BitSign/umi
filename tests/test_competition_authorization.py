from __future__ import annotations

import hashlib
import time
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_authorization import (
    EndpointAssignment,
    EndpointAuthorizationAuthority,
    EndpointAuthorizationCase,
    EndpointAuthorizationPublication,
    SignedEndpointAuthorization,
    assignment_batch_id,
    assignment_challenge_id,
    validate_publication,
    validate_publication_suite,
    validate_transport_cohort,
)
from umi.config import Limits
from umi.miner_admission import MinerAdmissionError
from umi.open_competition import (
    EvaluationCase,
    EvaluationRound,
    EvaluationSuite,
    Evaluator,
    SignedSubmission,
    SingleReferenceEvaluationCase,
    digest,
    sign_object,
)
from umi.policy import SINGLE_EVALUATOR_TRANSPORT_SCHEMA, ScoringPolicy, scoring_policy_hash
from umi.protocol import TranslationRequest, canonical_json_bytes
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .factories import challenge_request
from .test_open_competition import policy as policy
from .test_open_competition import submission, wallet
from .test_validator_plans import FinalizedPort, _block, _clock, _live_policy


def build_authorization_fixture(
    policy,
    *,
    case_count=3,
    legacy_policy=None,
    incumbent_sha256=None,
    model_bundle=None,
    extra_model_bundle=None,
    window_index=0,
    sequence=1,
    serving_origin="https://8.8.8.8:443",
    single_evaluator=False,
    legacy_calibration_inputs=False,
    issue_allowance_seconds=300,
):
    """Synthetic signed publication and owned-source test port; no network/files.

    Return the updated competition policy as .policy. This helper supplies test
    identities and allocations only; none of its values are release defaults.
    """
    legacy = _live_policy(activation_block=1000) if legacy_policy is None else legacy_policy
    evaluator_wallets = tuple(wallet(f"Validator{i}") for i in range(4))
    if single_evaluator:
        evaluator_wallets = evaluator_wallets[:1]
        data = legacy.model_dump(mode="json", by_alias=True)
        data["schema"] = SINGLE_EVALUATOR_TRANSPORT_SCHEMA
        data["publisher_registry"] = []
        data["control_group_registry"] = []
        data["validator_registry"] = [
            item
            for item in data["validator_registry"]
            if item["validator_hotkey"] == evaluator_wallets[0].hotkey.ss58_address
        ]
        legacy = ScoringPolicy.model_validate(data)
        if not legacy_calibration_inputs:
            legacy = ScoringPolicy.competition_transport(
                activation_block=legacy.activation_block,
                implementation_pins=legacy.implementation_pins,
                validator=legacy.validator_registry[0],
                issue_allowance_seconds=issue_allowance_seconds,
            )
    policy = policy.model_copy(
        update={
            "valid_from_block": 1000,
            "valid_through_block": 2000,
            "minimum_cases_per_stratum": 1,
            "required_evaluator_groups": 1 if single_evaluator else 2,
            "evaluators": tuple(
                Evaluator(hotkey=w.hotkey.ss58_address, control_group=f"group-{g}")
                for w, g in zip(
                    evaluator_wallets, (0, 1, 0, 3)[: len(evaluator_wallets)], strict=True
                )
            ),
        }
    )
    now_ms = time.time_ns() // 1_000_000
    announcement = _block(
        legacy,
        window_index,
        block_byte=f"{0x31 + window_index:02x}",
        timestamp_ms=now_ms
        - 1000
        * (
            legacy.clock.anchor_blocks * legacy.clock.target_block_interval_seconds
            + legacy.clock.selection_finality_buffer_seconds
        ),
    )
    schedule = _clock(legacy).derive(
        window_index,
        netuid=78,
        announcement_block_hash=announcement.block_hash,
        announcement_timestamp_ms=announcement.timestamp_ms,
        scoring_policy_hash=scoring_policy_hash(legacy),
    )
    issued = schedule.closing_block + 1
    issuance = _block(
        legacy,
        window_index,
        block_byte=f"{0x41 + window_index:02x}",
        height=issued,
        timestamp_ms=QUICKNET_GENESIS_MS + (schedule.selection_round - 1) * QUICKNET_PERIOD_MS,
    )
    finality = FinalizedPort(
        head=issued, blocks={announcement.height: announcement, issuance.height: issuance}
    )
    sub = submission(policy, start=1000, end=1900).submission.model_copy(
        update={"endpoint_url": serving_origin}
    )
    signed_sub = SignedSubmission(submission=sub, signature=sign_object(sub, wallet("Alice")))
    model_sub = (
        None
        if model_bundle is None
        else submission(policy, bundle=model_bundle, name="Bob", start=1000, end=1900)
    )
    extra_model_sub = (
        None
        if extra_model_bundle is None
        else submission(policy, bundle=extra_model_bundle, name="Eve", start=1000, end=1900)
    )
    submissions = tuple(
        sorted(
            (s for s in (signed_sub, model_sub, extra_model_sub) if s is not None),
            key=lambda s: digest(s.submission),
        )
    )
    video_bytes = tuple(f"inert-endpoint-video-{i}".encode() for i in range(case_count))
    two_task = policy.schema_ == "umi-open-competition-policy/2"
    case_type = SingleReferenceEvaluationCase if two_task else EvaluationCase
    strata = (
        ("fingerspelling", "continuous")
        if two_task
        else ("fingerspelling", "short_utterance", "continuous")
    )
    suite = EvaluationSuite(
        schema="umi-competition-suite/2" if two_task else "umi-competition-suite/1",
        policy_sha256=digest(policy),
        cases=tuple(
            case_type(
                case_id=f"{window_index * 1000 + i + 1:064x}",
                video_sha256=hashlib.sha256(video_bytes[i]).hexdigest(),
                stratum=strata[i % len(strata)],
                references=("hello",) if two_task else ("hello", "hi", "greetings"),
            )
            for i in range(case_count)
        ),
    )
    round_ = EvaluationRound(
        schema="umi-competition-round/1",
        policy_sha256=digest(policy),
        sequence=sequence,
        suite_sha256=digest(suite),
        incumbent_model_sha256=incumbent_sha256 or "b2" * 32,
        runtime_sha256=policy.evaluation_runtime_sha256,
        roster=tuple(digest(s.submission) for s in submissions),
        submission_close_block=issued - 1,
        evaluation_close_block=issued + schedule.response_deadline_blocks + 1,
        reveal_block=issued + schedule.response_deadline_blocks + 2,
        valid_through_block=max(
            1200 + window_index * legacy.clock.window_stride_blocks,
            issued + schedule.response_deadline_blocks + 3,
        ),
    )
    cases = tuple(
        EndpointAuthorizationCase(case_id=c.case_id, video_sha256=c.video_sha256, stratum=c.stratum)
        for c in suite.cases
    )
    assignments = []
    for evaluator in evaluator_wallets[:2]:
        for index, case in enumerate(cases):
            ids = dict(
                policy_sha256=digest(policy),
                round_sha256=digest(round_),
                submission_sha256=digest(sub),
                evaluator_hotkey=evaluator.hotkey.ss58_address,
            )
            request = challenge_request(stratum=case.stratum)
            request = request.model_copy(
                update={
                    "window_id": schedule.window_id,
                    "batch_id": assignment_batch_id(**ids),
                    "challenge_id": assignment_challenge_id(**ids, case_sha256=digest(case)),
                    "issued_block": issued,
                    "issued_block_hash": issuance.block_hash,
                    "deadline_block": issued + schedule.response_deadline_blocks,
                    "response_close_round": schedule.response_close_round,
                    "reveal_round": schedule.reveal_round,
                    "scoring_policy_hash": scoring_policy_hash(legacy),
                    "video": request.video.model_copy(
                        update={"sha256": case.video_sha256, "size_bytes": len(video_bytes[index])}
                    ),
                }
            )
            assignments.append(
                EndpointAssignment(
                    submission_sha256=digest(sub),
                    case_sha256=digest(case),
                    evaluator_hotkey=evaluator.hotkey.ss58_address,
                    request=request,
                )
            )
    body = EndpointAuthorizationPublication(
        schema="umi-endpoint-authorization-publication/1",
        policy_sha256=digest(policy),
        legacy_policy_sha256=scoring_policy_hash(legacy),
        round=round_,
        submissions=(signed_sub,),
        cases=cases,
        assignments=tuple(assignments),
    )
    publication = SignedEndpointAuthorization(
        publication=body, signatures=tuple(sign_object(body, w) for w in evaluator_wallets[:2])
    )
    return SimpleNamespace(
        policy=policy,
        legacy_policy=legacy,
        publication=publication,
        finalized_blocks=finality,
        request=assignments[0].request,
        miner_wallet=wallet("Alice"),
        validator_wallet=evaluator_wallets[0],
        evaluator_wallets=evaluator_wallets,
        model_revision=sub.model_revision,
        serving_origin=serving_origin,
        signed_submission=signed_sub,
        model_submission=model_sub,
        extra_model_submission=extra_model_sub,
        submissions=submissions,
        suite=suite,
        round=round_,
        cases=cases,
        schedule=schedule,
        video_bytes=video_bytes[0],
        all_video_bytes=video_bytes,
    )


@pytest.fixture
def authorization(policy):
    return build_authorization_fixture(policy)


def _authority(fixture, **overrides):
    return EndpointAuthorizationAuthority(
        **{
            "policy": fixture.policy,
            "legacy_policy": fixture.legacy_policy,
            "publication": fixture.publication,
            "finalized_blocks": fixture.finalized_blocks,
            "miner_hotkey": fixture.miner_wallet.hotkey.ss58_address,
            "model_revision": fixture.model_revision,
            "serving_origin": fixture.serving_origin,
            **overrides,
        }
    )


def _resign(fixture, body, *, signers=None):
    return SignedEndpointAuthorization(
        publication=body,
        signatures=tuple(sign_object(body, w) for w in (signers or fixture.evaluator_wallets[:2])),
    )


def _runtime(fixture, **overrides):
    limits = Limits.from_policy(fixture.legacy_policy)
    return {
        "miner_hotkey": fixture.miner_wallet.hotkey.ss58_address,
        "model_revision": fixture.model_revision,
        "transport_policy_sha256": scoring_policy_hash(fixture.legacy_policy),
        "allowed_validator_hotkeys": frozenset(
            v.validator_hotkey for v in fixture.legacy_policy.validator_registry
        ),
        "limits": replace(
            limits,
            inference_timeout_seconds=fixture.policy.maximum_inference_ms / 1000,
            maximum_hypothesis_utf8_bytes=fixture.policy.maximum_output_bytes,
        ),
        **overrides,
    }


async def test_exact_signed_assignment_still_uses_owned_legacy_schedule(authorization):
    authority = _authority(authorization)
    authority.validate_runtime(**_runtime(authorization))
    admission = await authority.authorize(
        authorization.request, validator_hotkey=authorization.validator_wallet.hotkey.ss58_address
    )
    assert admission.window_id == authorization.request.window_id
    assert admission.observed_finalized_height == authorization.request.issued_block
    assert authorization.finalized_blocks.block_calls == [1000, authorization.request.issued_block]
    assert authority.policy_sha256 == digest(authorization.policy)
    assert authority.transport_policy_sha256 == scoring_policy_hash(authorization.legacy_policy)
    assert authority.publication_sha256 == digest(authorization.publication.publication)
    assert authority.policy_sha256 != authority.transport_policy_sha256
    status = authority.status()
    assert status["no_weight"] is True
    assert status["chain_submission_authorized"] is False
    assert status["chain_announced_origin_verified"] is False
    assert status["publication_timing_proven"] is False
    assert b'"references"' not in canonical_json_bytes(authorization.publication)
    validate_publication_suite(authorization.publication, authorization.suite, authorization.policy)


@pytest.mark.parametrize("issue_seconds", [2700, 5400])
async def test_extended_transport_uses_signed_schedule_and_fresh_request_auth(
    policy, monkeypatch, issue_seconds
):
    import bittensor as bt

    from umi.auth import RequestAuthenticator
    from umi.miner import TRANSLATE_PATH
    from umi.validator import prepare_request_attempt

    fixture = build_authorization_fixture(
        policy, single_evaluator=True, issue_allowance_seconds=issue_seconds
    )
    issuance = fixture.finalized_blocks.blocks[fixture.request.issued_block]
    # The assignment spent ten minutes queued, but the request is signed now.
    now = (issuance.timestamp_ms + 600_000) * 1_000_000
    monkeypatch.setattr(time, "time_ns", lambda: now)
    fixture.finalized_blocks.head += 50
    authority = _authority(fixture)
    authority.validate_runtime(**_runtime(fixture))
    admission = await authority.authorize(
        fixture.request, validator_hotkey=fixture.validator_wallet.hotkey.ss58_address
    )
    assert admission.window_id == fixture.schedule.window_id
    assert (
        fixture.schedule.issue_close_round - fixture.schedule.selection_round == issue_seconds // 3
    )
    assert fixture.schedule.response_close_round - fixture.schedule.issue_close_round == 100
    assert (
        fixture.request.deadline_block == fixture.request.issued_block + (issue_seconds + 300) // 12
    )
    authenticator = RequestAuthenticator.in_memory(
        fixture.miner_wallet.hotkey.ss58_address,
        max_age_seconds=fixture.legacy_policy.limits.btauth_max_age_seconds,
    )
    fresh = prepare_request_attempt(
        fixture.request,
        wallet=fixture.validator_wallet,
        miner_hotkey=fixture.miner_wallet.hotkey.ss58_address,
        nonce_ns=now,
    )
    authenticator.verify_without_replay(
        dict(fresh.auth_headers), fresh.request_bytes, method="POST", path=TRANSLATE_PATH
    )
    stale = prepare_request_attempt(
        fixture.request,
        wallet=fixture.validator_wallet,
        miner_hotkey=fixture.miner_wallet.hotkey.ss58_address,
        nonce_ns=now - 400 * 1_000_000_000,
    )
    with pytest.raises(bt.http_auth.StaleRequest, match="freshness window"):
        authenticator.verify_without_replay(
            dict(stale.auth_headers), stale.request_bytes, method="POST", path=TRANSLATE_PATH
        )
    fixture.finalized_blocks.head = fixture.request.deadline_block + 1
    with pytest.raises(MinerAdmissionError, match="request_block_deadline_elapsed"):
        await authority.authorize(
            fixture.request, validator_hotkey=fixture.validator_wallet.hotkey.ss58_address
        )


@pytest.mark.parametrize("mutation", ["different_signer", "extra_evaluator", "larger_quorum"])
def test_single_evaluator_transport_rejects_a_different_competition_cohort(policy, mutation):
    fixture = build_authorization_fixture(policy, single_evaluator=True)
    validate_transport_cohort(fixture.policy, fixture.legacy_policy)
    evaluator = Evaluator(hotkey=wallet("Validator1").hotkey.ss58_address, control_group="other")
    updates = {
        "different_signer": {"evaluators": (evaluator,)},
        "extra_evaluator": {"evaluators": (*fixture.policy.evaluators, evaluator)},
        "larger_quorum": {"required_evaluator_groups": 2},
    }
    with pytest.raises(ValueError, match="cohort must match"):
        validate_transport_cohort(
            fixture.policy.model_copy(update=updates[mutation]), fixture.legacy_policy
        )


def test_single_evaluator_publication_still_requires_the_selected_signature(policy):
    fixture = build_authorization_fixture(policy, single_evaluator=True)
    assert len(fixture.publication.signatures) == 1
    validate_publication(fixture.publication, fixture.policy, fixture.legacy_policy)
    invalid = _resign(fixture, fixture.publication.publication, signers=[wallet("Validator1")])
    with pytest.raises(ValueError):
        validate_publication(invalid, fixture.policy, fixture.legacy_policy)
    duplicate = fixture.publication.model_copy(
        update={"signatures": fixture.publication.signatures * 2}
    )
    with pytest.raises(ValueError):
        validate_publication(duplicate, fixture.policy, fixture.legacy_policy)


@pytest.mark.parametrize(
    "kind", ["minority", "duplicate_key", "duplicate_group", "unknown", "bad_signature"]
)
def test_publication_requires_authentic_independent_control_groups(authorization, kind):
    body = authorization.publication.publication
    wallets = authorization.evaluator_wallets
    signatures = {
        "minority": (sign_object(body, wallets[0]),),
        "duplicate_key": (sign_object(body, wallets[0]), sign_object(body, wallets[0])),
        "duplicate_group": (sign_object(body, wallets[0]), sign_object(body, wallets[2])),
        "unknown": (sign_object(body, wallets[0]), sign_object(body, wallet("Eve"))),
        "bad_signature": (
            sign_object(body, wallets[0]),
            sign_object(body, wallets[1]).model_copy(update={"signature": "0x" + "00" * 64}),
        ),
    }[kind]
    publication = authorization.publication.model_copy(update={"signatures": signatures})
    with pytest.raises(ValueError):
        _authority(authorization, publication=publication)
    assert authorization.finalized_blocks.head_calls == 0


def test_signature_order_does_not_change_publication_identity(authorization):
    first = _authority(authorization)
    publication = authorization.publication.model_copy(
        update={"signatures": tuple(reversed(authorization.publication.signatures))}
    )
    assert (
        _authority(authorization, publication=publication).publication_sha256
        == first.publication_sha256
    )


@pytest.mark.parametrize(
    "field", ["challenge_id", "batch_id", "video", "scoring_policy_hash", "evaluator"]
)
async def test_authenticated_caller_cannot_choose_another_assignment(authorization, field):
    authority = _authority(authorization)
    request = authorization.request
    validator = authorization.validator_wallet.hotkey.ss58_address
    if field == "evaluator":
        validator = authorization.evaluator_wallets[1].hotkey.ss58_address
    else:
        changed = {
            "challenge_id": "AQEBAQEBAQEBAQEBAQEBAQ",
            "batch_id": "AgICAgICAgICAgICAgICAg",
            "video": request.video.model_copy(update={"sha256": "ff" * 32}),
            "scoring_policy_hash": digest(authorization.policy),
        }[field]
        request = request.model_copy(update={field: changed})
    with pytest.raises(MinerAdmissionError, match="not_authorized"):
        await authority.authorize(request, validator_hotkey=validator)
    assert authorization.finalized_blocks.head_calls == 0


def test_quorum_cannot_relabel_cached_request_into_another_round(authorization):
    body = authorization.publication.publication
    body = body.model_copy(update={"round": body.round.model_copy(update={"sequence": 2})})
    with pytest.raises(ValueError, match="wire IDs"):
        _authority(authorization, publication=_resign(authorization, body))


@pytest.mark.parametrize(
    "kind",
    ["duplicate", "missing_case", "wrong_case", "wrong_video", "outside_round", "wrong_policy"],
)
def test_resigned_invalid_mapping_is_not_accepted(authorization, kind):
    body = authorization.publication.publication
    assignments = list(body.assignments)
    first = assignments[0]
    if kind == "duplicate":
        assignments.append(first)
    elif kind == "missing_case":
        assignments.pop()
    elif kind == "wrong_case":
        assignments[0] = first.model_copy(update={"case_sha256": "ff" * 32})
    elif kind == "wrong_video":
        assignments[0] = first.model_copy(
            update={
                "request": first.request.model_copy(
                    update={"video": first.request.video.model_copy(update={"sha256": "ff" * 32})}
                )
            }
        )
    elif kind == "outside_round":
        assignments[0] = first.model_copy(
            update={
                "request": first.request.model_copy(
                    update={"issued_block": body.round.submission_close_block}
                )
            }
        )
    else:
        body = body.model_copy(update={"legacy_policy_sha256": digest(authorization.policy)})
    body = body.model_copy(update={"assignments": tuple(assignments)})
    with pytest.raises(ValueError):
        _authority(authorization, publication=_resign(authorization, body))


@pytest.mark.parametrize(
    "field,value",
    [
        ("miner_hotkey", wallet("Bob").hotkey.ss58_address),
        ("model_revision", "ff" * 32),
        ("serving_origin", "https://8.8.4.4:443"),
    ],
)
def test_local_deployment_binding_is_exact(authorization, field, value):
    with pytest.raises(ValueError):
        _authority(authorization, **{field: value})


def test_unsafe_copy_cannot_remove_no_weight_or_submission_signature(authorization):
    body = authorization.publication.publication.model_copy(update={"no_weight": False})
    with pytest.raises(ValueError):
        _authority(authorization, publication=_resign(authorization, body))
    signed = authorization.signed_submission
    forged = signed.model_copy(
        update={"submission": signed.submission.model_copy(update={"model_revision": "ff" * 32})}
    )
    body = authorization.publication.publication.model_copy(update={"submissions": (forged,)})
    with pytest.raises(ValueError, match="signature"):
        _authority(authorization, publication=_resign(authorization, body))


def test_publication_caps_exact_assignments_per_legacy_window(policy):
    fixture = build_authorization_fixture(policy, case_count=30)
    with pytest.raises(ValueError, match="quotas"):
        _authority(fixture)


@pytest.mark.parametrize(
    "kind",
    [
        "inference",
        "output",
        "attempts",
        "assignment_quota",
        "unknown_validator",
        "missing_validator",
    ],
)
def test_runtime_cannot_weaken_policy_or_assignment_quotas(authorization, kind):
    authority = _authority(authorization)
    kwargs = _runtime(authorization)
    limits = kwargs["limits"]
    fields = {
        "inference": {
            "inference_timeout_seconds": authorization.policy.maximum_inference_ms / 1000 + 1
        },
        "output": {"maximum_hypothesis_utf8_bytes": authorization.policy.maximum_output_bytes + 1},
        "attempts": {"maximum_request_transmissions_per_assignment": 3},
        "assignment_quota": {"maximum_assignments_per_validator_window": 2},
    }
    if kind in fields:
        kwargs["limits"] = replace(limits, **fields[kind])
    elif kind == "unknown_validator":
        kwargs["allowed_validator_hotkeys"] |= {wallet("Eve").hotkey.ss58_address}
    else:
        kwargs["allowed_validator_hotkeys"] = frozenset()
    with pytest.raises(ValueError):
        authority.validate_runtime(**kwargs)


@pytest.mark.parametrize(
    "name",
    [
        "maximum_retained_video_bytes_per_validator_window",
        "maximum_unique_videos_per_window",
        "maximum_retained_video_bytes",
        "maximum_nonce_rows_per_validator",
        "maximum_nonce_rows_total",
        "maximum_nonce_database_bytes",
        "btauth_max_age_seconds",
        "btauth_allowed_skew_seconds",
    ],
)
def test_runtime_cannot_widen_legacy_auth_or_storage_limits(authorization, name):
    authority = _authority(authorization)
    kwargs = _runtime(authorization)
    limits = kwargs["limits"]
    kwargs["limits"] = replace(limits, **{name: getattr(limits, name) + 1})
    with pytest.raises(ValueError, match="legacy transport quotas"):
        authority.validate_runtime(**kwargs)


def test_runtime_operational_timeouts_and_concurrency_remain_configurable(authorization):
    authority = _authority(authorization)
    kwargs = _runtime(authorization)
    kwargs["limits"] = replace(
        kwargs["limits"],
        request_body_timeout_seconds=15,
        video_fetch_timeout_seconds=60,
        backend_lifecycle_timeout_seconds=120,
        inference_admission_timeout_seconds=20,
        response_seal_margin_seconds=2,
        maximum_inference_concurrency=8,
    )
    authority.validate_runtime(**kwargs)


async def test_signed_mapping_cannot_replace_missing_finalized_history(authorization):
    authority = _authority(authorization)
    authorization.finalized_blocks.blocks.pop(authorization.request.issued_block)
    with pytest.raises(MinerAdmissionError, match="finalized_history_unavailable"):
        await authority.authorize(
            authorization.request,
            validator_hotkey=authorization.validator_wallet.hotkey.ss58_address,
        )


async def test_signed_mapping_cannot_extend_owned_block_deadline(authorization):
    authority = _authority(authorization)
    authorization.finalized_blocks.head = authorization.request.deadline_block + 1
    with pytest.raises(MinerAdmissionError, match="block_deadline_elapsed"):
        await authority.authorize(
            authorization.request,
            validator_hotkey=authorization.validator_wallet.hotkey.ss58_address,
        )


def test_delayed_first_observation_rejects_unusable_publication(authorization, monkeypatch):
    issue_close_ns = (
        QUICKNET_GENESIS_MS + (authorization.schedule.issue_close_round - 1) * QUICKNET_PERIOD_MS
    ) * 1_000_000
    monkeypatch.setattr("umi.competition_authorization.time.time_ns", lambda: issue_close_ns)
    with pytest.raises(ValueError, match="first observed"):
        _authority(authorization)


async def test_reload_excludes_elapsed_slots_but_keeps_future_windows(authorization, monkeypatch):
    legacy = authorization.legacy_policy
    first_announcement = authorization.finalized_blocks.blocks[1000]
    next_announcement = _block(
        legacy,
        1,
        block_byte="32",
        timestamp_ms=first_announcement.timestamp_ms
        + legacy.clock.window_stride_blocks * legacy.clock.target_block_interval_seconds * 1000,
    )
    next_schedule = _clock(legacy).derive(
        1,
        netuid=legacy.netuid,
        announcement_block_hash=next_announcement.block_hash,
        announcement_timestamp_ms=next_announcement.timestamp_ms,
        scoring_policy_hash=scoring_policy_hash(legacy),
    )
    issued = next_schedule.closing_block + 1
    next_issuance = _block(
        legacy,
        1,
        block_byte="42",
        height=issued,
        timestamp_ms=QUICKNET_GENESIS_MS + (next_schedule.selection_round - 1) * QUICKNET_PERIOD_MS,
    )
    round_ = authorization.round.model_copy(
        update={
            "evaluation_close_block": issued + next_schedule.response_deadline_blocks + 1,
            "reveal_block": issued + next_schedule.response_deadline_blocks + 2,
            "valid_through_block": 1600,
        }
    )
    assignments = []
    for assignment in authorization.publication.publication.assignments:
        ids = dict(
            policy_sha256=digest(authorization.policy),
            round_sha256=digest(round_),
            submission_sha256=assignment.submission_sha256,
            evaluator_hotkey=assignment.evaluator_hotkey,
        )
        updates = {
            "batch_id": assignment_batch_id(**ids),
            "challenge_id": assignment_challenge_id(**ids, case_sha256=assignment.case_sha256),
        }
        if assignment.case_sha256 != digest(authorization.cases[0]):
            updates.update(
                window_id=next_schedule.window_id,
                issued_block=issued,
                issued_block_hash=next_issuance.block_hash,
                deadline_block=issued + next_schedule.response_deadline_blocks,
                response_close_round=next_schedule.response_close_round,
                reveal_round=next_schedule.reveal_round,
            )
        assignments.append(
            assignment.model_copy(update={"request": assignment.request.model_copy(update=updates)})
        )
    body = authorization.publication.publication.model_copy(
        update={"round": round_, "assignments": tuple(assignments)}
    )
    publication = _resign(authorization, body)
    first_issue_close_ns = (
        QUICKNET_GENESIS_MS + (authorization.schedule.issue_close_round - 1) * QUICKNET_PERIOD_MS
    ) * 1_000_000
    monkeypatch.setattr("umi.competition_authorization.time.time_ns", lambda: first_issue_close_ns)
    authority = _authority(authorization, publication=publication)
    assert authority.publication_sha256 == digest(body)
    assert authority.status()["authorized_assignments"] == 4
    assert authority.status()["elapsed_assignments_excluded"] == 2
    with pytest.raises(MinerAdmissionError, match="assignment_not_authorized"):
        await authority.authorize(
            assignments[0].request, validator_hotkey=assignments[0].evaluator_hotkey
        )
    assert authorization.finalized_blocks.head_calls == 0
    authorization.finalized_blocks.head = issued
    authorization.finalized_blocks.blocks.update(
        {next_announcement.height: next_announcement, issued: next_issuance}
    )
    admission = await authority.authorize(
        assignments[1].request, validator_hotkey=assignments[1].evaluator_hotkey
    )
    assert admission.window_index == 1
    assert admission.observed_finalized_height == issued


def test_revealed_suite_must_match_reference_free_publication(authorization):
    suite = authorization.suite.model_copy(
        update={"cases": tuple(reversed(authorization.suite.cases))}
    )
    with pytest.raises(ValueError, match="revealed suite"):
        validate_publication_suite(authorization.publication, suite, authorization.policy)


def test_publication_validation_is_repeatable_and_keeps_legacy_hash(authorization):
    checked = validate_publication(
        authorization.publication, authorization.policy, authorization.legacy_policy
    )
    assert canonical_json_bytes(checked) == canonical_json_bytes(authorization.publication)
    for assignment in checked.publication.assignments:
        TranslationRequest.model_validate_json(canonical_json_bytes(assignment.request))
        assert assignment.request.scoring_policy_hash == scoring_policy_hash(
            authorization.legacy_policy
        )
