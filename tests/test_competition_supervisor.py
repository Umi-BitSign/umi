from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from tests.factories import dev_wallet
from umi.competition_package import competition_release_identity_digest
from umi.competition_supervisor import (
    SUCCESSOR_CHAIN_AUTHORIZATION_TARGET_SCHEMA,
    SUCCESSOR_CHAIN_TARGET_SCHEMA,
    SUCCESSOR_RELEASE_TARGET_SCHEMA,
    SUCCESSOR_REPLAY_PACKAGE_TARGET_SCHEMA,
    SUCCESSOR_SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
    SUCCESSOR_SUPERVISOR_DIRECTIVE_SCHEMA,
    SUCCESSOR_SUPERVISOR_DIRECTIVE_SIGNATURE_DOMAIN,
    SUCCESSOR_SUPERVISOR_OPERATOR_CONSENT_SCHEMA,
    SUCCESSOR_SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA,
    SUCCESSOR_WORKER_CAPABILITIES_SCHEMA,
    SignedSuccessorSupervisorDirective,
    SuccessorChainAuthorizationTarget,
    SuccessorReplayPackageTarget,
    SuccessorSupervisorChainTarget,
    SuccessorSupervisorDirective,
    SuccessorSupervisorDirectivePage,
    SuccessorSupervisorOperatorConsent,
    SuccessorSupervisorReleaseTarget,
    SuccessorWorkerCapabilities,
    advance_successor_supervisor_directive_history_state,
    advance_successor_supervisor_directive_state,
    load_bound_successor_replay_package,
    parse_canonical_signed_successor_supervisor_directive,
    parse_canonical_successor_operator_consent,
    parse_canonical_successor_supervisor_directive_page,
    successor_operator_consent_sha256,
    successor_source_config_sha256,
    successor_supervisor_directive_digest,
    successor_supervisor_directive_sha256,
    verify_bound_successor_chain_authorization,
    verify_signed_successor_supervisor_directive,
)
from umi.competition_weights import (
    CompetitionWeightAuthorizationBody,
    sign_competition_weight_authorization,
)
from umi.crypto import sign_response_digest
from umi.encoding import account_id32
from umi.policy import LiveChainObservationPin
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import (
    SUPERVISOR_DIRECTIVE_SIGNATURE_DOMAIN,
    SupervisorDirectiveSignature,
    ValidatorSupervisorError,
    advance_supervisor_directive_state,
    parse_canonical_signed_supervisor_directive,
    supervisor_directive_sha256,
)

from .test_competition_package import package_case as package_case
from .test_competition_package import package_limits as package_limits
from .test_competition_package import release_identity as release_identity
from .test_competition_publication import replay_limits as replay_limits
from .test_open_competition import policy as policy
from .test_validator_supervisor import _config as v3_config
from .test_validator_supervisor import _directive as v3_directive
from .test_validator_supervisor import _signed as v3_signed
from .test_validator_supervisor import _wallets as authority_wallets


def _reason(error: pytest.ExceptionInfo[ValidatorSupervisorError]) -> str:
    return error.value.reason_code


@pytest.fixture
def v3_predecessor():
    config = v3_config()
    signed = v3_signed(v3_directive())
    body = canonical_json_bytes(signed)
    state = advance_supervisor_directive_state(
        signed,
        config=config,
        finalized_block=120,
        prior_state=None,
    )
    return SimpleNamespace(config=config, signed=signed, body=body, state=state)


@pytest.fixture
def successor_chain() -> SuccessorSupervisorChainTarget:
    return SuccessorSupervisorChainTarget(
        schema=SUCCESSOR_CHAIN_TARGET_SCHEMA,
        network="finney",
        netuid=78,
        mechanism_id=0,
        chain_pin=LiveChainObservationPin(
            network="finney",
            genesis_block_hash="10" * 32,
            runtime_spec_version=449,
            transaction_version=1,
            state_version=1,
            metadata_sha256="11" * 32,
            subtensor_revision="12" * 20,
            live_chain_fixture_set_sha256="13" * 32,
        ),
    )


@pytest.fixture
def successor_release(release_identity) -> SuccessorSupervisorReleaseTarget:
    return SuccessorSupervisorReleaseTarget(
        schema=SUCCESSOR_RELEASE_TARGET_SCHEMA,
        artifact_type="oci",
        release_bundle_url="https://releases.umi.vision/competition/release.tar",
        release_bundle_sha256=release_identity.release_bundle_sha256,
        release_bundle_size_bytes=10_000_000,
        release_manifest_sha256=release_identity.release_manifest_sha256,
        release_authority_hotkey=authority_wallets()[0].hotkey.ss58_address,
        release_authority_signature_scheme="sr25519",
        oci_repository="ghcr.io/umi-bitsign/umi-validator",
        oci_manifest_sha256="14" * 32,
        target_platform="linux/amd64",
        umi_git_revision=release_identity.umi_revision,
        umi_source_tree_sha256="15" * 32,
        entrypoint_profile="umi-competition-replay-worker/1",
        state_schema_minimum=4,
        state_schema_maximum=4,
        replay_release_identity=release_identity,
    )


@pytest.fixture
def successor_package_target(
    package_case,
    package_limits,
    policy,
) -> SuccessorReplayPackageTarget:
    return _exact_package_target(package_case, package_limits, policy)


def _exact_package_target(package_case, package_limits, policy):
    manifest = package_case.path.joinpath("manifest.json").read_bytes()
    from umi.competition_package import CompetitionPackageManifest

    parsed = CompetitionPackageManifest.model_validate_json(manifest, strict=True)
    return SuccessorReplayPackageTarget(
        schema=SUCCESSOR_REPLAY_PACKAGE_TARGET_SCHEMA,
        artifact_type="sealed_competition_replay_package",
        profile="competition_publication_replay_no_weight/1",
        package_sha256=package_case.prepared.package_sha256,
        manifest_sha256=package_case.prepared.manifest_sha256,
        policy_sha256=parsed.policy_sha256,
        policy_valid_from_block=policy.valid_from_block,
        policy_valid_through_block=policy.valid_through_block,
        round_sha256=parsed.round_sha256,
        round_sequence=parsed.round_sequence,
        cutoff_publication_sha256=parsed.cutoff_publication_sha256,
        cutoff_certificate_sha256=parsed.cutoff_certificate_sha256,
        settlement_publication_sha256=parsed.settlement_publication_sha256,
        settlement_certificate_sha256=parsed.settlement_certificate_sha256,
        settlement_sha256=parsed.settlement_sha256,
        projection_sha256=parsed.projection_sha256,
        promotion_head_sha256=parsed.promotion_head_sha256,
        release_identity_sha256=parsed.release_identity_sha256,
        limits=package_limits,
    )


def _capabilities(mode: str) -> SuccessorWorkerCapabilities:
    if mode == "competition_replay":
        wallet, network, submit = "none", "none", False
    else:
        wallet, network, submit = (
            "configured_validator_hotkey_read_only",
            "finney_clients",
            True,
        )
    return SuccessorWorkerCapabilities(
        schema=SUCCESSOR_WORKER_CAPABILITIES_SCHEMA,
        package_access="read_only",
        wallet_access=wallet,
        network_access=network,
        chain_submission=submit,
        arbitrary_command_allowed=False,
        arbitrary_mount_allowed=False,
    )


def _authorization(target, predecessor: str) -> SuccessorChainAuthorizationTarget:
    return SuccessorChainAuthorizationTarget(
        schema=SUCCESSOR_CHAIN_AUTHORIZATION_TARGET_SCHEMA,
        artifact_type="canonical_json",
        profile="umi-signed-competition-weight-authorization/1",
        authorization_id="19" * 32,
        signed_authorization_sha256="1a" * 32,
        authorization_size_bytes=100_000,
        policy_sha256=target.policy_sha256,
        package_sha256=target.package_sha256,
        settlement_sha256=target.settlement_sha256,
        projection_sha256=target.projection_sha256,
        release_identity_sha256=target.release_identity_sha256,
        predecessor_directive_sha256=predecessor,
        valid_from_block=130,
        valid_through_block=220,
        required_recovery_profile="stopped_bootstrap_recovery/1",
    )


def _consent(predecessor, **changes) -> SuccessorSupervisorOperatorConsent:
    values = {
        "schema": SUCCESSOR_SUPERVISOR_OPERATOR_CONSENT_SCHEMA,
        "source_config_sha256": successor_source_config_sha256(predecessor.config),
        "channel_id": predecessor.config.channel_id,
        "validator_hotkey": predecessor.config.validator_hotkey,
        "predecessor_sequence": predecessor.state.accepted_sequence,
        "predecessor_directive_sha256": predecessor.state.accepted_directive_sha256,
        "predecessor_signed_directive_sha256": hashlib.sha256(predecessor.body).hexdigest(),
        "predecessor_accepted_at_finalized_block": (predecessor.state.accepted_at_finalized_block),
        "approved_host_manifest_sha256": "1b" * 32,
        "target_platform": predecessor.config.target_platform,
        "allowed_modes": ["competition_replay", "competition_weights"],
        "required_recovery_profile": "stopped_bootstrap_recovery/1",
        "authorized_at_finalized_block": 125,
        "valid_through_block": 1_000,
    }
    values.update(changes)
    return SuccessorSupervisorOperatorConsent.model_validate(values)


def _directive(
    predecessor,
    package_target,
    release,
    chain,
    consent,
    *,
    mode="competition_replay",
    sequence=2,
    predecessor_version=3,
    previous=None,
    issued_at_block=130,
    valid_from_block=140,
    valid_through_block=190,
    **changes,
) -> SuccessorSupervisorDirective:
    if mode == "hold":
        policy_sha256 = capabilities = selected_release = replay_package = authorization = None
    else:
        policy_sha256 = package_target.policy_sha256
        capabilities = _capabilities(mode)
        selected_release = release.model_copy(
            update={
                "entrypoint_profile": (
                    "umi-competition-replay-worker/1"
                    if mode == "competition_replay"
                    else "umi-competition-weight-worker/1"
                )
            }
        )
        replay_package = package_target
        authorization = (
            None
            if mode == "competition_replay"
            else _authorization(
                package_target, previous or predecessor.state.accepted_directive_sha256
            )
        )
    values = {
        "schema": SUCCESSOR_SUPERVISOR_DIRECTIVE_SCHEMA,
        "channel_id": predecessor.config.channel_id,
        "sequence": sequence,
        "predecessor_version": predecessor_version,
        "previous_directive_sha256": previous or predecessor.state.accepted_directive_sha256,
        "issued_at_block": issued_at_block,
        "valid_from_block": valid_from_block,
        "valid_through_block": valid_through_block,
        "minimum_activation_headroom_blocks": 2,
        "network": "finney",
        "netuid": 78,
        "mechanism_id": 0,
        "mode": mode,
        "validator_scope": "any_permitted_sn78",
        "validator_hotkeys": [],
        "policy_sha256": policy_sha256,
        "required_host_manifest_sha256": consent.approved_host_manifest_sha256,
        "required_recovery_profile": "stopped_bootstrap_recovery/1",
        "chain": chain,
        "capabilities": capabilities,
        "release": selected_release,
        "replay_package": replay_package,
        "chain_authorization": authorization,
    }
    values.update(changes)
    return SuccessorSupervisorDirective.model_validate(values)


def _signed(directive, signer_indexes=(0, 1)) -> SignedSuccessorSupervisorDirective:
    signatures = []
    for index in signer_indexes:
        wallet = authority_wallets()[index]
        scheme, signature = sign_response_digest(
            wallet,
            successor_supervisor_directive_digest(directive),
        )
        signatures.append(
            SupervisorDirectiveSignature(
                hotkey=wallet.hotkey.ss58_address,
                signature_scheme=scheme,
                signature=signature,
            )
        )
    signatures.sort(key=lambda item: account_id32(item.hotkey))
    return SignedSuccessorSupervisorDirective(
        schema=SUCCESSOR_SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA,
        directive=directive,
        directive_sha256=successor_supervisor_directive_sha256(directive),
        directive_digest=successor_supervisor_directive_digest(directive).hex(),
        signatures=signatures,
    )


@pytest.fixture
def successor_case(
    v3_predecessor,
    package_case,
    package_limits,
    policy,
    successor_release,
    successor_chain,
):
    target = _exact_package_target(package_case, package_limits, policy)
    consent = _consent(v3_predecessor)
    directive = _directive(
        v3_predecessor,
        target,
        successor_release,
        successor_chain,
        consent,
    )
    return SimpleNamespace(
        predecessor=v3_predecessor,
        target=target,
        release=successor_release,
        chain=successor_chain,
        consent=consent,
        directive=directive,
        signed=_signed(directive),
    )


def _signed_authorization_target(signed) -> SuccessorChainAuthorizationTarget:
    body = canonical_json_bytes(signed)
    authorization = signed.authorization
    return SuccessorChainAuthorizationTarget(
        schema=SUCCESSOR_CHAIN_AUTHORIZATION_TARGET_SCHEMA,
        artifact_type="canonical_json",
        profile="umi-signed-competition-weight-authorization/1",
        authorization_id=authorization.authorization_id,
        signed_authorization_sha256=hashlib.sha256(body).hexdigest(),
        authorization_size_bytes=len(body),
        policy_sha256=authorization.policy_sha256,
        package_sha256=authorization.package_sha256,
        settlement_sha256=authorization.settlement_sha256,
        projection_sha256=authorization.projection_sha256,
        release_identity_sha256=authorization.release_identity_sha256,
        predecessor_directive_sha256=authorization.predecessor_directive_sha256,
        valid_from_block=authorization.valid_from_block,
        valid_through_block=authorization.valid_through_block,
        required_recovery_profile=authorization.required_recovery_profile,
    )


@pytest.fixture
def successor_weight_case(successor_case, package_case, release_identity):
    package = load_bound_successor_replay_package(
        package_case.path,
        directive=successor_case.directive,
        observed_release=release_identity,
    )
    body = CompetitionWeightAuthorizationBody(
        schema="umi-competition-weight-authorization/1",
        authorization_id="19" * 32,
        validator_scope="any_permitted_sn78",
        policy_sha256=successor_case.target.policy_sha256,
        package_sha256=successor_case.target.package_sha256,
        settlement_sha256=successor_case.target.settlement_sha256,
        projection_sha256=successor_case.target.projection_sha256,
        release_identity_sha256=successor_case.target.release_identity_sha256,
        predecessor_directive_sha256=(successor_case.predecessor.state.accepted_directive_sha256),
        required_recovery_profile="stopped_bootstrap_recovery/1",
        chain_pin=successor_case.chain.chain_pin,
        required_finality_verifier_sha256_by_target={"x86_64-unknown-linux-gnu": "24" * 32},
        required_storage_proof_verifier_sha256_by_target={"x86_64-unknown-linux-gnu": "25" * 32},
        network="finney",
        netuid=78,
        mechanism_id=0,
        signed_at_block=160,
        valid_from_block=165,
        valid_through_block=200,
        weights_version_key=1,
        required_min_allowed_weights=1,
        required_max_allowed_uids=256,
        required_max_weights_limit=65535,
        required_weights_rate_limit=0,
        required_mechanism_count=1,
        required_commit_reveal_enabled=False,
        mortality_period=32,
        late_conflict_action="hold_no_automatic_correction",
    )
    signed_authorization = sign_competition_weight_authorization(body, authority_wallets()[0])
    target = _signed_authorization_target(signed_authorization)
    draft = _directive(
        successor_case.predecessor,
        successor_case.target,
        successor_case.release,
        successor_case.chain,
        successor_case.consent,
        mode="competition_weights",
        issued_at_block=160,
        valid_from_block=165,
        valid_through_block=198,
    )
    directive = _replace(draft, chain_authorization=target)
    return SimpleNamespace(
        package=package,
        body=body,
        signed_authorization=signed_authorization,
        authorization_bytes=canonical_json_bytes(signed_authorization),
        target=target,
        directive=directive,
        signed_directive=_signed(directive),
    )


def _replace(model, **changes):
    values = model.model_dump(mode="python", by_alias=True)
    values.update(changes)
    return type(model).model_validate(values)


def test_v4_signature_domain_and_canonical_parsers_use_real_dev_signatures(successor_case):
    signed = successor_case.signed
    body = canonical_json_bytes(signed)
    expected = hashlib.sha256(
        SUCCESSOR_SUPERVISOR_DIRECTIVE_SIGNATURE_DOMAIN + canonical_json_bytes(signed.directive)
    ).digest()

    assert SUCCESSOR_SUPERVISOR_DIRECTIVE_SIGNATURE_DOMAIN != (
        SUPERVISOR_DIRECTIVE_SIGNATURE_DOMAIN
    )
    assert successor_supervisor_directive_digest(signed.directive) == expected
    assert parse_canonical_signed_successor_supervisor_directive(body) == signed
    assert verify_signed_successor_supervisor_directive(
        signed,
        config=successor_case.predecessor.config,
        operator_consent=successor_case.consent,
        finalized_block=140,
    ) == successor_supervisor_directive_sha256(signed.directive)
    assert (
        parse_canonical_successor_operator_consent(canonical_json_bytes(successor_case.consent))
        == successor_case.consent
    )


def test_first_v4_transition_preserves_exact_v3_bytes_and_high_water(successor_case):
    predecessor = successor_case.predecessor
    original_v3_digest = supervisor_directive_sha256(predecessor.signed.directive)
    assert parse_canonical_signed_supervisor_directive(predecessor.body) == predecessor.signed

    state = advance_successor_supervisor_directive_state(
        successor_case.signed,
        config=predecessor.config,
        operator_consent=successor_case.consent,
        finalized_block=140,
        prior_state=predecessor.state,
        prior_v3_signed_bytes=predecessor.body,
    )

    assert supervisor_directive_sha256(predecessor.signed.directive) == original_v3_digest
    assert state.transition_v3_sequence == predecessor.state.accepted_sequence
    assert state.transition_v3_directive_sha256 == original_v3_digest
    assert (
        state.transition_v3_signed_directive_sha256 == hashlib.sha256(predecessor.body).hexdigest()
    )
    assert state.accepted_sequence == predecessor.state.accepted_sequence + 1
    assert state.operator_consent_sha256 == successor_operator_consent_sha256(
        successor_case.consent
    )

    retried = advance_successor_supervisor_directive_state(
        successor_case.signed,
        config=predecessor.config,
        operator_consent=successor_case.consent,
        finalized_block=141,
        prior_state=state,
    )
    assert retried == state


def test_v4_chain_continues_without_sequence_reset(successor_case):
    predecessor = successor_case.predecessor
    first = advance_successor_supervisor_directive_state(
        successor_case.signed,
        config=predecessor.config,
        operator_consent=successor_case.consent,
        finalized_block=140,
        prior_state=predecessor.state,
        prior_v3_signed_bytes=predecessor.body,
    )
    second_directive = _directive(
        predecessor,
        successor_case.target,
        successor_case.release,
        successor_case.chain,
        successor_case.consent,
        sequence=3,
        predecessor_version=4,
        previous=first.accepted_directive_sha256,
        issued_at_block=141,
        valid_from_block=142,
    )
    second = advance_successor_supervisor_directive_state(
        _signed(second_directive),
        config=predecessor.config,
        operator_consent=successor_case.consent,
        finalized_block=142,
        prior_state=first,
    )

    assert second.accepted_sequence == 3
    assert second.transition_v3_directive_sha256 == first.transition_v3_directive_sha256
    assert second.transition_v3_signed_directive_sha256 == (
        first.transition_v3_signed_directive_sha256
    )


def test_future_directive_can_be_inspected_but_cannot_advance_high_water(successor_case):
    directive = _replace(
        successor_case.directive,
        valid_from_block=160,
        valid_through_block=190,
    )
    signed = _signed(directive)
    predecessor = successor_case.predecessor

    verify_signed_successor_supervisor_directive(
        signed,
        config=predecessor.config,
        operator_consent=successor_case.consent,
        finalized_block=140,
    )
    with pytest.raises(ValidatorSupervisorError) as caught:
        advance_successor_supervisor_directive_state(
            signed,
            config=predecessor.config,
            operator_consent=successor_case.consent,
            finalized_block=140,
            prior_state=predecessor.state,
            prior_v3_signed_bytes=predecessor.body,
        )
    assert _reason(caught) == "successor_directive_not_yet_active"


def test_expired_successor_history_can_advance_only_after_activation(successor_case):
    directive = _replace(
        successor_case.directive,
        valid_from_block=130,
        valid_through_block=135,
    )
    predecessor = successor_case.predecessor
    state = advance_successor_supervisor_directive_history_state(
        _signed(directive),
        config=predecessor.config,
        operator_consent=successor_case.consent,
        finalized_block=140,
        prior_state=predecessor.state,
        prior_v3_signed_bytes=predecessor.body,
    )
    assert state.accepted_sequence == 2


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"sequence": 3}, "successor_v3_transition_binding_mismatch"),
        ({"previous_directive_sha256": "20" * 32}, "successor_v3_transition_binding_mismatch"),
        ({"predecessor_version": 4}, "successor_v3_transition_binding_mismatch"),
    ],
)
def test_v3_transition_rejects_gap_wrong_predecessor_or_wrong_version(
    successor_case,
    changes,
    reason,
):
    directive = _replace(successor_case.directive, **changes)
    predecessor = successor_case.predecessor
    with pytest.raises(ValidatorSupervisorError) as caught:
        advance_successor_supervisor_directive_state(
            _signed(directive),
            config=predecessor.config,
            operator_consent=successor_case.consent,
            finalized_block=140,
            prior_state=predecessor.state,
            prior_v3_signed_bytes=predecessor.body,
        )
    assert _reason(caught) == reason


def test_v4_sequence_one_is_rejected_by_schema(successor_case):
    values = successor_case.directive.model_dump(mode="python", by_alias=True)
    values["sequence"] = 1
    with pytest.raises(ValidationError):
        SuccessorSupervisorDirective.model_validate(values)


def test_transition_requires_exact_canonical_v3_signed_bytes(successor_case):
    predecessor = successor_case.predecessor
    with pytest.raises(ValidatorSupervisorError):
        advance_successor_supervisor_directive_state(
            successor_case.signed,
            config=predecessor.config,
            operator_consent=successor_case.consent,
            finalized_block=140,
            prior_state=predecessor.state,
            prior_v3_signed_bytes=predecessor.body + b"\n",
        )


def test_operator_consent_cannot_change_old_config_or_host_manifest(successor_case):
    predecessor = successor_case.predecessor
    changed_config = predecessor.config.model_copy(update={"poll_seconds": 301})
    with pytest.raises(ValidatorSupervisorError) as caught:
        verify_signed_successor_supervisor_directive(
            successor_case.signed,
            config=changed_config,
            operator_consent=successor_case.consent,
            finalized_block=140,
        )
    assert _reason(caught) == "successor_source_config_mismatch"

    directive = _replace(
        successor_case.directive,
        required_host_manifest_sha256="21" * 32,
    )
    with pytest.raises(ValidatorSupervisorError) as caught:
        verify_signed_successor_supervisor_directive(
            _signed(directive),
            config=predecessor.config,
            operator_consent=successor_case.consent,
            finalized_block=140,
        )
    assert _reason(caught) == "successor_host_manifest_not_consented"


def test_operator_may_consent_after_directive_issue_but_bounds_activation(successor_case):
    predecessor = successor_case.predecessor
    later_consent = _consent(predecessor, authorized_at_finalized_block=135)
    verify_signed_successor_supervisor_directive(
        successor_case.signed,
        config=predecessor.config,
        operator_consent=later_consent,
        finalized_block=140,
    )

    short_consent = _consent(predecessor, valid_through_block=180)
    with pytest.raises(ValidatorSupervisorError) as caught:
        verify_signed_successor_supervisor_directive(
            successor_case.signed,
            config=predecessor.config,
            operator_consent=short_consent,
            finalized_block=140,
        )
    assert _reason(caught) == "successor_directive_outside_operator_consent"


def test_authority_threshold_uses_unchanged_v3_trust(successor_case):
    with pytest.raises(ValidatorSupervisorError) as caught:
        verify_signed_successor_supervisor_directive(
            _signed(successor_case.directive, signer_indexes=(0,)),
            config=successor_case.predecessor.config,
            operator_consent=successor_case.consent,
            finalized_block=140,
        )
    assert _reason(caught) == "successor_directive_signature_threshold_not_met"

    stranger = dev_wallet("//SuccessorStranger")
    scheme, signature = sign_response_digest(
        stranger,
        successor_supervisor_directive_digest(successor_case.directive),
    )
    trusted = _signed(successor_case.directive).signatures[0]
    untrusted = SupervisorDirectiveSignature(
        hotkey=stranger.hotkey.ss58_address,
        signature_scheme=scheme,
        signature=signature,
    )
    signatures = sorted((trusted, untrusted), key=lambda item: account_id32(item.hotkey))
    envelope = SignedSuccessorSupervisorDirective(
        schema=SUCCESSOR_SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA,
        directive=successor_case.directive,
        directive_sha256=successor_supervisor_directive_sha256(successor_case.directive),
        directive_digest=successor_supervisor_directive_digest(successor_case.directive).hex(),
        signatures=signatures,
    )
    with pytest.raises(ValidatorSupervisorError) as caught:
        verify_signed_successor_supervisor_directive(
            envelope,
            config=successor_case.predecessor.config,
            operator_consent=successor_case.consent,
            finalized_block=140,
        )
    assert _reason(caught) == "successor_directive_signer_untrusted"


def test_profile_capabilities_forbid_wallet_or_chain_escalation(successor_case):
    replay_values = successor_case.directive.model_dump(mode="python", by_alias=True)
    replay_values["capabilities"] = _capabilities("competition_weights").model_dump(
        mode="python", by_alias=True
    )
    with pytest.raises(ValidationError):
        SuccessorSupervisorDirective.model_validate(replay_values)

    weight = _directive(
        successor_case.predecessor,
        successor_case.target,
        successor_case.release,
        successor_case.chain,
        successor_case.consent,
        mode="competition_weights",
    )
    without_authority = weight.model_dump(mode="python", by_alias=True)
    without_authority["chain_authorization"] = None
    with pytest.raises(ValidationError):
        SuccessorSupervisorDirective.model_validate(without_authority)

    replay_with_authority = successor_case.directive.model_dump(mode="python", by_alias=True)
    replay_with_authority["chain_authorization"] = weight.chain_authorization.model_dump(
        mode="python", by_alias=True
    )
    with pytest.raises(ValidationError):
        SuccessorSupervisorDirective.model_validate(replay_with_authority)


@pytest.mark.parametrize("field", ["command", "argv", "environment", "mounts", "wallet_path"])
def test_contract_has_no_arbitrary_command_or_mount_surface(successor_case, field):
    values = successor_case.directive.model_dump(mode="python", by_alias=True)
    values[field] = "/tmp/untrusted"
    with pytest.raises(ValidationError):
        SuccessorSupervisorDirective.model_validate(values)


def test_common_scope_is_generic_but_explicit_scope_must_include_local_validator(successor_case):
    verify_signed_successor_supervisor_directive(
        successor_case.signed,
        config=successor_case.predecessor.config,
        operator_consent=successor_case.consent,
        finalized_block=140,
    )
    other = dev_wallet("//OtherSuccessorValidator").hotkey.ss58_address
    directive = _replace(
        successor_case.directive,
        validator_scope="explicit_hotkeys",
        validator_hotkeys=[other],
    )
    with pytest.raises(ValidatorSupervisorError) as caught:
        verify_signed_successor_supervisor_directive(
            _signed(directive),
            config=successor_case.predecessor.config,
            operator_consent=successor_case.consent,
            finalized_block=140,
        )
    assert _reason(caught) == "successor_validator_not_authorized"


def test_bound_package_loader_checks_every_explicit_target_binding(
    successor_case,
    package_case,
    release_identity,
):
    loaded = load_bound_successor_replay_package(
        package_case.path,
        directive=successor_case.directive,
        observed_release=release_identity,
    )
    assert loaded.package_sha256 == successor_case.target.package_sha256

    changed_target = _replace(successor_case.target, projection_sha256="22" * 32)
    changed_directive = _replace(successor_case.directive, replay_package=changed_target)
    with pytest.raises(ValidatorSupervisorError) as caught:
        load_bound_successor_replay_package(
            package_case.path,
            directive=changed_directive,
            observed_release=release_identity,
        )
    assert _reason(caught) == "successor_replay_package_binding_mismatch"

    wrong_release = release_identity.model_copy(update={"release_bundle_sha256": "23" * 32})
    with pytest.raises(ValidatorSupervisorError) as caught:
        load_bound_successor_replay_package(
            package_case.path,
            directive=successor_case.directive,
            observed_release=wrong_release,
        )
    assert _reason(caught) == "successor_observed_release_mismatch"


def test_weight_profile_requires_exact_separately_signed_chain_authority(
    successor_weight_case,
    successor_case,
):
    verify_signed_successor_supervisor_directive(
        successor_weight_case.signed_directive,
        config=successor_case.predecessor.config,
        operator_consent=successor_case.consent,
        finalized_block=165,
    )
    verified = verify_bound_successor_chain_authorization(
        successor_weight_case.authorization_bytes,
        directive=successor_weight_case.directive,
        config=successor_case.predecessor.config,
        package=successor_weight_case.package,
    )
    assert verified == successor_weight_case.body


def test_chain_authorization_rejects_size_digest_and_semantic_mismatch(
    successor_weight_case,
    successor_case,
):
    target = successor_weight_case.target
    wrong_size = _replace(target, authorization_size_bytes=target.authorization_size_bytes + 1)
    with pytest.raises(ValidatorSupervisorError) as caught:
        verify_bound_successor_chain_authorization(
            successor_weight_case.authorization_bytes,
            directive=_replace(successor_weight_case.directive, chain_authorization=wrong_size),
            config=successor_case.predecessor.config,
            package=successor_weight_case.package,
        )
    assert _reason(caught) == "successor_chain_authorization_size_mismatch"

    wrong_digest = _replace(target, signed_authorization_sha256="26" * 32)
    with pytest.raises(ValidatorSupervisorError) as caught:
        verify_bound_successor_chain_authorization(
            successor_weight_case.authorization_bytes,
            directive=_replace(successor_weight_case.directive, chain_authorization=wrong_digest),
            config=successor_case.predecessor.config,
            package=successor_weight_case.package,
        )
    assert _reason(caught) == "successor_chain_authorization_digest_mismatch"

    wrong_identity = _replace(target, authorization_id="27" * 32)
    with pytest.raises(ValidatorSupervisorError) as caught:
        verify_bound_successor_chain_authorization(
            successor_weight_case.authorization_bytes,
            directive=_replace(successor_weight_case.directive, chain_authorization=wrong_identity),
            config=successor_case.predecessor.config,
            package=successor_weight_case.package,
        )
    assert _reason(caught) == "successor_chain_authorization_binding_mismatch"


def test_chain_authorization_rejects_wrong_chain_and_untrusted_signer(
    successor_weight_case,
    successor_case,
):
    wrong_pin = successor_weight_case.body.chain_pin.model_copy(
        update={"metadata_sha256": "28" * 32}
    )
    wrong_body = successor_weight_case.body.model_copy(update={"chain_pin": wrong_pin})
    wrong_signed = sign_competition_weight_authorization(wrong_body, authority_wallets()[0])
    wrong_bytes = canonical_json_bytes(wrong_signed)
    wrong_target = _signed_authorization_target(wrong_signed)
    with pytest.raises(ValidatorSupervisorError) as caught:
        verify_bound_successor_chain_authorization(
            wrong_bytes,
            directive=_replace(
                successor_weight_case.directive,
                chain_authorization=wrong_target,
            ),
            config=successor_case.predecessor.config,
            package=successor_weight_case.package,
        )
    assert _reason(caught) == "successor_chain_authorization_chain_mismatch"

    untrusted_signed = sign_competition_weight_authorization(
        successor_weight_case.body,
        dev_wallet("//UntrustedWeightAuthority"),
    )
    untrusted_bytes = canonical_json_bytes(untrusted_signed)
    untrusted_target = _signed_authorization_target(untrusted_signed)
    with pytest.raises(ValidatorSupervisorError) as caught:
        verify_bound_successor_chain_authorization(
            untrusted_bytes,
            directive=_replace(
                successor_weight_case.directive,
                chain_authorization=untrusted_target,
            ),
            config=successor_case.predecessor.config,
            package=successor_weight_case.package,
        )
    assert _reason(caught) == "successor_chain_authorization_signer_untrusted"


def test_chain_authorization_requires_exact_canonical_bytes(
    successor_weight_case,
    successor_case,
):
    body = successor_weight_case.authorization_bytes + b"\n"
    target = _replace(
        successor_weight_case.target,
        authorization_size_bytes=len(body),
        signed_authorization_sha256=hashlib.sha256(body).hexdigest(),
    )
    with pytest.raises(ValidatorSupervisorError) as caught:
        verify_bound_successor_chain_authorization(
            body,
            directive=_replace(successor_weight_case.directive, chain_authorization=target),
            config=successor_case.predecessor.config,
            package=successor_weight_case.package,
        )
    assert _reason(caught) == "successor_chain_authorization_noncanonical"


def test_successor_page_binds_v3_cursor_then_requires_v4_predecessors(successor_case):
    first = successor_case.signed
    second_directive = _directive(
        successor_case.predecessor,
        successor_case.target,
        successor_case.release,
        successor_case.chain,
        successor_case.consent,
        sequence=3,
        predecessor_version=4,
        previous=first.directive_sha256,
        issued_at_block=141,
        valid_from_block=142,
    )
    second = _signed(second_directive)
    page = SuccessorSupervisorDirectivePage(
        schema=SUCCESSOR_SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
        after_version=3,
        after_sequence=successor_case.predecessor.state.accepted_sequence,
        after_directive_sha256=(successor_case.predecessor.state.accepted_directive_sha256),
        directives=[first, second],
        more=False,
        head=second,
    )
    assert parse_canonical_successor_supervisor_directive_page(canonical_json_bytes(page)) == page

    values = page.model_dump(mode="python", by_alias=True)
    values["after_version"] = 4
    with pytest.raises(ValidationError):
        SuccessorSupervisorDirectivePage.model_validate(values)


def test_canonical_parser_rejects_duplicate_keys_whitespace_and_bounds(successor_case):
    body = canonical_json_bytes(successor_case.signed)
    duplicate = b'{"schema":"umi-validator-supervisor-signed-directive/4",' + body[1:]
    with pytest.raises(ValidatorSupervisorError) as caught:
        parse_canonical_signed_successor_supervisor_directive(duplicate)
    assert _reason(caught) == "successor_directive_duplicate_key"

    with pytest.raises(ValidatorSupervisorError) as caught:
        parse_canonical_signed_successor_supervisor_directive(body + b"\n")
    assert _reason(caught) == "successor_directive_noncanonical"

    with pytest.raises(ValidatorSupervisorError) as caught:
        parse_canonical_signed_successor_supervisor_directive(
            body,
            maximum_bytes=len(body) - 1,
        )
    assert _reason(caught) == "successor_directive_size_invalid"


def test_release_identity_is_exactly_bound_to_signed_oci_release(successor_case):
    identity = successor_case.release.replay_release_identity
    assert successor_case.target.release_identity_sha256 == competition_release_identity_digest(
        identity
    )
    values = successor_case.release.model_dump(mode="python", by_alias=True)
    values["release_bundle_sha256"] = "24" * 32
    with pytest.raises(ValidationError):
        SuccessorSupervisorReleaseTarget.model_validate(values)
