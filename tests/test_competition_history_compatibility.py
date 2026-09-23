from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from umi.competition_history_compatibility import (
    HistoryCompatibilityBody,
    SignedHistoryCompatibility,
    history_compatibility_digest,
    original_consent_digest,
    verify_history_compatibility,
)
from umi.competition_package import competition_release_identity_digest
from umi.competition_supervisor import (
    SuccessorSupervisorOperatorConsent,
    advance_successor_supervisor_directive_history_state,
    advance_successor_supervisor_directive_state,
    verify_signed_successor_supervisor_directive,
    verify_signed_successor_supervisor_directive_history,
)
from umi.crypto import sign_response_digest
from umi.encoding import account_id32
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import SupervisorDirectiveSignature, ValidatorSupervisorError

from .test_competition_supervisor import (
    _signed,
    authority_wallets,
)
from .test_competition_supervisor import (
    package_case as package_case,
)
from .test_competition_supervisor import (
    package_limits as package_limits,
)
from .test_competition_supervisor import (
    policy as policy,
)
from .test_competition_supervisor import (
    release_identity as release_identity,
)
from .test_competition_supervisor import (
    replay_limits as replay_limits,
)
from .test_competition_supervisor import (
    successor_case as successor_case,
)
from .test_competition_supervisor import (
    successor_chain as successor_chain,
)
from .test_competition_supervisor import (
    successor_release as successor_release,
)
from .test_competition_supervisor import (
    v3_predecessor as v3_predecessor,
)


def digest(value):
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def sign(body, signers=(0, 1)):
    signatures = []
    for index in signers:
        wallet = authority_wallets()[index]
        scheme, signature = sign_response_digest(wallet, history_compatibility_digest(body))
        signatures.append(
            SupervisorDirectiveSignature(
                hotkey=wallet.hotkey.ss58_address, signature_scheme=scheme, signature=signature
            )
        )
    return SignedHistoryCompatibility(
        schema="umi-signed-successor-history-compatibility/1",
        body=body,
        body_sha256=digest(body),
        signatures=sorted(signatures, key=lambda x: account_id32(x.hotkey)),
    )


@pytest.fixture
def transition(successor_case):
    case = successor_case
    config = case.predecessor.config
    before = advance_successor_supervisor_directive_state(
        case.signed,
        config=config,
        operator_consent=case.consent,
        finalized_block=145,
        prior_state=case.predecessor.state,
        prior_v3_signed_bytes=case.predecessor.body,
    )
    target = case.consent.model_copy(
        update={"approved_host_manifest_sha256": "ad" * 32, "authorized_at_finalized_block": 150}
    )
    new_identity = case.release.replay_release_identity.model_copy(
        update={"umi_revision": "ba" * 20}
    )
    new_release = case.release.model_copy(
        update={
            "replay_release_identity": new_identity,
            "umi_git_revision": "ba" * 20,
            "umi_source_tree_sha256": "cd" * 32,
            "oci_manifest_sha256": "de" * 32,
        }
    )
    new_package = case.target.model_copy(
        update={
            "release_identity_sha256": competition_release_identity_digest(new_identity),
            "round_sequence": case.target.round_sequence + 1,
        }
    )
    directive = case.directive.model_copy(
        update={
            "sequence": before.accepted_sequence + 1,
            "predecessor_version": 4,
            "previous_directive_sha256": before.accepted_directive_sha256,
            "required_host_manifest_sha256": target.approved_host_manifest_sha256,
            "issued_at_block": 150,
            "valid_from_block": 150,
            "release": new_release,
            "replay_package": new_package,
        }
    )
    values = dict(
        schema="umi-successor-history-compatibility/1",
        source_config_sha256=digest(config),
        channel_id=config.channel_id,
        validator_hotkey=config.validator_hotkey,
        target_platform=config.target_platform,
        chain_pin_sha256=digest(case.chain.chain_pin),
        original_consent_sha256=original_consent_digest(case.consent),
        target_consent_sha256=original_consent_digest(target),
        original_host_manifest_sha256=case.consent.approved_host_manifest_sha256,
        target_host_manifest_sha256=target.approved_host_manifest_sha256,
        original_installation_receipt_sha256="01" * 32,
        original_worker_limits_sha256="02" * 32,
        target_worker_limits_sha256="03" * 32,
        original_checkpoint_sha256="04" * 32,
        retained_history_sha256="05" * 32,
        predecessor_state_sha256=digest(before),
        predecessor_sequence=before.accepted_sequence,
        predecessor_accepted_at_finalized_block=before.accepted_at_finalized_block,
        predecessor_directive_sha256=before.accepted_directive_sha256,
        original_release_identity_sha256s=[
            competition_release_identity_digest(case.release.replay_release_identity)
        ],
        target_release_identity_sha256=competition_release_identity_digest(new_identity),
        target_oci_manifest_sha256=new_release.oci_manifest_sha256,
        target_source_tree_sha256=new_release.umi_source_tree_sha256,
        target_storage_config_sha256="06" * 32,
        first_round_sequence=new_package.round_sequence,
        last_round_sequence=new_package.round_sequence + 5,
        forward_policy_sha256s=[case.target.policy_sha256],
        migration_valid_from_block=150,
        migration_valid_through_block=170,
        minimum_transition_headroom_blocks=10,
        historical_use="verification_and_stopped_recovery_only",
    )
    body = HistoryCompatibilityBody(**values)
    consent = SuccessorSupervisorOperatorConsent.model_validate(
        {
            **target.model_dump(by_alias=True),
            "schema": "umi-validator-supervisor-operator-consent/2",
            "historical_consent": case.consent,
            "history_compatibility": sign(body),
        }
    )
    return SimpleNamespace(
        case=case,
        before=before,
        config=config,
        body=body,
        consent=consent,
        signed=_signed(directive),
    )


def test_old_history_keeps_exact_state_and_signatures(transition):
    t = transition
    raw = canonical_json_bytes(t.case.signed)
    result = advance_successor_supervisor_directive_history_state(
        t.case.signed,
        config=t.config,
        operator_consent=t.consent,
        finalized_block=145,
        prior_state=t.case.predecessor.state,
        prior_v3_signed_bytes=t.case.predecessor.body,
    )
    assert result == t.before
    assert canonical_json_bytes(t.case.signed) == raw
    with pytest.raises((ValueError, ValidatorSupervisorError)):
        verify_signed_successor_supervisor_directive(
            t.case.signed, config=t.config, operator_consent=t.consent, finalized_block=150
        )


def test_forward_transition_retains_anchor_and_advances_exactly_once(transition):
    t = transition
    result = advance_successor_supervisor_directive_state(
        t.signed,
        config=t.config,
        operator_consent=t.consent,
        finalized_block=155,
        prior_state=t.before,
    )
    assert result.accepted_sequence == t.before.accepted_sequence + 1
    assert result.transition_v3_directive_sha256 == t.before.transition_v3_directive_sha256
    assert result.operator_consent_sha256 != t.before.operator_consent_sha256
    assert (
        advance_successor_supervisor_directive_state(
            t.signed,
            config=t.config,
            operator_consent=t.consent,
            finalized_block=175,
            prior_state=result,
        )
        == result
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("accepted_at_finalized_block", 146),
        ("accepted_sequence", 1),
        ("accepted_directive_sha256", "ff" * 32),
        ("operator_consent_sha256", "ff" * 32),
    ],
)
def test_different_retained_boundary_rejected(transition, field, value):
    t = transition
    with pytest.raises((ValueError, ValidatorSupervisorError)):
        advance_successor_supervisor_directive_state(
            t.signed,
            config=t.config,
            operator_consent=t.consent,
            finalized_block=155,
            prior_state=t.before.model_copy(update={field: value}),
        )


@pytest.mark.parametrize("block", [149, 171])
def test_transition_outside_signed_window_rejected(transition, block):
    t = transition
    with pytest.raises((ValueError, ValidatorSupervisorError)):
        advance_successor_supervisor_directive_history_state(
            t.signed,
            config=t.config,
            operator_consent=t.consent,
            finalized_block=block,
            prior_state=t.before,
        )


@pytest.mark.parametrize("signers", [(0,)])
def test_incomplete_or_untrusted_quorum_rejected(transition, signers):
    t = transition
    with pytest.raises((ValueError, ValidatorSupervisorError)):
        verify_history_compatibility(sign(t.body, signers), config=t.config)


def test_changed_signed_body_not_authorized(transition):
    t = transition
    signed = t.consent.history_compatibility
    body = t.body.model_copy(update={"last_round_sequence": t.body.last_round_sequence + 1})
    changed = signed.model_copy(update={"body": body, "body_sha256": digest(body)})
    with pytest.raises(ValueError, match="signature invalid"):
        verify_history_compatibility(changed, config=t.config)


@pytest.mark.parametrize("kind", ["release", "scope", "source", "oci", "chain"])
def test_signed_new_directive_still_requires_compatibility_scope(transition, kind):
    t = transition
    d = t.signed.directive
    if kind == "release":
        changes = {"release": t.case.release, "replay_package": t.case.target}
    elif kind == "scope":
        changes = {"replay_package": d.replay_package.model_copy(update={"round_sequence": 10000})}
    elif kind == "chain":
        changes = {
            "chain": d.chain.model_copy(
                update={
                    "chain_pin": d.chain.chain_pin.model_copy(update={"metadata_sha256": "ef" * 32})
                }
            )
        }
    else:
        field = "umi_source_tree_sha256" if kind == "source" else "oci_manifest_sha256"
        changes = {"release": d.release.model_copy(update={field: "ef" * 32})}
    with pytest.raises((ValueError, ValidatorSupervisorError)):
        verify_signed_successor_supervisor_directive_history(
            _signed(d.model_copy(update=changes)),
            config=t.config,
            operator_consent=t.consent,
            finalized_block=155,
        )
