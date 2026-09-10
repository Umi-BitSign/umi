from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from tests.factories import dev_wallet
from umi.crypto import sign_response_digest
from umi.encoding import account_id32
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import (
    SUPERVISOR_CONFIG_SCHEMA,
    SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
    SUPERVISOR_DIRECTIVE_SCHEMA,
    SUPERVISOR_DIRECTIVE_SIGNATURE_DOMAIN,
    SUPERVISOR_DIRECTIVE_STATE_SCHEMA,
    SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA,
    SUPERVISOR_TRUST_POLICY_SCHEMA,
    SignedSupervisorDirective,
    SupervisorDirective,
    SupervisorDirectiveSignature,
    SupervisorDirectiveState,
    ValidatorSupervisorConfig,
    ValidatorSupervisorError,
    advance_supervisor_directive_state,
    load_supervisor_directive_state,
    load_validator_supervisor_config,
    parse_canonical_signed_supervisor_directive,
    parse_canonical_supervisor_directive_page,
    parse_canonical_supervisor_directive_state,
    parse_canonical_validator_supervisor_config,
    store_supervisor_directive_state,
    supervisor_directive_digest,
    supervisor_directive_sha256,
)

CHANNEL_ID = "11" * 32
POLICY_SHA256 = "22" * 32
RELEASE_SHA256 = "33" * 32
MANIFEST_SHA256 = "44" * 32
OCI_SHA256 = "55" * 32
SOURCE_TREE_SHA256 = "66" * 32
REVISION = "77" * 20


def _wallets():
    return sorted(
        [
            dev_wallet("//SupervisorAuthorityA"),
            dev_wallet("//SupervisorAuthorityB"),
            dev_wallet("//SupervisorAuthorityC"),
        ],
        key=lambda wallet: account_id32(wallet.hotkey.ss58_address),
    )


def _validator_hotkey() -> str:
    return dev_wallet("//SupervisorValidator").hotkey.ss58_address


def _config(**changes) -> ValidatorSupervisorConfig:
    authorities = _wallets()
    values = {
        "schema": SUPERVISOR_CONFIG_SCHEMA,
        "network": "finney",
        "netuid": 78,
        "mechanism_id": 0,
        "validator_hotkey": _validator_hotkey(),
        "channel_id": CHANNEL_ID,
        "signature_threshold": 2,
        "trusted_authorities": [
            {
                "hotkey": wallet.hotkey.ss58_address,
                "signature_scheme": "sr25519",
            }
            for wallet in authorities
        ],
        "allowed_oci_repositories": ["ghcr.io/umi-bitsign/umi-validator"],
        "release_origins": ["https://releases.umi.vision"],
        "target_platform": "linux/amd64",
        "state_schema_version": 1,
        "directive_url": "https://api.umi.vision/api/v1/validator-supervisor/directive",
        "poll_seconds": 300,
        "container_runtime": "/usr/bin/podman",
        "state_root": "/var/lib/umi-supervisor/state",
        "worker_state_root": "/var/lib/umi-supervisor-worker",
        "release_root": "/var/lib/umi-supervisor/releases",
        "operator_input_root": "/etc/umi/operator-input",
        "finality_verifier_binary": "/opt/umi/bin/umi-grandpa-finality",
        "finality_verifier_sha256": "77" * 32,
        "finality_chain_spec_path": "/opt/umi/finney.json",
        "worker_cpu_millis": 8_000,
        "worker_memory_bytes": 16 * 1024**3,
        "worker_pids_limit": 512,
        "worker_uid": 65_532,
        "worker_gid": 65_532,
        "wallet": {
            "path": "/var/lib/umi-validator-wallet",
            "name": "validator",
            "hotkey": "default",
        },
        "allowed_modes": [
            "hold",
            "inactive_shadow",
            "bootstrap_service_weights",
            "translation_weights",
        ],
    }
    values.update(changes)
    return ValidatorSupervisorConfig.model_validate(values)


def _release(**changes) -> dict[str, object]:
    values: dict[str, object] = {
        "artifact_type": "oci",
        "release_bundle_url": (
            f"https://releases.umi.vision/validator/{RELEASE_SHA256}/release.tar"
        ),
        "release_bundle_sha256": RELEASE_SHA256,
        "release_bundle_size_bytes": 10_000_000,
        "release_manifest_sha256": MANIFEST_SHA256,
        "release_authority_hotkey": _wallets()[0].hotkey.ss58_address,
        "release_authority_signature_scheme": "sr25519",
        "oci_repository": "ghcr.io/umi-bitsign/umi-validator",
        "oci_manifest_sha256": OCI_SHA256,
        "target_platform": "linux/amd64",
        "umi_git_revision": REVISION,
        "umi_source_tree_sha256": SOURCE_TREE_SHA256,
        "entrypoint_profile": "umi-bootstrap-weight-validator/2",
        "state_schema_minimum": 1,
        "state_schema_maximum": 1,
    }
    values.update(changes)
    return values


def _operator_inputs(**changes) -> dict[str, object]:
    values: dict[str, object] = {
        "artifact_type": "canonical_json",
        "profile": "umi-bootstrap-direct-inputs/2",
        "bundle_url": "https://releases.umi.vision/validator/bootstrap-inputs.json",
        "bundle_sha256": "88" * 32,
        "bundle_size_bytes": 1_000_000,
    }
    values.update(changes)
    return values


def _directive(**changes) -> SupervisorDirective:
    values = {
        "schema": SUPERVISOR_DIRECTIVE_SCHEMA,
        "channel_id": CHANNEL_ID,
        "sequence": 1,
        "previous_directive_sha256": None,
        "issued_at_block": 100,
        "valid_from_block": 110,
        "valid_through_block": 200,
        "network": "finney",
        "netuid": 78,
        "mechanism_id": 0,
        "mode": "bootstrap_service_weights",
        "validator_hotkeys": [_validator_hotkey()],
        "policy_sha256": POLICY_SHA256,
        "release": _release(),
        "operator_inputs": _operator_inputs(),
    }
    values.update(changes)
    return SupervisorDirective.model_validate(values)


def _signed(
    directive: SupervisorDirective | None = None,
    *,
    signer_indexes: tuple[int, ...] = (0, 1),
) -> SignedSupervisorDirective:
    selected_directive = directive or _directive()
    signatures = []
    for index in signer_indexes:
        wallet = _wallets()[index]
        scheme, signature = sign_response_digest(
            wallet,
            supervisor_directive_digest(selected_directive),
        )
        signatures.append(
            SupervisorDirectiveSignature(
                hotkey=wallet.hotkey.ss58_address,
                signature_scheme=scheme,
                signature=signature,
            )
        )
    signatures.sort(key=lambda item: account_id32(item.hotkey))
    return SignedSupervisorDirective(
        schema=SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA,
        directive=selected_directive,
        directive_sha256=supervisor_directive_sha256(selected_directive),
        directive_digest=supervisor_directive_digest(selected_directive).hex(),
        signatures=signatures,
    )


def _reason(error: pytest.ExceptionInfo[ValidatorSupervisorError]) -> str:
    return error.value.reason_code


def test_directive_digest_is_domain_separated_and_signed_threshold_verifies() -> None:
    import hashlib

    directive = _directive()
    expected = hashlib.sha256(
        SUPERVISOR_DIRECTIVE_SIGNATURE_DOMAIN + canonical_json_bytes(directive)
    ).digest()
    assert supervisor_directive_digest(directive) == expected
    assert (
        supervisor_directive_sha256(directive)
        == hashlib.sha256(canonical_json_bytes(directive)).hexdigest()
    )

    signed = _signed(directive)
    assert parse_canonical_signed_supervisor_directive(canonical_json_bytes(signed)) == signed


def test_common_directive_authorizes_any_locally_bound_validator() -> None:
    common = _directive(
        validator_scope="any_permitted_sn78",
        validator_hotkeys=[],
        release=_release(entrypoint_profile="umi-simple-bootstrap-validator/1"),
        operator_inputs=_operator_inputs(profile="umi-simple-bootstrap-common-inputs/1"),
    )
    signed = _signed(common)
    first_config = _config()
    second_config = _config(
        validator_hotkey=dev_wallet("//SecondSupervisorValidator").hotkey.ss58_address
    )

    first = advance_supervisor_directive_state(
        signed,
        config=first_config,
        finalized_block=120,
        prior_state=None,
    )
    second = advance_supervisor_directive_state(
        signed,
        config=second_config,
        finalized_block=120,
        prior_state=None,
    )

    assert first.accepted_directive_sha256 == second.accepted_directive_sha256
    assert common.validator_hotkeys == []


@pytest.mark.parametrize(
    "changes",
    [
        {"validator_scope": "explicit_hotkeys", "validator_hotkeys": []},
        {
            "validator_scope": "any_permitted_sn78",
            "validator_hotkeys": [_validator_hotkey()],
        },
        {
            "validator_scope": "any_permitted_sn78",
            "validator_hotkeys": [],
            "release": _release(entrypoint_profile="umi-bootstrap-weight-validator/2"),
            "operator_inputs": _operator_inputs(profile="umi-bootstrap-direct-inputs/2"),
        },
    ],
)
def test_common_and_explicit_validator_scopes_cannot_be_mixed(changes) -> None:
    with pytest.raises(ValidationError):
        _directive(**changes)


def test_canonical_parsers_reject_whitespace_duplicates_oversize_and_extra_fields() -> None:
    signed = _signed()
    canonical = canonical_json_bytes(signed)
    pretty = json.dumps(signed.model_dump(mode="json", by_alias=True), indent=2).encode()
    with pytest.raises(ValidatorSupervisorError) as noncanonical:
        parse_canonical_signed_supervisor_directive(pretty)
    assert _reason(noncanonical) == "directive_noncanonical"

    encoded_schema = SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA.encode("ascii")
    duplicate = canonical.replace(
        b'"schema":"' + encoded_schema + b'"',
        b'"schema":"' + encoded_schema + b'","schema":"' + encoded_schema + b'"',
        1,
    )
    with pytest.raises(ValidatorSupervisorError) as duplicated:
        parse_canonical_signed_supervisor_directive(duplicate)
    assert _reason(duplicated) == "directive_duplicate_key"

    with pytest.raises(ValidatorSupervisorError) as oversized:
        parse_canonical_signed_supervisor_directive(canonical, maximum_bytes=len(canonical) - 1)
    assert _reason(oversized) == "directive_size_invalid"

    extra = signed.model_dump(mode="json", by_alias=True)
    extra["unexpected"] = True
    with pytest.raises(ValidatorSupervisorError) as wrong_schema:
        parse_canonical_signed_supervisor_directive(canonical_json_bytes(extra))
    assert _reason(wrong_schema) == "directive_schema_invalid"


def test_directive_page_binds_cursor_contiguous_chain_and_authenticated_head() -> None:
    first = _signed()
    second = _signed(
        _directive(
            sequence=2,
            previous_directive_sha256=first.directive_sha256,
            issued_at_block=101,
        )
    )
    page = {
        "schema": SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
        "after_sequence": 0,
        "after_directive_sha256": None,
        "directives": [
            first.model_dump(mode="json", by_alias=True),
            second.model_dump(mode="json", by_alias=True),
        ],
        "more": False,
        "head": second.model_dump(mode="json", by_alias=True),
    }
    parsed = parse_canonical_supervisor_directive_page(canonical_json_bytes(page))
    assert parsed.directives == [first, second]
    assert parsed.head == second

    caught_up = {
        "schema": SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
        "after_sequence": 2,
        "after_directive_sha256": second.directive_sha256,
        "directives": [],
        "more": False,
        "head": second.model_dump(mode="json", by_alias=True),
    }
    assert parse_canonical_supervisor_directive_page(canonical_json_bytes(caught_up)).head == second


@pytest.mark.parametrize(
    "mutation",
    [
        "initial_empty",
        "continued_empty",
        "cursor_pair",
        "sequence_gap",
        "predecessor_mismatch",
        "wrong_head",
    ],
)
def test_directive_page_rejects_ambiguous_or_noncontiguous_history(mutation: str) -> None:
    first = _signed()
    second = _signed(
        _directive(
            sequence=2,
            previous_directive_sha256=first.directive_sha256,
            issued_at_block=101,
        )
    )
    page = {
        "schema": SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
        "after_sequence": 0,
        "after_directive_sha256": None,
        "directives": [first.model_dump(mode="json", by_alias=True)],
        "more": False,
        "head": first.model_dump(mode="json", by_alias=True),
    }
    if mutation == "initial_empty":
        page["directives"] = []
    elif mutation == "continued_empty":
        page.update(
            {
                "after_sequence": 1,
                "after_directive_sha256": first.directive_sha256,
                "directives": [],
                "more": True,
            }
        )
    elif mutation == "cursor_pair":
        page["after_directive_sha256"] = "aa" * 32
    elif mutation == "sequence_gap":
        page["directives"] = [second.model_dump(mode="json", by_alias=True)]
        page["head"] = second.model_dump(mode="json", by_alias=True)
    elif mutation == "predecessor_mismatch":
        wrong_second = _signed(
            _directive(
                sequence=2,
                previous_directive_sha256="aa" * 32,
                issued_at_block=101,
            )
        )
        page["directives"] = [
            first.model_dump(mode="json", by_alias=True),
            wrong_second.model_dump(mode="json", by_alias=True),
        ]
        page["head"] = wrong_second.model_dump(mode="json", by_alias=True)
    else:
        page["directives"] = [
            first.model_dump(mode="json", by_alias=True),
            second.model_dump(mode="json", by_alias=True),
        ]

    with pytest.raises(ValidatorSupervisorError) as raised:
        parse_canonical_supervisor_directive_page(canonical_json_bytes(page))
    assert _reason(raised) == "directive_page_schema_invalid"


def test_config_parser_is_canonical_and_trust_policy_is_exact() -> None:
    config = _config()
    payload = canonical_json_bytes(config)
    assert parse_canonical_validator_supervisor_config(payload) == config
    policy = config.trust_policy()
    assert policy.schema_ == SUPERVISOR_TRUST_POLICY_SCHEMA
    assert policy.channel_id == CHANNEL_ID
    assert policy.signature_threshold == 2
    assert policy.authorities == config.trusted_authorities


@pytest.mark.parametrize(
    "changes",
    [
        {"allowed_oci_repositories": ["ghcr.io/z/repo", "ghcr.io/a/repo"]},
        {"release_origins": ["https://releases.umi.vision/path"]},
        {"release_origins": ["https://user@releases.umi.vision"]},
        {"directive_url": "http://api.umi.vision/directive"},
        {"directive_url": "https://user@api.umi.vision/directive"},
        {"container_runtime": "/usr/bin/docker"},
        {"worker_uid": 0},
        {"worker_gid": 0},
        {"allowed_modes": ["translation_weights", "hold"]},
        {"release_root": "/var/lib/umi-supervisor/state/releases"},
    ],
)
def test_config_rejects_unsafe_or_ambiguous_local_authority(changes) -> None:
    with pytest.raises(ValidationError):
        _config(**changes)


@pytest.mark.parametrize(
    ("release_change", "reason"),
    [
        ({"oci_repository": "ghcr.io/another/validator"}, "directive_oci_repository_not_allowed"),
        ({"target_platform": "linux/arm64"}, "directive_target_platform_mismatch"),
        (
            {"state_schema_minimum": 2, "state_schema_maximum": 3},
            "directive_state_schema_incompatible",
        ),
        (
            {"release_bundle_url": "https://other.example/release.tar"},
            "directive_release_origin_not_allowed",
        ),
        (
            {
                "release_authority_hotkey": dev_wallet(
                    "//UntrustedReleaseAuthority"
                ).hotkey.ss58_address
            },
            "directive_release_authority_untrusted",
        ),
        (
            {"release_authority_signature_scheme": "ed25519"},
            "directive_release_authority_scheme_mismatch",
        ),
    ],
)
def test_local_config_pins_release_repository_origin_platform_and_state_schema(
    release_change, reason
) -> None:
    signed = _signed(_directive(release=_release(**release_change)))
    with pytest.raises(ValidatorSupervisorError) as raised:
        advance_supervisor_directive_state(
            signed,
            config=_config(),
            finalized_block=105,
            prior_state=None,
        )
    assert _reason(raised) == reason


def test_local_config_pins_operator_input_origin() -> None:
    signed = _signed(
        _directive(
            operator_inputs=_operator_inputs(
                bundle_url="https://other.example/bootstrap-inputs.json"
            )
        )
    )
    with pytest.raises(ValidatorSupervisorError) as raised:
        advance_supervisor_directive_state(
            signed,
            config=_config(),
            finalized_block=105,
            prior_state=None,
        )
    assert _reason(raised) == "directive_operator_input_origin_not_allowed"


@pytest.mark.parametrize(
    "release_change",
    [
        {"oci_repository": "ghcr.io/umi-bitsign/umi-validator:latest"},
        {"release_bundle_url": "http://releases.umi.vision/release.tar"},
        {"release_bundle_url": "https://user@releases.umi.vision/release.tar"},
        {"release_bundle_url": "https://releases.umi.vision/release.tar?version=1"},
        {"release_bundle_size_bytes": 1024**3 + 1},
        {"state_schema_minimum": 2, "state_schema_maximum": 1},
        {"umi_git_revision": "A" * 40},
    ],
)
def test_release_model_rejects_mutable_or_malformed_identity(release_change) -> None:
    with pytest.raises(ValidationError):
        _directive(release=_release(**release_change))


def test_directive_shape_binds_predecessor_blocks_order_and_entrypoint() -> None:
    invalid = [
        {"sequence": 1, "previous_directive_sha256": "aa" * 32},
        {"sequence": 2, "previous_directive_sha256": None},
        {"issued_at_block": 111, "valid_from_block": 110},
        {"valid_from_block": 201, "valid_through_block": 200},
        {"mode": "hold"},
        {
            "mode": "inactive_shadow",
            "release": _release(entrypoint_profile="umi-bootstrap-weight-validator/2"),
        },
    ]
    for changes in invalid:
        with pytest.raises(ValidationError):
            _directive(**changes)

    hold = _directive(mode="hold", policy_sha256=None, release=None, operator_inputs=None)
    assert hold.mode == "hold"

    with pytest.raises(ValidationError, match="immutable operator-input bundle"):
        _directive(operator_inputs=None)
    with pytest.raises(ValidationError, match="only bootstrap mode"):
        _directive(
            mode="inactive_shadow",
            release=_release(entrypoint_profile="umi-live-shadow-validator/1"),
        )


def test_authority_validator_and_signature_sets_are_unique_and_account_sorted() -> None:
    config = _config().model_dump(mode="json", by_alias=True)
    config["trusted_authorities"] = list(reversed(config["trusted_authorities"]))
    with pytest.raises(ValidationError, match="AccountId32-sorted"):
        ValidatorSupervisorConfig.model_validate(config)

    validator_a = dev_wallet("//SupervisorValidatorA").hotkey.ss58_address
    validator_b = dev_wallet("//SupervisorValidatorB").hotkey.ss58_address
    validators = sorted([validator_a, validator_b], key=account_id32, reverse=True)
    with pytest.raises(ValidationError, match="validator hotkeys"):
        _directive(validator_hotkeys=validators)

    signed = _signed()
    signed_values = signed.model_dump(mode="json", by_alias=True)
    signed_values["signatures"] = list(reversed(signed_values["signatures"]))
    with pytest.raises(ValidationError, match="supervisor signatures"):
        SignedSupervisorDirective.model_validate(signed_values)

    signed_values = signed.model_dump(mode="json", by_alias=True)
    signed_values["signatures"] = [signed_values["signatures"][0]] * 2
    with pytest.raises(ValidationError, match="supervisor signatures"):
        SignedSupervisorDirective.model_validate(signed_values)


def test_threshold_wrong_scheme_invalid_signature_and_untrusted_signer_fail_closed() -> None:
    with pytest.raises(ValidatorSupervisorError) as below:
        advance_supervisor_directive_state(
            _signed(signer_indexes=(0,)),
            config=_config(),
            finalized_block=105,
            prior_state=None,
        )
    assert _reason(below) == "directive_signature_threshold_not_met"

    config_values = _config().model_dump(mode="json", by_alias=True)
    config_values["trusted_authorities"][1]["signature_scheme"] = "ed25519"
    wrong_scheme_config = ValidatorSupervisorConfig.model_validate(config_values)
    with pytest.raises(ValidatorSupervisorError) as wrong_scheme:
        advance_supervisor_directive_state(
            _signed(),
            config=wrong_scheme_config,
            finalized_block=105,
            prior_state=None,
        )
    assert _reason(wrong_scheme) == "directive_signature_scheme_mismatch"

    signed = _signed()
    values = signed.model_dump(mode="json", by_alias=True)
    signature = values["signatures"][0]["signature"]
    values["signatures"][0]["signature"] = signature[:-1] + ("0" if signature[-1] != "0" else "1")
    tampered = SignedSupervisorDirective.model_validate(values)
    with pytest.raises(ValidatorSupervisorError) as invalid:
        advance_supervisor_directive_state(
            tampered,
            config=_config(),
            finalized_block=105,
            prior_state=None,
        )
    assert _reason(invalid) == "directive_signature_invalid"

    outsider = dev_wallet("//SupervisorOutsider")
    directive = _directive()
    scheme, signature = sign_response_digest(outsider, supervisor_directive_digest(directive))
    records = [
        *_signed(directive).signatures,
        SupervisorDirectiveSignature(
            hotkey=outsider.hotkey.ss58_address,
            signature_scheme=scheme,
            signature=signature,
        ),
    ]
    records.sort(key=lambda item: account_id32(item.hotkey))
    untrusted = SignedSupervisorDirective(
        schema=SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA,
        directive=directive,
        directive_sha256=supervisor_directive_sha256(directive),
        directive_digest=supervisor_directive_digest(directive).hex(),
        signatures=records,
    )
    with pytest.raises(ValidatorSupervisorError) as untrusted_error:
        advance_supervisor_directive_state(
            untrusted,
            config=_config(),
            finalized_block=105,
            prior_state=None,
        )
    assert _reason(untrusted_error) == "directive_signer_untrusted"


@pytest.mark.parametrize(
    ("directive_changes", "config_changes", "block", "reason"),
    [
        ({"channel_id": "99" * 32}, {}, 105, "directive_channel_mismatch"),
        (
            {"validator_hotkeys": [dev_wallet("//OtherValidator").hotkey.ss58_address]},
            {},
            105,
            "directive_validator_not_authorized",
        ),
        ({}, {"allowed_modes": ["hold"]}, 105, "directive_mode_not_locally_allowed"),
        ({}, {}, 99, "directive_issued_in_future"),
        ({}, {}, 201, "directive_expired"),
    ],
)
def test_directive_static_consent_and_block_lease_fail_closed(
    directive_changes, config_changes, block, reason
) -> None:
    signed = _signed(_directive(**directive_changes))
    with pytest.raises(ValidatorSupervisorError) as raised:
        advance_supervisor_directive_state(
            signed,
            config=_config(**config_changes),
            finalized_block=block,
            prior_state=None,
        )
    assert _reason(raised) == reason


def test_directive_channel_is_bound_to_exactly_one_validator() -> None:
    validators = sorted(
        [
            _validator_hotkey(),
            dev_wallet("//AdditionalSupervisorValidator").hotkey.ss58_address,
        ],
        key=account_id32,
    )
    signed = _signed(_directive(validator_hotkeys=validators))
    with pytest.raises(ValidatorSupervisorError) as raised:
        advance_supervisor_directive_state(
            signed,
            config=_config(),
            finalized_block=105,
            prior_state=None,
        )
    assert _reason(raised) == "directive_validator_not_authorized"


def test_monotonic_directive_chain_allows_exact_replay_and_next_record() -> None:
    config = _config()
    first_signed = _signed()
    first = advance_supervisor_directive_state(
        first_signed,
        config=config,
        finalized_block=105,
        prior_state=None,
    )
    assert first.accepted_sequence == 1
    assert first.accepted_mode == "bootstrap_service_weights"
    assert first.accepted_oci_manifest_sha256 == "55" * 32
    assert first.accepted_operator_input_sha256 == "88" * 32
    assert (
        advance_supervisor_directive_state(
            first_signed,
            config=config,
            finalized_block=106,
            prior_state=first,
        )
        == first
    )

    second_directive = _directive(
        sequence=2,
        previous_directive_sha256=first.accepted_directive_sha256,
        issued_at_block=106,
    )
    second = advance_supervisor_directive_state(
        _signed(second_directive),
        config=config,
        finalized_block=110,
        prior_state=first,
    )
    assert second.accepted_sequence == 2
    assert second.accepted_directive_sha256 == supervisor_directive_sha256(second_directive)

    with pytest.raises(ValidatorSupervisorError) as block_rollback:
        advance_supervisor_directive_state(
            _signed(second_directive),
            config=config,
            finalized_block=109,
            prior_state=second,
        )
    assert _reason(block_rollback) == "directive_finalized_block_rollback"


def test_directive_state_requires_mode_and_immutable_release_binding() -> None:
    base = {
        "schema": SUPERVISOR_DIRECTIVE_STATE_SCHEMA,
        "channel_id": CHANNEL_ID,
        "accepted_sequence": 1,
        "accepted_directive_sha256": "aa" * 32,
        "accepted_at_finalized_block": 100,
    }
    with pytest.raises(ValidationError):
        SupervisorDirectiveState(
            **base,
            accepted_mode="hold",
            accepted_oci_manifest_sha256="55" * 32,
        )
    with pytest.raises(ValidationError):
        SupervisorDirectiveState(
            **base,
            accepted_mode="translation_weights",
            accepted_oci_manifest_sha256=None,
        )
    with pytest.raises(ValidationError, match="operator-input digest"):
        SupervisorDirectiveState(
            **base,
            accepted_mode="bootstrap_service_weights",
            accepted_oci_manifest_sha256="55" * 32,
            accepted_operator_input_sha256=None,
        )


def test_exact_directive_replay_rejects_corrupt_execution_binding() -> None:
    config = _config()
    signed = _signed()
    first = advance_supervisor_directive_state(
        signed,
        config=config,
        finalized_block=105,
        prior_state=None,
    )
    corrupt = first.model_copy(
        update={
            "accepted_mode": "hold",
            "accepted_oci_manifest_sha256": None,
        }
    )

    with pytest.raises(ValidatorSupervisorError) as raised:
        advance_supervisor_directive_state(
            signed,
            config=config,
            finalized_block=106,
            prior_state=corrupt,
        )
    assert _reason(raised) == "directive_state_execution_binding_mismatch"


def test_monotonic_directive_chain_rejects_initial_gap_rollback_equivocation_and_predecessor() -> (
    None
):
    config = _config()
    first_signed = _signed()
    first = advance_supervisor_directive_state(
        first_signed,
        config=config,
        finalized_block=105,
        prior_state=None,
    )

    cases = [
        (
            _directive(
                sequence=2,
                previous_directive_sha256=first.accepted_directive_sha256,
            ),
            None,
            "directive_initial_sequence_invalid",
        ),
        (
            _directive(),
            first.model_copy(update={"accepted_sequence": 2}),
            "directive_sequence_rollback",
        ),
        (_directive(valid_through_block=199), first, "directive_sequence_equivocation"),
        (
            _directive(sequence=3, previous_directive_sha256=first.accepted_directive_sha256),
            first,
            "directive_sequence_gap",
        ),
        (
            _directive(sequence=2, previous_directive_sha256="aa" * 32),
            first,
            "directive_predecessor_mismatch",
        ),
    ]
    for directive, prior, reason in cases:
        with pytest.raises(ValidatorSupervisorError) as raised:
            advance_supervisor_directive_state(
                _signed(directive),
                config=config,
                finalized_block=105,
                prior_state=prior,
            )
        assert _reason(raised) == reason


def test_state_parser_and_atomic_compare_store_preserve_high_water_mark(tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    path = state_root / "directive-state.json"
    config = _config()
    policy = config.trust_policy()
    assert load_supervisor_directive_state(path, trust_policy=policy) is None

    first = advance_supervisor_directive_state(
        _signed(),
        config=config,
        finalized_block=105,
        prior_state=None,
    )
    store_supervisor_directive_state(
        path,
        first,
        trust_policy=policy,
        expected_prior=None,
    )
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.read_bytes() == canonical_json_bytes(first)
    assert load_supervisor_directive_state(path, trust_policy=policy) == first
    assert (
        parse_canonical_supervisor_directive_state(path.read_bytes(), trust_policy=policy) == first
    )

    different_prior = first.model_copy(update={"accepted_at_finalized_block": 106})
    with pytest.raises(ValidatorSupervisorError) as compare_failed:
        store_supervisor_directive_state(
            path,
            first,
            trust_policy=policy,
            expected_prior=different_prior,
        )
    assert _reason(compare_failed) == "directive_state_compare_failed"


def test_state_store_itself_rejects_sequence_gaps_and_same_sequence_changes(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    path = state_root / "directive-state.json"
    config = _config()
    policy = config.trust_policy()
    first = advance_supervisor_directive_state(
        _signed(),
        config=config,
        finalized_block=105,
        prior_state=None,
    )
    store_supervisor_directive_state(
        path,
        first,
        trust_policy=policy,
        expected_prior=None,
    )

    changed_height = first.model_copy(update={"accepted_at_finalized_block": 106})
    with pytest.raises(ValidatorSupervisorError) as same_sequence:
        store_supervisor_directive_state(
            path,
            changed_height,
            trust_policy=policy,
            expected_prior=first,
        )
    assert _reason(same_sequence) == "directive_state_same_sequence_changed"

    gap = first.model_copy(update={"accepted_sequence": 3})
    with pytest.raises(ValidatorSupervisorError) as sequence_gap:
        store_supervisor_directive_state(
            path,
            gap,
            trust_policy=policy,
            expected_prior=first,
        )
    assert _reason(sequence_gap) == "directive_state_sequence_gap"

    invalid_binding = first.model_copy(
        update={
            "accepted_mode": "hold",
            "accepted_oci_manifest_sha256": "55" * 32,
        }
    )
    with pytest.raises(ValidatorSupervisorError) as invalid_state:
        store_supervisor_directive_state(
            path,
            invalid_binding,
            trust_policy=policy,
            expected_prior=first,
        )
    assert _reason(invalid_state) == "directive_state_schema_invalid"


def test_state_load_rejects_permissions_symlink_hardlink_and_noncanonical(tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    policy = _config().trust_policy()
    state = SupervisorDirectiveState(
        schema=SUPERVISOR_DIRECTIVE_STATE_SCHEMA,
        channel_id=CHANNEL_ID,
        accepted_sequence=1,
        accepted_directive_sha256="aa" * 32,
        accepted_at_finalized_block=100,
        accepted_mode="hold",
        accepted_oci_manifest_sha256=None,
    )
    path = state_root / "state.json"
    path.write_bytes(canonical_json_bytes(state))
    path.chmod(0o644)
    with pytest.raises(ValidatorSupervisorError) as permissions:
        load_supervisor_directive_state(path, trust_policy=policy)
    assert _reason(permissions) == "directive_state_file_unsafe"

    path.chmod(0o600)
    link = state_root / "link.json"
    link.symlink_to(path)
    with pytest.raises(ValidatorSupervisorError):
        load_supervisor_directive_state(link, trust_policy=policy)

    hardlink = state_root / "hardlink.json"
    os.link(path, hardlink)
    with pytest.raises(ValidatorSupervisorError) as linked:
        load_supervisor_directive_state(path, trust_policy=policy)
    assert _reason(linked) == "directive_state_file_unsafe"
    hardlink.unlink()

    path.write_bytes(json.dumps(state.model_dump(mode="json", by_alias=True), indent=2).encode())
    path.chmod(0o600)
    with pytest.raises(ValidatorSupervisorError) as noncanonical:
        load_supervisor_directive_state(path, trust_policy=policy)
    assert _reason(noncanonical) == "state_noncanonical"


def test_config_loader_checks_file_and_private_runtime_roots(tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    worker_state_root = tmp_path / "worker-state"
    release_root = tmp_path / "releases"
    operator_root = tmp_path / "operator"
    wallet_root = tmp_path / "wallet"
    for path in (state_root, worker_state_root, release_root, operator_root, wallet_root):
        path.mkdir(mode=0o700)
    config = _config(
        state_root=str(state_root),
        worker_state_root=str(worker_state_root),
        release_root=str(release_root),
        operator_input_root=str(operator_root),
        wallet={"path": str(wallet_root), "name": "validator", "hotkey": "default"},
    )
    config_path = tmp_path / "supervisor.json"
    config_path.write_bytes(canonical_json_bytes(config))
    config_path.chmod(0o600)
    assert load_validator_supervisor_config(config_path) == config

    config_path.chmod(0o666)
    with pytest.raises(ValidatorSupervisorError) as writable:
        load_validator_supervisor_config(config_path)
    assert _reason(writable) == "config_file_unsafe"

    config_path.chmod(0o600)
    release_root.chmod(0o755)
    with pytest.raises(ValidatorSupervisorError) as unsafe_root:
        load_validator_supervisor_config(config_path)
    assert _reason(unsafe_root) == "directive_state_directory_unsafe"
