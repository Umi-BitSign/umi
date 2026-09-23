"""Native replacement admission/preflight; no service or production chain access."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_evidence_rollover import EvidenceRolloverPending, qualify_evidence_rollover
from umi.competition_evidence_stopped import hold_stopped_evidence_migration
from umi.competition_history_compatibility import original_consent_digest, transition_target_consent
from umi.competition_reward_continuity import (
    UNTIL_SUPERSEDED_BLOCK,
    RewardContinuation,
    admit_certified_allocation,
    sign_reward_continuity_authority,
)
from umi.competition_supervisor import SuccessorSupervisorOperatorConsent
from umi.competition_weights import sign_competition_weight_authorization
from umi.encoding import account_id32
from umi.open_competition import digest as competition_digest
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import ValidatorSupervisorError

from . import test_competition_publication as publication
from .test_competition_history_compatibility import (
    digest,
    sign,
)
from .test_competition_history_compatibility import (
    package_limits as package_limits,
)
from .test_competition_history_compatibility import (
    policy as policy,
)
from .test_competition_history_compatibility import (
    release_identity as release_identity,
)
from .test_competition_history_compatibility import (
    replay_limits as replay_limits,
)
from .test_competition_history_compatibility import (
    successor_case as successor_case,
)
from .test_competition_history_compatibility import (
    successor_chain as successor_chain,
)
from .test_competition_history_compatibility import (
    successor_release as successor_release,
)
from .test_competition_history_compatibility import (
    transition as transition,
)
from .test_competition_history_compatibility import (
    v3_predecessor as v3_predecessor,
)
from .test_competition_package import package_case as base_package_case
from .test_competition_reward_continuity import fixture_boundary
from .test_competition_reward_continuity_weights import enable, runtime_at
from .test_competition_supervisor import (
    _directive,
    _exact_package_target,
    _signed,
    _signed_authorization_target,
    authority_wallets,
)
from .test_competition_weights import (
    _advance,
    _run,
)
from .test_competition_weights import (
    chain as chain,
)
from .test_competition_weights import (
    chain_config as chain_config,
)
from .test_competition_weights import (
    weight_case as weight_case,
)
from .test_competition_weights import (
    worker_capacity as worker_capacity,
)
from .test_open_competition import wallet


@pytest.fixture
def package_case(tmp_path, policy, replay_limits, package_limits, release_identity, monkeypatch):
    original = publication.round_for
    monkeypatch.setattr(
        publication,
        "round_for",
        lambda *a, **k: original(*a, **k).model_copy(update={"sequence": 5}),
    )
    yield from base_package_case.__wrapped__(
        tmp_path, policy, replay_limits, package_limits, release_identity
    )


@pytest.fixture
def replacement(transition, weight_case):
    t, item = transition, enable(weight_case)
    authorities = authority_wallets()
    raw = t.config.model_dump(by_alias=True)
    raw["validator_hotkey"] = item.hotkey
    raw["trusted_authorities"].append(
        {"hotkey": wallet("Ferdie").hotkey.ss58_address, "signature_scheme": "sr25519"}
    )
    raw["trusted_authorities"].sort(key=lambda value: account_id32(value["hotkey"]))
    config = type(t.config).model_validate(raw)
    original = t.case.consent.model_copy(
        update={
            "source_config_sha256": digest(config),
            "validator_hotkey": item.hotkey,
            "reward_continuity_sha256": "0f" * 32,
            "valid_through_block": UNTIL_SUPERSEDED_BLOCK,
        }
    )
    # The historical accepted state is a fixture. Its replay/signatures are
    # qualified separately; the replacement package, certificates, quorum,
    # continuity admission, write authority and owned proof below are native.
    prior = t.before.model_copy(
        update={
            "source_config_sha256": digest(config),
            "operator_consent_sha256": original_consent_digest(original),
            "accepted_mode": "competition_weights",
            "accepted_chain_authorization_sha256": "f0" * 32,
            "accepted_package_sha256": "f3" * 32,
            "continuity_package_sha256": "f3" * 32,
            "continuity_authority_sha256": "0f" * 32,
            "continuity_round_sequence": 4,
            "continuity_stopped": False,
        }
    )
    continuity = item.body.continuation.authority.authority.model_copy(
        update={
            "first_round_sequence": 5,
        }
    )
    continuity = sign_reward_continuity_authority(continuity, authorities[:2])
    admission = admit_certified_allocation(
        continuity, item.package, fixture_boundary(160), wallet("Ferdie")
    )
    body = item.body.model_copy(
        update={
            "predecessor_directive_sha256": prior.accepted_directive_sha256,
            "continuation": RewardContinuation(
                schema="umi-reward-continuation/1",
                authority=continuity,
                admission=admission,
            ),
        }
    )
    authorization = sign_competition_weight_authorization(body, wallet("Ferdie"))
    target_consent = transition_target_consent(t.consent).model_copy(
        update={
            "source_config_sha256": digest(config),
            "validator_hotkey": item.hotkey,
            "reward_continuity_sha256": competition_digest(continuity),
            "valid_through_block": UNTIL_SUPERSEDED_BLOCK,
        }
    )
    release = t.case.release
    grant = t.body.model_copy(
        update={
            "source_config_sha256": digest(config),
            "validator_hotkey": item.hotkey,
            "original_consent_sha256": original_consent_digest(original),
            "target_consent_sha256": original_consent_digest(target_consent),
            "chain_pin_sha256": digest(item.config.chain_pin),
            "predecessor_state_sha256": digest(prior),
            "original_release_identity_sha256s": ["f1" * 32],
            "target_release_identity_sha256": item.package.manifest.release_identity_sha256,
            "target_oci_manifest_sha256": release.oci_manifest_sha256,
            "target_source_tree_sha256": release.umi_source_tree_sha256,
            "first_round_sequence": 5,
            "last_round_sequence": 10,
            "migration_valid_through_block": 400,
        }
    )
    consent = SuccessorSupervisorOperatorConsent.model_validate(
        {
            **target_consent.model_dump(by_alias=True),
            "schema": "umi-validator-supervisor-operator-consent/2",
            "historical_consent": original,
            "history_compatibility": sign(grant),
        }
    )
    target = _exact_package_target(item.case, item.worker.package_limits, item.policy)
    directive = _directive(
        t.case.predecessor,
        target,
        release,
        t.case.chain.model_copy(update={"chain_pin": item.config.chain_pin}),
        consent,
        mode="competition_weights",
        sequence=prior.accepted_sequence + 1,
        predecessor_version=4,
        previous=prior.accepted_directive_sha256,
        issued_at_block=201,
        valid_from_block=201,
        valid_through_block=301,
        reward_continuity_sha256=competition_digest(continuity),
        chain_authorization=_signed_authorization_target(authorization),
    )

    async def observe():
        return await item.provider.collect_weights(item.hotkey, item.recipients)

    return SimpleNamespace(
        item=item,
        body=body,
        arguments=dict(
            config=config,
            consent=consent,
            prior_state=prior,
            signed_directive=_signed(directive),
            package_path=item.case.path,
            authorization_bytes=canonical_json_bytes(authorization),
            chain_config=item.config,
            observe_after_audit=observe,
        ),
    )


async def test_only_actual_certified_newer_package_qualifies(replacement):
    r = replacement
    eligible = await qualify_evidence_rollover(**r.arguments)
    assert (
        eligible.recheck(config=r.arguments["config"], consent=r.arguments["consent"]).block == 201
    )
    assert not r.item.encoded


@pytest.mark.parametrize("block", [9_133_890, 9_133_891, 9_133_892, 9_140_000])
async def test_delayed_C5_leaves_C4_selected_and_renewing_past_launch(
    weight_case, monkeypatch, block
):
    # The shared small-height fixture repeats one byte. Realistic block numbers
    # need a fixed-width synthetic hash too, including the confirmation block.
    monkeypatch.setattr(
        "tests.test_competition_weights._hash", lambda height: "0x" + f"{height:064x}"
    )
    item = enable(weight_case, block=block)
    runtime_at(item, monkeypatch)
    retained = canonical_json_bytes(item.package.retained_settlement)

    async def never():
        pytest.fail("missing C5 must not reach audit, chain capture or stopped migration")

    # No compatibility consent is installed while C5 is missing. C4's native
    # worker still owns its current package, state and continuity authority.
    with pytest.raises(EvidenceRolloverPending, match="keep current renewals"):
        await qualify_evidence_rollover(
            config=None,
            consent=None,
            prior_state=None,
            signed_directive=None,
            package_path=None,
            authorization_bytes=None,
            chain_config=None,
            observe_after_audit=never,
        )
    result = await _run(item)
    assert result.submitted_by_this_attempt and result.exact_row_currently_applied
    assert len(item.encoded) == 1
    assert canonical_json_bytes(item.package.retained_settlement) == retained


@pytest.mark.parametrize("fault", ["stale", "permit", "recipient", "headroom", "fork", "boundary"])
async def test_stopped_refresh_rejects_changed_chain_or_stale_boundary(
    replacement, fault, monkeypatch
):
    r = replacement
    eligible = await qualify_evidence_rollover(**r.arguments)
    if fault == "stale":
        proof = replace(eligible._observation, expires_monotonic_ns=0)
    else:
        if fault == "permit":
            r.item.rpc.values[("SubtensorModule", "ValidatorPermit", (78,))] = [False] * 256
        elif fault == "recipient":
            uid = r.item.recipients[0].uid
            r.item.rpc.values[("SubtensorModule", "Keys", (78, uid))] = wallet(
                "Charlie"
            ).hotkey.ss58_address
        elif fault == "headroom":
            monkeypatch.setattr(
                "tests.test_competition_weights._hash", lambda height: "0x" + f"{height:064x}"
            )
            _advance(r.item, 276)  # 301 - mortality16 - block276 = 9 < signed10.
        elif fault == "fork":
            r.item.finality.ref = replace(r.item.finality.ref, block_hash="0x" + "ff" * 32)
        else:
            prior = r.arguments["prior_state"].model_copy(update={"accepted_sequence": 99})
            eligible = replace(eligible, _prior_state=prior)
    with pytest.raises((ValueError, ValidatorSupervisorError)):
        if fault != "stale":
            proof = await r.arguments["observe_after_audit"]()
        eligible.recheck(
            config=r.arguments["config"], consent=r.arguments["consent"], observation=proof
        )
    assert not r.item.encoded


async def test_pre_audit_capture_cannot_authorize_replacement(replacement):
    r = replacement
    proof = await r.arguments["observe_after_audit"]()

    async def cached():
        return proof

    with pytest.raises(ValueError, match="fresh proof after"):
        await qualify_evidence_rollover(**(r.arguments | {"observe_after_audit": cached}))


async def test_stopped_entrypoint_rejects_calendar_or_operator_assertion_before_OS_access():
    with pytest.raises(ValueError, match="without an eligible replacement"):
        async with hold_stopped_evidence_migration(
            None,
            config=None,
            unit_name=None,
            service_uid=None,
            candidate_receipt=None,
            consent=None,
            worker_limits_bytes=None,
            verified_host_tree=None,
            observer_config=None,
            observe_after_audit=None,
            verify_worker_stopped=None,
            eligible_replacement=True,
        ):
            pytest.fail("a launch date or boolean must not open a stopped migration lease")
