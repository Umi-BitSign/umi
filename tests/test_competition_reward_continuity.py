"""Forward authority with synthetic keys/heads and native certified packages."""

import json

import pytest

from umi.competition_reward_continuity import (
    UNTIL_SUPERSEDED_BLOCK,
    RewardContinuityAuthority,
    sign_reward_continuity_authority,
)
from umi.competition_successor_follow import AutomaticSuccessorPublisher
from umi.competition_successor_publication import (
    SuccessorRoundPublicationBuilder,
    SuccessorRoundPublicationPlan,
)
from umi.competition_supervisor import (
    advance_successor_supervisor_directive_state,
    verify_bound_successor_chain_authorization,
)
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor import ValidatorSupervisorError

from .test_competition_successor_publication import authority_wallets
from .test_competition_successor_renewal import (
    automatic as automatic,
)
from .test_competition_successor_renewal import (
    chain_config as chain_config,
)
from .test_competition_successor_renewal import (
    change_capture,
    completed,
    enable_follow,
)
from .test_competition_successor_renewal import (
    feed_case as feed_case,
)
from .test_competition_successor_renewal import (
    guarded as guarded,
)
from .test_competition_successor_renewal import (
    next_package as next_package,
)
from .test_competition_successor_renewal import (
    package_case as package_case,
)
from .test_competition_successor_renewal import (
    package_limits as package_limits,
)
from .test_competition_successor_renewal import (
    policy as policy,
)
from .test_competition_successor_renewal import (
    publication_case as publication_case,
)
from .test_competition_successor_renewal import (
    release_identity as release_identity,
)
from .test_competition_successor_renewal import (
    replay_limits as replay_limits,
)
from .test_competition_successor_renewal import (
    successor_case as successor_case,
)
from .test_competition_successor_renewal import (
    successor_chain as successor_chain,
)
from .test_competition_successor_renewal import (
    successor_release as successor_release,
)
from .test_competition_successor_renewal import (
    v3_predecessor as v3_predecessor,
)
from .test_competition_successor_renewal import (
    worker_capacity as worker_capacity,
)


def fixture_boundary(block):
    from umi.competition_execution import ExecutionBoundary

    return ExecutionBoundary(
        source="verifier_attested_finality",
        block=block,
        block_hash="0x" + f"{block:064x}",
        state_root="0x" + "11" * 32,
        snapshot_sha256="22" * 32,
        evidence_sha256="33" * 32,
    )


def continuity_plan(case, package):
    plan = case.publisher.builder.plan
    loaded = case.publisher.builder._load(package.prepared)
    authority = RewardContinuityAuthority(
        schema="umi-reward-continuity-authority/1",
        policy_sha256=plan.policy_sha256,
        first_round_sha256=loaded.manifest.round_sha256,
        first_round_sequence=1,
        last_round_sequence=10,
        release_identity_sha256=loaded.manifest.release_identity_sha256,
        chain_pin=plan.chain.chain_pin,
        issued_at_block=125,
        valid_from_block=125,
        lifetime="until_superseded_or_revoked",
        allocation_rule="latest_on_time_certified_exact_projection/1",
        recipient_change_action="hold_until_valid_certified_replacement",
        revocation_rule="stop_renewal_expire_outstanding_leases/1",
        admission_authority_hotkey=authority_wallets()[0].hotkey.ss58_address,
        maximum_write_authorization_blocks=50,
    )
    signed = sign_reward_continuity_authority(authority, authority_wallets()[:2])
    raw = json.loads(canonical_json_bytes(plan))
    raw.update(
        schema="umi-successor-round-publication-plan/4",
        renewal_interval_blocks=2,
        continuity=json.loads(canonical_json_bytes(signed)),
        valid_through_block=UNTIL_SUPERSEDED_BLOCK,
    )
    raw["consent"].update(
        reward_continuity_sha256=digest(signed), valid_through_block=UNTIL_SUPERSEDED_BLOCK
    )
    return SuccessorRoundPublicationPlan.model_validate_json(json.dumps(raw))


def setup(automatic, package, tmp_path):
    c = enable_follow(automatic, tmp_path, continuity_plan(automatic, package))
    completed(c, package)
    return c


async def test_original_expiry_and_delayed_replacement_preserve_exact_allocation(
    automatic,
    package_case,
    next_package,
    tmp_path,
):
    c = setup(automatic, package_case, tmp_path)
    assert (await c.service.tick())["status"] == "published"
    first = c.feed.history()[0]
    old_certificate = canonical_json_bytes(
        c.publisher.builder._load(package_case.prepared).settlement_certificate
    )
    for head in (201, 225):
        c.provider.block = head
        assert (await c.service.tick())["status"] == "published"
        renewal = c.feed.history()[-1]
        assert renewal.intent.package == first.intent.package
        assert renewal.intent.authorization.valid_through_block == head + 50
        assert (
            renewal.intent.authorization.continuation.admission
            == first.intent.authorization.continuation.admission
        )
        verify_bound_successor_chain_authorization(
            canonical_json_bytes(renewal.authorization),
            directive=renewal.signed.directive,
            config=c.publisher.builder.plan.supervisor,
            package=c.publisher.builder._load(package_case.prepared),
        )
    assert (
        canonical_json_bytes(
            c.publisher.builder._load(package_case.prepared).settlement_certificate
        )
        == old_certificate
    )
    completed(c, next_package)
    c.provider.block = 245
    assert (await c.service.tick())["round_sequence"] == 2
    replacement = c.feed.history()[-1]
    assert replacement.intent.package.round_sequence == 2
    c.service = AutomaticSuccessorPublisher(c.publisher, c.feed, c.config, **c.signers)
    assert (await c.service.tick())["status"] == "waiting_for_completed_round"
    c.provider.block = 5000  # Beyond both original round ends and the original outer plan.
    assert (await c.service.tick())["round_sequence"] == 2
    assert c.feed.history()[-1].intent.package == replacement.intent.package
    assert len(c.publisher.builder.journal.keys("continuity_admission")) == 2


async def test_first_certificate_presented_after_original_end_is_rejected(
    automatic, package_case, tmp_path
):
    c = setup(automatic, package_case, tmp_path)
    c.provider.block = 201
    with pytest.raises(ValueError, match="not admitted within its original round"):
        await c.service.tick()
    assert not c.publisher.builder.journal.keys("continuity_admission")
    assert not c.publisher.builder.journal.keys("authorization")


@pytest.mark.parametrize("crash_kind", ["intent", "authorization"])
async def test_expired_same_round_partial_attempt_retries_without_rewriting_signed_history(
    automatic,
    package_case,
    tmp_path,
    monkeypatch,
    crash_kind,
):
    c = setup(automatic, package_case, tmp_path)
    journal = c.publisher.builder.journal
    put = journal.put
    captured = {}

    def crash(kind, slot, value):
        result = put(kind, slot, value)
        if kind == crash_kind:
            captured[slot] = canonical_json_bytes(value)
            raise RuntimeError("crash after durable write")
        return result

    monkeypatch.setattr(journal, "put", crash)
    with pytest.raises(RuntimeError, match="crash after durable write"):
        await c.service.tick()
    monkeypatch.setattr(journal, "put", put)
    plan = c.publisher.builder.plan
    c.publisher.builder = SuccessorRoundPublicationBuilder(journal.root, plan)
    c.service = AutomaticSuccessorPublisher(c.publisher, c.feed, c.config, **c.signers)
    c.provider.block = 220
    assert (await c.service.tick())["status"] == "published"
    assert c.feed.history()[0].intent.authorization.signed_at_block == 220
    assert len(c.publisher.builder.journal.keys("expired_intent")) == 1
    for slot, raw in captured.items():
        assert canonical_json_bytes(c.publisher.builder.journal.get(crash_kind, slot)) == raw
    assert len(c.publisher.builder.journal.keys("intent")) == 2


async def test_recipient_reuse_holds_old_row_without_poisoning_later_certificate(
    automatic,
    package_case,
    next_package,
    tmp_path,
    monkeypatch,
):
    c = setup(automatic, package_case, tmp_path)
    assert (await c.service.tick())["status"] == "published"
    capture = c.provider.collect

    async def removed():
        return change_capture(await capture(), ())

    monkeypatch.setattr(c.provider, "collect", removed)
    c.provider.block = 220
    with pytest.raises(ValueError, match="recipient registration changed"):
        await c.service.tick()
    assert len(c.feed.history()) == 1
    monkeypatch.setattr(c.provider, "collect", capture)
    completed(c, next_package)
    c.provider.block = 245
    assert (await c.service.tick())["round_sequence"] == 2


@pytest.mark.parametrize("change", ["missing", "uid_reused", "hotkey_moved"])
async def test_exact_row_holds_one_changed_recipient_across_restart_and_recovers_on_return(
    automatic, package_case, tmp_path, monkeypatch, change
):
    from umi.competition_successor_publisher import CurrentSuccessorRoundPublisher
    from umi.open_competition import Registration

    from .test_open_competition import wallet

    c = setup(automatic, package_case, tmp_path)
    assert (await c.service.tick())["status"] == "published"
    first = canonical_json_bytes(c.feed.history()[0])
    capture = c.provider.collect
    original = await capture()
    allocation = c.publisher.builder._load(package_case.prepared).retained_settlement.projection
    removed = allocation.allocations[0]
    remaining = [r for r in original.snapshot.registrations if r.uid != removed.uid]
    if change == "uid_reused":
        remaining.append(
            Registration(uid=removed.uid, hotkey=wallet("Charlie").hotkey.ss58_address)
        )
    elif change == "hotkey_moved":
        assert 12 not in {r.uid for r in original.snapshot.registrations}
        remaining.append(Registration(uid=12, hotkey=removed.hotkey))

    async def changed():
        return change_capture(await capture(), tuple(sorted(remaining, key=lambda r: r.uid)))

    monkeypatch.setattr(c.provider, "collect", changed)
    for head in (220, 240):
        c.provider.block = head
        with pytest.raises(ValueError, match="recipient registration changed"):
            await c.service.tick()
        assert len(c.feed.history()) == 1
        assert canonical_json_bytes(c.feed.history()[0]) == first
        assert len(c.publisher.builder.journal.keys("authorization")) == 1
        old = c.publisher.builder
        builder = SuccessorRoundPublicationBuilder(old.journal.root, old.plan)
        c.publisher = CurrentSuccessorRoundPublisher(
            builder, c.guarded.store, c.guarded.replay, c.provider
        )
        c.service = AutomaticSuccessorPublisher(c.publisher, c.feed, c.config, **c.signers)
    monkeypatch.setattr(c.provider, "collect", capture)
    c.provider.block = 260
    assert (await c.service.tick())["status"] == "published"
    assert len(c.feed.history()) == 2
    assert c.feed.history()[-1].intent.package == c.feed.history()[0].intent.package


async def test_native_host_preserves_round_highwater_and_rejects_old_fallback(
    automatic,
    package_case,
    next_package,
    tmp_path,
    v3_predecessor,
):
    c = setup(automatic, package_case, tmp_path)
    assert (await c.service.tick())["status"] == "published"
    first = c.feed.history()[0]
    kwargs = dict(
        config=c.publisher.builder.plan.supervisor,
        operator_consent=c.publisher.builder.plan.consent,
    )
    state = advance_successor_supervisor_directive_state(
        first.signed,
        finalized_block=160,
        prior_state=v3_predecessor.state,
        prior_v3_signed_bytes=v3_predecessor.body,
        **kwargs,
    )
    assert state.continuity_round_sequence == 1
    completed(c, next_package)
    c.provider.block = 245
    assert (await c.service.tick())["round_sequence"] == 2
    second = c.feed.history()[-1]
    state = advance_successor_supervisor_directive_state(
        second.signed, finalized_block=245, prior_state=state, **kwargs
    )
    assert state.continuity_round_sequence == 2
    # Native durable state survives serialization; a lower signed sequence cannot return.
    state = type(state).model_validate_json(canonical_json_bytes(state))
    with pytest.raises(ValidatorSupervisorError):
        advance_successor_supervisor_directive_state(
            first.signed, finalized_block=245, prior_state=state, **kwargs
        )


async def test_authority_revocation_is_terminal_across_restart(automatic, package_case, tmp_path):
    from umi.competition_reward_continuity import (
        RewardContinuityRevocation,
        sign_reward_continuity_revocation,
    )

    c = setup(automatic, package_case, tmp_path)
    assert (await c.service.tick())["status"] == "published"
    plan = c.publisher.builder.plan
    c.provider.block = 162
    revocation = sign_reward_continuity_revocation(
        RewardContinuityRevocation(
            schema="umi-reward-continuity-revocation/1",
            authority_sha256=digest(plan.continuity),
            revoked_at_block=162,
            action="stop_renewal_expire_outstanding_leases",
        ),
        authority_wallets()[:2],
    )
    await c.publisher.revoke(revocation)
    c.publisher.builder = SuccessorRoundPublicationBuilder(c.publisher.builder.journal.root, plan)
    c.service = AutomaticSuccessorPublisher(c.publisher, c.feed, c.config, **c.signers)
    c.provider.block = 5000
    assert (await c.service.tick())["status"] == "continuity_revoked"
    assert len(c.feed.history()) == 1
    assert c.feed.history()[0].intent.authorization.valid_through_block == 210


async def test_native_hold_latches_continuity_stop(
    automatic, package_case, tmp_path, v3_predecessor
):
    from .test_competition_supervisor import _signed

    c = setup(automatic, package_case, tmp_path)
    await c.service.tick()
    first = c.feed.history()[0]
    plan = c.publisher.builder.plan
    kwargs = dict(config=plan.supervisor, operator_consent=plan.consent)
    state = advance_successor_supervisor_directive_state(
        first.signed,
        finalized_block=160,
        prior_state=v3_predecessor.state,
        prior_v3_signed_bytes=v3_predecessor.body,
        **kwargs,
    )
    hold = first.signed.directive.model_copy(
        update={
            "sequence": first.intent.sequence + 1,
            "predecessor_version": 4,
            "previous_directive_sha256": first.signed.directive_sha256,
            "issued_at_block": 162,
            "valid_from_block": 162,
            "valid_through_block": UNTIL_SUPERSEDED_BLOCK,
            "mode": "hold",
            "policy_sha256": None,
            "capabilities": None,
            "release": None,
            "replay_package": None,
            "chain_authorization": None,
            "reward_continuity_sha256": None,
        }
    )
    signed = _signed(hold)
    state = advance_successor_supervisor_directive_state(
        signed, finalized_block=162, prior_state=state, **kwargs
    )
    assert state.continuity_stopped and state.continuity_round_sequence == 1
    restarted = type(state).model_validate_json(canonical_json_bytes(state))
    assert (
        advance_successor_supervisor_directive_state(
            signed, finalized_block=200, prior_state=restarted, **kwargs
        )
        == state
    )
    returned = first.signed.directive.model_copy(
        update={
            "sequence": hold.sequence + 1,
            "predecessor_version": 4,
            "previous_directive_sha256": signed.directive_sha256,
            "issued_at_block": 163,
            "valid_from_block": 163,
        }
    )
    # Match the changed predecessor in the target before signing the invalid resumed directive.
    returned = returned.model_copy(
        update={
            "chain_authorization": returned.chain_authorization.model_copy(
                update={"predecessor_directive_sha256": signed.directive_sha256}
            )
        }
    )
    with pytest.raises(ValidatorSupervisorError, match="continuity_rollback_or_stopped"):
        advance_successor_supervisor_directive_state(
            _signed(returned), finalized_block=163, prior_state=state, **kwargs
        )


async def test_invalid_later_package_cannot_replace_certified_row(
    automatic, package_case, next_package, tmp_path
):
    from pathlib import Path

    c = setup(automatic, package_case, tmp_path)
    await c.service.tick()
    completed(c, next_package)
    path = Path(next_package.prepared.package_path) / "evidence.json"
    original = path.read_bytes()
    path.chmod(0o600)
    path.write_bytes(original + b" ")
    path.chmod(0o400)
    c.provider.block = 245
    assert (await c.service.tick())["round_sequence"] == 1
    assert len(c.publisher.builder.journal.keys("rejected_continuity_candidate")) == 1
    assert (
        c.feed.history()[-1].intent.package.package_sha256 == package_case.prepared.package_sha256
    )
    path.chmod(0o600)
    path.write_bytes(original)
    path.chmod(0o400)
    assert (await c.service.tick())["round_sequence"] == 2


async def test_higher_directive_sequence_cannot_return_to_older_round(
    automatic, package_case, next_package, tmp_path, v3_predecessor
):
    from .test_competition_supervisor import _signed

    c = setup(automatic, package_case, tmp_path)
    await c.service.tick()
    first = c.feed.history()[0]
    plan = c.publisher.builder.plan
    kwargs = dict(config=plan.supervisor, operator_consent=plan.consent)
    state = advance_successor_supervisor_directive_state(
        first.signed,
        finalized_block=160,
        prior_state=v3_predecessor.state,
        prior_v3_signed_bytes=v3_predecessor.body,
        **kwargs,
    )
    completed(c, next_package)
    c.provider.block = 245
    await c.service.tick()
    second = c.feed.history()[-1]
    state = advance_successor_supervisor_directive_state(
        second.signed, finalized_block=245, prior_state=state, **kwargs
    )
    target = first.signed.directive.chain_authorization.model_copy(
        update={
            "predecessor_directive_sha256": second.signed.directive_sha256,
            "valid_from_block": 247,
            "valid_through_block": 297,
        }
    )
    returned = first.signed.directive.model_copy(
        update={
            "sequence": second.intent.sequence + 1,
            "predecessor_version": 4,
            "previous_directive_sha256": second.signed.directive_sha256,
            "issued_at_block": 247,
            "valid_from_block": 247,
            "valid_through_block": 297,
            "chain_authorization": target,
        }
    )
    with pytest.raises(ValidatorSupervisorError, match="continuity_rollback_or_stopped"):
        advance_successor_supervisor_directive_state(
            _signed(returned), finalized_block=247, prior_state=state, **kwargs
        )


@pytest.mark.parametrize(
    "change", ["consent", "release", "authority_signature", "round", "certificate_time"]
)
async def test_continuity_cannot_widen_its_exact_signed_scope(
    automatic, package_case, tmp_path, change
):
    plan = continuity_plan(automatic, package_case)
    raw = json.loads(canonical_json_bytes(plan))
    if change == "consent":
        raw["consent"]["reward_continuity_sha256"] = "ff" * 32
    elif change == "release":
        raw["release"]["replay_release_identity"]["release_bundle_sha256"] = "ff" * 32
    elif change == "authority_signature":
        raw["continuity"]["signatures"][0]["signature"] = "0x" + "00" * 64
    else:
        from umi.competition_reward_continuity import admit_certified_allocation

        package = automatic.publisher.builder._load(package_case.prepared)
        authority = plan.continuity
        if change == "round":
            body = authority.authority.model_copy(update={"first_round_sha256": "ff" * 32})
            authority = sign_reward_continuity_authority(body, authority_wallets()[:2])
        with pytest.raises(ValueError):
            admit_certified_allocation(
                authority,
                package,
                fixture_boundary(201 if change == "certificate_time" else 160),
                authority_wallets()[0],
            )
        return
    with pytest.raises(ValueError):
        SuccessorRoundPublicationPlan.model_validate_json(json.dumps(raw))


async def test_late_unadmitted_replacement_does_not_starve_prior_allocation(
    automatic, package_case, next_package, tmp_path
):
    c = setup(automatic, package_case, tmp_path)
    assert (await c.service.tick())["status"] == "published"
    prior = c.feed.history()[-1]
    completed(c, next_package)
    later = c.publisher.builder._load(next_package.prepared)
    c.provider.block = later.settlement_certificate.publication.round.valid_through_block + 1
    for restart in (False, True):
        if restart:
            c.service = AutomaticSuccessorPublisher(c.publisher, c.feed, c.config, **c.signers)
            c.provider.block += c.publisher.builder.plan.renewal_interval_blocks
        result = await c.service.tick()
        assert result["status"] == "published"
        assert c.feed.history()[-1].intent.package == prior.intent.package
        assert len(c.publisher.builder.journal.keys("continuity_admission")) == 1
    assert len(c.publisher.builder.journal.keys("unavailable_continuity_admission")) == 1


async def test_out_of_scope_replacement_does_not_consume_existing_continuity(
    automatic, package_case, next_package, tmp_path
):
    plan = continuity_plan(automatic, package_case)
    limited = plan.continuity.authority.model_copy(update={"last_round_sequence": 1})
    signed = sign_reward_continuity_authority(limited, authority_wallets()[:2])
    plan = SuccessorRoundPublicationPlan.model_validate_json(
        canonical_json_bytes(
            plan.model_copy(
                update={
                    "continuity": signed,
                    "consent": plan.consent.model_copy(
                        update={"reward_continuity_sha256": digest(signed)}
                    ),
                }
            )
        )
    )
    c = enable_follow(automatic, tmp_path, plan)
    completed(c, package_case)
    assert (await c.service.tick())["status"] == "published"
    prior = c.feed.history()[-1]
    completed(c, next_package)
    c.provider.block = 245
    assert (await c.service.tick())["round_sequence"] == prior.intent.round_sequence
    assert c.feed.history()[-1].intent.package == prior.intent.package
    assert len(c.publisher.builder.journal.keys("continuity_admission")) == 1


@pytest.mark.parametrize("resume_offset", [1, 100], ids=["pending", "expired"])
@pytest.mark.parametrize("crash_kind", ["continuity_admission", "intent", "authorization"])
async def test_admitted_newer_package_resumes_after_its_original_end(
    automatic, package_case, next_package, tmp_path, monkeypatch, crash_kind, resume_offset
):
    c = setup(automatic, package_case, tmp_path)
    assert (await c.service.tick())["status"] == "published"
    completed(c, next_package)
    c.provider.block = 245
    journal = c.publisher.builder.journal
    put = journal.put
    captured = {}

    def crash(kind, slot, value):
        result = put(kind, slot, value)
        if kind == crash_kind:
            captured[slot] = canonical_json_bytes(value)
            raise RuntimeError("crash during newer publication")
        return result

    monkeypatch.setattr(journal, "put", crash)
    with pytest.raises(RuntimeError, match="crash during newer publication"):
        await c.service.tick()
    monkeypatch.setattr(journal, "put", put)
    admission = canonical_json_bytes(
        journal.get("continuity_admission", next_package.prepared.package_sha256)
    )
    assert len(c.feed.history()) == 1
    package = c.publisher.builder._load(next_package.prepared)
    c.provider.block = (
        package.settlement_certificate.publication.round.valid_through_block + resume_offset
    )
    c.publisher.builder = SuccessorRoundPublicationBuilder(journal.root, c.publisher.builder.plan)
    c.service = AutomaticSuccessorPublisher(c.publisher, c.feed, c.config, **c.signers)
    result = await c.service.tick()
    assert result["status"] == "published" and result["round_sequence"] == 2
    assert [p.intent.sequence for p in c.feed.history()] == [2, 3]
    assert (
        c.feed.history()[-1].intent.package.package_sha256 == next_package.prepared.package_sha256
    )
    assert (
        canonical_json_bytes(
            journal.get("continuity_admission", next_package.prepared.package_sha256)
        )
        == admission
    )
    assert not journal.keys("unavailable_continuity_admission")
    for slot, raw in captured.items():
        assert canonical_json_bytes(journal.get(crash_kind, slot)) == raw
    if resume_offset == 1 and crash_kind in {"intent", "authorization"}:
        # Resume preserves the still-live old lease; its renewal is already due.
        assert (await c.service.tick())["status"] == "published"
        assert (
            c.feed.history()[-1].intent.package.package_sha256
            == next_package.prepared.package_sha256
        )
        assert len(journal.keys("continuity_admission")) == 2
    assert (await c.service.tick())["status"] == "waiting_for_completed_round"
