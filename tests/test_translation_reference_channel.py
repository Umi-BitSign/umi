"""Actual signed approvals, channel pages and journals; synthetic chain/R2 ports."""

from types import SimpleNamespace

import pytest

from umi.protocol import canonical_json_bytes
from umi.translation_reference_channel import (
    ChannelObject,
    ReferenceChannelConflict,
    TranslationReferenceChannelPublisher,
    channel_page_key,
)
from umi.validator_supervisor import (
    SignedSupervisorDirective,
    SupervisorDirective,
    SupervisorDirectivePage,
    SupervisorDirectiveSignature,
    SupervisorReleaseTarget,
    ValidatorSupervisorError,
    parse_canonical_supervisor_directive_page,
    supervisor_directive_digest,
    supervisor_directive_sha256,
    verify_signed_supervisor_directive,
)

from .test_open_competition import wallet
from .test_translation_reference_publication import (
    base_policy as base_policy,
)
from .test_translation_reference_publication import (
    chain as chain,
)
from .test_translation_reference_publication import (
    chain_config as chain_config,
)
from .test_translation_reference_publication import (
    control as control,
)
from .test_translation_reference_publication import (
    policy as policy,
)
from .test_translation_reference_publication import (
    publication_case as publication_case,
)
from .test_translation_reference_publication import (
    series_case as series_case,
)
from .test_validator_supervisor import _config, _release


class Store:
    def __init__(self):
        self.objects, self.writes = {}, []
        self.before, self.after = None, None
        self.generation = 0

    def read(self, key):
        return self.objects.get(key)

    def compare_and_swap(self, key, previous, raw):
        if self.before is not None:
            self.before(key, raw)
        current = self.objects.get(key)
        if (None if current is None else current.etag) != (
            None if previous is None else previous.etag
        ):
            raise ReferenceChannelConflict("generation changed")
        self.generation += 1
        self.objects[key] = ChannelObject(raw, '"' + str(self.generation) + '"')
        self.writes.append((key, raw))
        if self.after is not None:
            self.after(key, raw)


def sign(body):
    signer = wallet("Charlie").hotkey
    return SignedSupervisorDirective(
        schema="umi-validator-supervisor-signed-directive/3",
        directive=body,
        directive_sha256=supervisor_directive_sha256(body),
        directive_digest=supervisor_directive_digest(body).hex(),
        signatures=[
            SupervisorDirectiveSignature(
                hotkey=signer.ss58_address,
                signature_scheme="sr25519",
                signature="0x" + signer.sign(supervisor_directive_digest(body)).hex(),
            )
        ],
    )


@pytest.fixture
def channel_case(publication_case, tmp_path):
    native = publication_case
    key = wallet("Charlie").hotkey.ss58_address
    config = _config(
        signature_threshold=1, trusted_authorities=[dict(hotkey=key, signature_scheme="sr25519")]
    )
    release = SupervisorReleaseTarget.model_validate(
        _release(release_authority_hotkey=key, entrypoint_profile="umi-translation-validator/1")
    )
    body = SupervisorDirective(
        schema="umi-validator-supervisor-directive/3",
        channel_id=config.channel_id,
        sequence=1,
        previous_directive_sha256=None,
        issued_at_block=1,
        valid_from_block=1,
        valid_through_block=2**53 - 1,
        network="finney",
        netuid=78,
        mechanism_id=0,
        mode="hold",
        validator_scope="any_permitted_sn78",
        validator_hotkeys=[],
        policy_sha256=None,
        release=None,
    )
    original = sign(body)
    initial = SupervisorDirectivePage(
        schema="umi-validator-supervisor-directive-page/3",
        after_sequence=0,
        after_directive_sha256=None,
        directives=[original],
        more=False,
        head=original,
    )
    store, signatures, events = Store(), [], []
    store.compare_and_swap(channel_page_key(config, 0, None), None, canonical_json_bytes(initial))
    terminal = initial.model_copy(
        update={
            "after_sequence": 1,
            "after_directive_sha256": original.directive_sha256,
            "directives": [],
        }
    )
    store.compare_and_swap(
        channel_page_key(config, 1, original.directive_sha256), None, canonical_json_bytes(terminal)
    )
    store.writes.clear()

    def signer():
        signatures.append(1)
        return wallet("Charlie").hotkey

    def reopen():
        return TranslationReferenceChannelPublisher(
            tmp_path / "channel",
            config=config,
            release=release,
            store=store,
            signer_loader=signer,
            maximum_bytes=8 * 1024**2,
            progress=events.append,
        )

    return SimpleNamespace(
        native=native,
        store=store,
        config=config,
        release=release,
        original=original,
        initial=initial,
        signatures=signatures,
        events=events,
        reopen=reopen,
        horizon=native.item.finality.ref.block_number + 1000,
    )


async def test_current_approval_selects_signed_successor_and_preserves_original_prefix(
    channel_case,
):
    c = channel_case
    result = c.reopen().step(
        c.native.reopen(), valid_through_block=c.horizon, **await c.native.inputs()
    )
    assert result.directive.sequence == 2
    assert result.directive.previous_directive_sha256 == c.original.directive_sha256
    assert result.directive.mode == "translation_weights"
    assert not result.directive.operator_inputs
    verify_signed_supervisor_directive(
        result, config=c.config, finalized_block=c.native.item.finality.ref.block_number
    )
    page = parse_canonical_supervisor_directive_page(
        c.store.read(channel_page_key(c.config, 0, None)).payload
    )
    assert page.directives[0] == c.original and page.directives[-1] == result
    edge = parse_canonical_supervisor_directive_page(
        c.store.read(channel_page_key(c.config, 1, c.original.directive_sha256)).payload
    )
    assert edge.directives == [result]
    writes = len(c.store.writes)
    assert (
        c.reopen().step(
            c.native.reopen(), valid_through_block=c.horizon + 100, **await c.native.inputs()
        )
        == result
    )
    assert len(c.store.writes) == writes and len(c.signatures) == 1
    assert c.events[-1]["eta_seconds"] == 0


@pytest.mark.parametrize(
    "position", ["before_terminal", "after_terminal", "after_edge", "before_mirror"]
)
async def test_interrupted_distribution_restarts_with_exact_signed_bytes(channel_case, position):
    c = channel_case
    owner = c.reopen()
    failed = []

    def fail(key, raw):
        if failed:
            return
        selected = parse_canonical_supervisor_directive_page(raw)
        target = (
            (position.endswith("terminal") and selected.after_sequence == 2)
            or (position == "after_edge" and selected.after_sequence == 1)
            or (position == "before_mirror" and selected.after_sequence == 0)
        )
        if target:
            failed.append(raw)
            raise OSError("lost transport")

    if position.startswith("before"):
        c.store.before = fail
        with pytest.raises(OSError):
            owner.step(c.native.reopen(), valid_through_block=c.horizon, **await c.native.inputs())
    else:
        c.store.after = fail
        owner.step(c.native.reopen(), valid_through_block=c.horizon, **await c.native.inputs())
    assert failed
    retained = owner.journal.get("reference_channel_signed", "0000000000000002")
    c.store.before = c.store.after = None
    result = c.reopen().step(
        c.native.reopen(), valid_through_block=c.horizon + 500, **await c.native.inputs()
    )
    assert canonical_json_bytes(result) == canonical_json_bytes(retained)
    assert result.directive.valid_through_block == c.horizon
    assert len(c.signatures) == 1
    initial = parse_canonical_supervisor_directive_page(
        c.store.read(channel_page_key(c.config, 0, None)).payload
    )
    assert initial.head == result


async def test_successor_cohort_advances_existing_channel_without_replacing_worker(channel_case):
    from umi.competition_reward_decisions import RewardActivation
    from umi.open_competition import digest

    c = channel_case
    first = c.reopen().step(
        c.native.reopen(), valid_through_block=c.horizon, **await c.native.inputs()
    )
    next_activation = RewardActivation.model_validate(c.native.activation.model_dump()).model_copy(
        update={"cohort_sha256": digest(c.native.c.series.cohorts[1])}
    )
    next_tip = c.native.c.decision(c.native.tip, 6, activation=next_activation)
    second = c.reopen().step(
        c.native.reopen(), valid_through_block=c.horizon, **await c.native.inputs(next_tip)
    )
    assert second.directive.sequence == 3
    assert second.directive.previous_directive_sha256 == first.directive_sha256
    assert second.directive.policy_sha256 != first.directive.policy_sha256
    assert second.directive.release == first.directive.release == c.release
    assert len(c.signatures) == 2


async def test_another_channel_generation_cannot_be_overwritten(channel_case):
    c = channel_case
    edge_key = channel_page_key(c.config, 1, c.original.directive_sha256)
    previous = c.store.read(edge_key)
    collided = []

    def race(key, raw):
        if key == edge_key and not collided:
            collided.append(1)
            c.store.objects[key] = ChannelObject(previous.payload, '"other-writer"')

    c.store.before = race
    with pytest.raises(ReferenceChannelConflict):
        c.reopen().step(c.native.reopen(), valid_through_block=c.horizon, **await c.native.inputs())
    assert c.store.read(edge_key).payload == previous.payload
    assert c.events[-1]["retrying"]
    c.store.before = None
    c.reopen().step(c.native.reopen(), valid_through_block=c.horizon, **await c.native.inputs())
    assert len(c.signatures) == 1


async def test_stale_native_inputs_cannot_select_channel_after_discovery(channel_case, monkeypatch):
    c = channel_case
    approval = c.native.reopen()
    original = approval.prepare_policy
    count = []

    def expire(**inputs):
        count.append(1)
        if len(count) > 1:
            raise ValueError("native proof expired while discovery ran")
        return original(**inputs)

    monkeypatch.setattr(approval, "prepare_policy", expire)
    with pytest.raises(ValueError, match="expired"):
        c.reopen().step(approval, valid_through_block=c.horizon, **await c.native.inputs())
    assert not c.signatures and not c.store.writes


async def test_unauthenticated_public_head_refuses_before_channel_signer(channel_case):
    c = channel_case
    raw = canonical_json_bytes(c.initial).replace(b'"mode":"hold"', b'"mode":"bad!"')
    c.store.objects[channel_page_key(c.config, 0, None)] = ChannelObject(raw, '"bad"')
    with pytest.raises(ValidatorSupervisorError):
        c.reopen().step(c.native.reopen(), valid_through_block=c.horizon, **await c.native.inputs())
    assert not c.signatures and not c.store.writes


def history(c, length, *, initial_length):
    values = [c.original]
    for sequence in range(2, length + 1):
        body = c.original.directive.model_copy(
            update={"sequence": sequence, "previous_directive_sha256": values[-1].directive_sha256}
        )
        values.append(sign(body))
    first = SupervisorDirectivePage(
        schema="umi-validator-supervisor-directive-page/3",
        after_sequence=0,
        after_directive_sha256=None,
        directives=values[:initial_length],
        more=False,
        head=values[initial_length - 1],
    )
    c.store.objects[channel_page_key(c.config, 0, None)] = ChannelObject(
        canonical_json_bytes(first), '"initial"'
    )
    for index, item in enumerate(values):
        following = [] if index == len(values) - 1 else [values[index + 1]]
        page = SupervisorDirectivePage(
            schema="umi-validator-supervisor-directive-page/3",
            after_sequence=item.directive.sequence,
            after_directive_sha256=item.directive_sha256,
            directives=following,
            more=False,
            head=following[-1] if following else item,
        )
        c.store.objects[
            channel_page_key(c.config, item.directive.sequence, item.directive_sha256)
        ] = ChannelObject(canonical_json_bytes(page), '"' + str(index) + '"')
    return first


async def test_full_initial_page_retains_history_and_advances_through_cursor(channel_case):
    c = channel_case
    original = history(c, 64, initial_length=64)
    selected = c.reopen().step(
        c.native.reopen(), valid_through_block=c.horizon, **await c.native.inputs()
    )
    assert selected.directive.sequence == 65
    assert c.store.read(channel_page_key(c.config, 0, None)).payload == canonical_json_bytes(
        original
    )
    assert (
        c.reopen().step(c.native.reopen(), valid_through_block=c.horizon, **await c.native.inputs())
        == selected
    )
    assert len(c.signatures) == 1


async def test_long_catchup_resumes_completed_discovery_instead_of_starting_over(channel_case):
    c = channel_case
    history(c, 80, initial_length=1)
    with pytest.raises(ValueError, match="bounded catch-up"):
        c.reopen().step(c.native.reopen(), valid_through_block=c.horizon, **await c.native.inputs())
    assert not c.signatures
    selected = c.reopen().step(
        c.native.reopen(), valid_through_block=c.horizon, **await c.native.inputs()
    )
    assert selected.directive.sequence == 81
    assert len(c.signatures) == 1


async def test_repeated_initial_mirror_interruptions_keep_original_forward_chain(channel_case):
    c = channel_case

    def failed_mirror(key, raw):
        if key == channel_page_key(c.config, 0, None):
            raise OSError("mirror transport down")

    c.store.before = failed_mirror
    for _ in range(2):
        with pytest.raises(OSError):
            c.reopen().step(
                c.native.reopen(), valid_through_block=c.horizon, **await c.native.inputs()
            )
    assert len(c.signatures) == 1
    c.store.before = None
    selected = c.reopen().step(
        c.native.reopen(), valid_through_block=c.horizon, **await c.native.inputs()
    )
    first = parse_canonical_supervisor_directive_page(
        c.store.read(channel_page_key(c.config, 0, None)).payload
    )
    assert first.directives[0] == c.original and first.head == selected


async def test_signed_revocation_selects_hold_with_no_chain_submission(channel_case):
    c = channel_case
    first = c.reopen().step(
        c.native.reopen(), valid_through_block=c.horizon, **await c.native.inputs()
    )
    revoked = c.native.c.decision(c.native.tip, kind="revoke")
    inputs = await c.native.inputs(revoked)
    owner = c.reopen()
    hold = owner.select_hold(
        c.native.c.reader,
        control=inputs["control"],
        source=inputs["source"],
        valid_through_block=c.horizon,
    )
    assert hold.directive.mode == "hold" and hold.directive.release is None
    assert hold.directive.policy_sha256 is None
    assert hold.directive.previous_directive_sha256 == first.directive_sha256
    count = len(c.store.writes)
    assert (
        c.reopen().select_hold(
            c.native.c.reader,
            control=inputs["control"],
            source=inputs["source"],
            valid_through_block=c.horizon,
        )
        == hold
    )
    assert len(c.store.writes) == count
    assert all(not name.startswith("author_") for name, _ in c.native.item.rpc.calls)


async def test_hold_requires_actual_signed_suspension_or_revocation(channel_case):
    c = channel_case
    inputs = await c.native.inputs()
    with pytest.raises(ValueError, match="suspension or revocation"):
        c.reopen().select_hold(
            c.native.c.reader,
            control=inputs["control"],
            source=inputs["source"],
            valid_through_block=c.horizon,
        )
    assert not c.signatures and not c.store.writes


async def test_expired_selected_horizon_refuses_before_any_approval_signature(channel_case):
    c = channel_case
    inputs = await c.native.inputs()
    with pytest.raises(ValueError, match="authorization horizon"):
        c.reopen().step(
            c.native.reopen(),
            valid_through_block=inputs["control"].snapshot.block_number - 1,
            **inputs,
        )
    assert not c.signatures and not c.store.writes and not c.native.calls
