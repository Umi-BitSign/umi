"""Conditional publication through the installed supervisor's signed channel.

The approval owner supplies current native control/allocation/registration. This
owner appends to the existing authenticated cursor; it never replaces history,
extends a retained signed clock or submits a validator transaction. A service
must own one configured channel; its private journal serializes local callers.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .competition_reward_decisions import StandingRewardControlReader
from .competition_round_journal import RoundJournal
from .open_competition import digest, identity
from .protocol import canonical_json_bytes
from .translation_reference_cursor import repair_forward_cursors
from .translation_reference_policy import reference_policy_sha256, verify_reference_policy
from .translation_reference_publication import TranslationReferenceApprovalPublisher
from .validator_supervisor import (
    MAX_SUPERVISOR_DIRECTIVES_PER_PAGE,
    SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
    SUPERVISOR_DIRECTIVE_SCHEMA,
    SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA,
    SignedSupervisorDirective,
    SupervisorDirective,
    SupervisorDirectivePage,
    SupervisorDirectiveSignature,
    SupervisorReleaseTarget,
    ValidatorSupervisorConfig,
    parse_canonical_supervisor_directive_page,
    supervisor_directive_digest,
    supervisor_directive_sha256,
    verify_signed_supervisor_directive,
    verify_signed_supervisor_directive_history,
)


@dataclass(frozen=True)
class ChannelObject:
    payload: bytes
    etag: str


class ReferenceChannelConflict(RuntimeError):
    """A concurrent or interrupted write requires a new authoritative read."""


class ReferenceHorizonExpired(ValueError):
    """Numeric, nonsecret diagnostics for an expired local authorization window."""

    def __init__(self, *, selected_horizon: int, current_block: int):
        if type(selected_horizon) is not int or type(current_block) is not int:
            raise ValueError("reference horizon diagnostics require integer blocks")
        super().__init__("reference directive lacks its selected future authorization horizon")
        self.selected_horizon = selected_horizon
        self.current_block = current_block


def _validate_window(valid_through_block, block, renew_before_blocks):
    if type(valid_through_block) is not int or type(block) is not int:
        raise ValueError("reference authorization window requires integer blocks")
    if valid_through_block < block:
        raise ReferenceHorizonExpired(selected_horizon=valid_through_block, current_block=block)
    if (
        type(renew_before_blocks) is not int
        or renew_before_blocks < 0
        or (renew_before_blocks and renew_before_blocks >= valid_through_block - block)
    ):
        raise ValueError("reference renewal margin does not fit its authorization window")


class ReferenceChannelStore(Protocol):
    def read(self, key: str) -> ChannelObject | None: ...
    def compare_and_swap(self, key: str, previous: ChannelObject | None, raw: bytes) -> None: ...


def channel_page_key(config, sequence, sha):
    platform = config.target_platform.replace("/", "-")
    return (
        f"validator-supervisor/channels/{config.channel_id}/{platform}/after/"
        f"{sequence}/{sha if sequence else 'initial'}.json"
    )


class TranslationReferenceChannelPublisher:
    """Publish exact successor bytes; chain and native policy checks stay separate."""

    def __init__(
        self,
        root: Path,
        *,
        config: ValidatorSupervisorConfig,
        release: SupervisorReleaseTarget,
        store: ReferenceChannelStore,
        signer_loader,
        maximum_bytes: int,
        progress=None,
        read_only: bool = False,
    ):
        self.config = ValidatorSupervisorConfig.model_validate_json(canonical_json_bytes(config))
        self.release = SupervisorReleaseTarget.model_validate_json(canonical_json_bytes(release))
        if (
            self.config.signature_threshold != 1
            or len(self.config.trusted_authorities) != 1
            or self.release.entrypoint_profile != "umi-translation-validator/1"
            or self.release.target_platform != self.config.target_platform
            or identity(self.release.release_authority_hotkey)
            != identity(self.config.trusted_authorities[0].hotkey)
        ):
            raise ValueError(
                "reference channel requires the selected single-authority translation release"
            )
        self.authority = self.config.trusted_authorities[0]
        self.store, self.signer_loader, self.progress = store, signer_loader, progress
        self.binding = dict(
            schema="umi-reference-channel-publisher/1",
            channel_id=self.config.channel_id,
            platform=self.config.target_platform,
            trust_sha256=digest(self.config.trust_policy()),
            release_sha256=digest(self.release),
        )
        if type(read_only) is not bool:
            raise ValueError("reference channel read-only selection must be explicit")
        self.journal = RoundJournal(
            root,
            self.binding,
            maximum_bytes=maximum_bytes,
            read_only=read_only,
            existing_only=read_only,
        )

    def _event(
        self,
        stage,
        started,
        *,
        completed=0,
        total=1,
        retrying=False,
        valid_through_block=None,
        renew_after_block=None,
    ):
        if self.progress is not None:
            elapsed = time.monotonic() - started
            self.progress(
                dict(
                    stage=stage,
                    completed=completed,
                    total=total,
                    percent=None if total is None else 100 * completed / total if total else 100,
                    elapsed_seconds=elapsed,
                    eta_seconds=0 if completed == total and not retrying else None,
                    planning_seconds=None if completed == total or retrying else [1, 120],
                    eta_basis="planning for healthy authenticated cursor reads/conditional writes; "
                    "retries extend range; external adoption separate",
                    retrying=retrying,
                    stalled=retrying,
                    **(
                        dict(
                            valid_through_block=valid_through_block,
                            renew_after_block=renew_after_block,
                        )
                        if valid_through_block is not None
                        else {}
                    ),
                )
            )

    def _page(self, value, *, sequence, sha, block):
        page = parse_canonical_supervisor_directive_page(value.payload)
        if (page.after_sequence, page.after_directive_sha256) != (sequence, sha):
            raise ValueError("reference channel page differs from its requested cursor")
        for signed in [*page.directives, page.head]:
            verify_signed_supervisor_directive_history(
                signed, config=self.config, finalized_block=block
            )
        return page

    def _head(self, block, started):
        # Old initial pages need not be rewritten when their page is full. Walk
        # immutable completed cursor edges to the current empty terminal page.
        sequence, sha = 0, None
        initial_value = self.store.read(channel_page_key(self.config, 0, None))
        if initial_value is None:
            raise ValueError("reference channel needs its retained original signed history")
        initial = page = self._page(initial_value, sequence=0, sha=None, block=block)
        prefix = list(initial.directives)
        cached = self.journal.keys("reference_channel_observed")
        if cached:
            retained = SignedSupervisorDirective.model_validate(
                self.journal.get("reference_channel_observed", cached[-1])
            )
            verify_signed_supervisor_directive_history(
                retained, config=self.config, finalized_block=block
            )
            if (
                retained.directive.sequence - initial.head.directive.sequence
                >= MAX_SUPERVISOR_DIRECTIVES_PER_PAGE
            ):
                page = SupervisorDirectivePage(
                    schema=SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
                    after_sequence=retained.directive.sequence,
                    after_directive_sha256=retained.directive_sha256,
                    directives=[],
                    more=False,
                    head=retained,
                )
                prefix = []  # Preserve initial discovery when the compact prefix is unavailable.
        for count in range(1, 65):
            head = page.head
            sequence, sha = head.directive.sequence, head.directive_sha256
            key = channel_page_key(self.config, sequence, sha)
            value = self.store.read(key)
            self._event("reference_channel_discovery", started, completed=count, total=None)
            if value is None:
                return head, None, initial_value, initial, prefix
            page = self._page(value, sequence=sequence, sha=sha, block=block)
            if not page.directives:
                return head, value, initial_value, initial, prefix
            if not self.journal.read_only:
                self.journal.put(
                    "reference_channel_observed", f"{page.head.directive.sequence:016d}", page.head
                )
            if prefix:
                prefix.extend(page.directives)
                if len(prefix) > MAX_SUPERVISOR_DIRECTIVES_PER_PAGE:
                    prefix = []
        raise ValueError("reference channel discovery needs another bounded catch-up pass")

    def _mirror(self, initial_value, initial, prefix, head):
        if prefix and prefix[-1] == head and initial.head != head:
            mirror = SupervisorDirectivePage(
                schema=SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
                after_sequence=0,
                after_directive_sha256=None,
                directives=prefix,
                more=False,
                head=head,
            )
            self._write(
                channel_page_key(self.config, 0, None), initial_value, canonical_json_bytes(mirror)
            )

    def inspect_state(self, *, observed_block: int) -> dict[str, object]:
        """Read authenticated history and retained transition metadata, never sign.

        The block is an observation hint, not an issued native finality capability.
        An actual publication still requires fresh native control and registration.
        """
        if not self.journal.read_only or type(observed_block) is not int or observed_block < 1:
            raise ValueError("reference inspection needs a read-only owner and observed block")
        with self.journal.locked():
            head, _value, _initial_value, _initial, _prefix = self._head(
                observed_block, time.monotonic()
            )
            key = f"{head.directive.sequence + 1:016d}"
            intent = self.journal.get("reference_channel_intent", key)
            signed = self.journal.get("reference_channel_signed", key)
            directive = None if intent is None else SupervisorDirective.model_validate(intent)
            if signed is not None:
                signed = SignedSupervisorDirective.model_validate(signed)
                if directive is None or signed.directive != directive:
                    raise ValueError("retained reference signature requires original intent repair")
                verify_signed_supervisor_directive_history(
                    signed, config=self.config, finalized_block=observed_block
                )
            if directive is not None and (
                directive.previous_directive_sha256 != head.directive_sha256
                or directive.sequence != head.directive.sequence + 1
            ):
                raise ValueError("retained reference intent differs from authenticated head")
            return {
                "platform": self.config.target_platform,
                "head_sequence": head.directive.sequence,
                "head_directive_sha256": head.directive_sha256,
                "head_valid_through_block": head.directive.valid_through_block,
                "head_expired_at_observation": head.directive.valid_through_block < observed_block,
                "pending_intent_sha256": None
                if directive is None
                else supervisor_directive_sha256(directive),
                "pending_signed": signed is not None,
                "pending_expired_at_observation": directive is not None
                and directive.valid_through_block < observed_block,
                "signer_loaded": False,
                "channel_writes": False,
                "independent_native_finality_verified": False,
            }

    def _sign(self, directive):
        signer = self.signer_loader()
        scheme = {0: "ed25519", 1: "sr25519"}.get(signer.crypto_type)
        if (
            identity(signer.ss58_address) != identity(self.authority.hotkey)
            or type(signer.crypto_type) is bool
            or scheme != self.authority.signature_scheme
        ):
            raise ValueError("reference channel signer differs from its configured authority")
        return SignedSupervisorDirective(
            schema=SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA,
            directive=directive,
            directive_sha256=supervisor_directive_sha256(directive),
            directive_digest=supervisor_directive_digest(directive).hex(),
            signatures=[
                SupervisorDirectiveSignature(
                    hotkey=signer.ss58_address,
                    signature_scheme=scheme,
                    signature="0x"
                    + bytes(signer.sign(supervisor_directive_digest(directive))).hex(),
                )
            ],
        )

    def _write(self, key, previous, raw):
        try:
            self.store.compare_and_swap(key, previous, raw)
        except OSError:
            # A transport failure can follow successful durable publication.
            # Only an exact readback settles that uncertainty; never overwrite.
            current = self.store.read(key)
            if current is None or current.payload != raw:
                raise
        current = self.store.read(key)
        if current is None or current.payload != raw:
            raise ReferenceChannelConflict("reference channel readback differs")
        return current

    def _repair_cursors(self, head, *, block):
        repair_forward_cursors(
            self, head, block=block, key_for=channel_page_key, conflict=ReferenceChannelConflict
        )

    def step(
        self,
        approval: TranslationReferenceApprovalPublisher,
        *,
        valid_through_block: int,
        renew_before_blocks: int = 0,
        **inputs,
    ) -> SignedSupervisorDirective:
        if self.journal.read_only:
            raise ValueError("read-only reference inspection cannot publish or load a signer")
        if type(approval) is not TranslationReferenceApprovalPublisher:
            raise TypeError("reference channel requires its current native approval owner")
        if identity(approval.authority_hotkey) != identity(self.authority.hotkey):
            raise ValueError("reference approval and channel have different authorities")
        started = time.monotonic()
        with self.journal.locked():
            try:
                return self._step(
                    approval, inputs, valid_through_block, started, renew_before_blocks
                )
            except BaseException:
                self._event("reference_channel_retry", started, retrying=True)
                raise

    def _step(self, approval, inputs, valid_through_block, started, renew_before_blocks=0):
        block = inputs["control"].snapshot.block_number
        _validate_window(valid_through_block, block, renew_before_blocks)
        policy = approval.step(**inputs)
        sha = reference_policy_sha256(policy)
        verify_reference_policy(
            approval.published_payload(policy),
            expected_policy_sha256=sha,
            expected_authority_hotkey=self.authority.hotkey,
        )

        def current():
            if approval.prepare_policy(**inputs) != policy:
                raise ValueError("native reference approval changed before channel selection")

        return self._publish_transition(
            mode="translation_weights",
            policy_sha256=sha,
            release=self.release,
            native_check=current,
            block=block,
            valid_through_block=valid_through_block,
            started=started,
            renew_before_blocks=renew_before_blocks,
        )

    def select_hold(
        self,
        reader: StandingRewardControlReader,
        *,
        control,
        source,
        valid_through_block: int,
        renew_before_blocks: int = 0,
    ) -> SignedSupervisorDirective:
        """Propagate an authenticated revocation/suspension through the same cursor."""
        if self.journal.read_only:
            raise ValueError("read-only reference inspection cannot publish or load a signer")
        if type(reader) is not StandingRewardControlReader:
            raise TypeError("reference hold requires the configured native control reader")
        started = time.monotonic()
        with self.journal.locked():
            try:
                expected = reader.select(control, source)
                if expected.state not in {"revoked", "suspended"}:
                    raise ValueError("reference hold lacks signed current suspension or revocation")

                def current():
                    if reader.select(control, source) != expected:
                        raise ValueError("native reference hold changed before channel selection")

                return self._publish_transition(
                    mode="hold",
                    policy_sha256=None,
                    release=None,
                    native_check=current,
                    block=control.snapshot.block_number,
                    valid_through_block=valid_through_block,
                    started=started,
                    renew_before_blocks=renew_before_blocks,
                )
            except BaseException:
                self._event("reference_channel_retry", started, retrying=True)
                raise

    def _publish_transition(
        self,
        *,
        mode,
        policy_sha256,
        release,
        native_check,
        block,
        valid_through_block,
        started,
        renew_before_blocks=0,
    ):
        sha = policy_sha256
        _validate_window(valid_through_block, block, renew_before_blocks)
        head, prior_value, initial_value, initial, prefix = self._head(block, started)
        if (
            head.directive.mode == mode
            and head.directive.policy_sha256 == sha
            and head.directive.release == release
            and head.directive.valid_through_block >= block
        ):
            verify_signed_supervisor_directive(head, config=self.config, finalized_block=block)
            if (
                head.directive.valid_through_block - block > renew_before_blocks
                or valid_through_block <= head.directive.valid_through_block
            ):
                native_check()
                self._mirror(initial_value, initial, prefix, head)
                self._repair_cursors(head, block=block)
                self._event(
                    "reference_channel_selected",
                    started,
                    completed=1,
                    valid_through_block=head.directive.valid_through_block,
                    renew_after_block=head.directive.valid_through_block - renew_before_blocks,
                )
                return head
        sequence = head.directive.sequence + 1
        key = f"{sequence:016d}"
        intent = self.journal.get("reference_channel_intent", key)
        if intent is None:
            directive = SupervisorDirective(
                schema=SUPERVISOR_DIRECTIVE_SCHEMA,
                channel_id=self.config.channel_id,
                sequence=sequence,
                previous_directive_sha256=head.directive_sha256,
                issued_at_block=block,
                valid_from_block=block,
                valid_through_block=valid_through_block,
                network="finney",
                netuid=78,
                mechanism_id=0,
                mode=mode,
                validator_scope="any_permitted_sn78",
                validator_hotkeys=[],
                policy_sha256=sha,
                release=release,
                operator_inputs=None,
            )
            self.journal.put("reference_channel_intent", key, directive)
        else:
            directive = SupervisorDirective.model_validate(intent)
            if (
                directive.previous_directive_sha256 != head.directive_sha256
                or directive.mode != mode
                or directive.policy_sha256 != sha
                or directive.release != release
            ):
                raise ValueError("pending signed channel transition requires reconciliation")
            # Preserve the original signed interval, including across restart.
        native_check()
        retained = self.journal.get("reference_channel_signed", key)
        if retained is None:
            signed = self._sign(directive)
            verify_signed_supervisor_directive(signed, config=self.config, finalized_block=block)
            self.journal.put("reference_channel_signed", key, signed)
        else:
            signed = SignedSupervisorDirective.model_validate(retained)
            if signed.directive != directive:
                raise ValueError("retained reference channel signature needs restoration")
            verify_signed_supervisor_directive(signed, config=self.config, finalized_block=block)
        self._event("reference_channel_distribution", started)
        successor_key = channel_page_key(self.config, sequence, signed.directive_sha256)
        terminal = SupervisorDirectivePage(
            schema=SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
            after_sequence=sequence,
            after_directive_sha256=signed.directive_sha256,
            directives=[],
            more=False,
            head=signed,
        )
        successor = self.store.read(successor_key)
        terminal_raw = canonical_json_bytes(terminal)
        if successor is None:
            self._write(successor_key, None, terminal_raw)
        elif successor.payload != terminal_raw:
            raise ReferenceChannelConflict("successor cursor already advanced; reload current head")
        native_check()
        edge = SupervisorDirectivePage(
            schema=SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
            after_sequence=head.directive.sequence,
            after_directive_sha256=head.directive_sha256,
            directives=[signed],
            more=True,
            head=signed,
        )
        self._write(
            channel_page_key(self.config, head.directive.sequence, head.directive_sha256),
            prior_value,
            canonical_json_bytes(edge),
        )
        # Keep the original prefix byte-for-byte. Mirror the latest head into
        # initial discovery while it fits; old/full initial pages still advance
        # through their cursor edges on the installed supervisor's next poll.
        if prefix and len(prefix) < MAX_SUPERVISOR_DIRECTIVES_PER_PAGE:
            self._mirror(initial_value, initial, [*prefix, signed], signed)
        self._repair_cursors(signed, block=block)
        self.journal.put(
            "reference_channel_selected",
            key,
            {"directive_sha256": signed.directive_sha256, "policy_sha256": sha},
        )
        self._event(
            "reference_channel_selected",
            started,
            completed=1,
            valid_through_block=signed.directive.valid_through_block,
            renew_after_block=signed.directive.valid_through_block - renew_before_blocks,
        )
        return signed
