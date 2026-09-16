"""Compile and retain per-round v4 updates under explicit operator controls.

This is the signing core for a separate release publisher. It does not serve
HTTP, upload artifacts, establish current finality, or activate a validator.
Its caller must check current source conflicts and obtain an owned finalized
head before signing or exposing a retained publication. Never put these signing
wallets in the wallet-free round coordinator.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator
from typing_extensions import Self

from .competition_package import (
    CompetitionPackageLimits,
    PreparedCompetitionPackage,
    load_competition_package,
)
from .competition_rounds import RoundJournal
from .competition_supervisor import (
    SignedSuccessorSupervisorDirective,
    SuccessorChainAuthorizationTarget,
    SuccessorReplayPackageTarget,
    SuccessorSupervisorChainTarget,
    SuccessorSupervisorDirective,
    SuccessorSupervisorDirectivePage,
    SuccessorSupervisorOperatorConsent,
    SuccessorSupervisorReleaseTarget,
    SuccessorWorkerCapabilities,
    successor_source_config_sha256,
    successor_supervisor_directive_digest,
    successor_supervisor_directive_sha256,
    verify_bound_successor_chain_authorization,
    verify_signed_successor_supervisor_directive_history,
)
from .competition_weights import (
    CompetitionWeightAuthorizationBody,
    SignedCompetitionWeightAuthorization,
    sign_competition_weight_authorization,
    verify_competition_weight_authorization,
)
from .crypto import sign_response_digest, verify_response_signature
from .encoding import account_id32
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .validator_supervisor import SupervisorDirectiveSignature, ValidatorSupervisorConfig


def _canonical(model, value):
    return model.model_validate_json(canonical_json_bytes(value))


class SuccessorPublicationWeightParameters(StrictProtocolModel):
    """Explicit chain requirements, never inferred from a settlement."""

    required_finality_verifier_sha256_by_target: dict[str, Hex32]
    required_storage_proof_verifier_sha256_by_target: dict[str, Hex32]
    required_runtime_metadata_executor_sha256_by_target: (
        Annotated[dict[str, Hex32], Field(min_length=1, max_length=8)] | None
    ) = None
    weights_version_key: Annotated[int, Field(ge=1, le=2**64 - 1)]
    required_min_allowed_weights: Annotated[int, Field(ge=1, le=256)]
    required_max_allowed_uids: Annotated[int, Field(ge=1, le=256)]
    required_max_weights_limit: Annotated[int, Field(ge=1, le=65535)]
    required_weights_rate_limit: Annotated[int, Field(ge=0, le=2**53 - 1)]
    mortality_period: Annotated[int, Field(ge=4, le=4096)]

    @model_serializer(mode="wrap")
    def preserve_legacy_parameters(self, handler):
        value = handler(self)
        if self.required_runtime_metadata_executor_sha256_by_target is None:
            value.pop("required_runtime_metadata_executor_sha256_by_target", None)
        return value

    @model_validator(mode="after")
    def coherent_bounds(self) -> Self:
        pins = self.required_runtime_metadata_executor_sha256_by_target
        if pins is not None and (
            set(pins) != set(self.required_finality_verifier_sha256_by_target)
            or set(pins) != set(self.required_storage_proof_verifier_sha256_by_target)
        ):
            raise ValueError("publication runtime execution must cover every verifier target")
        if self.mortality_period & (self.mortality_period - 1):
            raise ValueError("publication mortality must be a power of two")
        if self.required_min_allowed_weights > self.required_max_allowed_uids:
            raise ValueError("publication minimum weights exceed UID capacity")
        for pins in (
            self.required_finality_verifier_sha256_by_target,
            self.required_storage_proof_verifier_sha256_by_target,
        ):
            if not 1 <= len(pins) <= 8:
                raise ValueError("publication verifier pins must be bounded and nonempty")
        return self


class SuccessorRoundPublicationPlan(StrictProtocolModel):
    """Fixed operator-selected policy, release and signing limits for a channel."""

    schema_: Literal["umi-successor-round-publication-plan/1"] = Field(alias="schema")
    policy_sha256: Hex32
    supervisor: ValidatorSupervisorConfig
    consent: SuccessorSupervisorOperatorConsent
    chain: SuccessorSupervisorChainTarget
    release: SuccessorSupervisorReleaseTarget
    package_limits: CompetitionPackageLimits
    weights: SuccessorPublicationWeightParameters
    valid_from_block: Annotated[int, Field(ge=1, le=2**53 - 1)]
    valid_through_block: Annotated[int, Field(ge=1, le=2**53 - 1)]
    maximum_lifetime_blocks: Annotated[int, Field(ge=4, le=100_000)]
    minimum_activation_headroom_blocks: Annotated[int, Field(ge=2, le=100_000)]

    @model_validator(mode="after")
    def fixed_controls(self) -> Self:
        config, consent = self.supervisor, self.consent
        if (
            consent.source_config_sha256 != successor_source_config_sha256(config)
            or consent.channel_id != config.channel_id
            or account_id32(consent.validator_hotkey) != account_id32(config.validator_hotkey)
            or consent.target_platform != config.target_platform
            or self.release.target_platform != config.target_platform
            or "competition_weights" not in consent.allowed_modes
            or self.release.entrypoint_profile != "umi-competition-weight-worker/1"
            or not consent.authorized_at_finalized_block
            <= self.valid_from_block
            < self.valid_through_block
            <= consent.valid_through_block
            or self.maximum_lifetime_blocks < self.weights.mortality_period
            or self.maximum_lifetime_blocks < self.minimum_activation_headroom_blocks
        ):
            raise ValueError("publication plan exceeds its fixed successor controls")
        target = self.release.replay_release_identity.target_triple
        if target not in self.weights.required_finality_verifier_sha256_by_target or (
            target not in self.weights.required_storage_proof_verifier_sha256_by_target
        ):
            raise ValueError("publication lacks the selected platform's verifier pins")
        return self


class SuccessorRoundPublicationIntent(StrictProtocolModel):
    schema_: Literal["umi-successor-round-publication-intent/1"] = Field(alias="schema")
    plan_sha256: Hex32
    round_sequence: Annotated[int, Field(ge=1, le=2**53 - 1)]
    sequence: Annotated[int, Field(ge=2, le=2**53 - 1)]
    predecessor_version: Literal[3, 4]
    package: SuccessorReplayPackageTarget
    authorization: CompetitionWeightAuthorizationBody


class SignedSuccessorRoundPublication(StrictProtocolModel):
    schema_: Literal["umi-signed-successor-round-publication/1"] = Field(alias="schema")
    intent: SuccessorRoundPublicationIntent
    authorization: SignedCompetitionWeightAuthorization
    signed: SignedSuccessorSupervisorDirective


def _package_target(package, limits):
    fields = {
        name: getattr(package.manifest, name)
        for name in (
            "policy_sha256",
            "round_sha256",
            "round_sequence",
            "cutoff_publication_sha256",
            "cutoff_certificate_sha256",
            "settlement_publication_sha256",
            "settlement_certificate_sha256",
            "settlement_sha256",
            "projection_sha256",
            "promotion_head_sha256",
            "release_identity_sha256",
        )
    }
    return SuccessorReplayPackageTarget(
        schema="umi-successor-replay-package-target/1",
        package_sha256=package.package_sha256,
        manifest_sha256=package.manifest_sha256,
        policy_valid_from_block=package.policy.valid_from_block,
        policy_valid_through_block=package.policy.valid_through_block,
        limits=limits,
        **fields,
    )


class PublicationWindowUnavailable(ValueError):
    """An intact completed round cannot be activated at this finalized head."""


def publication_valid_through(plan, package, block):
    settlement = package.retained_settlement
    policy = package.policy
    if not plan.valid_from_block <= block <= plan.valid_through_block or (
        block < settlement.observed_block
    ):
        raise PublicationWindowUnavailable(
            "publication is outside its policy or precedes settlement"
        )
    valid_through = min(
        plan.valid_through_block,
        policy.valid_through_block,
        package.settlement_certificate.publication.round.valid_through_block,
        settlement.registration_snapshot.block + policy.maximum_snapshot_age_blocks,
        block + plan.maximum_lifetime_blocks,
    )
    if valid_through - block < max(
        plan.weights.mortality_period, plan.minimum_activation_headroom_blocks
    ):
        raise PublicationWindowUnavailable(
            "publication lacks its original activation and mortality window"
        )
    return valid_through


def _intent(plan, package, *, sequence, predecessor_version, predecessor, block):
    policy = package.policy
    valid_through = publication_valid_through(plan, package, block)
    target = _package_target(package, plan.package_limits)
    identifier = hashlib.sha256(
        b"umi-successor-round-authorization-v1\0"
        + canonical_json_bytes(
            [digest(plan), package.package_sha256, predecessor, block, valid_through]
        )
    ).hexdigest()
    body = CompetitionWeightAuthorizationBody(
        schema="umi-competition-weight-authorization/1",
        authorization_id=identifier,
        validator_scope="any_permitted_sn78",
        policy_sha256=digest(policy),
        package_sha256=package.package_sha256,
        settlement_sha256=target.settlement_sha256,
        projection_sha256=target.projection_sha256,
        release_identity_sha256=target.release_identity_sha256,
        predecessor_directive_sha256=predecessor,
        required_recovery_profile=plan.consent.required_recovery_profile,
        chain_pin=plan.chain.chain_pin,
        network="finney",
        netuid=78,
        mechanism_id=0,
        signed_at_block=block,
        valid_from_block=block,
        valid_through_block=valid_through,
        required_mechanism_count=1,
        required_commit_reveal_enabled=False,
        late_conflict_action="hold_no_automatic_correction",
        **plan.weights.model_dump(),
    )
    return SuccessorRoundPublicationIntent(
        schema="umi-successor-round-publication-intent/1",
        plan_sha256=digest(plan),
        round_sequence=target.round_sequence,
        sequence=sequence,
        predecessor_version=predecessor_version,
        package=target,
        authorization=body,
    )


def _directive(plan, intent, authorization):
    body = authorization.authorization
    raw = canonical_json_bytes(authorization)
    target = SuccessorChainAuthorizationTarget(
        schema="umi-successor-chain-authorization-target/1",
        signed_authorization_sha256=hashlib.sha256(raw).hexdigest(),
        authorization_size_bytes=len(raw),
        **{
            name: getattr(body, name)
            for name in (
                "authorization_id",
                "policy_sha256",
                "package_sha256",
                "settlement_sha256",
                "projection_sha256",
                "release_identity_sha256",
                "predecessor_directive_sha256",
                "valid_from_block",
                "valid_through_block",
                "required_recovery_profile",
            )
        },
    )
    return SuccessorSupervisorDirective(
        schema="umi-validator-supervisor-directive/4",
        channel_id=plan.supervisor.channel_id,
        sequence=intent.sequence,
        predecessor_version=intent.predecessor_version,
        previous_directive_sha256=body.predecessor_directive_sha256,
        issued_at_block=body.signed_at_block,
        valid_from_block=body.valid_from_block,
        valid_through_block=body.valid_through_block,
        minimum_activation_headroom_blocks=plan.minimum_activation_headroom_blocks,
        mode="competition_weights",
        validator_scope="any_permitted_sn78",
        validator_hotkeys=[],
        policy_sha256=plan.policy_sha256,
        required_host_manifest_sha256=plan.consent.approved_host_manifest_sha256,
        required_recovery_profile=plan.consent.required_recovery_profile,
        chain=plan.chain,
        release=plan.release,
        replay_package=intent.package,
        chain_authorization=target,
        capabilities=SuccessorWorkerCapabilities(
            schema="umi-successor-worker-capabilities/1",
            wallet_access="configured_validator_hotkey_read_only",
            network_access="finney_clients",
            chain_submission=True,
        ),
    )


def verify_successor_round_publication(plan, publication, package=None):
    """Verify exported signed records without opening an authority journal."""
    plan = _canonical(SuccessorRoundPublicationPlan, plan)
    publication = _canonical(SignedSuccessorRoundPublication, publication)
    intent = publication.intent
    signed, authorization = publication.signed, publication.authorization
    if (
        intent.plan_sha256 != digest(plan)
        or intent.round_sequence != intent.package.round_sequence
        or authorization.authorization != intent.authorization
        or signed.directive != _directive(plan, intent, authorization)
    ):
        raise ValueError("retained publication differs from its signing intent")
    verify_signed_successor_supervisor_directive_history(
        signed,
        config=plan.supervisor,
        operator_consent=plan.consent,
        finalized_block=signed.directive.issued_at_block,
    )
    if package is not None:
        if intent.package != _package_target(package, plan.package_limits):
            raise ValueError("retained publication differs from the complete package")
        expected = _intent(
            plan,
            package,
            sequence=intent.sequence,
            predecessor_version=intent.predecessor_version,
            predecessor=intent.authorization.predecessor_directive_sha256,
            block=intent.authorization.signed_at_block,
        )
        if intent != expected:
            raise ValueError("retained publication exceeds its approved signing plan")
        verify_bound_successor_chain_authorization(
            canonical_json_bytes(authorization),
            directive=signed.directive,
            config=plan.supervisor,
            package=package,
        )
    return publication


class SuccessorRoundPublicationBuilder:
    """Durably sign one byte-stable update per round, without distributing it."""

    def __init__(
        self,
        root: Path,
        plan: SuccessorRoundPublicationPlan,
        *,
        maximum_rounds=1024,
        maximum_bytes=1024**3,
    ):
        self.plan = _canonical(SuccessorRoundPublicationPlan, plan)
        self._plan_digest = digest(self.plan)
        self.journal = RoundJournal(
            root,
            {
                "schema": "umi-successor-publication-journal/2",
                "plan": self.plan.model_dump(mode="json", by_alias=True),
            },
            maximum_rounds=maximum_rounds,
            maximum_bytes=maximum_bytes,
        )

    @contextmanager
    def _locked(self):
        # Lock the already-owned journal file rather than an unvalidated new path.
        self.journal._check_files()
        fd = os.open(self.journal.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.journal._check_files()
            if os.fstat(fd).st_ino != self.journal.path.stat().st_ino:
                raise ValueError("publication journal identity changed")
            yield
        finally:
            os.close(fd)

    def _load(self, prepared):
        prepared = _canonical(PreparedCompetitionPackage, prepared)
        if prepared.policy_sha256 != self.plan.policy_sha256:
            raise ValueError("publication package belongs to another approved policy")
        package = load_competition_package(
            Path(prepared.package_path),
            expected_package_sha256=prepared.package_sha256,
            expected_policy_sha256=self.plan.policy_sha256,
            observed_release=self.plan.release.replay_release_identity,
            limits=self.plan.package_limits,
        )
        if package.manifest_sha256 != prepared.manifest_sha256:
            raise ValueError("publication package manifest differs")
        return package

    def _check_signers(self, authorization_wallet, directive_wallets):
        # Reject wrong identities or an insufficient cohort before reserving an
        # immutable intent. Loading the selected hotkeys never needs a coldkey.
        import bittensor as bt

        authorities = {
            account_id32(a.hotkey): a.signature_scheme
            for a in self.plan.supervisor.trusted_authorities
        }
        schemes = {
            bt.sp_core.CRYPTO_SR25519: "sr25519",
            bt.sp_core.CRYPTO_ED25519: "ed25519",
        }

        def checked(wallet):
            signer = bt.resolve_signer(wallet, role="hotkey")
            account = account_id32(signer.ss58_address)
            if account not in authorities or (
                schemes.get(signer.crypto_type) != authorities[account]
            ):
                raise ValueError("publication signer or crypto scheme is not trusted")
            return account

        checked(authorization_wallet)
        accounts = [checked(wallet) for wallet in directive_wallets]
        if len(set(accounts)) != len(accounts) or (
            len(accounts) < self.plan.supervisor.signature_threshold
        ):
            raise ValueError("publication requires a distinct trusted signing quorum")

    def _verify(self, publication, package=None):
        if digest(self.plan) != self._plan_digest:
            raise ValueError("publication plan changed")
        return verify_successor_round_publication(self.plan, publication, package)

    def history(self):
        prior, sequence, version, last_round = (
            self.plan.consent.predecessor_directive_sha256,
            self.plan.consent.predecessor_sequence,
            3,
            0,
        )
        result = []
        for key in sorted(self.journal.keys("publication"), key=int):
            item = SignedSuccessorRoundPublication.model_validate(
                self.journal.get("publication", key)
            )
            self._verify(item)
            if (
                key != str(item.intent.sequence)
                or item.intent.sequence != sequence + 1
                or item.intent.predecessor_version != version
                or item.intent.authorization.predecessor_directive_sha256 != prior
                or item.intent.round_sequence <= last_round
            ):
                raise ValueError("publication history is not one increasing predecessor chain")
            prior, sequence, version, last_round = (
                item.signed.directive_sha256,
                item.intent.sequence,
                4,
                item.intent.round_sequence,
            )
            result.append(item)
        return result

    @staticmethod
    def _intent_slot(sequence, round_sequence):
        # A directive sequence is consumed only by a complete retained publication.
        # Expired partial attempts keep separate immutable records for their round.
        return f"{sequence}:{round_sequence}"

    def _reserved_intent(self, *, sequence, round_sequence, predecessor, block):
        existing = None
        for slot in self.journal.keys("intent"):
            pending = SuccessorRoundPublicationIntent.model_validate(
                self.journal.get("intent", slot)
            )
            if pending.plan_sha256 != self._plan_digest or slot != self._intent_slot(
                pending.sequence, pending.round_sequence
            ):
                raise ValueError("reserved publication identity differs")
            if pending.sequence < sequence:
                continue
            if pending.sequence != sequence or (
                pending.authorization.predecessor_directive_sha256 != predecessor
            ):
                raise ValueError("reserved publication predecessor differs")
            if pending.round_sequence > round_sequence:
                raise ValueError("cannot return to a round older than a reserved publication")
            if pending.round_sequence == round_sequence:
                existing = pending
                continue
            if block <= pending.authorization.valid_through_block:
                raise ValueError("an unfinished publication is still within its original window")
            expired = self.journal.get("expired_intent", slot)
            if expired is None:
                self.journal.put(
                    "expired_intent",
                    slot,
                    {
                        "schema": "umi-expired-successor-publication-intent/1",
                        "intent_sha256": digest(pending),
                        "first_observed_expired_block": block,
                    },
                )
            elif (
                expired.get("schema") != "umi-expired-successor-publication-intent/1"
                or expired.get("intent_sha256") != digest(pending)
                or type(expired.get("first_observed_expired_block")) is not int
                or not pending.authorization.valid_through_block
                < expired["first_observed_expired_block"]
                <= block
            ):
                raise ValueError("expired publication audit record differs")
        return existing

    def build(
        self,
        prepared,
        *,
        finalized_block: int,
        authorization_wallet,
        directive_wallets,
        current_gate=None,
    ):
        """Caller must supply its current owned head; never an API request's block."""
        with self._locked():
            if digest(_canonical(SuccessorRoundPublicationPlan, self.plan)) != self._plan_digest:
                raise ValueError("publication plan changed")
            directive_wallets = tuple(directive_wallets)
            self._check_signers(authorization_wallet, directive_wallets)
            self.journal.observe(finalized_block)
            package = self._load(prepared)
            history = self.history()

            def current(authorization=None):
                nonlocal finalized_block
                if current_gate is not None:
                    block = current_gate(package)
                    self.journal.observe(block)
                    finalized_block = block
                    if authorization is not None and (
                        block < authorization.valid_from_block
                        or authorization.valid_through_block - block
                        < max(
                            self.plan.weights.mortality_period,
                            self.plan.minimum_activation_headroom_blocks,
                        )
                    ):
                        raise ValueError("publication lost its original activation window")

            current()
            for item in history:
                if item.intent.round_sequence == package.manifest.round_sequence:
                    self.journal.put(
                        "round", str(item.intent.round_sequence), package.package_sha256
                    )
                    verified = self._verify(item, package)
                    # Offline history remains readable; the guarded publisher
                    # must not return it as a current activation after expiry.
                    current(item.authorization.authorization)
                    return verified
            if history and package.manifest.round_sequence <= history[-1].intent.round_sequence:
                raise ValueError("cannot publish an older round after a newer round")
            prior = history[-1] if history else None
            sequence = (
                prior.intent.sequence if prior else self.plan.consent.predecessor_sequence
            ) + 1
            predecessor = (
                prior.signed.directive_sha256
                if prior
                else self.plan.consent.predecessor_directive_sha256
            )
            self.journal.put("round", str(package.manifest.round_sequence), package.package_sha256)
            slot = self._intent_slot(sequence, package.manifest.round_sequence)
            reserved = self._reserved_intent(
                sequence=sequence,
                round_sequence=package.manifest.round_sequence,
                predecessor=predecessor,
                block=finalized_block,
            )
            intent = _intent(
                self.plan,
                package,
                sequence=sequence,
                predecessor_version=4 if prior else 3,
                predecessor=predecessor,
                block=(
                    finalized_block if reserved is None else reserved.authorization.signed_at_block
                ),
            )
            self.journal.put("intent", slot, intent)
            if intent.authorization.valid_through_block - finalized_block < max(
                self.plan.weights.mortality_period, self.plan.minimum_activation_headroom_blocks
            ):
                raise ValueError("reserved publication expired; preserve history for recovery")
            auth = self.journal.get("authorization", slot)
            current(intent.authorization)
            authorization = (
                SignedCompetitionWeightAuthorization.model_validate(auth)
                if auth is not None
                else sign_competition_weight_authorization(
                    intent.authorization, authorization_wallet
                )
            )
            verify_competition_weight_authorization(
                authorization,
                package=package,
                trusted_authority_hotkeys=tuple(
                    a.hotkey for a in self.plan.supervisor.trusted_authorities
                ),
            )
            if authorization.authorization != intent.authorization:
                raise ValueError("authorization differs from reserved signing bytes")
            self.journal.put("authorization", slot, authorization)
            directive = _directive(self.plan, intent, authorization)
            signatures = []
            directive_digest = successor_supervisor_directive_digest(directive)
            for wallet in directive_wallets:
                current(intent.authorization)
                account = account_id32(wallet.hotkey.ss58_address)
                signature_slot = f"{slot}:{account.hex()}"
                raw_signature = self.journal.get("directive_signature", signature_slot)
                if raw_signature is None:
                    scheme, signature = sign_response_digest(wallet, directive_digest)
                    item = SupervisorDirectiveSignature(
                        hotkey=wallet.hotkey.ss58_address,
                        signature_scheme=scheme,
                        signature=signature,
                    )
                else:
                    item = SupervisorDirectiveSignature.model_validate(raw_signature)
                expected_scheme = next(
                    a.signature_scheme
                    for a in self.plan.supervisor.trusted_authorities
                    if account_id32(a.hotkey) == account
                )
                if (
                    account_id32(item.hotkey) != account
                    or item.signature_scheme != expected_scheme
                    or not verify_response_signature(
                        directive_digest,
                        hotkey_ss58=item.hotkey,
                        scheme=item.signature_scheme,
                        signature=item.signature,
                    )
                ):
                    raise ValueError("reserved directive signature differs or is invalid")
                self.journal.put("directive_signature", signature_slot, item)
                signatures.append(item)
            signed = SignedSuccessorSupervisorDirective(
                schema="umi-validator-supervisor-signed-directive/4",
                directive=directive,
                directive_sha256=successor_supervisor_directive_sha256(directive),
                directive_digest=successor_supervisor_directive_digest(directive).hex(),
                signatures=sorted(signatures, key=lambda s: account_id32(s.hotkey)),
            )
            publication = SignedSuccessorRoundPublication(
                schema="umi-signed-successor-round-publication/1",
                intent=intent,
                authorization=authorization,
                signed=signed,
            )
            self._verify(publication, package)
            current(intent.authorization)
            self.journal.put("publication", str(sequence), publication)
            return publication

    def page(self, *, after_version, after_sequence, after_directive_sha256, maximum=16):
        if type(maximum) is not int or not 1 <= maximum <= 16:
            raise ValueError("publication page size is outside its bound")
        with self._locked():
            history = self.history()
            if not history:
                raise ValueError("no successor publication is available")
            cursor = (after_version, after_sequence, after_directive_sha256)
            initial = (
                3,
                self.plan.consent.predecessor_sequence,
                self.plan.consent.predecessor_directive_sha256,
            )
            index = 0 if cursor == initial else None
            for position, item in enumerate(history, 1):
                if cursor == (4, item.intent.sequence, item.signed.directive_sha256):
                    index = position
            if index is None:
                raise ValueError("unknown successor publication cursor")
            items = [p.signed for p in history[index : index + maximum]]
            return SuccessorSupervisorDirectivePage(
                schema="umi-validator-supervisor-directive-page/4",
                after_version=after_version,
                after_sequence=after_sequence,
                after_directive_sha256=after_directive_sha256,
                directives=items,
                more=index + len(items) < len(history),
                head=items[-1] if items else history[-1].signed,
            )
