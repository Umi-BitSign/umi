"""Publish an approved reference row from current signed reward control.

This is common-authority delegation, not independent cohort certification. The
selected signed quorum commits the effective allocation; current native control
and complete registration proofs bind its projection to the reference's actual
row. No large reward package or already verified evidence is replayed here.
Directive selection belongs to the authenticated channel publisher.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .competition_chain import CompetitionChainConfig
from .competition_chain_state import (
    OwnedCompetitionChainObservation,
    validate_owned_weight_observation,
)
from .competition_cohort_reward_allocation import (
    CohortRewardAllocation,
    project_owned_reward_allocation,
)
from .competition_reward_control import OwnedRewardControlObservation, validate_owned_reward_control
from .competition_reward_decisions import DecisionSource, StandingRewardControlReader
from .competition_round_journal import RoundJournal
from .grandpa_finality import FINNEY_GENESIS_HASH
from .open_competition import digest, identity
from .protocol import canonical_json_bytes, sha256_hex
from .translation_reference_policy import (
    ApprovedTranslationReferencePolicy,
    SignedTranslationReferencePolicy,
    reference_policy_sha256,
    reference_policy_signature_digest,
    verify_reference_policy,
)
from .validator_supervisor import COMMON_SUPERVISOR_AUTHORITY_HOTKEY
from .weight_storage import subtensor_stored_weights


class ReferenceRowPending(ValueError):
    """Current native row must catch up before a reference approval can be issued."""

    def __init__(self, *, last_update: int, minimum_update: int):
        super().__init__("native reference row does not match the signed effective allocation")
        self.last_update, self.minimum_update = last_update, minimum_update


class TranslationReferenceApprovalPublisher:
    """Retain exact approvals before idempotent immutable publication.

    A single caller owns step() under the publication service's writer lease.
    The sink must create the named immutable object or verify its exact existing
    bytes. A lost acknowledgement retries those same bytes, without signing
    again. This does not select an image/directive or submit any chain call.
    """

    def __init__(
        self,
        root: Path,
        reader: StandingRewardControlReader,
        *,
        reference_hotkey: str,
        signer_loader: Callable[[], Any],
        publish_immutable: Callable[[str, bytes], None],
        maximum_bytes: int,
        progress: Callable[[dict], None] | None = None,
        authority_hotkey: str = COMMON_SUPERVISOR_AUTHORITY_HOTKEY,
    ):
        if type(reader) is not StandingRewardControlReader:
            raise TypeError("reference publication requires the selected reward control reader")
        if identity(reference_hotkey) not in {identity(k) for k in reader.series.validators}:
            raise ValueError("reference is not in the independently selected standing series")
        self.reader = reader
        self.reference_hotkey, self.authority_hotkey = reference_hotkey, authority_hotkey
        self.signer_loader, self.publish_immutable = signer_loader, publish_immutable
        self.progress = progress
        self.series_sha256, self.policy_sha256 = digest(reader.series), digest(reader.policy)
        self.journal = RoundJournal(
            root,
            {
                "schema": "umi-translation-reference-approval-publisher/1",
                "series_sha256": self.series_sha256,
                "policy_sha256": self.policy_sha256,
                "reference_account": identity(reference_hotkey),
                "authority_account": identity(authority_hotkey),
            },
            maximum_bytes=maximum_bytes,
        )

    def _event(self, stage, started, *, complete=False, retrying=False):
        if self.progress is not None:
            self.progress(
                dict(
                    stage=stage,
                    completed=int(complete),
                    total=1,
                    elapsed_seconds=time.monotonic() - started,
                    percent=100 if complete else 0,
                    eta_seconds=0 if complete else None,
                    planning_seconds=None if complete or retrying else [1, 120],
                    eta_basis="bounded signed-control/native projection and immutable upload; "
                    "channel selection and external adoption remain separate",
                    retrying=retrying,
                    stalled=retrying,
                )
            )

    def prepare_policy(
        self,
        *,
        control: OwnedRewardControlObservation,
        source: DecisionSource,
        allocation: CohortRewardAllocation,
        chain: OwnedCompetitionChainObservation,
        chain_config: CompetitionChainConfig,
    ) -> ApprovedTranslationReferencePolicy:
        if (
            digest(self.reader.series) != self.series_sha256
            or digest(self.reader.policy) != self.policy_sha256
        ):
            raise ValueError("selected reference publication authority changed")
        validate_owned_weight_observation(chain)
        selected = self.reader.select(control, source)
        if (
            selected.state != "selected"
            or selected.activation is None
            or selected.effective_at_block is None
            or chain.snapshot != control.snapshot
            or digest(chain_config) != self.reader.chain_config_sha256
            or chain.registered_uid_count != 256
            or identity(chain.validator_hotkey) != identity(self.reference_hotkey)
            or not chain.validator_permit
        ):
            raise ValueError("reference approval lacks current effective native selection")
        allocation = CohortRewardAllocation.model_validate_json(canonical_json_bytes(allocation))
        expected = (
            selected.activation.effective_allocation_sha256 or selected.activation.allocation_sha256
        )
        if digest(allocation) != expected:
            raise ValueError(
                "reference approval allocation differs from the signed current decision"
            )
        projection = project_owned_reward_allocation(
            allocation, chain, self.reader.policy, chain_config=chain_config
        )
        amounts = dict(zip(projection.uids, projection.weights, strict=True))
        weights = subtensor_stored_weights(
            tuple(amounts.get(uid, 0) for uid in range(chain.registered_uid_count))
        )
        row = tuple(enumerate(weights))
        cohort = next(
            p for p in self.reader.series.cohorts if digest(p) == selected.activation.cohort_sha256
        )
        minimum = max(selected.effective_at_block, cohort.not_before_block)
        if tuple(chain.validator_row) != row or chain.validator_last_update < minimum:
            raise ReferenceRowPending(
                last_update=chain.validator_last_update, minimum_update=minimum
            )
        # The body is stable across reference refreshes and daemon restarts.
        # Registration changes or a new signed activation get a new approval.
        result = ApprovedTranslationReferencePolicy(
            schema="umi-translation-reference-policy/2",
            network="finney",
            genesis_hash="0x" + FINNEY_GENESIS_HASH,
            netuid=78,
            mechanism_id=0,
            implementation_profile="umi-certified-reference-follower/1",
            reference_hotkey=self.reference_hotkey,
            minimum_reference_update_block=minimum,
            first_cohort_sequence=cohort.sequence,
            lifetime="until_signed_supersession",
            reference_activity_rule="owned_finalized_epoch_activity/1",
            legacy_recovery_rule="native_reconcile_before_first_new_write/1",
            row_rule="exact_proven_and_authority_approved_reference_row/1",
            expected_row_sha256=sha256_hex(canonical_json_bytes(row)),
        )
        validate_owned_weight_observation(chain)
        validate_owned_reward_control(
            control,
            expected_control_hotkey=self.reader.series.control_hotkey,
            expected_chain_config_sha256=self.reader.chain_config_sha256,
        )
        return result

    def step(self, **inputs):
        with self.journal.locked():
            return self._step(**inputs)

    def published_payload(self, policy: ApprovedTranslationReferencePolicy) -> bytes:
        """Return the retained exact signature only after immutable distribution."""
        key = reference_policy_sha256(policy)
        retained = self.journal.get("reference_approval", key)
        receipt = self.journal.get("reference_approval_published", key)
        if retained is None or receipt != {
            "schema": "umi-reference-approval-distributed/1",
            "policy_sha256": key,
            "signed_sha256": digest(retained),
        }:
            raise ValueError("reference approval distribution needs completion or restoration")
        raw = canonical_json_bytes(retained)
        verify_reference_policy(
            raw, expected_policy_sha256=key, expected_authority_hotkey=self.authority_hotkey
        )
        return raw

    def _step(self, **inputs):
        started = time.monotonic()
        self._event("reference_approval_preparation", started)
        try:
            policy = self.prepare_policy(**inputs)
            key = reference_policy_sha256(policy)
            retained = self.journal.get("reference_approval", key)
            published = self.journal.get("reference_approval_published", key)
            if retained is None:
                if published is not None:
                    raise ValueError(
                        "published reference approval requires restoration of signed bytes"
                    )
                signer = self.signer_loader()
                if identity(signer.ss58_address) != identity(self.authority_hotkey):
                    raise ValueError("reference approval signer differs from the release authority")
                scheme = {0: "ed25519", 1: "sr25519"}.get(signer.crypto_type)
                if scheme is None or type(signer.crypto_type) is bool:
                    raise ValueError("reference approval signer scheme is unsupported")
                signed = SignedTranslationReferencePolicy(
                    schema="umi-signed-translation-reference-policy/1",
                    policy=policy,
                    authority_hotkey=self.authority_hotkey,
                    signature_scheme=scheme,
                    signature="0x"
                    + bytes(signer.sign(reference_policy_signature_digest(policy))).hex(),
                )
                # Authenticate the actual signed result before retaining it.
                raw = canonical_json_bytes(signed)
                verify_reference_policy(
                    raw, expected_policy_sha256=key, expected_authority_hotkey=self.authority_hotkey
                )
                self.journal.put("reference_approval", key, signed)
            else:
                raw = canonical_json_bytes(retained)
                verify_reference_policy(
                    raw, expected_policy_sha256=key, expected_authority_hotkey=self.authority_hotkey
                )
            self._event("reference_approval_preparation", started, complete=True)
            self._event("reference_approval_distribution", started)
            receipt = {
                "schema": "umi-reference-approval-distributed/1",
                "policy_sha256": key,
                "signed_sha256": digest(retained) if retained is not None else digest(signed),
            }
            if published is not None and published != receipt:
                raise ValueError("reference publication receipt requires explicit repair")
            if published is None:
                self.publish_immutable(
                    "validator-supervisor/translation-reference-policies/" + key + ".json", raw
                )
                self.journal.put("reference_approval_published", key, receipt)
            self._event("reference_approval_distribution", started, complete=True)
            return policy
        except BaseException:
            self._event("reference_approval_retry", started, retrying=True)
            raise
