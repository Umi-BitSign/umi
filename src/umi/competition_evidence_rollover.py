"""Require a certified replacement before retiring the current reward worker.

A launch time is deliberately not an input. Call qualification while the old
worker/publisher continue renewing. Only an eligible replacement permits the
caller to begin stopped migration; its chain proof must be refreshed after the
heavy copy/history audit. This capability never signs, submits, or stops services.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field

from .competition_chain_state import validate_owned_weight_observation
from .competition_history_compatibility import verify_history_compatibility
from .competition_supervisor import (
    advance_successor_supervisor_directive_state,
    load_bound_successor_replay_package,
    verify_bound_successor_chain_authorization,
)
from .competition_weights import validate_weight_preflight
from .encoding import account_id32
from .protocol import canonical_json_bytes

_ISSUER = object()


class EvidenceRolloverPending(ValueError):
    """Leave the existing worker selected and renewing; retry when ready."""


@dataclass(frozen=True)
class EligibleEvidenceRollover:
    _config: object
    _consent: object
    _prior_state: object
    _signed: object
    _package: object
    _authorization_bytes: bytes
    _chain_config: object
    _observation: object
    _issuer: object = field(repr=False)

    def recheck(self, *, config, consent, observation=None):
        if (
            type(self) is not EligibleEvidenceRollover
            or self._issuer is not _ISSUER
            or canonical_json_bytes(config) != canonical_json_bytes(self._config)
            or canonical_json_bytes(consent) != canonical_json_bytes(self._consent)
        ):
            raise ValueError("replacement capability differs from this migration")
        current = self._observation if observation is None else observation
        validate_owned_weight_observation(current)
        if (
            account_id32(current.validator_hotkey) != account_id32(config.validator_hotkey)
            or current.block < self._observation.block
            or (
                current.block == self._observation.block
                and current.block_hash != self._observation.block_hash
            )
        ):
            raise ValueError("replacement proof belongs to another validator or rolled back")
        grant = verify_history_compatibility(consent.history_compatibility, config=config)
        prior = self._prior_state
        directive = self._signed.directive
        target = directive.replay_package
        if (
            prior.accepted_mode != "competition_weights"
            or prior.continuity_stopped is not False
            or prior.continuity_round_sequence is None
            or target is None
            or target.round_sequence <= prior.continuity_round_sequence
            or directive.mode != "competition_weights"
            or directive.sequence != grant.predecessor_sequence + 1
        ):
            raise ValueError("migration needs a newer certified allocation after active renewal")
        advance_successor_supervisor_directive_state(
            self._signed,
            config=config,
            operator_consent=consent,
            finalized_block=current.block,
            prior_state=prior,
        )
        authorization = verify_bound_successor_chain_authorization(
            self._authorization_bytes,
            directive=directive,
            config=config,
            package=self._package,
        )
        if authorization.continuation is None:
            raise ValueError("migration requires the replacement's timely certified admission")
        validate_weight_preflight(
            self._package,
            authorization,
            current,
            self._chain_config,
            submission=True,
        )
        remaining = (
            min(
                directive.valid_through_block,
                authorization.valid_through_block - authorization.mortality_period,
                grant.migration_valid_through_block,
            )
            - current.block
        )
        if remaining < grant.minimum_transition_headroom_blocks:
            raise ValueError("replacement lease lacks signed transition headroom")
        return current

    def validate_migration(self, *, plan, config, consent, receipt, observation):
        """Bind the refreshed readiness proof to the exact stopped transition."""
        seal = receipt.evidence_migration
        if (
            seal is None
            or plan.compatibility_sha256
            != hashlib.sha256(canonical_json_bytes(consent.history_compatibility)).hexdigest()
            or bytes.fromhex(seal.predecessor_state_hex) != canonical_json_bytes(self._prior_state)
        ):
            raise ValueError("replacement readiness differs from the migration boundary")
        return self.recheck(config=config, consent=consent, observation=observation)


async def qualify_evidence_rollover(
    *,
    config,
    consent,
    prior_state,
    signed_directive,
    package_path,
    authorization_bytes,
    chain_config,
    observe_after_audit,
):
    """Verify the replacement without any changes to active C4 controls.

    Missing publication is a wait state, including at/after a future launch.
    Invalid publications raise and likewise cannot mint a stopped capability.
    The returned proof is short-lived; the stopped phase must obtain a new one.
    """
    if signed_directive is None or package_path is None or authorization_bytes is None:
        raise EvidenceRolloverPending("certified replacement unavailable; keep current renewals")
    if consent.history_compatibility is None:
        raise ValueError("replacement requires explicit signed historical compatibility")
    directive = signed_directive.directive
    if directive.mode != "competition_weights" or directive.release is None:
        raise EvidenceRolloverPending("replacement is not ready for weight execution")
    package = load_bound_successor_replay_package(
        package_path,
        directive=directive,
        observed_release=directive.release.replay_release_identity,
    )
    verify_bound_successor_chain_authorization(
        authorization_bytes,
        directive=directive,
        config=config,
        package=package,
    )
    audited_at = time.monotonic_ns()
    observation = await observe_after_audit()
    validate_owned_weight_observation(observation)
    if observation.captured_monotonic_ns < audited_at:
        raise ValueError("replacement needs fresh proof after package/certificate audit")
    result = EligibleEvidenceRollover(
        config,
        consent,
        prior_state,
        signed_directive,
        package,
        authorization_bytes,
        chain_config,
        observation,
        _ISSUER,
    )
    result.recheck(config=config, consent=consent)
    return result
