"""Bridge eligibility and deterministic weight allocation from supplied observations."""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Sequence
from datetime import datetime
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from typing_extensions import Self

from ..chain import _public_axon_origin
from ..encoding import account_id32
from ..encoding import datetime_to_unix_ms as _datetime_ms
from ..grandpa_finality import FINNEY_GENESIS_HASH
from ..protocol import BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes
from ..registration_funding_snapshot import FundingSnapshot, matching_funders
from .policy import (
    PositiveInt,
    RegistrationBridgeFrozenPolicyBody,
    RegistrationBridgeFundingPolicyBody,
    SignedRegistrationBridgePolicy,
    UInt,
    _require,
    verify_registration_bridge_policy,
)


class RegistrationBridgeParticipant(StrictProtocolModel):
    uid: Annotated[int, Field(ge=0, le=255)]
    hotkey: str
    coldkey: str
    validator_permit: bool
    last_update: UInt
    registered_at_block: UInt
    origin: str | None

    @field_validator("hotkey", "coldkey")
    @classmethod
    def hotkey_address(cls, value: str) -> str:
        account_id32(value)
        return value

    @field_validator("origin")
    @classmethod
    def endpoint(cls, value: str | None) -> str | None:
        if value is not None and _bridge_public_origin(value) != value:
            raise ValueError("bridge origin must be a canonical public IP HTTPS endpoint")
        return value


class RegistrationBridgeObservation(StrictProtocolModel):
    network: Literal["finney"]
    genesis_hash: Literal[f"0x{FINNEY_GENESIS_HASH}"]
    block_number: PositiveInt
    block_hash: BlockHash
    block_timestamp_ms: PositiveInt
    runtime_spec_version: UInt
    mechanism_count: UInt
    commit_reveal_enabled: bool
    commit_reveal_version: UInt
    reveal_period_epochs: UInt
    weights_version_key: UInt
    min_allowed_weights: UInt
    max_weights_limit: Annotated[int, Field(ge=0, le=65535)]
    max_allowed_uids: UInt
    weights_set_rate_limit: UInt
    activity_cutoff_factor_milli: UInt
    tempo: UInt
    block_time_seconds: float
    total_pending_commit_count: UInt
    subnet_owner_hotkey: str
    owner_associated_hotkeys: Annotated[list[str], Field(min_length=1, max_length=4096)]
    participants: Annotated[
        list[RegistrationBridgeParticipant], Field(min_length=256, max_length=256)
    ]
    validator_hotkey: str
    validator_row: Annotated[list[list[int]], Field(max_length=256)]
    storage_proofs_verified: Literal[False] = False

    @model_validator(mode="after")
    def bindings(self) -> Self:
        if [p.uid for p in self.participants] != list(range(256)):
            raise ValueError("bridge requires the exact registered UID domain 0..255")
        accounts = [account_id32(p.hotkey) for p in self.participants]
        if len(set(accounts)) != 256:
            raise ValueError("bridge roster has duplicate hotkeys")
        owners = [account_id32(h) for h in self.owner_associated_hotkeys]
        if owners != sorted(set(owners)):
            raise ValueError("bridge owner hotkeys must be unique and sorted")
        owner = account_id32(self.subnet_owner_hotkey)
        if owner not in owners or accounts[0] != owner:
            raise ValueError("bridge subnet owner must bind UID0 and the burn exclusion set")
        if account_id32(self.validator_hotkey) not in accounts:
            raise ValueError("bridge writer is not uniquely registered")
        if any(
            p.last_update > self.block_number or p.registered_at_block > self.block_number
            for p in self.participants
        ):
            raise ValueError("bridge roster contains future chain state")
        _validate_row(self.validator_row, allow_sparse=True)
        return self


class RegistrationBridgeHealth(StrictProtocolModel):
    uid: Annotated[int, Field(ge=0, le=255)]
    hotkey: str
    origin: str
    checked_at_unix_ms: PositiveInt
    available: bool
    reason_code: Literal["http_200", "endpoint_unavailable"]
    body_sha256: Hex32 | None


class RegistrationBridgeDecision(StrictProtocolModel):
    action: Literal["wait", "submit", "retiring"]
    reason_code: str
    finalized_block: PositiveInt
    next_action_block: PositiveInt | None
    expected_row: Annotated[list[list[int]], Field(min_length=256, max_length=256)]
    roster_sha256: Hex32
    eligible_count: Annotated[int, Field(ge=1, le=255)]
    eligible_coldkey_count: Annotated[int, Field(ge=1, le=255)]
    validator_uid: Annotated[int, Field(ge=0, le=255)]
    validator_last_update: UInt


def registration_bridge_roster_sha256(observation: RegistrationBridgeObservation) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "participants": [
                    p.model_dump(mode="json", exclude={"last_update"})
                    for p in observation.participants
                ],
                "owner_associated_hotkeys": observation.owner_associated_hotkeys,
            }
        )
    ).hexdigest()


def _registered_candidates(
    observation: RegistrationBridgeObservation,
) -> list[RegistrationBridgeParticipant]:
    owner_accounts = {account_id32(h) for h in observation.owner_associated_hotkeys}
    return [
        p
        for p in observation.participants
        if p.uid != 0 and not p.validator_permit and account_id32(p.hotkey) not in owner_accounts
    ]


def _bridge_public_origin(origin: str) -> str:
    canonical = _public_axon_origin(origin)
    address = ipaddress.ip_address(urlsplit(canonical).hostname or "")
    _require(
        address.is_global
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_reserved
        and not getattr(address, "scope_id", None),
        "health_origin_not_public_unicast",
    )
    if getattr(address, "ipv4_mapped", None) is not None:
        mapped = address.ipv4_mapped
        _require(
            mapped.is_global and not mapped.is_multicast and not mapped.is_reserved,
            "health_origin_not_public_unicast",
        )
    return canonical


def _coldkey_group_row(
    live: Sequence[RegistrationBridgeParticipant],
) -> tuple[list[list[int]], int]:
    """Equal integer group budgets; UID order breaks the per-group remainder tie.

    B = 65535 * min(group sizes). Every group receives exactly B, and a
    smallest group's per-UID weight is 65535, preserving the row under the
    runtime's maximum-weight scaling. A coldkey is only an ownership proxy,
    not evidence that separate coldkeys belong to separate people.
    """
    _require(bool(live), "no_live_eligible_miners")
    groups: dict[bytes, list[int]] = {}
    for participant in live:
        groups.setdefault(account_id32(participant.coldkey), []).append(participant.uid)
    return _equal_group_row(list(groups.values())), len(groups)


def _coldkey_ip_groups(
    live: Sequence[RegistrationBridgeParticipant],
    *,
    funding_snapshot: FundingSnapshot | None = None,
) -> list[list[int]]:
    """Merge live UIDs sharing an owner or public IP, transitively and without ports.

    IPs are an infrastructure cap, not proof of independent operators. Preserve
    the coldkey cap across multiple IPs. Mapped IPv4 and native IPv4 identify
    the same destination. Failed/non-candidate endpoints cannot bridge groups.
    """
    _require(bool(live), "no_live_eligible_miners")
    parent = {p.uid: p.uid for p in live}
    _require(len(parent) == len(live), "duplicate_live_uid")

    def root(uid: int) -> int:
        while parent[uid] != uid:
            parent[uid] = parent[parent[uid]]
            uid = parent[uid]
        return uid

    owners, addresses, funders = {}, {}, {}
    funding = matching_funders(funding_snapshot, live) if funding_snapshot is not None else {}
    for participant in sorted(live, key=lambda p: p.uid):
        _require(participant.origin is not None, "live_endpoint_missing")
        canonical = _bridge_public_origin(participant.origin)
        address = ipaddress.ip_address(urlsplit(canonical).hostname or "")
        address = getattr(address, "ipv4_mapped", None) or address
        edges = [
            (owners, account_id32(participant.coldkey)),
            (addresses, address),
        ]
        if participant.uid in funding:
            edges.append((funders, funding[participant.uid]))
        for index, key in edges:
            prior = index.setdefault(key, participant.uid)
            left, right = root(participant.uid), root(prior)
            parent[max(left, right)] = min(left, right)
    groups = {}
    for uid in sorted(parent):
        groups.setdefault(root(uid), []).append(uid)
    return [groups[key] for key in sorted(groups)]


def _equal_group_row(groups: Sequence[Sequence[int]]) -> list[list[int]]:
    _require(bool(groups) and all(groups), "no_live_eligible_miners")
    budget = 65_535 * min(len(uids) for uids in groups)
    row = [[uid, 0] for uid in range(256)]
    for uids in groups:
        quotient, remainder = divmod(budget, len(uids))
        for index, uid in enumerate(sorted(uids)):
            row[uid][1] = quotient + (index < remainder)
    _validate_row(row)
    _require(max(pair[1] for pair in row) == 65_535, "group_weight_scale_invalid")
    return row


def _validate_row(row: list[list[int]], *, allow_sparse: bool = False) -> None:
    _require(
        all(
            isinstance(pair, list)
            and len(pair) == 2
            and all(type(value) is int for value in pair)
            and 0 <= pair[0] < 256
            and 0 <= pair[1] <= 65535
            for pair in row
        ),
        "row_shape",
    )
    uids = [pair[0] for pair in row]
    _require(uids == sorted(set(uids)), "row_order")
    if not allow_sparse:
        _require(uids == list(range(256)), "row_domain")


def validate_registration_bridge_chain(
    policy: SignedRegistrationBridgePolicy,
    observation: RegistrationBridgeObservation,
    *,
    expected_revision: str,
    now: datetime,
) -> RegistrationBridgeParticipant:
    verify_registration_bridge_policy(
        policy, expected_revision=expected_revision, current_block=observation.block_number
    )
    age = _datetime_ms(now) - observation.block_timestamp_ms
    _require(
        -30_000 <= age <= policy.body.maximum_finalized_age_seconds * 1000,
        "finalized_head_stale_or_future",
    )
    body = policy.body
    gates = {
        "mechanism_count": body.required_mechanism_count,
        "commit_reveal_enabled": body.required_commit_reveal_enabled,
        "commit_reveal_version": body.required_commit_reveal_version,
        "reveal_period_epochs": body.required_reveal_period_epochs,
        "weights_version_key": body.weights_version_key,
        "min_allowed_weights": body.required_min_allowed_weights,
        "max_allowed_uids": body.required_max_allowed_uids,
        "weights_set_rate_limit": body.required_weights_set_rate_limit,
        "activity_cutoff_factor_milli": body.required_activity_cutoff_factor_milli,
        "tempo": body.required_tempo,
        "block_time_seconds": 12.0,
        "total_pending_commit_count": 0,
    }
    for field, expected in gates.items():
        _require(getattr(observation, field) == expected, f"{field}_changed")
    _require(
        max(1, observation.activity_cutoff_factor_milli * observation.tempo // 1000)
        == body.required_activity_cutoff_blocks,
        "activity_cutoff_changed",
    )
    writer = next(p for p in observation.participants if p.hotkey == observation.validator_hotkey)
    _require(writer.validator_permit, "validator_permit_missing")
    return writer


def validate_registration_bridge_observation(
    policy: SignedRegistrationBridgePolicy,
    observation: RegistrationBridgeObservation,
    health: Sequence[RegistrationBridgeHealth],
    *,
    expected_revision: str,
    now: datetime,
    health_observation: RegistrationBridgeObservation | None = None,
) -> RegistrationBridgeDecision:
    writer = validate_registration_bridge_chain(
        policy, observation, expected_revision=expected_revision, now=now
    )
    probed = health_observation if health_observation is not None else observation
    _require(probed.validator_hotkey == observation.validator_hotkey, "health_writer_changed")
    _require(observation.block_number >= probed.block_number, "health_finality_rollback")
    _require(
        observation.block_number != probed.block_number
        or observation.block_hash == probed.block_hash,
        "health_finality_equivocation",
    )
    if observation.block_number == probed.block_number:
        _require(
            registration_bridge_roster_sha256(observation)
            == registration_bridge_roster_sha256(probed),
            "health_roster_equivocation",
        )
    prior_writer = next(p for p in probed.participants if p.hotkey == probed.validator_hotkey)
    _require(
        _health_registration_identity(writer) == _health_registration_identity(prior_writer),
        "health_writer_registration_changed",
    )
    current = {p.uid: p for p in _registered_candidates(observation)}
    expected_health = [p for p in _registered_candidates(probed) if p.origin is not None]
    _require([h.uid for h in health] == [p.uid for p in expected_health], "health_coverage_changed")
    live = []
    for receipt, participant in zip(health, expected_health, strict=True):
        _require(
            receipt.hotkey == participant.hotkey and receipt.origin == participant.origin,
            "health_identity_changed",
        )
        _require(
            0
            <= _datetime_ms(now) - receipt.checked_at_unix_ms
            <= policy.body.health_ttl_seconds * 1000,
            "health_expired",
        )
        _require(
            receipt.available == (receipt.reason_code == "http_200")
            and receipt.available == (receipt.body_sha256 is not None),
            "health_result_invalid",
        )
        candidate = current.get(participant.uid)
        if (
            receipt.available
            and candidate is not None
            and _health_registration_identity(candidate)
            == _health_registration_identity(participant)
        ):
            live.append(candidate)
    if isinstance(policy.body, RegistrationBridgeFrozenPolicyBody):
        retained = {
            (p.uid, account_id32(p.hotkey), p.registered_at_block)
            for p in policy.body.registration_snapshot.participants
        }
        live = [
            p for p in live if (p.uid, account_id32(p.hotkey), p.registered_at_block) in retained
        ]
    _require(bool(live), "no_live_eligible_miners")
    # Historical signed policies retain their exact allocation semantics.
    # A new signed rule is required to enable the IP cap.
    row, coldkey_count = _coldkey_group_row(live)
    if policy.body.reward_rule == "equal_live_coldkey_ip_groups/1":
        row = _equal_group_row(_coldkey_ip_groups(live))
    elif isinstance(policy.body, RegistrationBridgeFundingPolicyBody):
        row = _equal_group_row(
            _coldkey_ip_groups(live, funding_snapshot=policy.body.funding_snapshot)
        )
    _require(
        observation.max_weights_limit > 0
        and sum(pair[1] for pair in row) * observation.max_weights_limit >= 65_535 * 65_535,
        "row_exceeds_max_weight_ratio",
    )
    body = policy.body
    refresh = writer.last_update + body.required_activity_cutoff_blocks - body.refresh_margin_blocks
    rate_ready = writer.last_update + body.required_weights_set_rate_limit
    newest_registration = max(p.registered_at_block for p in live)
    if observation.block_number + body.submission_headroom_blocks >= body.submission_limit:
        action, reason, next_block = "retiring", "submission_cutoff_reached", None
    elif observation.block_number <= newest_registration:
        action, reason, next_block = (
            "wait",
            "registration_must_precede_weight",
            newest_registration + 1,
        )
    elif (
        observation.validator_row == row
        and writer.last_update > newest_registration
        and observation.block_number < refresh
    ):
        action, reason, next_block = "wait", "exact_row_active", refresh
    elif observation.block_number < rate_ready:
        action, reason, next_block = "wait", "weights_rate_limit_not_elapsed", rate_ready
    else:
        action, reason, next_block = "submit", "live_registered_row_due", observation.block_number
    return RegistrationBridgeDecision(
        action=action,
        reason_code=reason,
        finalized_block=observation.block_number,
        next_action_block=next_block,
        expected_row=row,
        roster_sha256=registration_bridge_roster_sha256(observation),
        eligible_count=len(live),
        eligible_coldkey_count=coldkey_count,
        validator_uid=writer.uid,
        validator_last_update=writer.last_update,
    )


def _health_registration_identity(participant: RegistrationBridgeParticipant) -> tuple:
    """Bind a probe to its registration; unrelated weight writes may advance."""
    return (
        participant.uid,
        account_id32(participant.hotkey),
        account_id32(participant.coldkey),
        participant.registered_at_block,
        participant.origin,
        participant.validator_permit,
    )
